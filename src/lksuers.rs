use std::fs;
use std::path::Path;
use std::collections::HashMap;
use anyhow::{anyhow, Context, Result};
use colored::*;
use rusqlite::{params, Connection};

fn open_db(path: &str) -> Result<Connection> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite db at {}", path))?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS permissions (
            username TEXT NOT NULL,
            command  TEXT NOT NULL,
            PRIMARY KEY (username, command)
        )",
        [],
    )
    .context("failed to initialize permissions table")?;
    Ok(conn)
}

fn user_exists(conn: &Connection, username: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM permissions WHERE username = ?1)",
        params![username],
        |row| row.get(0),
    )
    .context("failed to check the permitted list")
}

pub fn add_user(path: &str, username: &str, commands: &[String]) -> Result<()> {
    validate(username, commands)?;
    let conn = open_db(path)?;
    if user_exists(&conn, username)? {
        return Err(anyhow!(
            "{} is already in the permitted list! Use --edit instead",
            username
        ));
    }
    for command in commands {
        conn.execute(
            "INSERT INTO permissions (username, command) VALUES (?1, ?2)",
            params![username, command],
        )
        .context("failed to write to the permitted list")?;
    }
    crate::ui::success(&format!("{} is added to the permitted list!", username));
    Ok(())
}

pub fn edit_user(path: &str, username: &str, commands: &[String]) -> Result<()> {
    validate(username, commands)?;
    let mut conn = open_db(path)?;
    if !user_exists(&conn, username)? {
        return Err(anyhow!(
            "{} is not in the permitted list! Use --add instead",
            username
        ));
    }
    let tx = conn
        .transaction()
        .context("failed to start a transaction")?;
    tx.execute(
        "DELETE FROM permissions WHERE username = ?1",
        params![username],
    )
    .context("failed to clear previous permissions")?;
    for command in commands {
        tx.execute(
            "INSERT INTO permissions (username, command) VALUES (?1, ?2)",
            params![username, command],
        )
        .context("failed to write to the permitted list")?;
    }
    tx.commit().context("failed to save the permitted list")?;
    crate::ui::success(&format!("Permissions for {} has been updated!", username));
    Ok(())
}

pub fn remove_user(path: &str, username: &str) -> Result<()> {
    let conn = open_db(path)?;
    let affected = conn
        .execute(
            "DELETE FROM permissions WHERE username = ?1",
            params![username],
        )
        .context("failed to write to the permitted list")?;
    if affected == 0 {
        return Err(anyhow!("{} is not in the permitted list", username));
    }
    crate::ui::success(&format!(
        "{} has been removed from the permitted list!",
        username
    ));
    Ok(())
}

fn validate(username: &str, commands: &[String]) -> Result<()> {
    if username.trim().is_empty() {
        return Err(anyhow!("username cannot be empty"));
    }
    if commands.is_empty() {
        return Err(anyhow!("provide at least one command or \"ALL\""));
    }
    Ok(())
}

pub struct SystemAccount {
    pub username: String,
    pub uid: u32,
    pub command: Vec<String>,
}

fn read_uid_map() -> Result<HashMap<String, u32>> {
    let contents = fs::read_to_string("/etc/passwd").context("failed to read /etc/passwd")?;
    let mut map = HashMap::new();
    for line in contents.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 3 {
            continue;
        }
        if let Ok(uid) = fields[2].parse::<u32>() {
            map.insert(fields[0].to_string(), uid);
        }
    }
    Ok(map)
}

pub fn list_permitted_users(path: &str) -> Result<Vec<SystemAccount>> {
    let conn = open_db(path)?;
    let mut stmt = conn
        .prepare("SELECT username, command FROM permissions ORDER BY username, command")
        .context("failed to query the permitted list")?;

    let rows = stmt
        .query_map([], |row| {
            let username: String = row.get(0)?;
            let command: String = row.get(1)?;
            Ok((username, command))
        })
        .context("failed to query the permitted list")?;
    let uid_map = read_uid_map()?;
    let mut accounts: Vec<SystemAccount> = Vec::new();
    for row in rows {
        let (username, command) = row.context("failed to read row from permitted list")?;
        if let Some(last) = accounts.last_mut() {
            if last.username == username {
                last.command.push(command);
                continue;
            }
        }
        let uid = uid_map.get(&username).copied().unwrap_or(u32::MAX);
        accounts.push(SystemAccount {
            username,
            uid,
            command: vec![command],
        });
    }
    Ok(accounts)
}

pub fn print_permitted_users(accounts: &[SystemAccount]) {
    if accounts.is_empty() {
        crate::ui::warning("No accounts found!");
        return;
    }
    crate::ui::info("All accounts on this system:");
    for account in accounts {
        let uid_ui = format!("[ UID: {} ]", account.uid);
        println!("");
        println!(
            "• {} {}",
            account.username.bright_cyan(),
            uid_ui.bright_green()
        );
        if account.command.iter().any(|c| c == "ALL") {
            println!("  ➔ Permitted: {}", "ALL commands".bright_green());
        } else {
            println!("  ➔ Permitted:");
            for command in &account.command {
                println!("    ‣ {}", command.bright_green());
            }
        }
    }
}
