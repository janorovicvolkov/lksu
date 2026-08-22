use std::fs;
use std::path::Path;
use anyhow::{anyhow, Context, Result};
use colored::*;
use rusqlite::{params, Connection};
use crate::config::{Permission, UserLists};

// Opens (creating if needed) the sqlite db backing the permitted-users
// list, and makes sure the "permissions" table exists. Schema:
//   permissions(username TEXT, command TEXT, PRIMARY KEY (username, command))
// A row with command = "ALL" grants Permission::All for that user, see
// config::UserLists::load, which reads the same table.
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

// Add "username" to the permitted list with "commands" or "["ALL"]".
// Fails if the user is already listed, use "edit_user" for that.
pub fn add_user(path: &str, username: &str, commands: &[String]) -> Result<()> {
    validate(username, commands)?;
    let conn = open_db(path)?;
    if user_exists(&conn, username)? {
        return Err(anyhow!(
            "{} is already in the permitted list! Use --edit-user instead",
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

// Replace the command list for an already-permitted "username".
pub fn edit_user(path: &str, username: &str, commands: &[String]) -> Result<()> {
    validate(username, commands)?;
    let mut conn = open_db(path)?;
    if !user_exists(&conn, username)? {
        return Err(anyhow!(
            "{} is not in the permitted list! Use --add-user instead",
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

// Remove "username" from the permitted list entirely.
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

// Print what "user" is permitted to run through lksu (`--command-list`).
pub fn print_permitted_commands(user: &str, lists: &UserLists) {
    match lists.permissions_for(user) {
        Some(Permission::All) => {
            crate::ui::info(&format!("{} is permitted to run: {}.", user, "ALL commands".bright_green()))
        }
        Some(Permission::Commands(cmds)) => {
            crate::ui::info(&format!("{} is permitted to run:", user));
            for c in cmds {
                println!("  > {}", c.bright_green());
            }
        }
        None => crate::ui::info(&format!("{} is not permitted to run any commands.", user)),
    }
}

// One row of "--user-list" output.
pub struct SystemAccount {
    pub username: String,
    pub uid: u32,
}

// List real accounts from "/etc/passwd": root plus anything at or
// above "min_uid" (1000 on most distros, matching /etc/login.defs
// UID_MIN), so system/service accounts don't clutter the output.
pub fn list_system_accounts(min_uid: u32) -> Result<Vec<SystemAccount>> {
    let contents = fs::read_to_string("/etc/passwd").context("failed to read /etc/passwd")?;
    let mut accounts = Vec::new();
    for line in contents.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 3 {
            continue;
        }
        let username = fields[0];
        let Ok(uid) = fields[2].parse::<u32>() else {
            continue;
        };
        if uid == 0 || uid >= min_uid {
            accounts.push(SystemAccount {
                username: username.to_string(),
                uid,
            });
        }
    }
    accounts.sort_by_key(|a| a.uid);
    Ok(accounts)
}

// Print "--user-list" output.
pub fn print_system_accounts(accounts: &[SystemAccount]) {
    if accounts.is_empty() {
        crate::ui::warning("No accounts found!");
        return;
    }
    crate::ui::info("All accounts on this system:");
    for account in accounts {
        let uid_ui = format!("UID: {}", account.uid);
        println!("  > {} [ {} ]", account.username.bright_green(), uid_ui.bright_green());
    }
}
