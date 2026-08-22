use std::io::Write;
use std::process::{Command, Stdio};
use anyhow::{anyhow, Context, Result};
use colored::*;
use nix::unistd::{setgid, setuid, Gid, Uid};

fn elevate() -> Result<()> {
    setgid(Gid::from_raw(0)).context("failed to setgid(0)! Is lksu installed setuid-root?")?;
    setuid(Uid::from_raw(0)).context("failed to setuid(0)! Is lksu installed setuid-root?")?;
    Ok(())
}

fn valid_username(username: &str) -> bool {
    !username.trim().is_empty() && username.trim() == username
}

// Create a new Linux account (with "useradd --create-home") and
// immediately prompt for its initial password.
pub fn create_account(username: &str) -> Result<()> {
    if !valid_username(username) {
        return Err(anyhow!("username cannot be empty"));
    }
    elevate()?;
    let status = Command::new("useradd")
        .args(["--create-home", username])
        .status()
        .context("failed to invoke useradd! Does useradd already exist?")?;
    if !status.success() {
        return Err(anyhow!(
            "useradd exited with {}! Does {} already exist?",
            status,
            username
        ));
    }
    crate::ui::success(&format!("{} has been created!", username));
    set_password_interactive(username)
}

// Delete a Linux account and its home directory (with
// "userdel --remove"). Refuses to touch root.
pub fn delete_account(username: &str) -> Result<()> {
    if !valid_username(username) {
        return Err(anyhow!("username cannot be empty!"));
    }
    if username == "root" {
        return Err(anyhow!("refusing to delete the root account!"));
    }
    elevate()?;
    let status = Command::new("userdel")
        .args(["--remove", username])
        .status()
        .context("failed to invoke userdel! Does userdel already exist?")?;
    if !status.success() {
        return Err(anyhow!("userdel exited with {}", status));
    }
    crate::ui::success(&format!("{} has been deleted!", username));
    Ok(())
}

// Prompt for a new password (with confirmation) and set it for
// "username" with "chpasswd".
pub fn reset_password(username: &str) -> Result<()> {
    if !valid_username(username) {
        return Err(anyhow!("username cannot be empty!"));
    }
    elevate()?;
    set_password_interactive(username)
}

fn set_password_interactive(username: &str) -> Result<()> {
    crate::ui::info(&format!("Set a password for {}.", username));
    println!("{}", "Password:".bright_cyan());
    let cfg = rpassword::ConfigBuilder::new()
        .password_feedback_mask('*')
        .build();
    let p1 = rpassword::prompt_password_with_config(crate::ui::password_prompt_label(), cfg)
        .context("failed to read password")?;
    if p1.is_empty() {
        return Err(anyhow!("password cannot be empty"));
    }
    println!("{}", "Retype the password:".bright_cyan());
    let cfg = rpassword::ConfigBuilder::new()
        .password_feedback_mask('*')
        .build();
    let p2 = rpassword::prompt_password_with_config(crate::ui::password_prompt_label(), cfg)
        .context("failed to read password")?;
    if p2.is_empty() {
        return Err(anyhow!("password cannot be empty"));
    }
    if p1 != p2 {
        return Err(anyhow!("passwords did not match"));
    }
    let mut child = Command::new("chpasswd")
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to invoke chpasswd! Does chpasswd already exist?")?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("failed to open chpasswd stdin!"))?;
        writeln!(stdin, "{}:{}", username, p1).context("failed to write to chpasswd!")?;
    }
    let status = child.wait().context("failed to wait for chpasswd!")?;
    if !status.success() {
        return Err(anyhow!("chpasswd exited with {}", status));
    }
    crate::ui::success(&format!("Password for {} has been updated!", username));
    Ok(())
}
