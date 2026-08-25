use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use anyhow::{Context, Result};
use chrono::Local;
use crate::security;

// A single audit entry. lksu logs every attempt: allowed, denied, or
// authentication failure so incidents can be reviewed later.
pub struct Entry<'a> {
    pub user: &'a str,
    pub command: &'a str,
    pub outcome: Outcome,
}

pub enum Outcome {
    Allowed,
    DeniedNotPermitted,
    DeniedBadPassword { attempts: u32 },
}

impl Outcome {
    fn as_str(&self) -> String {
        match self {
            Outcome::Allowed => "ALLOWED".to_string(),
            Outcome::DeniedNotPermitted => "DENIED: not in permitted list".to_string(),
            Outcome::DeniedBadPassword { attempts } => {
                if *attempts == 1 {
                    format!("DENIED: {} incorrect password attempt", attempts)
                } else {
                    format!("DENIED: {} incorrect password attempts", attempts)
                }
            }
        }
    }
}

pub fn record(log_dir: &str, entry: Entry) {
    if let Err(e) = try_record(log_dir, entry) {
        crate::ui::warning(&format!("Could not write to log file: {}", e));
    }
}

// Each user gets their own log file under "log_dir" (default
// /var/log/lksu/<user>) instead of one shared file, so a user's history
// can be reviewed (rotated or permissioned) independently of everyone
// else.
fn try_record(log_dir: &str, entry: Entry) -> Result<()> {
    let dir = Path::new(log_dir);
    let _ = security::ensure_dir_0700(&dir);
    let user_dir = Path::new(dir).join(entry.user);
    let _ = security::ensure_dir_0700(&user_dir);
    let date_str = Local::now().format("%d-%m-%Y").to_string();
    let filename = format!("{}.{}.log", entry.user, date_str);
    let path = user_dir.join(filename);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open log file at {}", path.display()))?;
    let line = format!(
        "::: [ {} ] :::\n‣ Username: {}\n‣ Command: \"{}\"\n‣ Result: {}\n\n",
        Local::now().format("%d-%m-%Y %H:%M:%S %z"),
        entry.user,
        entry.command,
        entry.outcome.as_str(),
    );
    file.write_all(line.as_bytes())
        .context("failed to write log entry")?;
    let _ = security::ensure_file_0600(&path);
    Ok(())
}
