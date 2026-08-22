use std::fs::OpenOptions;
use std::io::Write;
use anyhow::{Context, Result};
use chrono::Local;

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

pub fn record(log_path: &str, entry: Entry) {
    if let Err(e) = try_record(log_path, entry) {
        crate::ui::warning(&format!("Could not write to log file: {}", e));
    }
}

fn try_record(log_path: &str, entry: Entry) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("failed to open log file at {}", log_path))?;
    let line = format!(
        "[ {} ]\nuser = {}\ncommand = \"{}\"\nresult = {}\n",
        Local::now().format("%d-%m-%Y %H:%M:%S%z"),
        entry.user,
        entry.command,
        entry.outcome.as_str(),
    );
    file.write_all(line.as_bytes())
        .context("failed to write log entry")?;
    Ok(())
}
