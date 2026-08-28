use std::collections::HashMap;
use std::fs;
use std::path::Path;
use anyhow::{anyhow, Context, Result};
use mlua::{Lua, LuaSerdeExt};
use serde::{Deserialize, Serialize};
pub const DEFAULT_CONFIG_PATH: &str = "/etc/lksu.d/config.lua";
pub const DEFAULT_USER_LISTS_PATH: &str = "/var/db/lksu/lksuers.db";
pub const DEFAULT_LOG_PATH: &str = "/var/log/lksu";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub timeout: u64,
    pub max_attempts: u32,
    pub require_password: bool,
    pub blacklist: Vec<String>,
    pub max_processes: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            timeout: 300,
            max_attempts: 3,
            require_password: true,
            blacklist: Vec::new(),
            max_processes: 256,
        }
    }
}

// Splits a command line into normalized tokens: this is what lets
// "rm  -rf   /", "rm -r -f /", and "rm --recursive --force /" all be
// recognized as equivalent to "rm -rf /" below. It is intentionally
// simple (whitespace split) since lksu commands are not passed through
// a shell, so there's no quoting or escaping to worry about.
fn normalize_tokens(s: &str) -> Vec<String> {
    s.split_whitespace().map(|t| t.to_lowercase()).collect()
}

// A blacklist entry can either be a single bare token (matches if that
// token appears anywhere in the command, e.g. "lksu") or a short
// sequence (matches only as a contiguous, order-sensitive run of
// tokens). Long-form flags are treated as aliases of their short-form
// equivalents for the common destructive cases.
fn expand_aliases(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .flat_map(|t| match t.as_str() {
            "--recursive" => vec!["-r".to_string()],
            "--force" => vec!["-f".to_string()],
            "--no-preserve-root" => vec!["--no-preserve-root".to_string()],
            // Split combined short flags like "-rf" into "-r" "-f" so
            // ordering or spacing differences don't matter.
            t if t.starts_with('-') && !t.starts_with("--") && t.len() > 2 => {
                t[1..].chars().map(|c| format!("-{}", c)).collect()
            }
            other => vec![other.to_string()],
        })
        .collect()
}

pub fn is_blacklisted(full_command: &str, blacklist: &[String]) -> bool {
    let cmd_tokens = expand_aliases(&normalize_tokens(full_command));
    blacklist.iter().any(|rule| {
        let rule_tokens = expand_aliases(&normalize_tokens(rule));
        if rule_tokens.is_empty() {
            return false;
        }
        // Every token required by the rule must be present in the
        // command (order-independent), so "rm -rf /" matches "rm -r -f /"
        // and "rm -f -r /" alike, but "rm -r /home" does not match a
        // "rm -rf /" rule because "-f" and the exact path "/" are both
        // still required.
        rule_tokens.iter().all(|rt| cmd_tokens.contains(rt))
    })
}

impl Config {
    pub fn load(path: &str) -> Result<Config> {
        if !Path::new(path).exists() {
            return Ok(Config::default());
        }
        let src = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file at {}", path))?;
        let lua = Lua::new();
        let value = lua
            .load(&src)
            .set_name(path)
            .eval::<mlua::Value>()
            .map_err(|e| anyhow!("failed to evaluate lua config at {}: {}", path, e))?;
        let mut cfg: Config = lua
            .from_value(value)
            .map_err(|e| anyhow!("config at {} does not match expected schema: {}", path, e))?;
        if cfg.max_attempts == 0 {
            cfg.max_attempts = Config::default().max_attempts;
        }
        if cfg.max_processes == 0 {
            cfg.max_processes = Config::default().max_processes;
        }
        Ok(cfg)
    }
}

#[derive(Debug, Clone)]
pub enum Permission {
    All,
    Commands(Vec<String>),
}

impl Permission {
    pub fn allows(&self, command: &str) -> bool {
        match self {
            Permission::All => true,
            Permission::Commands(list) => list.iter().any(|c| c == command),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct UserLists {
    entries: HashMap<String, Permission>,
}

impl UserLists {
    pub fn load(path: &str) -> Result<UserLists> {
        let conn = rusqlite::Connection::open(path)
            .with_context(|| format!("failed to open sqlite db at {}", path))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS permissions (
                username TEXT NOT NULL,
                command  TEXT NOT NULL,
                PRIMARY KEY (username, command)
            )",
            [],
        )
        .map_err(|e| anyhow!("failed to initialize permissions table at {}: {}", path, e))?;
        let mut stmt = conn
            .prepare("SELECT username, command FROM permissions")
            .map_err(|e| anyhow!("failed to query permissions at {}: {}", path, e))?;
        let rows = stmt
            .query_map([], |row| {
                let username: String = row.get(0)?;
                let command: String = row.get(1)?;
                Ok((username, command))
            })
            .map_err(|e| anyhow!("failed to read permissions at {}: {}", path, e))?;
        let mut raw: HashMap<String, Vec<String>> = HashMap::new();
        for row in rows {
            let (user, command) =
                row.map_err(|e| anyhow!("failed to read a permissions row at {}: {}", path, e))?;
            raw.entry(user).or_default().push(command);
        }
        let mut entries = HashMap::new();
        for (user, commands) in raw {
            let perm = if commands.iter().any(|c| c.eq_ignore_ascii_case("ALL")) {
                Permission::All
            } else {
                Permission::Commands(commands)
            };
            entries.insert(user, perm);
        }
        Ok(UserLists { entries })
    }
    pub fn is_permitted(&self, user: &str, command: &str) -> bool {
        self.entries
            .get(user)
            .map(|perm| perm.allows(command))
            .unwrap_or(false)
    }
    pub fn permissions_for(&self, user: &str) -> Option<&Permission> {
        self.entries.get(user)
    }
}
