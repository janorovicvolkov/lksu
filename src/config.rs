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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            timeout: 300,
            max_attempts: 3,
            require_password: true,
        }
    }
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
    // Permitted-user list now backed by sqlite at DEFAULT_USER_LISTS_PATH
    // (/var/db/lksu/lksuers.db) instead of user-lists.lua. Table schema
    // (also created by list.rs own open_db, which is what actually
    // writes rows via --add-user/--edit-user/--remove-user):
    //   CREATE TABLE permissions (username TEXT, command TEXT,
    //                              PRIMARY KEY (username, command))
    // A row with command = "ALL" grants Permission::All for that user,
    // same sentinel value the old Lua format used.
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
