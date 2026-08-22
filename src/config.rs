use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use mlua::{Lua, LuaSerdeExt};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/lksu.d/config.lua";
pub const DEFAULT_USER_LISTS_PATH: &str = "/etc/lksu.d/user-lists.lua";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub log_path: String,
    pub timeout: u64,
    pub max_attempts: u32,
    pub require_password: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            log_path: "/var/log/lksu.log".to_string(),
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
        if cfg.log_path.trim().is_empty() {
            cfg.log_path = Config::default().log_path;
        }
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
    pub fn load(path: &str) -> Result<UserLists> {
        if !Path::new(path).exists() {
            return Ok(UserLists::default());
        }
        let src = fs::read_to_string(path)
            .with_context(|| format!("failed to read user-lists file at {}", path))?;
        let lua = Lua::new();
        let value = lua
            .load(&src)
            .set_name(path)
            .eval::<mlua::Value>()
            .map_err(|e| anyhow!("failed to evaluate lua user-lists at {}: {}", path, e))?;
        let raw: HashMap<String, Vec<String>> = lua
            .from_value(value)
            .map_err(|e| anyhow!("user-lists at {} does not match expected schema: {}", path, e))?;
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
