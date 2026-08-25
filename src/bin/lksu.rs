use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::exit;
use std::time::SystemTime;
use colored::*;
use lksu::config::{Config, Permission, UserLists, DEFAULT_CONFIG_PATH, DEFAULT_USER_LISTS_PATH, DEFAULT_LOG_PATH};
use lksu::log::{self, Entry, Outcome};
use lksu::{exec, password, security, ui, lksuers};

fn current_username() -> String {
    users::get_current_username()
        .and_then(|s| s.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

fn timestamp_path(user: &str) -> PathBuf {
    PathBuf::from(format!("/run/lksu/{}", user))
}

fn has_recent_auth(user: &str, timeout_secs: u64) -> bool {
    if timeout_secs == 0 {
        return false;
    }
    let path = timestamp_path(user);
    let Ok(meta) = fs::metadata(&path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let Ok(elapsed) = SystemTime::now().duration_since(modified) else {
        return false;
    };
    elapsed.as_secs() < timeout_secs
}

fn touch_auth_timestamp(user: &str) {
    let path = timestamp_path(user);
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = security::ensure_dir_0700(parent);
    }
    let _ = fs::write(&path, b"");
    let _ = security::ensure_file_0400(&path);
}

fn authenticate(user: &str, command: &str, max_attempts: u32, log_path: &str) -> bool {
    for attempt in 1..=max_attempts {
        ui::auth_info(&format!("Password for {}:", user.bright_cyan()));
        let rp_config = rpassword::ConfigBuilder::new()
            .password_feedback_mask('•')
            .build();
        let pass = match rpassword::prompt_password_with_config(
            ui::password_prompt_label(),
            rp_config,
        ) {
            Ok(p) => p,
            Err(e) => {
                ui::error(&format!("Failed to read password: {}", e));
                return false;
            }
        };
        match password::verify(user, &pass) {
            Ok(true) => {
                log::record(
                    &log_path,
                    Entry {
                        user: &user,
                        command: &command,
                        outcome: Outcome::Allowed,
                    }
                );
                return true;
            }
            Ok(false) => {
                if attempt < max_attempts {
                    ui::auth_warn(&format!(
                        "Looks like the password is wrong. Try again! [ {}/{} attempts ]",
                        attempt, max_attempts
                    ));
                }
            }
            Err(e) => {
                ui::error(&format!("Authentication backend error: {}", e));
                return false;
            }
        }
    }
    if max_attempts == 1 {
        ui::auth_warn("1 incorrect password attempt detected!");
    } else {
        ui::auth_warn(&format!(
            "{} incorrect password attempts detected!",
            max_attempts
        ));
    }
    log::record(
        &log_path,
        Entry {
            user: &user,
            command: &command,
            outcome: Outcome::DeniedBadPassword {
                attempts: max_attempts,
            },
        },
    );
    ui::error("This incident has been logged!");
    false
}

fn require_root(user: &str, command: &str, log_path: &str) -> bool {
    if unsafe { libc::getuid() } == 0 {
        true
    } else {
        ui::error("You are not permitted to run lksu management commands!");
        log::record(
            &log_path,
            Entry {
                user: &user,
                command: &command,
                outcome: Outcome::DeniedNotPermitted,
            },
        );
        ui::error("This incident has been logged!");
        false
    }
}

fn print_permitted(user: &str, lists: &UserLists) {
    match lists.permissions_for(user) {
        Some(Permission::All) => ui::info(&format!("You are permitted to run: {}.", "ALL commands".bright_green())),
        Some(Permission::Commands(cmds)) => {
            ui::info("You are permitted to run:");
            for c in cmds {
                println!("  > {}", c.bright_green());
            }
        }
        None => ui::info("You are not permitted to run any commands!"),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        ui::print_help();
        exit(0);
    }
    let config_path = DEFAULT_CONFIG_PATH.to_string();
    let user_lists_path = DEFAULT_USER_LISTS_PATH.to_string();
    let log_path = DEFAULT_LOG_PATH.to_string();
    let config_dir = PathBuf::from("/etc/lksu.d");
    let user_lists_dir = PathBuf::from("/var/db/lksu");
    let auth_cache_dir = PathBuf::from("/run/lksu");
    let _ = security::ensure_dir_0700(&config_dir);
    let _ = security::ensure_dir_0700(&user_lists_dir);
    let _ = security::ensure_dir_0700(&auth_cache_dir);
    let _ = security::ensure_dir_0700(&log_path);
    let full_command = args[1..].join(" ");
    let lksu_command = &format!("lksu {}", full_command);
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            ui::error(&format!("Failed to load {}: {}", config_path, e));
            exit(1);
        }
    };
    let _ = security::ensure_file_0600(&config_path);
    let user_lists = match UserLists::load(&user_lists_path) {
        Ok(l) => l,
        Err(e) => {
            ui::error(&format!("Failed to load {}: {}", user_lists_path, e));
            exit(1);
        }
    };
    let _ = security::ensure_file_0400(&user_lists_path);
    let user = current_username();
    if args[1] == "--add" || args[1] == "-a" {
        if !require_root(&user, &lksu_command, &log_path) {
            exit(1);
        }
        let Some(target) = args.get(2) else {
            ui::error("Usage: lksu --add <username> [command|ALL] <more commands....>");
            exit(1);
        };
        let commands = &args[3..];
        let attempts_allowed = config.max_attempts.max(1);
        if !authenticate(&user, &lksu_command, attempts_allowed, &log_path) {
            exit(1);
        }
        if let Err(e) = lksuers::add_user(&user_lists_path, target, commands) {
            ui::error(&format!("{}", e));
            exit(1);
        }
        exit(0);
    }
    if args[1] == "--edit" || args[1] == "-e" {
        if !require_root(&user, &lksu_command, &log_path) {
            exit(1);
        }
        let Some(target) = args.get(2) else {
            ui::error("Usage: lksu --edit-user <username> [command|ALL] <more commands....>");
            exit(1);
        };
        let commands = &args[3..];
        let attempts_allowed = config.max_attempts.max(1);
        if !authenticate(&user, &lksu_command, attempts_allowed, &log_path) {
            exit(1);
        }
        if let Err(e) = lksuers::edit_user(&user_lists_path, target, commands) {
            ui::error(&format!("{}", e));
            exit(1);
        }
        exit(0);
    }
    if args[1] == "--remove" || args[1] == "-r" {
        if !require_root(&user, &lksu_command, &log_path) {
            exit(1);
        }
        let Some(target) = args.get(2) else {
            ui::error("Usage: lksu --remove-user <username>");
            exit(1);
        };
        let attempts_allowed = config.max_attempts.max(1);
        if !authenticate(&user, &lksu_command, attempts_allowed, &log_path) {
            exit(1);
        }
        if let Err(e) = lksuers::remove_user(&user_lists_path, target) {
            ui::error(&format!("{}", e));
            exit(1);
        }
        exit(0);
    }
    if args[1] == "--user-list" || args[1] == "-ul" {
        match lksuers::list_permitted_users(&user_lists_path) {
            Ok(accounts) => lksuers::print_permitted_users(&accounts),
            Err(e) => {
                ui::error(&format!("{}", e));
                exit(1);
            }
        }
        exit(0);
    }
    if args[1] == "--command-list" || args[1] == "-cl" {
        print_permitted(&user, &user_lists);
        exit(0);
    }
    if args[1] == "--reset-cache" || args[1] == "-rc" {
        let _ = fs::remove_file(timestamp_path(&user));
        ui::success("Cached authentication has been cleared!");
        exit(0);
    }
    let command = &args[1];
    let command_args = &args[2..];
    if !user_lists.is_permitted(&user, command) {
        ui::error(&format!(
            "{} is not permitted to run {}!",
            user, command
        ));
        log::record(
            &log_path,
            Entry {
                user: &user,
                command: &full_command,
                outcome: Outcome::DeniedNotPermitted,
            },
        );
        ui::error("This incident has been logged!");
        exit(1);
    }
    let already_authenticated = !config.require_password || has_recent_auth(&user, config.timeout);
    if !already_authenticated {
        let attempts_allowed = config.max_attempts.max(1);
        if !authenticate(&user, &full_command, attempts_allowed, &log_path) {
            exit(1);
        }
        touch_auth_timestamp(&user);
    }
    if let Err(e) = exec::run_as_root(command, command_args) {
        ui::error(&format!("{}", e));
        exit(1);
    }
}
