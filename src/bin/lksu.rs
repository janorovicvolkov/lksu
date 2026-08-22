use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::exit;
use std::time::SystemTime;
use colored::*;
use lksu::config::{Config, Permission, UserLists, DEFAULT_CONFIG_PATH, DEFAULT_USER_LISTS_PATH};
use lksu::log::{self, Entry, Outcome};
use lksu::{account, exec, list, password, ui};

fn current_username() -> String {
    users::get_current_username()
        .and_then(|s| s.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

// Path used to cache "this user recently authenticated successfully",
// so lksu doesn't re-prompt for a password on every single invocation
// within "config.timeout".
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
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&path, b"");
}

// Ask for the root password up to "max_attempts" times, verifying each
// one with PAM. Returns true if authentication succeeded.
fn authenticate(user: &str, command: &str, max_attempts: u32, log_path: &str) -> bool {
    println!("");
    println!(
        "    {}",
        "WARNING: Unauthorized access is prohibited! You must type the root password before performing superuser action!".bright_yellow()
    );
    println!("");
    for attempt in 1..=max_attempts {
        println!("{}", "Root password:".bright_cyan());
        let rp_config = rpassword::ConfigBuilder::new()
            .password_feedback_mask('*')
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
                    ui::warning(&format!(
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
        ui::error("1 incorrect password attempt detected!");
    } else {
        ui::error(&format!(
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

// Account-management commands (--add-user, --made, --delete, ...)
// change who can use lksu or what real system accounts exist, so they
// require the invoking user to actually be root. Matching the check
// --reset-pass already had. Without this, any user who can supply
// their own password could grant themselves ALL permissions via
// --add-user, which would defeat the whole permitted-list mechanism.
fn require_root(user: &str, command: &str, log_path: &str) -> bool {
    if user == "root" {
        true
    } else {
        ui::error("You are not permitted to run account management commands!");
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
        Some(Permission::All) => ui::info("You are permitted to run: ALL commands."),
        Some(Permission::Commands(cmds)) => {
            ui::info("You are permitted to run:");
            for c in cmds {
                println!("  > {}", c);
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
    let config_path = env::var("LKSU_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    let full_command = args[1..].join(" ");
    let user_lists_path =
        env::var("LKSU_USER_LISTS").unwrap_or_else(|_| DEFAULT_USER_LISTS_PATH.to_string());
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            ui::error(&format!("Failed to load {}: {}", config_path, e));
            exit(1);
        }
    };
    let user_lists = match UserLists::load(&user_lists_path) {
        Ok(l) => l,
        Err(e) => {
            ui::error(&format!("Failed to load {}: {}", user_lists_path, e));
            exit(1);
        }
    };
    let user = current_username();
    if args[1] == "--add-user" || args[1] == "-au" {
        if !require_root(&user, &full_command, &config.log_path) {
            exit(1);
        }
        let Some(target) = args.get(2) else {
            ui::error("Usage: lksu --add-user <username> <command|ALL> [more commands...]");
            exit(1);
        };
        let commands = &args[3..];
        let attempts_allowed = config.max_attempts.max(1);
        if !authenticate(&user, &full_command, attempts_allowed, &config.log_path) {
            exit(1);
        }
        if let Err(e) = list::add_user(&user_lists_path, target, commands) {
            ui::error(&format!("{}", e));
            exit(1);
        }
        exit(0);
    }
    if args[1] == "--command-list" || args[1] == "-cl" {
        // Root may check any user's permitted commands, everyone else
        // may only check their own.
        let target = match args.get(2) {
            Some(t) if t != &user && user != "root" => {
                ui::error("You are not permitted to check another users permitted commands!");
                log::record(
                    &config.log_path,
                    Entry {
                        user: &user,
                        command: &full_command,
                        outcome: Outcome::DeniedNotPermitted,
                    },
                );
                ui::error("This incident has been logged!");
                exit(1);
            }
            Some(t) => t.clone(),
            None => user.clone(),
        };
        print_permitted(&target, &user_lists);
        exit(0);
    }
    if args[1] == "--delete" || args[1] == "-d" {
        if !require_root(&user, &full_command, &config.log_path) {
            exit(1);
        }
        let Some(target) = args.get(2) else {
            ui::error("Usage: lksu --delete <username>");
            exit(1);
        };
        let attempts_allowed = config.max_attempts.max(1);
        if !authenticate(&user, &full_command, attempts_allowed, &config.log_path) {
            exit(1);
        }
        if let Err(e) = account::delete_account(target) {
            ui::error(&format!("{}", e));
            exit(1);
        }
        exit(0);
    }
    if args[1] == "--edit-user" || args[1] == "-eu" {
        if !require_root(&user, &full_command, &config.log_path) {
            exit(1);
        }
        let Some(target) = args.get(2) else {
            ui::error("Usage: lksu --edit-user <username> <command|ALL> [more commands...]");
            exit(1);
        };
        let commands = &args[3..];
        let attempts_allowed = config.max_attempts.max(1);
        if !authenticate(&user, &full_command, attempts_allowed, &config.log_path) {
            exit(1);
        }
        if let Err(e) = list::edit_user(&user_lists_path, target, commands) {
            ui::error(&format!("{}", e));
            exit(1);
        }
        exit(0);
    }
    if args[1] == "--made" || args[1] == "-m" {
        if !require_root(&user, &full_command, &config.log_path) {
            exit(1);
        }
        let Some(target) = args.get(2) else {
            ui::error("Usage: lksu --made <username>");
            exit(1);
        };
        let attempts_allowed = config.max_attempts.max(1);
        if !authenticate(&user, &full_command, attempts_allowed, &config.log_path) {
            exit(1);
        }
        if let Err(e) = account::create_account(target) {
            ui::error(&format!("{}", e));
            exit(1);
        }
        exit(0);
    }
    if args[1] == "--reset-cache" || args[1] == "-rc" {
        let _ = fs::remove_file(timestamp_path(&user));
        ui::success("Cached authentication has been cleared!");
        exit(0);
    }
    if args[1] == "--reset-pass" || args[1] == "-rp" {
        if !require_root(&user, &full_command, &config.log_path) {
            exit(1);
        }
        let Some(target) = args.get(2) else {
            ui::error("Usage: lksu --reset-pass <username>");
            exit(1);
        };
        let attempts_allowed = config.max_attempts.max(1);
        if !authenticate(&user, &full_command, attempts_allowed, &config.log_path) {
            exit(1);
        }
        if let Err(e) = account::reset_password(target) {
            ui::error(&format!("{}", e));
            exit(1);
        }
        exit(0);
    }
    if args[1] == "--remove-user" || args[1] == "-ru" {
        if !require_root(&user, &full_command, &config.log_path) {
            exit(1);
        }
        let Some(target) = args.get(2) else {
            ui::error("Usage: lksu --remove-user <username>");
            exit(1);
        };
        let attempts_allowed = config.max_attempts.max(1);
        if !authenticate(&user, &full_command, attempts_allowed, &config.log_path) {
            exit(1);
        }
        if let Err(e) = list::remove_user(&user_lists_path, target) {
            ui::error(&format!("{}", e));
            exit(1);
        }
        exit(0);
    }
    if args[1] == "--user-list" || args[1] == "-ul" {
        match list::list_system_accounts(1000) {
            Ok(accounts) => list::print_system_accounts(&accounts),
            Err(e) => {
                ui::error(&format!("{}", e));
                exit(1);
            }
        }
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
            &config.log_path,
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
        if !authenticate(&user, &full_command, attempts_allowed, &config.log_path) {
            exit(1);
        }
        touch_auth_timestamp(&user);
    }
    if let Err(e) = exec::run_as_root(command, command_args) {
        ui::error(&format!("{}", e));
        exit(1);
    }
}
