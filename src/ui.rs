use colored::*;

// Print a warning line, e.g. "ui::warning("nothing ever happens")".
// For formatted messages, build the string with "format!" first:
// "ui::warning(&format!("attempt {}/3", n))".
pub fn warning(msg: &str) {
    println!("{} {}", "[!]".bright_yellow(), msg.bright_yellow());
}

pub fn error(msg: &str) {
    eprintln!("{} {}", "[✗]".bright_red(), msg.bright_red());
}

pub fn success(msg: &str) {
    println!("{} {}", "[✓]".bright_green(), msg.bright_green());
}

pub fn password_prompt_label() -> String {
    "> ".bright_cyan().to_string()
}

pub fn print_help() {
    println!("");
    println!("-----------------------------------");
    println!("::: [ Liska Superuser (1.0.0) ] :::");
    println!("-----------------------------------");
    println!("");
    println!("Usage: lksu <options> [command] <args>");
    println!("> -l | --list                  list commands you are permitted to run");
    println!("> -k | --reset                 forget any cached authentication timestamp");
    println!("> /etc/lksu/config.lua         lksu behaviour configuration");
    println!("> /etc/lksu/user-lists.lua     lksu permitted users configuration");
    println!("");
}