use colored::*;

// Print a warning line, e.g. "ui::warning("nothing ever happens")".
// For formatted messages, build the string with "format!" first:
// "ui::warning(&format!("attempt {}/3", n))".
pub fn info(msg: &str) {
    println!("{} {}", "[i]".bright_cyan(), msg);
}

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
    println!("> -au | --add-user             add a user to lksu permitted lists");
    println!("> -cl | --command-list         list commands a user are permitted to run");
    println!("> -d  | --delete               delete a user account from the system");
    println!("> -eu | --edit-user            edit a user permissions on lksu permitted lists");
    println!("> -m  | --made                 made a user account to the system");
    println!("> -rc | --reset-cache          forget any cached authentication timestamp");
    println!("> -rp | --reset-pass           reset a user password (root only)");
    println!("> -ru | --remove-user          remove a user from lksu permitted lists");
    println!("> -ul | --user-list            list all users from the system");
    println!("> /etc/lksu/config.lua         lksu behaviour configuration");
    println!("> /etc/lksu/user-lists.lua     lksu permitted users configuration");
    println!("");
}