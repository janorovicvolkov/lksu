use colored::*;

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

pub fn auth_info(msg: &str) {
    println!("{} {}", "[ AUTH ]".bright_cyan(), msg.bright_cyan());
}

pub fn auth_warn(msg: &str) {
    eprintln!("{} {}", "[ AUTH ]".bright_yellow(), msg.bright_yellow());
}

pub fn print_help() {
    println!("");
    println!("-----------------------------------");
    println!("::: [ Liska Superuser (1.0.0) ] :::");
    println!("-----------------------------------");
    println!("");
    println!("Usage: lksu [command] <args>");
    println!("> -a  | --add                  add a user to lksu permitted lists");
    println!("> -e  | --edit                 edit a user permissions on lksu permitted lists");
    println!("> -r  | --remove               remove a user from lksu permitted lists");
    println!("> -cl | --command-list         list commands you are permitted to run");
    println!("> -rc | --reset-cache          clear any cached authentication timestamp");
    println!("> -ul | --user-list            list all users from lksu permitted lists with their uid");
    println!("> /etc/lksu.d/config.lua       lksu behaviour configuration");
    println!("> /var/db/lksu/lksuers.db      lksu permitted users list (edit directly, as root)");
    println!("");
}