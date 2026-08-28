use std::os::unix::process::CommandExt;
use std::process::Command;
use anyhow::{Context, Result};
use nix::unistd::{setgid, setuid, Gid, Uid};

// Replace the current process with "command" and "args" running as
// root. This only actually succeeds if the lksu binary itself is running
// with root privileges (e.g. installed setuid-root).
//
// This never returns on success: the process image is replaced. On
// failure (bad command, insufficient privilege, etc) it returns an Err
// so the caller can log and report it.
pub fn run_as_root(command: &str, args: &[String]) -> Result<()> {
    // Drop to uid or gid 0 explicitly. If we're not already privileged this
    // will fail loudly rather than silently running as the calling user.
    setgid(Gid::from_raw(0)).context("failed to setgid(0)! Is lksu installed setuid-root?")?;
    setuid(Uid::from_raw(0)).context("failed to setuid(0)! Is lksu installed setuid-root?")?;
    let err = Command::new(command).args(args).exec();
    // Command::exec only returns if it failed to even start the program.
    Err(err).with_context(|| format!("failed to execute '{}'", command))
}
