use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use anyhow::{Context, Result};
use nix::unistd::{setgid, setuid, Gid, Uid};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CGROUP_PARENT: &str = "/sys/fs/cgroup/lksu.slice";

// Puts the current process into a fresh cgroup v2 leaf with a pids.max
// cap before we exec the target command. This is the structural
// fork-bomb defense: unlike RLIMIT_NPROC (ulimit -u), which the kernel
// exempts processes holding CAP_SYS_ADMIN or CAP_SYS_RESOURCE from
// exactly the capabilities we're about to have as root. Cgroup pid
// limits are enforced unconditionally, regardless of capabilities. It
// doesn't matter whether the runaway process is a known fork-bomb
// idiom, a Perl one-liner, or a compiled binary: once the cgroup's
// pids.max is hit, fork() or clone() in that cgroup starts failing with
// EAGAIN, full stop.
//
// This intentionally fails OPEN: if cgroup v2 isn't mounted or
// delegated (some containers, systems still on cgroup v1), we return
// an error, the caller logs a warning, and the command still runs
// without the cap rather than lksu refusing to function at all. If you
// want a hard guarantee even at the cost of availability, make the
// caller exit instead of warning when this returns Err.
fn apply_pid_limit(max_pids: u32) -> Result<()> {
    if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
        anyhow::bail!("cgroup v2 does not appear to be mounted at {}", CGROUP_ROOT);
    }
    fs::create_dir_all(CGROUP_PARENT)
        .with_context(|| format!("failed to create {}", CGROUP_PARENT))?;
    // Controllers must be delegated top-down in cgroup v2: enable "pids"
    // on the root cgroup so our parent slice (and its children) are
    // allowed to use it. Already-enabled is not an error, so ignore
    // failures here, the write to pids.max below is what actually
    // matters and will fail loudly if delegation didn't work.
    let _ = fs::write(format!("{}/cgroup.subtree_control", CGROUP_ROOT), "+pids");
    let leaf = format!("{}/lksu-{}", CGROUP_PARENT, std::process::id());
    fs::create_dir_all(&leaf).with_context(|| format!("failed to create {}", leaf))?;
    fs::write(format!("{}/pids.max", leaf), max_pids.to_string())
        .with_context(|| format!("failed to set pids.max in {}", leaf))?;
    fs::write(format!("{}/cgroup.procs", leaf), std::process::id().to_string())
        .with_context(|| format!("failed to join cgroup {}", leaf))?;
    Ok(())
}

// Replace the current process with "command" and "args" running as
// root. This only actually succeeds if the lksu binary itself is running
// with root privileges (e.g. installed setuid-root).
//
// This never returns on success: the process image is replaced. On
// failure (bad command, insufficient privilege, etc) it returns an Err
// so the caller can log and report it.
pub fn run_as_root(command: &str, args: &[String], max_pids: u32) -> Result<()> {
    // Drop to uid or gid 0 explicitly. If we're not already privileged this
    // will fail loudly rather than silently running as the calling user.
    setgid(Gid::from_raw(0)).context("failed to setgid(0)! Is lksu installed setuid-root?")?;
    setuid(Uid::from_raw(0)).context("failed to setuid(0)! Is lksu installed setuid-root?")?;
    if let Err(e) = apply_pid_limit(max_pids) {
        crate::ui::warning(&format!(
            "Could not apply a process-count limit ({})! Continuing....",
            e
        ));
    }
    let err = Command::new(command).args(args).exec();
    // Command::exec only returns if it failed to even start the program.
    Err(err).with_context(|| format!("failed to execute '{}'", command))
}
