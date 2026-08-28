-- ------------------------------------------------
-- ::: [ LISKA SUPERUSER SYSTEM CONFIGURATION ] :::
-- ------------------------------------------------
--
-- This file configures behavior rules for lksu.
--
-- > Param: [ timeout | max_attempts | require_password | blacklist | max_processes ]
--
-- > timeout           : The seconds an authentication is cached before lksu asks for the
--                       password again.
-- > max_attempts      : The password attempts allowed before lksu gives up and logs the 
--                       incident.
-- > require_password  : Set to false to skip the password prompt entirely (not recommended, 
--                       permission list checks still apply either way).
-- > blacklist         : Commands that are always denied, even for users permitted to run
--                       ALL commands. Each entry is matched token-by-token against the
--                       full command line (order-independent, "-rf" == "-r -f" ==
--                       "--recursive --force"), so "rm -rf /" also blocks "rm -f -r /"
--                       and "rm --recursive --force /". It does NOT block related but
--                       distinct invocations like "rm -rf /home", list those separately
--                       if needed. lksu invoking itself ("lksu ...") is ALWAYS blocked
--                       unconditionally and doesn't need an entry here.
-- > max_processes     : Process-count cap (cgroup v2 pids.max) applied to every escalated
--                       command, regardless of what it is. This is what stops fork bombs,
--                       since a fork bomb can be written in any language and no fixed list 
--                       of strings could ever cover them all. It works even against root, 
--                       unlike a plain "ulimit -u". Requires cgroup v2 to be mounted, if 
--                       it isn't, lksu warns and runs the command anyway rather than 
--                       refusing to work at all.
-- --------------------------------------------------------------------------

return {
    timeout = 300,
    max_attempts = 3,
    require_password = true,
    blacklist = {
        "rm -rf /",
        "rm -rf / --no-preserve-root",
        "mkfs /",
        "dd if=/dev/zero of=/dev/sda",
    },
    max_processes = 256,
}
