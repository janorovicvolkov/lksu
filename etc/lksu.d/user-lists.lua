-- ---------------------------------------------------------
-- ::: [ LISKA SUPERUSER PERMITTED-USERS CONFIGURATION ] :::
-- ---------------------------------------------------------
--
-- This file configures users permissions for lksu.
--
-- > lksu fails closed: any user not listed here may not run anything
-- through lksu. "ALL" grants every command, otherwise list the exact
-- absolute paths a user may run.
-- --------------------------------------------------------------------------

return {
    -- root already has full privileges, so granting "ALL" here does not
    -- elevate anything. It just lets root use lksu logging or timeout
    -- machinery like any other user would.
    root = { "ALL" },
    -- Example: uncomment and edit to permit another user.
    -- foo = { "ALL" },
    -- bar = { "/usr/bin/lkpm", "/usr/bin/lksysctl" },
}
