-- ------------------------------------------------
-- ::: [ LISKA SUPERUSER SYSTEM CONFIGURATION ] :::
-- ------------------------------------------------
--
-- This file configures behavior rules for lksu.
--
-- > Param: [ log_path | timeout | max_attempts
--          | require_password ]
--
-- > log_path          : The path to the lksu default log file directory.
-- > timeout           : The seconds an authentication is cached before lksu asks for the
--                       password again.
-- > max_attempts      : The password attempts allowed before lksu gives up and logs the 
--                       incident.
-- > require_password  : Set to false to skip the password prompt entirely (not recommended, 
--                       permission list checks still apply either way).
-- --------------------------------------------------------------------------

return {
    log_path = "/var/log/lksu",
    timeout = 300,
    max_attempts = 3,
    require_password = true,
}
