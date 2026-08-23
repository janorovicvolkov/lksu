-- ------------------------------------------------
-- ::: [ LISKA SUPERUSER SYSTEM CONFIGURATION ] :::
-- ------------------------------------------------
--
-- This file configures behavior rules for lksu.
--
-- > Param: [ timeout | max_attempts | require_password ]
--
-- > timeout           : The seconds an authentication is cached before lksu asks for the
--                       password again.
-- > max_attempts      : The password attempts allowed before lksu gives up and logs the 
--                       incident.
-- > require_password  : Set to false to skip the password prompt entirely (not recommended, 
--                       permission list checks still apply either way).
-- --------------------------------------------------------------------------

return {
    timeout = 300,
    max_attempts = 3,
    require_password = true,
}
