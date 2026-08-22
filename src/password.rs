use anyhow::{anyhow, Result};

// Verify "password" for "username" against the system PAM stack
// (service "lksu", falling back to "login" behaviour via /etc/pam.d).
// Returns Ok(true) if authentication succeeded, Ok(false) if the
// credentials were simply wrong, and Err for anything else (PAM
// misconfigured, service missing, etc).
pub fn verify(username: &str, password: &str) -> Result<bool> {
    let mut client = pam::Client::with_password("lksu")
        .map_err(|e| anyhow!("failed to initialize PAM: {}", e))?;
    client
        .conversation_mut()
        .set_credentials(username, password);
    match client.authenticate() {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}
