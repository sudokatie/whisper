//! CLI command implementations.

use std::path::Path;

use anyhow::Result;

/// Initialize a new identity.
pub async fn handle_init(_data_dir: &Path) -> Result<()> {
    todo!("Implement init")
}

/// Send a message.
pub async fn handle_send(_alias: &str, _message: &str, _data_dir: &Path) -> Result<()> {
    todo!("Implement send")
}

/// List contacts.
pub async fn handle_contacts(_data_dir: &Path) -> Result<()> {
    todo!("Implement contacts")
}

/// Show status.
pub async fn handle_status(_data_dir: &Path) -> Result<()> {
    todo!("Implement status")
}
