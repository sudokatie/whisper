//! Whisper - Decentralized P2P Messaging
//!
//! No servers. No tracking. Just you and whoever you're talking to.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use whisper::cli;

/// Decentralized peer-to-peer messaging.
#[derive(Parser)]
#[command(name = "whisper")]
#[command(author = "Katie")]
#[command(version = "0.1.0")]
#[command(about = "Decentralized P2P messaging. No servers. No tracking.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Data directory for keys and messages
    #[arg(long, default_value = "~/.whisper")]
    pub data_dir: PathBuf,

    /// Passphrase for keypair encryption (or set WHISPER_PASSPHRASE)
    #[arg(long, env = "WHISPER_PASSPHRASE", default_value = "")]
    pub passphrase: String,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Initialize a new identity
    Init,

    /// Export your public key
    ExportKey,

    /// Import a contact from a key file
    ImportContact {
        /// Path to the key file
        file: std::path::PathBuf,
        /// Alias for the contact
        alias: String,
    },

    /// Send a message to a contact
    Send {
        /// Contact alias
        alias: String,
        /// Message text
        message: String,
    },

    /// Open interactive chat with a contact
    Chat {
        /// Contact alias
        alias: String,
    },

    /// List all contacts
    Contacts,

    /// Add a new contact
    Add {
        /// Alias for the contact
        alias: String,
        /// Peer ID of the contact
        peer_id: String,
    },

    /// Mark a contact as trusted
    Trust {
        /// Contact alias
        alias: String,
    },

    /// Block a contact
    Block {
        /// Contact alias
        alias: String,
    },

    /// Show network status
    Status,

    /// List connected peers
    Peers,

    /// Group commands
    #[command(subcommand)]
    Group(GroupCommands),
}

#[derive(Subcommand, Debug, Clone)]
pub enum GroupCommands {
    /// Create a new group
    Create {
        /// Group name
        name: String,
    },

    /// Invite a contact to a group
    Invite {
        /// Group name
        name: String,
        /// Contact alias
        alias: String,
    },

    /// Open interactive group chat
    Chat {
        /// Group name
        name: String,
    },

    /// List all groups
    List,
}

/// Expand ~ to home directory.
pub fn expand_data_dir(path: PathBuf) -> PathBuf {
    if path.starts_with("~") {
        dirs::home_dir()
            .expect("Could not find home directory")
            .join(path.strip_prefix("~").unwrap())
    } else {
        path
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let data_dir = expand_data_dir(cli.data_dir);
    let passphrase = cli.passphrase;

    match cli.command {
        Commands::Init => {
            cli::handle_init(&data_dir, &passphrase).await?;
        }
        Commands::ExportKey => {
            cli::handle_export_key(&data_dir, &passphrase).await?;
        }
        Commands::ImportContact { file, alias } => {
            cli::handle_import_contact(&file, &alias, &data_dir).await?;
        }
        Commands::Send { alias, message } => {
            cli::handle_send(&alias, &message, &data_dir).await?;
        }
        Commands::Chat { alias } => {
            cli::handle_chat(&alias, &data_dir).await?;
        }
        Commands::Contacts => {
            cli::handle_contacts(&data_dir).await?;
        }
        Commands::Add { alias, peer_id } => {
            cli::handle_add_contact(&alias, &peer_id, &data_dir).await?;
        }
        Commands::Trust { alias } => {
            cli::handle_trust(&alias, &data_dir).await?;
        }
        Commands::Block { alias } => {
            cli::handle_block(&alias, &data_dir).await?;
        }
        Commands::Status => {
            cli::handle_status(&data_dir, &passphrase).await?;
        }
        Commands::Peers => {
            cli::handle_peers(&data_dir, &passphrase).await?;
        }
        Commands::Group(cmd) => {
            match cmd {
                GroupCommands::Create { name } => {
                    cli::handle_group_create(&name, &data_dir).await?;
                }
                GroupCommands::Invite { name, alias } => {
                    cli::handle_group_invite(&name, &alias, &data_dir).await?;
                }
                GroupCommands::Chat { name } => {
                    cli::handle_group_chat(&name, &data_dir).await?;
                }
                GroupCommands::List => {
                    cli::handle_group_list(&data_dir).await?;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parses_init() {
        let cli = Cli::parse_from(["whisper", "init"]);
        assert!(matches!(cli.command, Commands::Init));
    }

    #[test]
    fn cli_parses_send() {
        let cli = Cli::parse_from(["whisper", "send", "alice", "hello"]);
        match cli.command {
            Commands::Send { alias, message } => {
                assert_eq!(alias, "alice");
                assert_eq!(message, "hello");
            }
            _ => panic!("Expected Send command"),
        }
    }

    #[test]
    fn cli_help_works() {
        // Just verify the command can be built
        let cmd = Cli::command();
        assert!(cmd.get_about().is_some());
    }

    #[test]
    fn cli_version_works() {
        let cmd = Cli::command();
        assert!(cmd.get_version().is_some());
        assert_eq!(cmd.get_version().unwrap(), "0.1.0");
    }
}
