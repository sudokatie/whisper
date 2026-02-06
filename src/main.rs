//! Whisper - Decentralized P2P Messaging
//!
//! No servers. No tracking. Just you and whoever you're talking to.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// Decentralized peer-to-peer messaging.
#[derive(Parser)]
#[command(name = "whisper")]
#[command(author = "Katie")]
#[command(version)]
#[command(about = "Decentralized P2P messaging. No servers. No tracking.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Data directory for keys and messages
    #[arg(long, default_value = "~/.whisper")]
    data_dir: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new identity
    Init,

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
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Expand ~ in data_dir
    let data_dir = if cli.data_dir.starts_with("~") {
        dirs::home_dir()
            .expect("Could not find home directory")
            .join(cli.data_dir.strip_prefix("~").unwrap())
    } else {
        cli.data_dir
    };

    match cli.command {
        Commands::Init => {
            println!("Initializing new identity in {:?}...", data_dir);
            // TODO: Implement init
        }
        Commands::Send { alias, message } => {
            println!("Sending to {}: {}", alias, message);
            // TODO: Implement send
        }
        Commands::Chat { alias } => {
            println!("Opening chat with {}...", alias);
            // TODO: Implement chat
        }
        Commands::Contacts => {
            println!("Contacts:");
            // TODO: Implement contacts list
        }
        Commands::Add { alias, peer_id } => {
            println!("Adding contact {} with peer ID {}", alias, peer_id);
            // TODO: Implement add contact
        }
        Commands::Trust { alias } => {
            println!("Marking {} as trusted", alias);
            // TODO: Implement trust
        }
        Commands::Block { alias } => {
            println!("Blocking {}", alias);
            // TODO: Implement block
        }
        Commands::Status => {
            println!("Network status:");
            // TODO: Implement status
        }
    }

    Ok(())
}
