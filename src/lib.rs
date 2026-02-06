//! Whisper - Decentralized P2P Messaging Library
//!
//! Core library for peer-to-peer encrypted messaging.

pub mod cli;
pub mod crypto;
pub mod identity;
pub mod message;
pub mod network;
pub mod storage;
pub mod ui;

// Re-export commonly used types
pub use identity::{Contact, ContactStore, TrustLevel};
pub use message::{Message, MessageStatus, Recipient};
pub use network::WhisperNode;
pub use storage::Database;
