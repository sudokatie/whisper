//! Voice message support for Whisper.
//!
//! This module provides voice recording, encoding, and playback
//! for audio messages.

mod types;
mod db;
mod wire;

pub use types::*;
pub use db::*;
pub use wire::*;

#[cfg(test)]
mod tests;
