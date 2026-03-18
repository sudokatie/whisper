//! Voice message support for Whisper.
//!
//! This module provides voice recording, encoding, and playback
//! for audio messages.

mod types;
mod db;

pub use types::*;
pub use db::*;

#[cfg(test)]
mod tests;
