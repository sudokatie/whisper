//! Voice message support for Whisper.
//!
//! This module provides voice recording, encoding, and playback
//! for audio messages.

mod types;
mod db;
mod wire;
mod audio;

pub use types::*;
pub use db::*;
pub use wire::*;
pub use audio::*;

#[cfg(test)]
mod tests;
