//! Voice message support for Whisper.
//!
//! This module provides voice recording, encoding, and playback
//! for audio messages.

mod types;
mod db;
mod wire;
mod audio;
mod chat_recorder;

pub use types::*;
pub use db::*;
pub use wire::*;
pub use audio::*;
pub use chat_recorder::*;

#[cfg(test)]
mod tests;
