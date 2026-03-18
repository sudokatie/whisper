//! Voice message CLI commands.

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::voice::{
    AudioCodec, VoiceConfig, VoiceMessage,
    has_input_device, has_output_device,
    record_voice_message, play_audio,
};

/// Check if voice recording is available on this system.
pub fn is_recording_available() -> bool {
    has_input_device()
}

/// Check if voice playback is available on this system.
pub fn is_playback_available() -> bool {
    has_output_device()
}

/// Record a voice message.
/// 
/// Returns the recorded audio data and metadata.
pub fn record_voice(config: &VoiceConfig, _max_seconds: u32) -> Result<(VoiceMessage, Vec<u8>)> {
    let stop_signal = Arc::new(AtomicBool::new(false));
    
    // Set up ctrl+c handler to stop recording
    let stop_clone = Arc::clone(&stop_signal);
    ctrlc_once(move || {
        stop_clone.store(true, Ordering::Relaxed);
    });
    
    println!("Recording... Press Ctrl+C to stop.");
    record_voice_message(config, stop_signal)
}

/// Play a voice message.
pub fn play_voice(audio_data: &[u8], codec: AudioCodec) -> Result<()> {
    play_audio(audio_data, codec)
}

/// Stop current recording.
pub fn stop_recording() -> Result<()> {
    // Recording is stopped via the stop_signal in record_voice
    Err(anyhow!("Use Ctrl+C to stop recording."))
}

/// Stop current playback.
pub fn stop_playback() -> Result<()> {
    // Playback is blocking, so this is informational
    Err(anyhow!("Playback is blocking. Wait for completion."))
}

/// Set a one-time ctrl+c handler.
fn ctrlc_once<F: FnOnce() + Send + 'static>(handler: F) {
    use std::sync::Once;
    static INIT: Once = Once::new();
    static mut HANDLER: Option<Box<dyn FnOnce() + Send>> = None;
    
    INIT.call_once(|| {
        let _ = ctrlc::set_handler(|| {
            unsafe {
                if let Some(h) = HANDLER.take() {
                    h();
                }
            }
        });
    });
    
    unsafe {
        HANDLER = Some(Box::new(handler));
    }
}

/// Get voice recording capabilities info.
pub fn get_capabilities() -> VoiceCapabilities {
    VoiceCapabilities {
        can_record: is_recording_available(),
        can_play: is_playback_available(),
        supported_codecs: vec![AudioCodec::Opus, AudioCodec::Pcm16],
        max_duration_secs: 120,
    }
}

/// Voice capabilities on this system.
#[derive(Debug, Clone)]
pub struct VoiceCapabilities {
    /// Whether recording is available.
    pub can_record: bool,
    /// Whether playback is available.
    pub can_play: bool,
    /// Supported audio codecs.
    pub supported_codecs: Vec<AudioCodec>,
    /// Maximum recording duration in seconds.
    pub max_duration_secs: u32,
}

impl std::fmt::Display for VoiceCapabilities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Voice Capabilities:")?;
        writeln!(f, "  Recording: {}", if self.can_record { "available" } else { "unavailable" })?;
        writeln!(f, "  Playback: {}", if self.can_play { "available" } else { "unavailable" })?;
        writeln!(f, "  Max duration: {}s", self.max_duration_secs)?;
        write!(f, "  Codecs: ")?;
        for (i, codec) in self.supported_codecs.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{:?}", codec)?;
        }
        Ok(())
    }
}

/// Handle 'voice' CLI command.
pub fn handle_voice(args: &[&str]) -> Result<()> {
    match args.first() {
        Some(&"status") | None => {
            let caps = get_capabilities();
            println!("{}", caps);
            Ok(())
        }
        Some(&"record") => {
            if !is_recording_available() {
                return Err(anyhow!("Voice recording not available. Audio crates not integrated."));
            }
            println!("Recording... (press Enter to stop)");
            // TODO: Start recording thread
            Err(anyhow!("Recording not implemented yet."))
        }
        Some(&"play") => {
            if args.len() < 2 {
                return Err(anyhow!("Usage: voice play <message-id>"));
            }
            if !is_playback_available() {
                return Err(anyhow!("Voice playback not available. Audio crates not integrated."));
            }
            // TODO: Play voice message
            Err(anyhow!("Playback not implemented yet."))
        }
        Some(&"help") => {
            println!("Voice message commands:");
            println!("  voice status   - Show voice capabilities");
            println!("  voice record   - Record a voice message");
            println!("  voice play <id> - Play a voice message");
            Ok(())
        }
        Some(cmd) => Err(anyhow!("Unknown voice command: {}. Try 'voice help'.", cmd)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_is_recording_available() {
        // Returns true if system has input device, false otherwise
        // Just verify it doesn't panic
        let _ = is_recording_available();
    }
    
    #[test]
    fn test_is_playback_available() {
        // Returns true if system has output device, false otherwise
        // Just verify it doesn't panic
        let _ = is_playback_available();
    }
    
    #[test]
    fn test_get_capabilities() {
        let caps = get_capabilities();
        // Verify structure, not specific values (device-dependent)
        assert_eq!(caps.max_duration_secs, 120);
        assert!(!caps.supported_codecs.is_empty());
        assert!(caps.supported_codecs.contains(&crate::voice::AudioCodec::Opus));
    }
    
    #[test]
    fn test_handle_voice_status() {
        // Should not error
        let result = handle_voice(&["status"]);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_handle_voice_help() {
        let result = handle_voice(&["help"]);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_handle_voice_play_missing_id() {
        let result = handle_voice(&["play"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Usage"));
    }
    
    #[test]
    fn test_handle_voice_unknown_command() {
        let result = handle_voice(&["unknown"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown"));
    }
}
