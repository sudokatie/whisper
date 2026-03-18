//! Voice message CLI commands.

use anyhow::{anyhow, Result};

use crate::voice::{AudioCodec, VoiceConfig, VoiceMessage};

/// Check if voice recording is available on this system.
pub fn is_recording_available() -> bool {
    // TODO: Check for audio input device via cpal
    // For now, return false as audio crates aren't integrated yet
    false
}

/// Check if voice playback is available on this system.
pub fn is_playback_available() -> bool {
    // TODO: Check for audio output device via rodio/cpal
    // For now, return false as audio crates aren't integrated yet
    false
}

/// Record a voice message.
/// 
/// Returns the recorded audio data and metadata.
pub fn record_voice(_config: &VoiceConfig, _max_seconds: u32) -> Result<(VoiceMessage, Vec<u8>)> {
    // TODO: Implement actual recording with cpal
    Err(anyhow!("Voice recording not yet implemented. Requires cpal crate integration."))
}

/// Play a voice message.
pub fn play_voice(_audio_data: &[u8], _codec: AudioCodec) -> Result<()> {
    // TODO: Implement playback with rodio
    Err(anyhow!("Voice playback not yet implemented. Requires rodio crate integration."))
}

/// Stop current recording.
pub fn stop_recording() -> Result<()> {
    // TODO: Signal recording thread to stop
    Err(anyhow!("No recording in progress."))
}

/// Stop current playback.
pub fn stop_playback() -> Result<()> {
    // TODO: Signal playback thread to stop
    Err(anyhow!("No playback in progress."))
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
        // Should return false until cpal is integrated
        assert!(!is_recording_available());
    }
    
    #[test]
    fn test_is_playback_available() {
        // Should return false until rodio is integrated
        assert!(!is_playback_available());
    }
    
    #[test]
    fn test_get_capabilities() {
        let caps = get_capabilities();
        assert!(!caps.can_record);
        assert!(!caps.can_play);
        assert_eq!(caps.max_duration_secs, 120);
        assert!(!caps.supported_codecs.is_empty());
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
    fn test_handle_voice_record_unavailable() {
        let result = handle_voice(&["record"]);
        assert!(result.is_err());
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
