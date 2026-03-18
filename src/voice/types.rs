//! Voice message types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Audio codec for voice messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AudioCodec {
    /// Opus codec (default, best compression)
    Opus,
    /// PCM 16-bit (uncompressed, for compatibility)
    Pcm16,
}

impl Default for AudioCodec {
    fn default() -> Self {
        Self::Opus
    }
}

impl AudioCodec {
    /// Get file extension for this codec.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Opus => "opus",
            Self::Pcm16 => "wav",
        }
    }
    
    /// Get MIME type for this codec.
    pub fn mime_type(&self) -> &'static str {
        match self {
            Self::Opus => "audio/opus",
            Self::Pcm16 => "audio/wav",
        }
    }
}

/// Voice message metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceMessage {
    /// Unique identifier.
    pub id: Uuid,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Audio codec used.
    pub codec: AudioCodec,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Waveform data for visualization (amplitude samples).
    pub waveform: Vec<u8>,
}

impl VoiceMessage {
    /// Create a new voice message.
    pub fn new(duration_ms: u64, codec: AudioCodec, sample_rate: u32, size_bytes: u64) -> Self {
        Self {
            id: Uuid::new_v4(),
            duration_ms,
            codec,
            sample_rate,
            size_bytes,
            waveform: Vec::new(),
        }
    }
    
    /// Format duration as MM:SS.
    pub fn duration_str(&self) -> String {
        let secs = self.duration_ms / 1000;
        let mins = secs / 60;
        let secs = secs % 60;
        format!("{:02}:{:02}", mins, secs)
    }
}

/// Voice recording configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceConfig {
    /// Preferred codec.
    pub codec: AudioCodec,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// Maximum recording duration in seconds.
    pub max_duration_secs: u32,
    /// Whether voice messages are enabled.
    pub enabled: bool,
}

impl Default for VoiceConfig {
    fn default() -> Self {
        Self {
            codec: AudioCodec::Opus,
            sample_rate: 16000,
            max_duration_secs: 120,
            enabled: true,
        }
    }
}

/// Voice recording state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingState {
    /// Not recording.
    Idle,
    /// Currently recording.
    Recording,
    /// Recording paused.
    Paused,
    /// Processing recorded audio.
    Processing,
}

impl Default for RecordingState {
    fn default() -> Self {
        Self::Idle
    }
}

/// Voice playback state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaybackState {
    /// Not playing.
    Stopped,
    /// Currently playing.
    Playing,
    /// Playback paused.
    Paused,
}

impl Default for PlaybackState {
    fn default() -> Self {
        Self::Stopped
    }
}

#[cfg(test)]
mod type_tests {
    use super::*;
    
    #[test]
    fn test_audio_codec_extension() {
        assert_eq!(AudioCodec::Opus.extension(), "opus");
        assert_eq!(AudioCodec::Pcm16.extension(), "wav");
    }
    
    #[test]
    fn test_audio_codec_mime_type() {
        assert_eq!(AudioCodec::Opus.mime_type(), "audio/opus");
        assert_eq!(AudioCodec::Pcm16.mime_type(), "audio/wav");
    }
    
    #[test]
    fn test_voice_message_duration_str() {
        let msg = VoiceMessage::new(65000, AudioCodec::Opus, 16000, 1024);
        assert_eq!(msg.duration_str(), "01:05");
    }
    
    #[test]
    fn test_voice_message_duration_str_short() {
        let msg = VoiceMessage::new(5000, AudioCodec::Opus, 16000, 512);
        assert_eq!(msg.duration_str(), "00:05");
    }
    
    #[test]
    fn test_voice_config_default() {
        let config = VoiceConfig::default();
        assert_eq!(config.codec, AudioCodec::Opus);
        assert_eq!(config.sample_rate, 16000);
        assert_eq!(config.max_duration_secs, 120);
        assert!(config.enabled);
    }
}
