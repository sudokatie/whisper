//! Wire protocol for voice messages.
//!
//! Voice messages are sent as a series of chunks with metadata.

use serde::{Deserialize, Serialize};

use super::VoiceMessage;

#[cfg(test)]
use super::AudioCodec;

/// Wire message prefix for voice data.
pub const VOICE_PREFIX: &[u8] = b"VOIC:";

/// Voice message wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceWire {
    /// Voice message metadata.
    pub message: VoiceMessage,
    /// Compressed audio data.
    pub audio_data: Vec<u8>,
}

impl VoiceWire {
    /// Create a new voice wire message.
    pub fn new(message: VoiceMessage, audio_data: Vec<u8>) -> Self {
        Self { message, audio_data }
    }
    
    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = VOICE_PREFIX.to_vec();
        let payload = bincode::serialize(self).unwrap_or_default();
        bytes.extend_from_slice(&payload);
        bytes
    }
    
    /// Parse from wire format.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if !data.starts_with(VOICE_PREFIX) {
            return None;
        }
        let payload = &data[VOICE_PREFIX.len()..];
        bincode::deserialize(payload).ok()
    }
}

/// Check if data is a voice message.
pub fn is_voice_message(data: &[u8]) -> bool {
    data.starts_with(VOICE_PREFIX)
}

/// Parse voice message from wire data.
pub fn parse_voice_message(data: &[u8]) -> Option<VoiceWire> {
    VoiceWire::from_bytes(data)
}

/// Create voice message wire data.
pub fn create_voice_wire(voice: &VoiceMessage, audio_data: &[u8]) -> Vec<u8> {
    VoiceWire::new(voice.clone(), audio_data.to_vec()).to_bytes()
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    
    #[test]
    fn test_voice_wire_roundtrip() {
        let voice = VoiceMessage::new(5000, AudioCodec::Opus, 16000, 1024);
        let audio = vec![1, 2, 3, 4, 5];
        
        let wire = VoiceWire::new(voice.clone(), audio.clone());
        let bytes = wire.to_bytes();
        
        assert!(is_voice_message(&bytes));
        
        let parsed = VoiceWire::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.message.duration_ms, 5000);
        assert_eq!(parsed.audio_data, audio);
    }
    
    #[test]
    fn test_is_voice_message() {
        assert!(is_voice_message(b"VOIC:test"));
        assert!(!is_voice_message(b"TEXT:test"));
        assert!(!is_voice_message(b""));
    }
    
    #[test]
    fn test_parse_invalid_data() {
        let result = parse_voice_message(b"invalid data");
        assert!(result.is_none());
    }
    
    #[test]
    fn test_create_voice_wire() {
        let voice = VoiceMessage::new(10000, AudioCodec::Pcm16, 44100, 8000);
        let audio = vec![0; 100];
        
        let wire = create_voice_wire(&voice, &audio);
        assert!(is_voice_message(&wire));
        
        let parsed = parse_voice_message(&wire).unwrap();
        assert_eq!(parsed.message.codec, AudioCodec::Pcm16);
        assert_eq!(parsed.message.sample_rate, 44100);
    }
}
