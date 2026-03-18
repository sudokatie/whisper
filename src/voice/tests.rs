//! Integration tests for voice module.

use super::*;

#[test]
fn test_voice_module_exports() {
    // Verify all public types are exported
    let _codec = AudioCodec::default();
    let _config = VoiceConfig::default();
    let _rec_state = RecordingState::default();
    let _play_state = PlaybackState::default();
    
    let voice = VoiceMessage::new(10000, AudioCodec::Opus, 16000, 5000);
    assert_eq!(voice.duration_str(), "00:10");
}
