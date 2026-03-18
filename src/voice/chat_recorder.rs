//! Voice recorder for use in chat loops.
//!
//! Provides a simple interface for recording voice messages during chat sessions.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use anyhow::{anyhow, Result};

use super::{
    AudioCodec, AudioRecorder, VoiceConfig, VoiceMessage,
    encode_wav, calculate_waveform,
};

/// Voice recording state for chat integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatRecordingState {
    /// Not recording.
    Idle,
    /// Recording in progress.
    Recording,
    /// Recording finished, audio ready.
    Ready,
    /// Recording failed.
    Failed,
}

/// Chat voice recorder.
///
/// Manages voice recording in a background thread for use in async chat loops.
pub struct ChatVoiceRecorder {
    /// Recording configuration.
    config: VoiceConfig,
    /// Current state.
    state: Arc<Mutex<ChatRecordingState>>,
    /// Stop signal.
    stop_signal: Arc<AtomicBool>,
    /// Recording thread handle.
    thread: Option<JoinHandle<()>>,
    /// Recorded audio data.
    audio_data: Arc<Mutex<Option<(VoiceMessage, Vec<u8>)>>>,
    /// Error message if failed.
    error: Arc<Mutex<Option<String>>>,
}

impl ChatVoiceRecorder {
    /// Create a new chat voice recorder.
    pub fn new(config: VoiceConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(ChatRecordingState::Idle)),
            stop_signal: Arc::new(AtomicBool::new(false)),
            thread: None,
            audio_data: Arc::new(Mutex::new(None)),
            error: Arc::new(Mutex::new(None)),
        }
    }

    /// Get the current recording state.
    pub fn state(&self) -> ChatRecordingState {
        *self.state.lock().unwrap()
    }

    /// Check if currently recording.
    pub fn is_recording(&self) -> bool {
        self.state() == ChatRecordingState::Recording
    }

    /// Start recording.
    pub fn start(&mut self) -> Result<()> {
        if self.is_recording() {
            return Err(anyhow!("Already recording"));
        }

        // Reset state
        self.stop_signal.store(false, Ordering::Relaxed);
        *self.state.lock().unwrap() = ChatRecordingState::Recording;
        *self.audio_data.lock().unwrap() = None;
        *self.error.lock().unwrap() = None;

        // Clone refs for the recording thread
        let config = self.config.clone();
        let state = Arc::clone(&self.state);
        let stop_signal = Arc::clone(&self.stop_signal);
        let audio_data = Arc::clone(&self.audio_data);
        let error = Arc::clone(&self.error);

        // Spawn recording thread
        self.thread = Some(thread::spawn(move || {
            let result = record_in_thread(&config, &stop_signal);
            
            match result {
                Ok((msg, data)) => {
                    *audio_data.lock().unwrap() = Some((msg, data));
                    *state.lock().unwrap() = ChatRecordingState::Ready;
                }
                Err(e) => {
                    *error.lock().unwrap() = Some(e.to_string());
                    *state.lock().unwrap() = ChatRecordingState::Failed;
                }
            }
        }));

        Ok(())
    }

    /// Stop recording.
    pub fn stop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
        
        // Wait for thread to finish
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }

    /// Cancel recording (stop and discard).
    pub fn cancel(&mut self) {
        self.stop();
        *self.audio_data.lock().unwrap() = None;
        *self.state.lock().unwrap() = ChatRecordingState::Idle;
    }

    /// Take the recorded audio data.
    ///
    /// Returns None if not ready or already taken.
    pub fn take_audio(&mut self) -> Option<(VoiceMessage, Vec<u8>)> {
        if self.state() != ChatRecordingState::Ready {
            return None;
        }
        
        let result = self.audio_data.lock().unwrap().take();
        *self.state.lock().unwrap() = ChatRecordingState::Idle;
        result
    }

    /// Get the error message if recording failed.
    pub fn error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }

    /// Reset to idle state.
    pub fn reset(&mut self) {
        self.cancel();
        *self.error.lock().unwrap() = None;
    }
}

impl Drop for ChatVoiceRecorder {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Record audio in a thread.
fn record_in_thread(
    config: &VoiceConfig,
    stop_signal: &AtomicBool,
) -> Result<(VoiceMessage, Vec<u8>)> {
    let recorder = AudioRecorder::new(config.sample_rate);
    let _handle = recorder.start()?;

    let max_samples = config.sample_rate as u64 * config.max_duration_secs as u64;
    let check_interval = std::time::Duration::from_millis(50);

    // Record until stopped or max duration
    while !stop_signal.load(Ordering::Relaxed) {
        std::thread::sleep(check_interval);
        if recorder.sample_count() as u64 >= max_samples {
            break;
        }
    }

    let samples = recorder.stop();
    
    if samples.is_empty() {
        return Err(anyhow!("No audio recorded"));
    }

    let duration_ms = (samples.len() as u64 * 1000) / config.sample_rate as u64;

    // Minimum duration check (500ms)
    if duration_ms < 500 {
        return Err(anyhow!("Recording too short (minimum 0.5 seconds)"));
    }

    // Encode to WAV
    let audio_data = encode_wav(&samples, config.sample_rate)?;
    let waveform = calculate_waveform(&samples, 50);

    let mut message = VoiceMessage::new(
        duration_ms,
        AudioCodec::Pcm16,
        config.sample_rate,
        audio_data.len() as u64,
    );
    message.waveform = waveform;

    Ok((message, audio_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_recorder_new() {
        let config = VoiceConfig::default();
        let recorder = ChatVoiceRecorder::new(config);
        assert_eq!(recorder.state(), ChatRecordingState::Idle);
        assert!(!recorder.is_recording());
    }

    #[test]
    fn test_chat_recorder_state_transitions() {
        let config = VoiceConfig::default();
        let mut recorder = ChatVoiceRecorder::new(config);
        
        assert_eq!(recorder.state(), ChatRecordingState::Idle);
        
        // Can't take audio when idle
        assert!(recorder.take_audio().is_none());
        
        // Reset works from any state
        recorder.reset();
        assert_eq!(recorder.state(), ChatRecordingState::Idle);
    }

    #[test]
    fn test_chat_recorder_cancel() {
        let config = VoiceConfig::default();
        let mut recorder = ChatVoiceRecorder::new(config);
        
        // Cancel from idle is fine
        recorder.cancel();
        assert_eq!(recorder.state(), ChatRecordingState::Idle);
    }

    #[test]
    fn test_chat_recording_state_eq() {
        assert_eq!(ChatRecordingState::Idle, ChatRecordingState::Idle);
        assert_ne!(ChatRecordingState::Idle, ChatRecordingState::Recording);
    }
}
