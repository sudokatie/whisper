//! Audio recording and playback for voice messages.
//!
//! Uses cpal for cross-platform audio input and rodio for playback.

use anyhow::{anyhow, Result};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::voice::{AudioCodec, VoiceConfig, VoiceMessage};

/// Check if an audio input device is available.
pub fn has_input_device() -> bool {
    let host = cpal::default_host();
    host.default_input_device().is_some()
}

/// Check if an audio output device is available.
pub fn has_output_device() -> bool {
    let host = cpal::default_host();
    host.default_output_device().is_some()
}

/// List available audio input devices.
pub fn list_input_devices() -> Vec<String> {
    let host = cpal::default_host();
    host.input_devices()
        .map(|devices| {
            devices
                .filter_map(|d| d.name().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// List available audio output devices.
pub fn list_output_devices() -> Vec<String> {
    let host = cpal::default_host();
    host.output_devices()
        .map(|devices| {
            devices
                .filter_map(|d| d.name().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Audio recorder for voice messages.
pub struct AudioRecorder {
    /// Recorded samples (16-bit PCM).
    samples: Arc<Mutex<Vec<i16>>>,
    /// Sample rate.
    sample_rate: u32,
    /// Recording flag.
    is_recording: Arc<AtomicBool>,
}

impl AudioRecorder {
    /// Create a new audio recorder.
    pub fn new(sample_rate: u32) -> Self {
        Self {
            samples: Arc::new(Mutex::new(Vec::new())),
            sample_rate,
            is_recording: Arc::new(AtomicBool::new(false)),
        }
    }
    
    /// Check if currently recording.
    pub fn is_recording(&self) -> bool {
        self.is_recording.load(Ordering::Relaxed)
    }
    
    /// Start recording from the default input device.
    ///
    /// Returns a handle that stops recording when dropped.
    pub fn start(&self) -> Result<RecordingHandle> {
        if self.is_recording() {
            return Err(anyhow!("Already recording"));
        }
        
        let host = cpal::default_host();
        let device = host.default_input_device()
            .ok_or_else(|| anyhow!("No audio input device found"))?;
        
        let config = cpal::StreamConfig {
            channels: 1,
            sample_rate: cpal::SampleRate(self.sample_rate),
            buffer_size: cpal::BufferSize::Default,
        };
        
        let samples = Arc::clone(&self.samples);
        let is_recording = Arc::clone(&self.is_recording);
        
        // Clear previous samples
        samples.lock().unwrap().clear();
        is_recording.store(true, Ordering::Relaxed);
        
        let err_fn = |err| eprintln!("Audio input error: {}", err);
        
        let is_recording_clone = Arc::clone(&is_recording);
        let stream = device.build_input_stream(
            &config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                if is_recording_clone.load(Ordering::Relaxed) {
                    let mut samples = samples.lock().unwrap();
                    for &sample in data {
                        // Convert f32 to i16
                        let sample_i16 = (sample * 32767.0).clamp(-32768.0, 32767.0) as i16;
                        samples.push(sample_i16);
                    }
                }
            },
            err_fn,
            None,
        )?;
        
        stream.play()?;
        
        Ok(RecordingHandle {
            stream: Some(stream),
            is_recording: Arc::clone(&self.is_recording),
        })
    }
    
    /// Stop recording and get the recorded samples.
    pub fn stop(&self) -> Vec<i16> {
        self.is_recording.store(false, Ordering::Relaxed);
        std::mem::take(&mut *self.samples.lock().unwrap())
    }
    
    /// Get the current sample count.
    pub fn sample_count(&self) -> usize {
        self.samples.lock().unwrap().len()
    }
    
    /// Get recording duration in milliseconds.
    pub fn duration_ms(&self) -> u64 {
        let count = self.sample_count() as u64;
        (count * 1000) / self.sample_rate as u64
    }
}

/// Handle that stops recording when dropped.
pub struct RecordingHandle {
    #[allow(dead_code)]
    stream: Option<cpal::Stream>,
    is_recording: Arc<AtomicBool>,
}

impl Drop for RecordingHandle {
    fn drop(&mut self) {
        self.is_recording.store(false, Ordering::Relaxed);
    }
}

/// Encode PCM samples to WAV format.
pub fn encode_wav(samples: &[i16], sample_rate: u32) -> Result<Vec<u8>> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = hound::WavWriter::new(&mut cursor, spec)?;
        for &sample in samples {
            writer.write_sample(sample)?;
        }
        writer.finalize()?;
    }
    
    Ok(cursor.into_inner())
}

/// Calculate waveform data (amplitude envelope) from samples.
///
/// Returns amplitude values (0-255) for visualization.
pub fn calculate_waveform(samples: &[i16], num_points: usize) -> Vec<u8> {
    if samples.is_empty() || num_points == 0 {
        return Vec::new();
    }
    
    let chunk_size = samples.len() / num_points;
    if chunk_size == 0 {
        return samples.iter()
            .map(|&s| ((s.unsigned_abs() as u32 * 255) / 32768) as u8)
            .collect();
    }
    
    samples
        .chunks(chunk_size)
        .take(num_points)
        .map(|chunk| {
            let max = chunk.iter().map(|&s| s.unsigned_abs() as u32).max().unwrap_or(0);
            ((max * 255) / 32768) as u8
        })
        .collect()
}

/// Record a voice message.
///
/// Records for `max_duration_secs` or until `stop_signal` is true.
pub fn record_voice_message(
    config: &VoiceConfig,
    stop_signal: Arc<AtomicBool>,
) -> Result<(VoiceMessage, Vec<u8>)> {
    let recorder = AudioRecorder::new(config.sample_rate);
    let _handle = recorder.start()?;
    
    let max_samples = config.sample_rate as u64 * config.max_duration_secs as u64;
    let check_interval = std::time::Duration::from_millis(100);
    
    // Record until stopped or max duration
    while !stop_signal.load(Ordering::Relaxed) {
        std::thread::sleep(check_interval);
        if recorder.sample_count() as u64 >= max_samples {
            break;
        }
    }
    
    let samples = recorder.stop();
    let duration_ms = (samples.len() as u64 * 1000) / config.sample_rate as u64;
    
    // Encode to WAV (Opus encoding deferred to future work)
    let audio_data = encode_wav(&samples, config.sample_rate)?;
    let waveform = calculate_waveform(&samples, 50);
    
    let mut message = VoiceMessage::new(
        duration_ms,
        AudioCodec::Pcm16, // WAV for now, Opus later
        config.sample_rate,
        audio_data.len() as u64,
    );
    message.waveform = waveform;
    
    Ok((message, audio_data))
}

/// Play audio data.
pub fn play_audio(audio_data: &[u8], codec: AudioCodec) -> Result<()> {
    match codec {
        AudioCodec::Pcm16 => play_wav(audio_data),
        AudioCodec::Opus => Err(anyhow!("Opus playback not yet implemented")),
    }
}

/// Play WAV audio data.
fn play_wav(audio_data: &[u8]) -> Result<()> {
    use rodio::{Decoder, OutputStream, Sink};
    
    let (_stream, stream_handle) = OutputStream::try_default()?;
    let sink = Sink::try_new(&stream_handle)?;
    
    let cursor = std::io::Cursor::new(audio_data.to_vec());
    let source = Decoder::new(cursor)?;
    
    sink.append(source);
    sink.sleep_until_end();
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encode_wav() {
        let samples = vec![0i16, 1000, -1000, 0];
        let result = encode_wav(&samples, 16000);
        assert!(result.is_ok());
        let wav = result.unwrap();
        // WAV header is 44 bytes, plus 8 bytes (4 samples * 2 bytes)
        assert!(wav.len() >= 44);
        // Check RIFF header
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
    }
    
    #[test]
    fn test_calculate_waveform_empty() {
        let waveform = calculate_waveform(&[], 10);
        assert!(waveform.is_empty());
    }
    
    #[test]
    fn test_calculate_waveform() {
        // Max amplitude samples
        let samples = vec![32767i16; 100];
        let waveform = calculate_waveform(&samples, 10);
        assert_eq!(waveform.len(), 10);
        // All should be near max (255)
        for &w in &waveform {
            assert!(w > 250);
        }
    }
    
    #[test]
    fn test_calculate_waveform_silence() {
        let samples = vec![0i16; 100];
        let waveform = calculate_waveform(&samples, 10);
        assert_eq!(waveform.len(), 10);
        // All should be 0
        for &w in &waveform {
            assert_eq!(w, 0);
        }
    }
    
    #[test]
    fn test_audio_recorder_new() {
        let recorder = AudioRecorder::new(16000);
        assert!(!recorder.is_recording());
        assert_eq!(recorder.sample_count(), 0);
        assert_eq!(recorder.duration_ms(), 0);
    }
    
    #[test]
    fn test_list_input_devices() {
        // Should not panic, result depends on system
        let devices = list_input_devices();
        // Just verify it returns a vec
        let _ = devices.len();
    }
    
    #[test]
    fn test_list_output_devices() {
        // Should not panic, result depends on system
        let devices = list_output_devices();
        let _ = devices.len();
    }
}
