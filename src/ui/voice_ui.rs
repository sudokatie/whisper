//! Voice message TUI components.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame,
};

use crate::voice::{PlaybackState, RecordingState};

/// Voice recording overlay state.
#[derive(Debug, Clone, Default)]
pub struct VoiceOverlay {
    /// Recording state.
    pub recording_state: RecordingState,
    /// Playback state.
    pub playback_state: PlaybackState,
    /// Current recording duration in milliseconds.
    pub duration_ms: u64,
    /// Maximum duration in milliseconds.
    pub max_duration_ms: u64,
    /// Current audio level (0-100).
    pub level: u8,
    /// Waveform data for playback visualization.
    pub waveform: Vec<u8>,
    /// Playback progress (0.0 - 1.0).
    pub playback_progress: f64,
    /// Error message if any.
    pub error: Option<String>,
}

impl VoiceOverlay {
    /// Create a new voice overlay.
    pub fn new(max_duration_secs: u32) -> Self {
        Self {
            recording_state: RecordingState::Idle,
            playback_state: PlaybackState::Stopped,
            duration_ms: 0,
            max_duration_ms: max_duration_secs as u64 * 1000,
            level: 0,
            waveform: Vec::new(),
            playback_progress: 0.0,
            error: None,
        }
    }

    /// Check if overlay should be visible.
    pub fn is_visible(&self) -> bool {
        self.recording_state != RecordingState::Idle
            || self.playback_state != PlaybackState::Stopped
            || self.error.is_some()
    }

    /// Reset to idle state.
    pub fn reset(&mut self) {
        self.recording_state = RecordingState::Idle;
        self.playback_state = PlaybackState::Stopped;
        self.duration_ms = 0;
        self.level = 0;
        self.waveform.clear();
        self.playback_progress = 0.0;
        self.error = None;
    }

    /// Format duration as MM:SS.
    pub fn duration_str(&self) -> String {
        let secs = self.duration_ms / 1000;
        let mins = secs / 60;
        let secs = secs % 60;
        format!("{:02}:{:02}", mins, secs)
    }

    /// Format max duration as MM:SS.
    pub fn max_duration_str(&self) -> String {
        let secs = self.max_duration_ms / 1000;
        let mins = secs / 60;
        let secs = secs % 60;
        format!("{:02}:{:02}", mins, secs)
    }
}

/// Render the voice overlay.
pub fn render_voice_overlay(frame: &mut Frame, area: Rect, overlay: &VoiceOverlay) {
    if !overlay.is_visible() {
        return;
    }

    // Center the overlay
    let popup_width = 50.min(area.width.saturating_sub(4));
    let popup_height = 7;
    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(
        area.x + popup_x,
        area.y + popup_y,
        popup_width,
        popup_height,
    );

    // Clear background
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Black)),
        popup_area,
    );

    // Handle error state
    if let Some(ref err) = overlay.error {
        let block = Block::default()
            .title(" Error ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red));
        
        let inner = block.inner(popup_area);
        frame.render_widget(block, popup_area);
        
        let text = Paragraph::new(err.as_str())
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center);
        frame.render_widget(text, inner);
        return;
    }

    // Recording state
    if overlay.recording_state != RecordingState::Idle {
        render_recording_overlay(frame, popup_area, overlay);
        return;
    }

    // Playback state
    if overlay.playback_state != PlaybackState::Stopped {
        render_playback_overlay(frame, popup_area, overlay);
    }
}

/// Render the recording overlay.
fn render_recording_overlay(frame: &mut Frame, area: Rect, overlay: &VoiceOverlay) {
    let title = match overlay.recording_state {
        RecordingState::Recording => " Recording ",
        RecordingState::Paused => " Paused ",
        RecordingState::Processing => " Processing... ",
        RecordingState::Idle => " Voice ",
    };

    let border_color = match overlay.recording_state {
        RecordingState::Recording => Color::Red,
        RecordingState::Paused => Color::Yellow,
        _ => Color::White,
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner);

    // Duration line
    let duration_text = format!(
        "{} / {}",
        overlay.duration_str(),
        overlay.max_duration_str()
    );
    let duration = Paragraph::new(duration_text)
        .alignment(Alignment::Center)
        .style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(duration, chunks[0]);

    // Level meter
    let level_ratio = overlay.level as f64 / 100.0;
    let level_gauge = Gauge::default()
        .ratio(level_ratio)
        .gauge_style(Style::default().fg(Color::Green))
        .label("");
    frame.render_widget(level_gauge, chunks[1]);

    // Instructions
    let instructions = match overlay.recording_state {
        RecordingState::Recording => "Press V to stop, ESC to cancel",
        RecordingState::Paused => "Press V to resume, ESC to cancel",
        RecordingState::Processing => "Please wait...",
        RecordingState::Idle => "Press V to start recording",
    };
    let help = Paragraph::new(instructions)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(help, chunks[2]);
}

/// Render the playback overlay.
fn render_playback_overlay(frame: &mut Frame, area: Rect, overlay: &VoiceOverlay) {
    let title = match overlay.playback_state {
        PlaybackState::Playing => " Playing ",
        PlaybackState::Paused => " Paused ",
        PlaybackState::Stopped => " Voice ",
    };

    let border_color = match overlay.playback_state {
        PlaybackState::Playing => Color::Blue,
        PlaybackState::Paused => Color::Yellow,
        _ => Color::White,
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner);

    // Waveform visualization (simplified)
    let waveform_str = render_waveform(&overlay.waveform, chunks[0].width as usize);
    let waveform = Paragraph::new(waveform_str)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(waveform, chunks[0]);

    // Progress bar
    let progress_gauge = Gauge::default()
        .ratio(overlay.playback_progress)
        .gauge_style(Style::default().fg(Color::Blue))
        .label("");
    frame.render_widget(progress_gauge, chunks[1]);

    // Instructions
    let instructions = match overlay.playback_state {
        PlaybackState::Playing => "Press V to pause, ESC to stop",
        PlaybackState::Paused => "Press V to resume, ESC to stop",
        PlaybackState::Stopped => "",
    };
    let help = Paragraph::new(instructions)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(help, chunks[2]);
}

/// Render waveform as ASCII art.
fn render_waveform(waveform: &[u8], width: usize) -> String {
    if waveform.is_empty() {
        return String::new();
    }

    let bars = "▁▂▃▄▅▆▇█";
    let step = waveform.len().max(1) / width.max(1);
    if step == 0 {
        return waveform
            .iter()
            .take(width)
            .map(|&v| {
                let idx = (v as usize * 7) / 255;
                bars.chars().nth(idx).unwrap_or('▁')
            })
            .collect();
    }

    waveform
        .chunks(step)
        .take(width)
        .map(|chunk| {
            let avg = chunk.iter().map(|&v| v as usize).sum::<usize>() / chunk.len().max(1);
            let idx = (avg * 7) / 255;
            bars.chars().nth(idx).unwrap_or('▁')
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_voice_overlay_new() {
        let overlay = VoiceOverlay::new(120);
        assert_eq!(overlay.max_duration_ms, 120_000);
        assert!(!overlay.is_visible());
    }

    #[test]
    fn test_voice_overlay_is_visible() {
        let mut overlay = VoiceOverlay::new(120);
        assert!(!overlay.is_visible());

        overlay.recording_state = RecordingState::Recording;
        assert!(overlay.is_visible());

        overlay.reset();
        assert!(!overlay.is_visible());

        overlay.error = Some("Test error".to_string());
        assert!(overlay.is_visible());
    }

    #[test]
    fn test_voice_overlay_duration_str() {
        let mut overlay = VoiceOverlay::new(120);
        overlay.duration_ms = 65_000;
        assert_eq!(overlay.duration_str(), "01:05");
    }

    #[test]
    fn test_render_waveform_empty() {
        let result = render_waveform(&[], 10);
        assert!(result.is_empty());
    }

    #[test]
    fn test_render_waveform() {
        let waveform = vec![0, 128, 255, 64, 192];
        let result = render_waveform(&waveform, 5);
        assert_eq!(result.chars().count(), 5);
    }

    #[test]
    fn test_voice_overlay_reset() {
        let mut overlay = VoiceOverlay::new(120);
        overlay.recording_state = RecordingState::Recording;
        overlay.duration_ms = 5000;
        overlay.error = Some("Error".to_string());

        overlay.reset();
        assert_eq!(overlay.recording_state, RecordingState::Idle);
        assert_eq!(overlay.duration_ms, 0);
        assert!(overlay.error.is_none());
    }
}
