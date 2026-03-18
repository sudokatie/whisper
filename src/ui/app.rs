//! TUI application state.

use chrono::{DateTime, Utc};
use crossterm::event::{KeyCode, KeyEvent};
use libp2p::PeerId;

use crate::identity::Contact;

/// Application mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    /// Viewing chat messages.
    Chat,
    /// Viewing contact list.
    Contacts,
    /// Entering text input.
    Input,
}

/// Message delivery status for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisplayStatus {
    /// Message is being sent.
    #[default]
    Pending,
    /// Message was sent to the network.
    Sent,
    /// Message was delivered to recipient.
    Delivered,
    /// Message was read by recipient.
    Read,
    /// Message send failed.
    Failed,
}

impl DisplayStatus {
    /// Get status indicator character.
    pub fn indicator(&self) -> &'static str {
        match self {
            DisplayStatus::Pending => "...",
            DisplayStatus::Sent => "✓",
            DisplayStatus::Delivered => "✓✓",
            DisplayStatus::Read => "✓✓", // Same as delivered but colored
            DisplayStatus::Failed => "✗",
        }
    }
    
    /// Whether this status indicates the message was read.
    pub fn is_read(&self) -> bool {
        matches!(self, DisplayStatus::Read)
    }
}

/// A message formatted for display.
#[derive(Debug, Clone)]
pub struct DisplayMessage {
    /// Sender's peer ID.
    pub from: PeerId,
    /// Message content.
    pub content: String,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// Whether this message is from us.
    pub is_ours: bool,
    /// Reaction summary: (emoji, count).
    pub reactions: Vec<(String, usize)>,
    /// Delivery status (only shown for our messages).
    pub status: DisplayStatus,
}

impl DisplayMessage {
    /// Create a new display message.
    pub fn new(from: PeerId, content: String, timestamp: DateTime<Utc>, is_ours: bool) -> Self {
        Self {
            from,
            content,
            timestamp,
            is_ours,
            reactions: Vec::new(),
            status: DisplayStatus::default(),
        }
    }
    
    /// Create a display message with status.
    pub fn with_status(from: PeerId, content: String, timestamp: DateTime<Utc>, is_ours: bool, status: DisplayStatus) -> Self {
        Self {
            from,
            content,
            timestamp,
            is_ours,
            reactions: Vec::new(),
            status,
        }
    }

    /// Create a display message with reactions.
    pub fn with_reactions(
        from: PeerId,
        content: String,
        timestamp: DateTime<Utc>,
        is_ours: bool,
        reactions: Vec<(String, usize)>,
    ) -> Self {
        Self {
            from,
            content,
            timestamp,
            is_ours,
            reactions,
            status: DisplayStatus::default(),
        }
    }
}

/// Input action result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputAction {
    /// No action needed.
    None,
    /// Send the current input.
    Send(String),
    /// Cancel input mode.
    Cancel,
    /// Voice recording action.
    Voice(VoiceAction),
}

/// Voice action result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoiceAction {
    /// No voice action.
    None,
    /// Start recording.
    StartRecording,
    /// Stop recording.
    StopRecording,
    /// Cancel recording.
    CancelRecording,
}

/// TUI application.
pub struct App {
    /// Current mode.
    pub mode: AppMode,
    /// Currently selected chat (peer).
    pub current_chat: Option<PeerId>,
    /// Messages in current chat.
    pub messages: Vec<DisplayMessage>,
    /// Current input buffer.
    pub input: String,
    /// Contact list.
    pub contacts: Vec<Contact>,
    /// Selected contact index.
    pub selected_contact: usize,
    /// Whether the app should quit.
    pub should_quit: bool,
    /// Our peer ID.
    pub our_peer_id: Option<PeerId>,
    /// Voice recording active.
    pub voice_recording: bool,
}

impl App {
    /// Create a new app.
    pub fn new() -> Self {
        Self {
            mode: AppMode::Contacts,
            current_chat: None,
            messages: Vec::new(),
            input: String::new(),
            contacts: Vec::new(),
            selected_contact: 0,
            should_quit: false,
            our_peer_id: None,
            voice_recording: false,
        }
    }

    /// Set our peer ID.
    pub fn set_peer_id(&mut self, peer_id: PeerId) {
        self.our_peer_id = Some(peer_id);
    }

    /// Handle a key event.
    pub fn handle_key(&mut self, key: KeyEvent) -> InputAction {
        match self.mode {
            AppMode::Chat => self.handle_chat_key(key),
            AppMode::Contacts => self.handle_contacts_key(key),
            AppMode::Input => self.handle_input_key(key),
        }
    }

    /// Handle key in chat mode.
    fn handle_chat_key(&mut self, key: KeyEvent) -> InputAction {
        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
            }
            KeyCode::Char('c') => {
                self.mode = AppMode::Contacts;
            }
            KeyCode::Char('i') => {
                self.mode = AppMode::Input;
            }
            KeyCode::Char('v') | KeyCode::Char('V') => {
                // Toggle voice recording - handled by caller
                return InputAction::Voice(if self.voice_recording {
                    VoiceAction::StopRecording
                } else {
                    VoiceAction::StartRecording
                });
            }
            KeyCode::Esc => {
                if self.voice_recording {
                    return InputAction::Voice(VoiceAction::CancelRecording);
                }
                self.mode = AppMode::Contacts;
                self.current_chat = None;
            }
            _ => {}
        }
        InputAction::None
    }

    /// Handle key in contacts mode.
    fn handle_contacts_key(&mut self, key: KeyEvent) -> InputAction {
        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_contact > 0 {
                    self.selected_contact -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_contact + 1 < self.contacts.len() {
                    self.selected_contact += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(contact) = self.contacts.get(self.selected_contact) {
                    self.current_chat = Some(contact.peer_id);
                    self.mode = AppMode::Chat;
                }
            }
            _ => {}
        }
        InputAction::None
    }

    /// Handle key in input mode.
    fn handle_input_key(&mut self, key: KeyEvent) -> InputAction {
        match key.code {
            KeyCode::Esc => {
                self.input.clear();
                self.mode = AppMode::Chat;
                InputAction::Cancel
            }
            KeyCode::Enter => {
                if !self.input.is_empty() {
                    let text = std::mem::take(&mut self.input);
                    self.mode = AppMode::Chat;
                    InputAction::Send(text)
                } else {
                    InputAction::None
                }
            }
            KeyCode::Backspace => {
                self.input.pop();
                InputAction::None
            }
            KeyCode::Char(c) => {
                self.input.push(c);
                InputAction::None
            }
            _ => InputAction::None,
        }
    }

    /// Handle an incoming message.
    pub fn handle_message(&mut self, msg: DisplayMessage) {
        // Add to messages if it's for the current chat
        if let Some(current) = &self.current_chat {
            // Message is relevant if it's from/to the current peer
            let is_relevant = *current == msg.from;
            if is_relevant {
                self.messages.push(msg);
            }
        }
    }

    /// Add a contact to the list.
    pub fn add_contact(&mut self, contact: Contact) {
        self.contacts.push(contact);
    }

    /// Clear messages.
    pub fn clear_messages(&mut self) {
        self.messages.clear();
    }

    /// Get the current chat peer.
    pub fn current_peer(&self) -> Option<PeerId> {
        self.current_chat
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_app_starts_in_contacts_mode() {
        let app = App::new();
        assert_eq!(app.mode, AppMode::Contacts);
    }

    #[test]
    fn new_app_should_not_quit() {
        let app = App::new();
        assert!(!app.should_quit);
    }

    #[test]
    fn q_key_sets_should_quit() {
        let mut app = App::new();
        let key = KeyEvent::from(KeyCode::Char('q'));
        app.handle_key(key);
        assert!(app.should_quit);
    }

    #[test]
    fn input_buffer_appends_chars() {
        let mut app = App::new();
        app.mode = AppMode::Input;
        
        app.handle_key(KeyEvent::from(KeyCode::Char('h')));
        app.handle_key(KeyEvent::from(KeyCode::Char('i')));
        
        assert_eq!(app.input, "hi");
    }

    #[test]
    fn backspace_removes_char() {
        let mut app = App::new();
        app.mode = AppMode::Input;
        app.input = "hello".to_string();
        
        app.handle_key(KeyEvent::from(KeyCode::Backspace));
        
        assert_eq!(app.input, "hell");
    }

    #[test]
    fn enter_in_input_mode_sends() {
        let mut app = App::new();
        app.mode = AppMode::Input;
        app.input = "test message".to_string();
        
        let action = app.handle_key(KeyEvent::from(KeyCode::Enter));
        
        assert_eq!(action, InputAction::Send("test message".to_string()));
        assert!(app.input.is_empty());
        assert_eq!(app.mode, AppMode::Chat);
    }

    #[test]
    fn display_status_indicators() {
        assert_eq!(DisplayStatus::Pending.indicator(), "...");
        assert_eq!(DisplayStatus::Sent.indicator(), "✓");
        assert_eq!(DisplayStatus::Delivered.indicator(), "✓✓");
        assert_eq!(DisplayStatus::Read.indicator(), "✓✓");
        assert_eq!(DisplayStatus::Failed.indicator(), "✗");
    }

    #[test]
    fn display_status_is_read() {
        assert!(!DisplayStatus::Pending.is_read());
        assert!(!DisplayStatus::Sent.is_read());
        assert!(!DisplayStatus::Delivered.is_read());
        assert!(DisplayStatus::Read.is_read());
        assert!(!DisplayStatus::Failed.is_read());
    }

    #[test]
    fn display_message_with_status() {
        let peer = libp2p::PeerId::random();
        let msg = DisplayMessage::with_status(
            peer,
            "Hello".to_string(),
            chrono::Utc::now(),
            true,
            DisplayStatus::Delivered,
        );
        
        assert!(msg.is_ours);
        assert_eq!(msg.status, DisplayStatus::Delivered);
        assert_eq!(msg.content, "Hello");
    }

    #[test]
    fn display_message_default_status() {
        let peer = libp2p::PeerId::random();
        let msg = DisplayMessage::new(peer, "Test".to_string(), chrono::Utc::now(), true);
        
        assert_eq!(msg.status, DisplayStatus::Pending);
    }
}
