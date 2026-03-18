//! Terminal UI.

mod app;
mod input;
mod views;
mod voice_ui;

pub use app::{App, AppMode, DisplayMessage, DisplayStatus, InputAction};
pub use input::{
    handle_chat_mode, handle_contacts_mode, handle_input_mode, ChatAction, ContactAction,
    InputResult,
};
pub use views::{render_chat, render_contacts, render_empty, render_status, short_peer_id};
pub use voice_ui::{render_voice_overlay, VoiceOverlay};
