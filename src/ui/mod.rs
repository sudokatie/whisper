//! Terminal UI.

mod app;
mod input;
mod views;

pub use app::{App, AppMode, DisplayMessage, InputAction};
pub use views::{render_chat, render_contacts, render_empty, render_status, short_peer_id};
