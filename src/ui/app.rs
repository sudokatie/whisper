//! TUI application state.

/// Application mode.
pub enum AppMode {
    Chat,
    Contacts,
    Input,
}

/// TUI application.
pub struct App {
    pub mode: AppMode,
    pub should_quit: bool,
}

impl App {
    /// Create a new app.
    pub fn new() -> Self {
        Self {
            mode: AppMode::Contacts,
            should_quit: false,
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
