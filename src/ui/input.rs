//! Input handling for the TUI.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Result of input mode key handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputResult {
    /// Continue editing.
    Continue,
    /// Submit the input.
    Submit,
    /// Cancel input.
    Cancel,
}

/// Action from chat mode key handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatAction {
    /// No action.
    None,
    /// Enter input mode.
    EnterInput,
    /// Go to contacts.
    GoToContacts,
    /// Scroll up.
    ScrollUp,
    /// Scroll down.
    ScrollDown,
    /// Quit the app.
    Quit,
}

/// Action from contacts mode key handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactAction {
    /// No action.
    None,
    /// Select the current contact.
    Select,
    /// Move selection up.
    MoveUp,
    /// Move selection down.
    MoveDown,
    /// Go to chat with selected.
    OpenChat,
    /// Quit the app.
    Quit,
}

/// Handle key events in input mode.
/// 
/// Modifies the input buffer based on the key event.
pub fn handle_input_mode(key: KeyEvent, input: &mut String) -> InputResult {
    match key.code {
        KeyCode::Esc => InputResult::Cancel,
        KeyCode::Enter => InputResult::Submit,
        KeyCode::Backspace => {
            input.pop();
            InputResult::Continue
        }
        KeyCode::Char(c) => {
            // Handle Ctrl+C as cancel
            if c == 'c' && key.modifiers.contains(KeyModifiers::CONTROL) {
                return InputResult::Cancel;
            }
            input.push(c);
            InputResult::Continue
        }
        KeyCode::Delete => {
            // Delete clears all input
            input.clear();
            InputResult::Continue
        }
        _ => InputResult::Continue,
    }
}

/// Handle key events in chat mode.
pub fn handle_chat_mode(key: KeyEvent) -> ChatAction {
    match key.code {
        KeyCode::Char('q') => ChatAction::Quit,
        KeyCode::Char('c') => ChatAction::GoToContacts,
        KeyCode::Char('i') => ChatAction::EnterInput,
        KeyCode::Up | KeyCode::Char('k') => ChatAction::ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ChatAction::ScrollDown,
        KeyCode::Esc => ChatAction::GoToContacts,
        _ => ChatAction::None,
    }
}

/// Handle key events in contacts mode.
/// 
/// Modifies selected index based on navigation keys.
pub fn handle_contacts_mode(key: KeyEvent, selected: &mut usize, max: usize) -> ContactAction {
    if max == 0 {
        // No contacts to select
        return match key.code {
            KeyCode::Char('q') => ContactAction::Quit,
            _ => ContactAction::None,
        };
    }

    match key.code {
        KeyCode::Char('q') => ContactAction::Quit,
        KeyCode::Up | KeyCode::Char('k') => {
            if *selected > 0 {
                *selected -= 1;
                ContactAction::MoveUp
            } else {
                ContactAction::None
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if *selected + 1 < max {
                *selected += 1;
                ContactAction::MoveDown
            } else {
                ContactAction::None
            }
        }
        KeyCode::Enter => ContactAction::OpenChat,
        KeyCode::Char(' ') => ContactAction::Select,
        _ => ContactAction::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_mode_appends_chars() {
        let mut input = String::new();
        let key = KeyEvent::from(KeyCode::Char('a'));
        
        let result = handle_input_mode(key, &mut input);
        
        assert_eq!(result, InputResult::Continue);
        assert_eq!(input, "a");
    }

    #[test]
    fn input_mode_backspace_removes() {
        let mut input = "hello".to_string();
        let key = KeyEvent::from(KeyCode::Backspace);
        
        handle_input_mode(key, &mut input);
        
        assert_eq!(input, "hell");
    }

    #[test]
    fn input_mode_enter_submits() {
        let mut input = "test".to_string();
        let key = KeyEvent::from(KeyCode::Enter);
        
        let result = handle_input_mode(key, &mut input);
        
        assert_eq!(result, InputResult::Submit);
    }

    #[test]
    fn input_mode_esc_cancels() {
        let mut input = "test".to_string();
        let key = KeyEvent::from(KeyCode::Esc);
        
        let result = handle_input_mode(key, &mut input);
        
        assert_eq!(result, InputResult::Cancel);
    }

    #[test]
    fn contacts_mode_navigation() {
        let mut selected = 1usize;
        let max = 5usize;
        
        // Move up
        let up_key = KeyEvent::from(KeyCode::Up);
        let action = handle_contacts_mode(up_key, &mut selected, max);
        assert_eq!(action, ContactAction::MoveUp);
        assert_eq!(selected, 0);
        
        // Can't go past top
        let action = handle_contacts_mode(up_key, &mut selected, max);
        assert_eq!(action, ContactAction::None);
        assert_eq!(selected, 0);
    }

    #[test]
    fn chat_mode_quit() {
        let key = KeyEvent::from(KeyCode::Char('q'));
        let action = handle_chat_mode(key);
        assert_eq!(action, ChatAction::Quit);
    }
}
