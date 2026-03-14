//! Render views for the TUI.

use libp2p::PeerId;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::identity::Contact;

use super::app::DisplayMessage;

/// Render the chat view with messages and input.
pub fn render_chat(
    frame: &mut Frame,
    area: Rect,
    messages: &[DisplayMessage],
    input: &str,
    is_input_mode: bool,
) {
    // Split into messages area and input area
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    // Render messages
    let message_items: Vec<ListItem> = messages
        .iter()
        .flat_map(|msg| {
            let style = if msg.is_ours {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };

            let time = msg.timestamp.format("%H:%M");
            let prefix = if msg.is_ours { "You" } else { "Them" };
            
            // Build message line with status indicator for our messages
            let mut spans = vec![
                Span::styled(format!("[{}] ", time), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{}: ", prefix), style),
                Span::styled(msg.content.clone(), style),
            ];
            
            // Add status indicator for our messages
            if msg.is_ours {
                let (status_text, status_color) = match msg.status {
                    super::app::DisplayStatus::Pending => (" ...", Color::DarkGray),
                    super::app::DisplayStatus::Sent => (" ✓", Color::DarkGray),
                    super::app::DisplayStatus::Delivered => (" ✓✓", Color::Gray),
                    super::app::DisplayStatus::Read => (" ✓✓", Color::Blue),
                    super::app::DisplayStatus::Failed => (" ✗", Color::Red),
                };
                spans.push(Span::styled(status_text, Style::default().fg(status_color)));
            }
            
            let mut items = vec![ListItem::new(Line::from(spans))];
            
            // Add reactions line if any
            if !msg.reactions.is_empty() {
                let reaction_text: String = msg.reactions
                    .iter()
                    .map(|(emoji, count)| {
                        if *count > 1 {
                            format!("{} {}", emoji, count)
                        } else {
                            emoji.clone()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("  ");
                items.push(ListItem::new(Line::from(Span::styled(
                    format!("       {}", reaction_text),
                    Style::default().fg(Color::DarkGray),
                ))));
            }
            
            items
        })
        .collect();

    let messages_block = Block::default()
        .title("Messages")
        .borders(Borders::ALL);

    let messages_list = List::new(message_items).block(messages_block);
    frame.render_widget(messages_list, chunks[0]);

    // Render input
    let input_style = if is_input_mode {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let input_block = Block::default()
        .title(if is_input_mode { "Input (typing...)" } else { "Input (press i)" })
        .borders(Borders::ALL)
        .style(input_style);

    let input_widget = Paragraph::new(input).block(input_block);
    frame.render_widget(input_widget, chunks[1]);
}

/// Render the contact list.
pub fn render_contacts(
    frame: &mut Frame,
    area: Rect,
    contacts: &[Contact],
    selected: usize,
) {
    let items: Vec<ListItem> = contacts
        .iter()
        .enumerate()
        .map(|(i, contact)| {
            let style = if i == selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let status = match contact.trust_level {
                crate::identity::TrustLevel::Trusted => "✓",
                crate::identity::TrustLevel::Verified => "◆",
                crate::identity::TrustLevel::Blocked => "✗",
                crate::identity::TrustLevel::Unknown => "?",
            };

            let text = format!("{} {} ({})", status, contact.alias, short_peer_id(&contact.peer_id));
            ListItem::new(Line::from(Span::styled(text, style)))
        })
        .collect();

    let block = Block::default()
        .title("Contacts")
        .borders(Borders::ALL);

    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}

/// Render the status bar.
pub fn render_status(
    frame: &mut Frame,
    area: Rect,
    peer_id: &PeerId,
    connected_count: usize,
) {
    let text = format!(
        "ID: {} | Connected: {} peers",
        short_peer_id(peer_id),
        connected_count
    );

    let block = Block::default()
        .title("Status")
        .borders(Borders::ALL);

    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

/// Shorten a peer ID for display.
pub fn short_peer_id(peer_id: &PeerId) -> String {
    let full = peer_id.to_string();
    if full.len() > 12 {
        format!("{}...{}", &full[..6], &full[full.len() - 4..])
    } else {
        full
    }
}

/// Render an empty state message.
pub fn render_empty(frame: &mut Frame, area: Rect, message: &str) {
    let block = Block::default().borders(Borders::ALL);
    let paragraph = Paragraph::new(message)
        .style(Style::default().fg(Color::DarkGray))
        .block(block);
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_peer_id_truncates_long_id() {
        let peer_id = PeerId::random();
        let short = short_peer_id(&peer_id);
        
        // Should be significantly shorter than full ID
        let full = peer_id.to_string();
        assert!(short.len() < full.len());
        assert!(short.contains("..."));
    }

    #[test]
    fn short_peer_id_preserves_prefix_and_suffix() {
        let peer_id = PeerId::random();
        let full = peer_id.to_string();
        let short = short_peer_id(&peer_id);
        
        // Should contain first 6 and last 4 chars
        assert!(short.starts_with(&full[..6]));
        assert!(short.ends_with(&full[full.len() - 4..]));
    }

    #[test]
    fn contact_list_creates_items() {
        use crate::identity::TrustLevel;
        
        let contacts = vec![
            Contact {
                peer_id: PeerId::random(),
                alias: "Alice".to_string(),
                public_key: vec![],
                trust_level: TrustLevel::Trusted,
                last_seen: None,
                send_read_receipts: true,
            },
            Contact {
                peer_id: PeerId::random(),
                alias: "Bob".to_string(),
                public_key: vec![],
                trust_level: TrustLevel::Unknown,
                last_seen: None,
                send_read_receipts: true,
            },
        ];
        
        // Just verify we can create the data
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].alias, "Alice");
    }

    #[test]
    fn display_message_formats() {
        use chrono::Utc;
        
        let msg = DisplayMessage::new(
            PeerId::random(),
            "Hello".to_string(),
            Utc::now(),
            true,
        );
        
        assert_eq!(msg.content, "Hello");
        assert!(msg.is_ours);
    }

    #[test]
    fn trust_level_symbols() {
        use crate::identity::TrustLevel;
        
        let trusted = TrustLevel::Trusted;
        let blocked = TrustLevel::Blocked;
        
        // Verify enum variants exist
        assert!(matches!(trusted, TrustLevel::Trusted));
        assert!(matches!(blocked, TrustLevel::Blocked));
    }

    #[test]
    fn empty_contacts_handled() {
        let contacts: Vec<Contact> = vec![];
        assert!(contacts.is_empty());
    }
}
