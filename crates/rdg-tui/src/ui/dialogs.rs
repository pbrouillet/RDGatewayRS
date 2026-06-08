use crate::app::{App, InputMode};
use crate::ui::centered_rect;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

pub fn draw(f: &mut Frame, app: &App) {
    let dialog = match &app.dialog {
        Some(d) => d,
        None => return,
    };

    let title = match app.input_mode {
        InputMode::AddUser => " Add User ",
        InputMode::AddGroup => " Add Group ",
        InputMode::AddAclRule => " Add ACL Rule ",
        InputMode::AssignGroup => " Assign Group ",
        InputMode::Normal => return,
    };

    let field_count = dialog.fields.len() as u16;
    // 2 lines per field (label + input) + 3 for borders + 1 for hint
    let height = (field_count * 2 + 4).min(20);
    let area = centered_rect(50, height as u16 * 3, f.area());

    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout: one chunk per field
    let constraints: Vec<Constraint> = dialog
        .fields
        .iter()
        .map(|_| Constraint::Length(2))
        .chain(std::iter::once(Constraint::Min(1)))
        .collect();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    for (i, field) in dialog.fields.iter().enumerate() {
        let is_active = i == dialog.active_field;
        let label_style = if is_active {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };

        let display_value = if !field.options.is_empty() {
            // Select field: show ◀ option ▶
            format!(
                "◀ {} ▶",
                field.options.get(field.selected_option).unwrap_or(&String::new())
            )
        } else if field.masked {
            "•".repeat(field.value.len())
        } else {
            field.value.clone()
        };

        let cursor = if is_active && field.options.is_empty() {
            "▏"
        } else {
            ""
        };

        let lines = vec![
            Line::from(Span::styled(&field.label, label_style)),
            Line::from(vec![
                Span::styled(
                    display_value,
                    Style::default().fg(Color::White),
                ),
                Span::styled(cursor, Style::default().fg(Color::Yellow)),
            ]),
        ];

        let paragraph = Paragraph::new(lines);
        f.render_widget(paragraph, chunks[i]);
    }
}
