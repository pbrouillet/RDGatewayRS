use crate::tui::app::App;
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["ID", "Username", "Enabled", "Groups"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app
        .users
        .iter()
        .enumerate()
        .map(|(i, user)| {
            let groups = app
                .user_groups
                .get(&user.id)
                .map(|gs| {
                    gs.iter()
                        .map(|g| g.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "—".to_string());

            let enabled = if user.enabled { "✓" } else { "✗" };
            let style = if i == app.user_index {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else if !user.enabled {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(user.id.to_string()),
                Cell::from(user.username.clone()),
                Cell::from(enabled),
                Cell::from(groups),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Percentage(30),
            Constraint::Length(9),
            Constraint::Percentage(50),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Users ({}) ", app.users.len())),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::BOLD));

    let mut state = TableState::default();
    if !app.users.is_empty() {
        state.select(Some(app.user_index));
    }
    f.render_stateful_widget(table, area, &mut state);
}
