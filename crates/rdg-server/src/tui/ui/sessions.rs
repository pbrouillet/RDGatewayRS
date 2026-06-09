use crate::tui::app::App;
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["ID", "User", "Client IP", "Target", "Connected At"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app
        .sessions
        .iter()
        .enumerate()
        .map(|(i, session)| {
            let user = app
                .users
                .iter()
                .find(|u| u.id == session.user_id)
                .map(|u| u.username.as_str())
                .unwrap_or("unknown");
            let target = format!(
                "{}:{}",
                session.target_host.as_deref().unwrap_or("—"),
                session
                    .target_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "—".to_string())
            );

            let style = if i == app.session_index {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(session.id.clone()),
                Cell::from(user.to_string()),
                Cell::from(session.client_ip.clone()),
                Cell::from(target),
                Cell::from(session.connected_at.clone()),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Percentage(15),
            Constraint::Percentage(20),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Active Sessions ({}) ", app.sessions.len())),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::BOLD));

    let mut state = TableState::default();
    if !app.sessions.is_empty() {
        state.select(Some(app.session_index));
    }
    f.render_stateful_widget(table, area, &mut state);
}
