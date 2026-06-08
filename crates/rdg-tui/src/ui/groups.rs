use crate::app::App;
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["ID", "Name"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app
        .groups
        .iter()
        .enumerate()
        .map(|(i, group)| {
            let style = if i == app.group_index {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(group.id.to_string()),
                Cell::from(group.name.clone()),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [Constraint::Length(6), Constraint::Percentage(80)],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Groups ({}) ", app.groups.len())),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::BOLD));

    let mut state = TableState::default();
    if !app.groups.is_empty() {
        state.select(Some(app.group_index));
    }
    f.render_stateful_widget(table, area, &mut state);
}
