use crate::tui::app::App;
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["ID", "Priority", "User", "Group", "Target", "Action"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app
        .acl_rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let user = rule
                .user_id
                .and_then(|uid| app.users.iter().find(|u| u.id == uid))
                .map(|u| u.username.as_str())
                .unwrap_or("*");
            let group = rule
                .group_id
                .and_then(|gid| app.groups.iter().find(|g| g.id == gid))
                .map(|g| g.name.as_str())
                .unwrap_or("*");
            let target = format!(
                "{}:{}",
                rule.target_host.as_deref().unwrap_or("*"),
                rule.target_port.map(|p| p.to_string()).unwrap_or_else(|| "*".to_string())
            );
            let action_style = if rule.action == "allow" {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };

            let style = if i == app.acl_index {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(rule.id.to_string()),
                Cell::from(rule.priority.to_string()),
                Cell::from(user.to_string()),
                Cell::from(group.to_string()),
                Cell::from(target),
                Cell::from(rule.action.clone()).style(action_style),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(30),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" ACL Rules ({}) ", app.acl_rules.len())),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::BOLD));

    let mut state = TableState::default();
    if !app.acl_rules.is_empty() {
        state.select(Some(app.acl_index));
    }
    f.render_stateful_widget(table, area, &mut state);
}
