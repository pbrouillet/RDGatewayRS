pub mod acl;
pub mod dialogs;
pub mod groups;
pub mod sessions;
pub mod tabs;
pub mod tls;
pub mod users;

use crate::tui::app::{ActiveTab, App, InputMode};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs as TabsWidget};

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tab bar
            Constraint::Min(5),   // content
            Constraint::Length(1), // status bar
        ])
        .split(f.area());

    draw_tab_bar(f, app, chunks[0]);

    match app.active_tab {
        ActiveTab::Users => users::draw(f, app, chunks[1]),
        ActiveTab::Groups => groups::draw(f, app, chunks[1]),
        ActiveTab::AclRules => acl::draw(f, app, chunks[1]),
        ActiveTab::Sessions => sessions::draw(f, app, chunks[1]),
        ActiveTab::Tls => tls::draw(f, app, chunks[1]),
    }

    draw_status_bar(f, app, chunks[2]);

    // Draw dialog overlay if active
    if app.input_mode != InputMode::Normal {
        dialogs::draw(f, app);
    }
}

fn draw_tab_bar(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = ["Users", "Groups", "ACL Rules", "Sessions", "TLS"]
        .iter()
        .map(|t| Line::from(Span::styled(*t, Style::default().fg(Color::White))))
        .collect();

    let tabs = TabsWidget::new(titles)
        .block(Block::default().borders(Borders::ALL).title(" RDG Gateway Manager "))
        .select(app.active_tab as usize)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(tabs, area);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let help = match app.input_mode {
        InputMode::Normal => match app.active_tab {
            ActiveTab::Users => " Tab:switch  ↑↓:navigate  a:add  d:toggle  g:groups  q:quit ",
            ActiveTab::Groups => " Tab:switch  ↑↓:navigate  a:add  q:quit ",
            ActiveTab::AclRules => " Tab:switch  ↑↓:navigate  a:add  d:delete  q:quit ",
            ActiveTab::Sessions => " Tab:switch  ↑↓:navigate  r:refresh  q:quit ",
            ActiveTab::Tls => " Tab:switch  ↑↓:navigate  a:add SAN  d:delete SAN  e:cert path  k:key path  s:save  q:quit ",
        },
        _ => " Enter:confirm  Tab:next field  Esc:cancel ",
    };

    let status = if let Some(msg) = &app.status_message {
        format!("{} │ {}", msg, help)
    } else {
        help.to_string()
    };

    let paragraph = Paragraph::new(status)
        .style(Style::default().fg(Color::White).bg(Color::DarkGray));
    f.render_widget(paragraph, area);
}

/// Helper: centered rect for dialogs
pub fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
