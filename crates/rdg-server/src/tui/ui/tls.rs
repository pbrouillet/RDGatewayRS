use crate::tui::app::App;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9), // TLS mode & cert info
            Constraint::Min(5),   // SAN list
        ])
        .split(area);

    draw_tls_info(f, app, chunks[0]);
    draw_san_list(f, app, chunks[1]);
}

fn draw_tls_info(f: &mut Frame, app: &App, area: Rect) {
    let mode = if app.config.tls.cert_path.is_some() && app.config.tls.key_path.is_some() {
        "External Certificate"
    } else if app.config.tls.auto_generate {
        "Self-Signed (auto-generated)"
    } else {
        "Not Configured"
    };

    let cert_path = app
        .config
        .tls
        .cert_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "—".to_string());

    let key_path = app
        .config
        .tls
        .key_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "—".to_string());

    let mut text = vec![
        Line::from(vec![
            Span::styled("Mode:    ", Style::default().fg(Color::Yellow)),
            Span::raw(mode),
        ]),
        Line::from(vec![
            Span::styled("Cert:    ", Style::default().fg(Color::Yellow)),
            Span::raw(cert_path),
        ]),
        Line::from(vec![
            Span::styled("Key:     ", Style::default().fg(Color::Yellow)),
            Span::raw(key_path),
        ]),
    ];

    // Show certificate metadata from DB if available
    if let Some(cert) = &app.cert_info {
        text.push(Line::from(vec![
            Span::styled("Subject: ", Style::default().fg(Color::Cyan)),
            Span::raw(&cert.subject),
        ]));
        text.push(Line::from(vec![
            Span::styled("Thumb:   ", Style::default().fg(Color::Cyan)),
            Span::raw(&cert.thumbprint),
        ]));
        text.push(Line::from(vec![
            Span::styled("Valid:   ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{} → {}", cert.not_before, cert.not_after)),
        ]));
        text.push(Line::from(vec![
            Span::styled("On disk: ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{}, {}", cert.cert_path, cert.key_path)),
        ]));
    } else {
        text.push(Line::from(Span::styled(
            "  No certificate in database",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" TLS Configuration ");
    let paragraph = Paragraph::new(text).block(block);
    f.render_widget(paragraph, area);
}

fn draw_san_list(f: &mut Frame, app: &App, area: Rect) {
    let sans: Vec<ListItem> = app
        .config
        .tls
        .san_names
        .as_ref()
        .map(|names| {
            names
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    let style = if i == app.tls_san_index {
                        Style::default().bg(Color::DarkGray).fg(Color::White)
                    } else {
                        Style::default()
                    };
                    ListItem::new(Line::from(Span::styled(name.clone(), style)))
                })
                .collect()
        })
        .unwrap_or_default();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Subject Alternative Names (custom) ");

    let list = List::new(sans).block(block);
    f.render_widget(list, area);
}
