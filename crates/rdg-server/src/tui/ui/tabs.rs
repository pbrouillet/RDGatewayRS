use crate::tui::app::App;
use ratatui::Frame;

pub fn draw(_f: &mut Frame, _app: &App, _area: ratatui::layout::Rect) {
    // Tab bar is drawn by the parent ui::draw function
    // This is a placeholder for any tab-specific chrome
}
