use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use rdg_core::config::ServerConfig;
use rdg_core::db::DbProvider;
use rdg_core::db::models::{AclRule, Group, Session, User};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::tui::ui;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Users = 0,
    Groups = 1,
    AclRules = 2,
    Sessions = 3,
    Tls = 4,
}

impl ActiveTab {
    pub fn next(self) -> Self {
        match self {
            Self::Users => Self::Groups,
            Self::Groups => Self::AclRules,
            Self::AclRules => Self::Sessions,
            Self::Sessions => Self::Tls,
            Self::Tls => Self::Users,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Users => Self::Tls,
            Self::Groups => Self::Users,
            Self::AclRules => Self::Groups,
            Self::Sessions => Self::AclRules,
            Self::Tls => Self::Sessions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    AddUser,
    AddGroup,
    AddAclRule,
    AssignGroup,
    AddSan,
    SetCertPath,
    SetKeyPath,
}

#[derive(Debug, Clone)]
pub struct DialogState {
    pub fields: Vec<DialogField>,
    pub active_field: usize,
}

#[derive(Debug, Clone)]
pub struct DialogField {
    pub label: String,
    pub value: String,
    pub masked: bool,
    /// For select fields: list of options
    pub options: Vec<String>,
    /// Current selected option index (for select fields)
    pub selected_option: usize,
}

impl DialogField {
    pub fn text(label: &str) -> Self {
        Self {
            label: label.to_string(),
            value: String::new(),
            masked: false,
            options: Vec::new(),
            selected_option: 0,
        }
    }

    pub fn password(label: &str) -> Self {
        Self {
            label: label.to_string(),
            value: String::new(),
            masked: true,
            options: Vec::new(),
            selected_option: 0,
        }
    }

    pub fn select(label: &str, options: Vec<String>) -> Self {
        Self {
            label: label.to_string(),
            value: options.first().cloned().unwrap_or_default(),
            masked: false,
            options,
            selected_option: 0,
        }
    }
}

impl DialogState {
    pub fn new(fields: Vec<DialogField>) -> Self {
        Self {
            fields,
            active_field: 0,
        }
    }

    pub fn next_field(&mut self) {
        self.active_field = (self.active_field + 1) % self.fields.len();
    }

    pub fn active_field_mut(&mut self) -> &mut DialogField {
        &mut self.fields[self.active_field]
    }

    pub fn field_value(&self, index: usize) -> &str {
        &self.fields[index].value
    }
}

pub struct App {
    pub db: Arc<dyn DbProvider>,
    pub config: ServerConfig,
    pub config_path: String,
    pub active_tab: ActiveTab,
    pub input_mode: InputMode,
    pub dialog: Option<DialogState>,
    pub status_message: Option<String>,
    pub should_quit: bool,

    // Data
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub acl_rules: Vec<AclRule>,
    pub sessions: Vec<Session>,

    // Table selection indices
    pub user_index: usize,
    pub group_index: usize,
    pub acl_index: usize,
    pub session_index: usize,
    pub tls_san_index: usize,

    // Group membership cache: user_id -> Vec<Group>
    pub user_groups: std::collections::HashMap<i64, Vec<Group>>,
}

impl App {
    pub fn new(db: Arc<dyn DbProvider>, config: ServerConfig, config_path: String) -> Self {
        Self {
            db,
            config,
            config_path,
            active_tab: ActiveTab::Users,
            input_mode: InputMode::Normal,
            dialog: None,
            status_message: None,
            should_quit: false,
            users: Vec::new(),
            groups: Vec::new(),
            acl_rules: Vec::new(),
            sessions: Vec::new(),
            user_index: 0,
            group_index: 0,
            acl_index: 0,
            session_index: 0,
            tls_san_index: 0,
            user_groups: std::collections::HashMap::new(),
        }
    }

    pub async fn load_all(&mut self) -> Result<()> {
        self.users = self.db.list_users().await?;
        self.groups = self.db.list_groups().await?;
        self.acl_rules = self.db.get_acl_rules().await?;
        self.sessions = self.db.get_active_sessions().await?;

        // Load group memberships for each user
        self.user_groups.clear();
        for user in &self.users {
            let groups = self.db.get_user_groups(user.id).await?;
            self.user_groups.insert(user.id, groups);
        }

        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let result = self.event_loop(&mut terminal).await;

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        result
    }

    async fn event_loop(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> Result<()> {
        loop {
            terminal.draw(|f| ui::draw(f, self))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                        self.should_quit = true;
                    } else {
                        self.handle_key(key).await?;
                    }
                }
            }

            if self.should_quit {
                break;
            }
        }
        Ok(())
    }

    async fn handle_key(&mut self, key: KeyEvent) -> Result<()> {
        match &self.input_mode {
            InputMode::Normal => self.handle_normal_key(key).await,
            _ => self.handle_dialog_key(key).await,
        }
    }

    async fn handle_normal_key(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.should_quit = true;
            }
            KeyCode::Tab => {
                self.active_tab = self.active_tab.next();
            }
            KeyCode::BackTab => {
                self.active_tab = self.active_tab.prev();
            }
            KeyCode::Up => {
                self.move_selection(-1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1);
            }
            KeyCode::Char('a') => {
                self.start_add_dialog();
            }
            KeyCode::Char('d') => {
                self.handle_delete_action().await?;
            }
            KeyCode::Char('g') => {
                if self.active_tab == ActiveTab::Users {
                    self.start_assign_group_dialog();
                }
            }
            KeyCode::Char('r') => {
                if self.active_tab == ActiveTab::Sessions {
                    self.sessions = self.db.get_active_sessions().await?;
                    self.status_message = Some("Sessions refreshed".to_string());
                }
            }
            KeyCode::Char('e') => {
                if self.active_tab == ActiveTab::Tls {
                    self.input_mode = InputMode::SetCertPath;
                    let current = self.config.tls.cert_path.as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    let mut field = DialogField::text("Certificate PEM path");
                    field.value = current;
                    self.dialog = Some(DialogState::new(vec![field]));
                }
            }
            KeyCode::Char('k') if self.active_tab == ActiveTab::Tls => {
                self.input_mode = InputMode::SetKeyPath;
                let current = self.config.tls.key_path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                let mut field = DialogField::text("Private Key PEM path");
                field.value = current;
                self.dialog = Some(DialogState::new(vec![field]));
            }
            KeyCode::Char('s') => {
                if self.active_tab == ActiveTab::Tls {
                    self.save_config()?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_dialog_key(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
                self.dialog = None;
                self.status_message = None;
            }
            KeyCode::Tab => {
                if let Some(dialog) = &mut self.dialog {
                    dialog.next_field();
                }
            }
            KeyCode::Enter => {
                self.submit_dialog().await?;
            }
            KeyCode::Left => {
                if let Some(dialog) = &mut self.dialog {
                    let field = dialog.active_field_mut();
                    if !field.options.is_empty() && field.selected_option > 0 {
                        field.selected_option -= 1;
                        field.value = field.options[field.selected_option].clone();
                    }
                }
            }
            KeyCode::Right => {
                if let Some(dialog) = &mut self.dialog {
                    let field = dialog.active_field_mut();
                    if !field.options.is_empty() && field.selected_option + 1 < field.options.len()
                    {
                        field.selected_option += 1;
                        field.value = field.options[field.selected_option].clone();
                    }
                }
            }
            KeyCode::Backspace => {
                if let Some(dialog) = &mut self.dialog {
                    let field = dialog.active_field_mut();
                    if field.options.is_empty() {
                        field.value.pop();
                    }
                }
            }
            KeyCode::Char(c) => {
                if let Some(dialog) = &mut self.dialog {
                    let field = dialog.active_field_mut();
                    if field.options.is_empty() {
                        field.value.push(c);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn move_selection(&mut self, delta: i32) {
        let (index, len) = match self.active_tab {
            ActiveTab::Users => (&mut self.user_index, self.users.len()),
            ActiveTab::Groups => (&mut self.group_index, self.groups.len()),
            ActiveTab::AclRules => (&mut self.acl_index, self.acl_rules.len()),
            ActiveTab::Sessions => (&mut self.session_index, self.sessions.len()),
            ActiveTab::Tls => {
                let san_count = self.config.tls.san_names.as_ref().map_or(0, |v| v.len());
                (&mut self.tls_san_index, san_count)
            }
        };
        if len == 0 {
            return;
        }
        let new = *index as i32 + delta;
        *index = if new < 0 {
            len - 1
        } else if new >= len as i32 {
            0
        } else {
            new as usize
        };
    }

    fn start_add_dialog(&mut self) {
        match self.active_tab {
            ActiveTab::Users => {
                self.input_mode = InputMode::AddUser;
                self.dialog = Some(DialogState::new(vec![
                    DialogField::text("Username"),
                    DialogField::password("Password"),
                ]));
            }
            ActiveTab::Groups => {
                self.input_mode = InputMode::AddGroup;
                self.dialog = Some(DialogState::new(vec![DialogField::text("Group Name")]));
            }
            ActiveTab::AclRules => {
                self.input_mode = InputMode::AddAclRule;
                self.dialog = Some(DialogState::new(vec![
                    DialogField::text("Priority (0-100)"),
                    DialogField::text("Target Host (or * for any)"),
                    DialogField::text("Target Port (or * for any)"),
                    DialogField::select("Action", vec!["allow".to_string(), "deny".to_string()]),
                ]));
            }
            ActiveTab::Sessions => {} // read-only
            ActiveTab::Tls => {
                self.input_mode = InputMode::AddSan;
                self.dialog = Some(DialogState::new(vec![DialogField::text("SAN Name (DNS or IP)")]));
            }
        }
    }

    fn start_assign_group_dialog(&mut self) {
        if self.users.is_empty() || self.groups.is_empty() {
            self.status_message = Some("No users or groups available".to_string());
            return;
        }
        let group_names: Vec<String> = self.groups.iter().map(|g| g.name.clone()).collect();
        self.input_mode = InputMode::AssignGroup;
        self.dialog = Some(DialogState::new(vec![DialogField::select(
            "Group",
            group_names,
        )]));
    }

    async fn handle_delete_action(&mut self) -> Result<()> {
        match self.active_tab {
            ActiveTab::Users => {
                if let Some(user) = self.users.get(self.user_index) {
                    let new_enabled = !user.enabled;
                    let user_id = user.id;
                    let username = user.username.clone();
                    self.db.set_user_enabled(user_id, new_enabled).await?;
                    self.users = self.db.list_users().await?;
                    self.status_message = Some(format!(
                        "User {} {}",
                        username,
                        if new_enabled { "enabled" } else { "disabled" }
                    ));
                }
            }
            ActiveTab::AclRules => {
                if let Some(rule) = self.acl_rules.get(self.acl_index) {
                    self.db.delete_acl_rule(rule.id).await?;
                    self.acl_rules = self.db.get_acl_rules().await?;
                    if self.acl_index > 0 && self.acl_index >= self.acl_rules.len() {
                        self.acl_index = self.acl_rules.len().saturating_sub(1);
                    }
                    self.status_message = Some("ACL rule deleted".to_string());
                }
            }
            ActiveTab::Tls => {
                if let Some(sans) = &mut self.config.tls.san_names {
                    if self.tls_san_index < sans.len() {
                        let removed = sans.remove(self.tls_san_index);
                        if self.tls_san_index > 0 && self.tls_san_index >= sans.len() {
                            self.tls_san_index = sans.len().saturating_sub(1);
                        }
                        self.status_message = Some(format!("Removed SAN '{}'", removed));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn submit_dialog(&mut self) -> Result<()> {
        let dialog = match &self.dialog {
            Some(d) => d.clone(),
            None => return Ok(()),
        };

        match &self.input_mode {
            InputMode::AddUser => {
                let username = dialog.field_value(0);
                let password = dialog.field_value(1);
                if username.is_empty() || password.is_empty() {
                    self.status_message = Some("Username and password required".to_string());
                    return Ok(());
                }
                let nt_hash = compute_nt_hash(password);
                self.db.create_user(username, &nt_hash).await?;
                self.users = self.db.list_users().await?;
                self.status_message = Some(format!("User '{}' created", username));
            }
            InputMode::AddGroup => {
                let name = dialog.field_value(0);
                if name.is_empty() {
                    self.status_message = Some("Group name required".to_string());
                    return Ok(());
                }
                self.db.create_group(name).await?;
                self.groups = self.db.list_groups().await?;
                self.status_message = Some(format!("Group '{}' created", name));
            }
            InputMode::AddAclRule => {
                let priority: i32 = dialog.field_value(0).parse().unwrap_or(0);
                let host = dialog.field_value(1);
                let port_str = dialog.field_value(2);
                let action = dialog.field_value(3);

                let target_host = if host == "*" || host.is_empty() {
                    None
                } else {
                    Some(host.to_string())
                };
                let target_port: Option<i32> = if port_str == "*" || port_str.is_empty() {
                    None
                } else {
                    port_str.parse().ok()
                };

                let rule = AclRule {
                    id: 0,
                    priority,
                    user_id: None,
                    group_id: None,
                    target_host,
                    target_port,
                    action: action.to_string(),
                };
                self.db.create_acl_rule(&rule).await?;
                self.acl_rules = self.db.get_acl_rules().await?;
                self.status_message = Some("ACL rule created".to_string());
            }
            InputMode::AssignGroup => {
                if let Some(user) = self.users.get(self.user_index) {
                    let group_name = dialog.field_value(0);
                    if let Some(group) = self.groups.iter().find(|g| g.name == group_name) {
                        self.db.add_user_to_group(user.id, group.id).await?;
                        // Refresh group memberships
                        let groups = self.db.get_user_groups(user.id).await?;
                        self.user_groups.insert(user.id, groups);
                        self.status_message = Some(format!(
                            "User '{}' added to group '{}'",
                            user.username, group_name
                        ));
                    }
                }
            }
            InputMode::Normal => {}
            InputMode::AddSan => {
                let san = dialog.field_value(0).to_string();
                if san.is_empty() {
                    self.status_message = Some("SAN name required".to_string());
                    return Ok(());
                }
                let sans = self.config.tls.san_names.get_or_insert_with(Vec::new);
                if sans.contains(&san) {
                    self.status_message = Some(format!("SAN '{}' already exists", san));
                } else {
                    sans.push(san.clone());
                    self.status_message = Some(format!("Added SAN '{}'", san));
                }
            }
            InputMode::SetCertPath => {
                let path = dialog.field_value(0).to_string();
                if path.is_empty() {
                    self.config.tls.cert_path = None;
                    self.status_message = Some("Certificate path cleared".to_string());
                } else {
                    self.config.tls.cert_path = Some(path.into());
                    self.status_message = Some("Certificate path updated".to_string());
                }
            }
            InputMode::SetKeyPath => {
                let path = dialog.field_value(0).to_string();
                if path.is_empty() {
                    self.config.tls.key_path = None;
                    self.status_message = Some("Key path cleared".to_string());
                } else {
                    self.config.tls.key_path = Some(path.into());
                    self.status_message = Some("Key path updated".to_string());
                }
            }
        }

        self.input_mode = InputMode::Normal;
        self.dialog = None;
        Ok(())
    }

    fn save_config(&mut self) -> Result<()> {
        let content = toml::to_string_pretty(&self.config)?;
        std::fs::write(&self.config_path, content)?;
        self.status_message = Some(format!("Config saved to {}", self.config_path));
        Ok(())
    }
}

/// Compute NT hash: MD4(UTF-16LE(password))
fn compute_nt_hash(password: &str) -> Vec<u8> {
    use md4::{Digest, Md4};
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut hasher = Md4::new();
    hasher.update(&utf16);
    hasher.finalize().to_vec()
}
