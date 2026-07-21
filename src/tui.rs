//! Terminal UI (TUI) for interactively exploring cryptographic assets.
//!
//! Uses `ratatui` and `crossterm` to render a scrollable table of findings
//! with severity-colored rows and a detail panel showing remediation advice.

use std::io;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
    Frame, Terminal,
};

use crate::models::{CryptoAsset, DetectionSource, QuantumSafe, Severity};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Launch the interactive TUI with the given set of crypto assets.
///
/// Blocks until the user presses `q` or `Esc` to quit.
pub fn run(assets: Vec<CryptoAsset>) -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(assets);
    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct App {
    assets: Vec<CryptoAsset>,
    table_state: TableState,
    show_help: bool,
}

impl App {
    fn new(assets: Vec<CryptoAsset>) -> Self {
        let mut state = TableState::default();
        if !assets.is_empty() {
            state.select(Some(0));
        }
        Self {
            assets,
            table_state: state,
            show_help: false,
        }
    }

    fn next(&mut self) {
        if self.assets.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.assets.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn previous(&mut self) {
        if self.assets.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.assets.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn selected_asset(&self) -> Option<&CryptoAsset> {
        self.table_state.selected().and_then(|i| self.assets.get(i))
    }
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Down | KeyCode::Char('j') => app.next(),
                    KeyCode::Up | KeyCode::Char('k') => app.previous(),
                    KeyCode::Char('?') => app.show_help = !app.show_help,
                    _ => {}
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// UI rendering
// ---------------------------------------------------------------------------

fn ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main content (table + detail split)
            Constraint::Length(1), // Status bar
        ])
        .split(f.area());

    render_header(f, chunks[0], app);
    render_main(f, chunks[1], app);
    render_status_bar(f, chunks[2], app);

    if app.show_help {
        render_help_popup(f);
    }
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let critical = app
        .assets
        .iter()
        .filter(|a| a.severity == Severity::Critical)
        .count();
    let warnings = app
        .assets
        .iter()
        .filter(|a| a.severity == Severity::Warning)
        .count();
    let safe = app
        .assets
        .iter()
        .filter(|a| a.severity == Severity::Safe)
        .count();
    let info = app
        .assets
        .iter()
        .filter(|a| a.severity == Severity::Info)
        .count();

    let header_text = vec![Line::from(vec![
        Span::styled(
            " 🔐 KeyLens CBOM Viewer ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" │ "),
        Span::styled(
            format!("{} assets", app.assets.len()),
            Style::default().fg(Color::White),
        ),
        Span::raw(" │ "),
        Span::styled(format!("🚨 {}", critical), Style::default().fg(Color::Red)),
        Span::raw(" "),
        Span::styled(
            format!("⚠ {}", warnings),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(" "),
        Span::styled(format!("ℹ {}", info), Style::default().fg(Color::Blue)),
        Span::raw(" "),
        Span::styled(format!("✅ {}", safe), Style::default().fg(Color::Green)),
    ])];

    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(header, area);
}

fn render_main(f: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(55), // Table
            Constraint::Percentage(45), // Detail panel
        ])
        .split(area);

    render_table(f, chunks[0], app);
    render_detail(f, chunks[1], app);
}

fn render_table(f: &mut Frame, area: Rect, app: &mut App) {
    let header_cells = [
        "Algorithm",
        "Severity",
        "Quantum",
        "Source",
        "Library",
        "Location",
    ]
    .iter()
    .map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).height(1);

    let rows = app.assets.iter().map(|asset| {
        let severity_style = severity_style(&asset.severity);
        let quantum_display = match &asset.quantum_safe {
            QuantumSafe::Safe => ("✅ Safe", Color::Green),
            QuantumSafe::Vulnerable => ("⚠ Vuln", Color::Yellow),
            QuantumSafe::Unknown => ("? N/A", Color::DarkGray),
        };
        let source_display = match &asset.detection_source {
            DetectionSource::SourceCode => "Code",
            DetectionSource::Dependency => "Dep",
        };
        let location = if asset.line_number > 0 {
            format!("{}:{}", short_path(&asset.file_path), asset.line_number)
        } else {
            short_path(&asset.file_path)
        };

        Row::new(vec![
            Cell::from(asset.algorithm.clone()),
            Cell::from(severity_label(&asset.severity)).style(severity_style),
            Cell::from(quantum_display.0).style(Style::default().fg(quantum_display.1)),
            Cell::from(source_display),
            Cell::from(asset.library_source.clone()),
            Cell::from(location),
        ])
        .style(Style::default().fg(Color::White))
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(18), // Algorithm
            Constraint::Length(12), // Severity
            Constraint::Length(10), // Quantum
            Constraint::Length(6),  // Source
            Constraint::Length(20), // Library
            Constraint::Min(20),    // Location
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" Cryptographic Assets ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    )
    .row_highlight_style(
        Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(Color::Cyan),
    )
    .highlight_symbol("▶ ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn render_detail(f: &mut Frame, area: Rect, app: &App) {
    let detail_block = Block::default()
        .title(" Details & Remediation ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    if let Some(asset) = app.selected_asset() {
        let mut lines = Vec::new();

        // Algorithm + severity header
        lines.push(Line::from(vec![
            Span::styled("Algorithm: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                &asset.algorithm,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                severity_label(&asset.severity),
                severity_style(&asset.severity),
            ),
        ]));

        // File location
        lines.push(Line::from(vec![
            Span::styled("Location:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}:{}", &asset.file_path, asset.line_number),
                Style::default().fg(Color::Blue),
            ),
        ]));

        // Library
        lines.push(Line::from(vec![
            Span::styled("Library:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(&asset.library_source, Style::default().fg(Color::White)),
        ]));

        // Dependency path (if present)
        if let Some(ref dep_path) = asset.dependency_path {
            lines.push(Line::from(vec![
                Span::styled("Dep Path:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(dep_path, Style::default().fg(Color::Magenta)),
            ]));
        }

        // Key size / mode / curve
        let mut meta_parts = Vec::new();
        if let Some(ks) = asset.key_size {
            meta_parts.push(format!("key={}bit", ks));
        }
        if let Some(ref m) = asset.mode {
            meta_parts.push(format!("mode={}", m));
        }
        if let Some(ref c) = asset.curve {
            meta_parts.push(format!("curve={}", c));
        }
        if !meta_parts.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("Details:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(meta_parts.join(", "), Style::default().fg(Color::White)),
            ]));
        }

        // Findings
        if !asset.findings.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Findings:",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
            for finding in &asset.findings {
                lines.push(Line::from(vec![
                    Span::styled("  • ", Style::default().fg(Color::Yellow)),
                    Span::styled(finding, Style::default().fg(Color::White)),
                ]));
            }
        }

        // Remediation
        if let Some(ref rem) = asset.remediation {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "🔧 Fix Suggestion:",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )));
            for rem_line in rem.lines() {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(rem_line, Style::default().fg(Color::Green)),
                ]));
            }
        }

        let detail = Paragraph::new(Text::from(lines))
            .block(detail_block)
            .wrap(Wrap { trim: true });
        f.render_widget(detail, area);
    } else {
        let empty = Paragraph::new("  Select an asset to view details.")
            .style(Style::default().fg(Color::DarkGray))
            .block(detail_block);
        f.render_widget(empty, area);
    }
}

fn render_status_bar(f: &mut Frame, area: Rect, app: &App) {
    let selected = app
        .table_state
        .selected()
        .map(|i| format!("{}/{}", i + 1, app.assets.len()))
        .unwrap_or_else(|| "—".to_string());

    let bar = Line::from(vec![
        Span::styled(" ↑↓/jk", Style::default().fg(Color::Cyan)),
        Span::styled(" Navigate ", Style::default().fg(Color::DarkGray)),
        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
        Span::styled("?", Style::default().fg(Color::Cyan)),
        Span::styled(" Help ", Style::default().fg(Color::DarkGray)),
        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
        Span::styled("q/Esc", Style::default().fg(Color::Cyan)),
        Span::styled(" Quit ", Style::default().fg(Color::DarkGray)),
        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
        Span::styled(selected, Style::default().fg(Color::White)),
    ]);

    let status = Paragraph::new(bar);
    f.render_widget(status, area);
}

fn render_help_popup(f: &mut Frame) {
    let area = centered_rect(50, 50, f.area());
    f.render_widget(Clear, area);

    let help_text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Keyboard Shortcuts",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  ↑ / k      Move selection up"),
        Line::from("  ↓ / j      Move selection down"),
        Line::from("  ?          Toggle this help"),
        Line::from("  q / Esc    Quit"),
        Line::from(""),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .title(" Help ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default().fg(Color::White));

    f.render_widget(help, area);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn severity_style(severity: &Severity) -> Style {
    match severity {
        Severity::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::Warning => Style::default().fg(Color::Yellow),
        Severity::Info => Style::default().fg(Color::Blue),
        Severity::Safe => Style::default().fg(Color::Green),
        Severity::Unknown => Style::default().fg(Color::DarkGray),
    }
}

fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "🚨 CRITICAL",
        Severity::Warning => "⚠  WARNING",
        Severity::Info => "ℹ  INFO",
        Severity::Safe => "✅ SAFE",
        Severity::Unknown => "?  UNKNOWN",
    }
}

/// Shorten a file path for table display.
fn short_path(path: &str) -> String {
    // Show last 2 components
    let parts: Vec<&str> = path.split(['/', '\\']).collect();
    if parts.len() <= 2 {
        path.to_string()
    } else {
        format!("…/{}", parts[parts.len() - 2..].join("/"))
    }
}

/// Helper to create a centered rectangle for popups.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
