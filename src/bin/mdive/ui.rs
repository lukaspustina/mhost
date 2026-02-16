use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use mhost::app::common::styles::{record_type_color, record_type_is_bold};
use mhost::RecordType;

use crate::app::{format_nameserver_human, format_rdata_human, record_type_info, App, Mode, Popup, QueryState, TOGGLEABLE_TYPES};

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3), // title + input
        Constraint::Length(1), // type toggles
        Constraint::Min(5),    // results table
        Constraint::Length(1), // detail line
        Constraint::Length(1), // status bar
    ])
    .split(f.area());

    draw_input(f, app, chunks[0]);
    draw_type_toggles(f, app, chunks[1]);
    draw_table(f, app, chunks[2]);
    draw_detail(f, app, chunks[3]);
    draw_status(f, app, chunks[4]);

    match app.popup {
        Popup::RecordDetail(_) => draw_record_popup(f, app),
        Popup::Help => draw_help_popup(f),
        Popup::None => {}
    }
}

fn draw_input(f: &mut Frame, app: &App, area: Rect) {
    let title_right = " [?]help [/]search [r]re-run [h]uman [a]ll [n]one [q]uit ";
    let block = Block::default()
        .title(" mdive ")
        .title_bottom(Line::from(title_right).right_aligned())
        .borders(Borders::ALL)
        .border_style(match app.mode {
            Mode::Input => Style::default().fg(Color::Cyan),
            Mode::Normal => Style::default().fg(Color::DarkGray),
        });

    let input_line = Line::from(vec![
        Span::styled("Domain: ", Style::default().fg(Color::Gray)),
        Span::raw(&app.input),
    ]);

    let paragraph = Paragraph::new(input_line).block(block);
    f.render_widget(paragraph, area);

    if app.mode == Mode::Input {
        // Position cursor after "Domain: " prefix + cursor_pos
        let cursor_x = area.x + 1 + 8 + app.cursor_pos as u16;
        let cursor_y = area.y + 1;
        if cursor_x < area.x + area.width - 1 {
            f.set_cursor_position((cursor_x, cursor_y));
        }
    }
}

fn draw_type_toggles(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = Vec::new();
    spans.push(Span::raw(" "));

    for (i, rt) in TOGGLEABLE_TYPES.iter().enumerate() {
        let key = if i < 9 {
            format!("{}", i + 1)
        } else if i == 9 {
            "0".to_string()
        } else {
            " ".to_string()
        };

        let active = app.active_types.contains(rt);
        let label = format!("{rt}");

        if i > 0 {
            spans.push(Span::raw(" "));
        }

        if active {
            spans.push(Span::styled(
                format!("{key}[{label}]"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(
                format!("{key} {label} "),
                Style::default().fg(Color::Gray),
            ));
        }
    }

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_table(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Name").style(Style::default().fg(Color::Gray)),
        Cell::from("Type").style(Style::default().fg(Color::Gray)),
        Cell::from("TTL").style(Style::default().fg(Color::Gray)),
        Cell::from("Value").style(Style::default().fg(Color::Gray)),
    ])
    .bottom_margin(0);

    let rows: Vec<Row> = app
        .rows
        .iter()
        .map(|r| {
            let type_style = to_ratatui_style(r.record_type);
            let type_str: &'static str = r.record_type.into();
            if app.human_view {
                let human = format_rdata_human(r);
                let value_lines: Vec<Line> = human
                    .lines()
                    .map(|line| {
                        if let Some((label, value)) = line.split_once(": ") {
                            Line::from(vec![
                                Span::styled(
                                    format!("{label}: "),
                                    Style::default().fg(Color::Gray),
                                ),
                                Span::raw(value.to_string()),
                            ])
                        } else {
                            Line::raw(line.to_string())
                        }
                    })
                    .collect();
                let height = value_lines.len() as u16;
                Row::new(vec![
                    Cell::from(r.name.as_str()),
                    Cell::from(type_str).style(type_style),
                    Cell::from(r.ttl.to_string()).style(Style::default().fg(Color::Gray)),
                    Cell::from(Text::from(value_lines)),
                ])
                .height(height)
            } else {
                Row::new(vec![
                    Cell::from(r.name.as_str()),
                    Cell::from(type_str).style(type_style),
                    Cell::from(r.ttl.to_string()).style(Style::default().fg(Color::Gray)),
                    Cell::from(r.value.as_str()),
                ])
            }
        })
        .collect();

    let widths = [
        Constraint::Min(20),
        Constraint::Length(10),
        Constraint::Length(7),
        Constraint::Percentage(60),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .row_highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::Indexed(236)),
        )
        .highlight_symbol("▸ ");

    f.render_stateful_widget(table, area, &mut app.table_state.clone());
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let detail = if let Some(idx) = app.table_state.selected() {
        if let Some(row) = app.rows.get(idx) {
            Line::from(vec![
                Span::styled(" server: ", Style::default().fg(Color::Gray)),
                Span::styled(format_nameserver_human(&row.nameserver), Style::default().fg(Color::Yellow)),
            ])
        } else {
            Line::raw("")
        }
    } else {
        Line::raw("")
    };

    f.render_widget(
        Paragraph::new(detail).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        area,
    );
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let mode_span = match app.mode {
        Mode::Normal => Span::styled(
            " NORMAL ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        Mode::Input => Span::styled(
            " INPUT ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let status_text = match &app.query_state {
        QueryState::Idle => " Ready — press / to enter a domain".to_string(),
        QueryState::Loading { domain } => format!(" Loading {domain}..."),
        QueryState::Querying { domain } => format!(" Querying {domain}..."),
        QueryState::Done {
            record_count,
            server_count,
            elapsed,
            ..
        } => {
            let secs = elapsed.as_secs_f64();
            format!(" {record_count} records | {server_count} servers | {secs:.1}s")
        }
        QueryState::Error { message, .. } => format!(" Error: {message}"),
    };

    let status_color = match &app.query_state {
        QueryState::Error { .. } => Color::Red,
        QueryState::Loading { .. } | QueryState::Querying { .. } => Color::Yellow,
        _ => Color::Gray,
    };

    let line = Line::from(vec![
        mode_span,
        Span::styled(status_text, Style::default().fg(status_color)),
    ]);

    f.render_widget(Paragraph::new(line), area);
}

fn draw_record_popup(f: &mut Frame, app: &App) {
    let idx = match app.popup {
        Popup::RecordDetail(i) => i,
        _ => return,
    };
    let row = match app.rows.get(idx) {
        Some(r) => r,
        None => return,
    };

    let (summary, detail, rfc) = record_type_info(row.record_type)
        .map(|(s, d, r)| (s, d, r.unwrap_or("")))
        .unwrap_or(("", "", ""));

    let human = format_rdata_human(row);

    let mut lines: Vec<Line> = vec![
        Line::raw(""),
        Line::from(Span::styled(
            &row.name,
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("TTL: ", Style::default().fg(Color::Gray)),
            Span::raw(row.ttl.to_string()),
        ]),
        Line::raw(""),
    ];

    for field_line in human.lines() {
        if let Some((label, value)) = field_line.split_once(": ") {
            lines.push(Line::from(vec![
                Span::styled(format!("{label}: "), Style::default().fg(Color::Gray)),
                Span::raw(value.to_string()),
            ]));
        } else {
            lines.push(Line::raw(field_line.to_string()));
        }
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("Server: ", Style::default().fg(Color::Gray)),
        Span::styled(format_nameserver_human(&row.nameserver), Style::default().fg(Color::Yellow)),
    ]));

    if !detail.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::raw(detail.to_string()));
    }

    if !rfc.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            rfc,
            Style::default().fg(Color::Gray),
        )));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(
        Span::styled("[Esc] close", Style::default().fg(Color::Gray)),
    ).right_aligned());

    // Build title
    let title = if summary.is_empty() {
        format!(" {} Record ", row.record_type)
    } else {
        format!(" {} Record — {} ", row.record_type, summary)
    };

    let area = f.area();
    let popup_area = centered_rect(area, 60, 70, 40, 80);

    let popup = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

    f.render_widget(Clear, popup_area);
    f.render_widget(popup, popup_area);
}

fn draw_help_popup(f: &mut Frame) {
    let dim = Style::default().fg(Color::Gray);
    let key_style = Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD);

    let help_line = |key: &str, desc: &str| -> Line<'static> {
        Line::from(vec![
            Span::styled(format!("  {key:<14}"), key_style),
            Span::styled(desc.to_string(), dim),
        ])
    };

    let lines: Vec<Line> = vec![
        Line::raw(""),
        Line::from(Span::styled(
            "Navigation",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        help_line("j / Down", "Move selection down"),
        help_line("k / Up", "Move selection up"),
        help_line("g / Home", "Jump to first row"),
        help_line("G / End", "Jump to last row"),
        help_line("PgUp / PgDn", "Scroll by 10 rows"),
        help_line("Enter", "Show record details"),
        help_line("h", "Toggle human-readable view"),
        Line::raw(""),
        Line::from(Span::styled(
            "Query",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        help_line("/ or i", "Enter search / input mode"),
        help_line("r", "Re-run current query"),
        Line::raw(""),
        Line::from(Span::styled(
            "Record Types",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        help_line("1-9, 0", "Toggle individual record types"),
        help_line("a", "Select all record types"),
        help_line("n", "Deselect all record types"),
        Line::raw(""),
        Line::from(Span::styled(
            "General",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        help_line("?", "Show this help"),
        help_line("q", "Quit"),
        help_line("Ctrl+C", "Force quit"),
        Line::raw(""),
        Line::from(Span::styled(
            "Input Mode",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        help_line("Enter", "Submit query"),
        help_line("Esc", "Back to normal mode"),
        help_line("Ctrl+W", "Delete word"),
        Line::raw(""),
        Line::from(
            Span::styled("[Esc] close", dim),
        ).right_aligned(),
    ];

    let area = f.area();
    let popup_area = centered_rect(area, 50, 70, 38, 60);

    let popup = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(" Help ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

    f.render_widget(Clear, popup_area);
    f.render_widget(popup, popup_area);
}

/// Returns a centered `Rect` using percentage of the outer area, clamped to min/max width.
fn centered_rect(outer: Rect, pct_width: u16, pct_height: u16, min_width: u16, max_width: u16) -> Rect {
    let popup_w = (outer.width * pct_width / 100).clamp(min_width.min(outer.width), max_width.min(outer.width));
    let popup_h = (outer.height * pct_height / 100).max(10).min(outer.height);
    let x = outer.x + (outer.width.saturating_sub(popup_w)) / 2;
    let y = outer.y + (outer.height.saturating_sub(popup_h)) / 2;
    Rect::new(x, y, popup_w, popup_h)
}

fn to_ratatui_style(rt: RecordType) -> Style {
    let color = match record_type_color(rt) {
        yansi::Color::Red => Color::Red,
        yansi::Color::Green => Color::Green,
        yansi::Color::Yellow => Color::Yellow,
        yansi::Color::Blue => Color::Blue,
        yansi::Color::Magenta => Color::Magenta,
        yansi::Color::Cyan => Color::Cyan,
        yansi::Color::White => Color::White,
        _ => Color::Gray,
    };
    let mut style = Style::default().fg(color);
    if record_type_is_bold(rt) {
        style = style.add_modifier(Modifier::BOLD);
    }
    style
}
