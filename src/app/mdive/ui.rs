use std::time::Duration;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, Wrap,
};
use ratatui::Frame;

use crate::app::common::reference_data;
use crate::app::common::styles::{record_type_color, record_type_is_bold};
use crate::app::common::lints::CheckResult;
use crate::app::common::styles::is_ascii;
use crate::services::whois::WhoisResponse;
use crate::RecordType;

use super::app::{
    category_short_label, format_nameserver_human, record_type_info, App, DiscoveryStrategy, DnssecStatus, Mode, Popup,
    QueryState, StrategyStatus, TOGGLEABLE_CATEGORIES,
};

pub fn draw(f: &mut Frame, app: &mut App) {
    let status_height = if app.show_stats && app.stats_data.is_some() {
        3
    } else {
        1
    };
    let chunks = Layout::vertical([
        Constraint::Length(3),             // title + input
        Constraint::Length(1),             // category toggles
        Constraint::Min(5),                // results table
        Constraint::Length(1),             // detail line
        Constraint::Length(status_height), // status bar (+ stats when active)
    ])
    .split(f.area());

    draw_input(f, app, chunks[0]);
    draw_category_toggles(f, app, chunks[1]);
    draw_table(f, app, chunks[2]);
    draw_detail(f, app, chunks[3]);
    draw_status_area(f, app, chunks[4]);

    match app.popup {
        Popup::RecordDetail { .. } => draw_record_popup(f, app),
        Popup::Help => draw_help_popup(f, app),
        Popup::Servers => draw_servers_popup(f, app),
        Popup::Whois => draw_whois_popup(f, app),
        Popup::Lints => draw_lints_popup(f, app),
        Popup::Discovery => draw_discovery_popup(f, app),
        Popup::None => {}
    }
}

fn draw_input(f: &mut Frame, app: &App, area: Rect) {
    let title_right = " [?] help  [i] query  [/] filter ";

    let title_left: Line = {
        let mut spans = Vec::new();
        if !app.history.is_empty() {
            spans.push(Span::styled(
                format!(
                    " {} [{}] ",
                    if is_ascii() { "<-" } else { "\u{2190}" },
                    app.history.len()
                ),
                Style::default().fg(Color::DarkGray),
            ));
        }
        spans.push(Span::raw(" mdive "));
        if let Some(ref filter) = app.filter {
            spans.push(Span::styled(
                format!("regex: \"{}\" ", filter.as_str()),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ));
        }
        Line::from(spans)
    };

    let search_border_color = if app.filter_error.is_some() {
        Color::Red
    } else {
        Color::Green
    };

    let block = Block::default()
        .title(title_left)
        .title_bottom(Line::from(title_right).right_aligned())
        .borders(Borders::ALL)
        .border_style(match app.mode {
            Mode::Input => Style::default().fg(Color::Cyan),
            Mode::Search => Style::default().fg(search_border_color),
            Mode::Normal => Style::default().fg(Color::DarkGray),
        });

    let (prompt, text, cursor_pos) = match app.mode {
        Mode::Search => ("Filter (regex): ", app.filter_input.as_str(), app.filter_cursor_pos),
        _ => ("Domain: ", app.input.as_str(), app.cursor_pos),
    };

    let prompt_style = if app.mode == Mode::Search && app.filter_error.is_some() {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Gray)
    };

    let mut lines = vec![Line::from(vec![Span::styled(prompt, prompt_style), Span::raw(text)])];

    // Show regex error message below the input
    if app.mode == Mode::Search {
        if let Some(ref err) = app.filter_error {
            lines.push(Line::from(Span::styled(
                format!("  {err}"),
                Style::default().fg(Color::Red),
            )));
        }
    }

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);

    if app.mode == Mode::Input || app.mode == Mode::Search {
        let cursor_x = area.x + 1 + prompt.len() as u16 + cursor_pos as u16;
        let cursor_y = area.y + 1;
        if cursor_x < area.x + area.width - 1 {
            f.set_cursor_position((cursor_x, cursor_y));
        }
    }
}

fn draw_category_toggles(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = Vec::new();
    spans.push(Span::styled(" [Tab] ", Style::default().fg(Color::DarkGray)));
    spans.push(Span::styled(
        format!(
            "{}{}",
            if is_ascii() { ">" } else { "\u{25B8}" },
            app.group_mode.label()
        ),
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw("  "));

    for (i, cat) in TOGGLEABLE_CATEGORIES.iter().enumerate() {
        let key = if i < 9 {
            format!("{}", i + 1)
        } else if i == 9 {
            "0".to_string()
        } else {
            " ".to_string()
        };

        let active = app.active_categories.contains(cat);
        let label = category_short_label(*cat);

        if i > 0 {
            spans.push(Span::raw(" "));
        }

        if active {
            spans.push(Span::styled(
                format!("{key} {label}"),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(
                format!("{key} {label}"),
                Style::default().fg(Color::DarkGray),
            ));
        }
    }

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_status_area(f: &mut Frame, app: &App, area: Rect) {
    if app.show_stats && app.stats_data.is_some() {
        let chunks = Layout::vertical([
            Constraint::Length(2), // stats
            Constraint::Length(1), // status bar
        ])
        .split(area);
        draw_stats(f, app, chunks[0]);
        draw_status(f, app, chunks[1]);
    } else {
        draw_status(f, app, area);
    }
}

fn draw_stats(f: &mut Frame, app: &App, area: Rect) {
    let stats = match &app.stats_data {
        Some(s) => s,
        None => return,
    };

    // Line 1: Record type distribution
    let mut line1_spans = vec![Span::styled(
        " Records  ",
        Style::default().add_modifier(Modifier::BOLD),
    )];
    for (rt, count) in &stats.rr_type_counts {
        let type_str: &'static str = (*rt).into();
        line1_spans.push(Span::styled(format!("{type_str}:{count}"), to_ratatui_style(*rt)));
        line1_spans.push(Span::raw("  "));
    }
    line1_spans.push(Span::styled(
        format!("({} unique)", stats.total_unique),
        Style::default().fg(Color::DarkGray),
    ));

    // Line 2: Query health
    let mut line2_spans = vec![Span::styled(
        " Queries  ",
        Style::default().add_modifier(Modifier::BOLD),
    )];
    line2_spans.push(Span::styled(
        format!("{} OK", stats.responses),
        Style::default().fg(Color::Green),
    ));
    line2_spans.push(Span::raw("  "));
    line2_spans.push(Span::styled(
        format!("{} NX", stats.nxdomains),
        if stats.nxdomains > 0 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        },
    ));
    line2_spans.push(Span::raw("  "));
    let err_style = if stats.total_errors > 0 {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    line2_spans.push(Span::styled(format!("{} err", stats.total_errors), err_style));
    line2_spans.push(Span::styled(
        format!(
            " [{} TO, {} QR, {} SF]",
            stats.timeout_errors, stats.refuse_errors, stats.servfail_errors
        ),
        err_style,
    ));
    line2_spans.push(Span::raw("  "));
    line2_spans.push(Span::styled(
        format!("{} servers", stats.responding_servers),
        Style::default().fg(Color::Gray),
    ));
    line2_spans.push(Span::raw("  "));
    let time_str = match (stats.min_time_ms, stats.max_time_ms) {
        (Some(min), Some(max)) if min == max => format!("{min}ms"),
        (Some(min), Some(max)) => format!("{min}{}{max}ms", if is_ascii() { "-" } else { "\u{2013}" }),
        _ => if is_ascii() { "-" } else { "\u{2013}" }.to_string(),
    };
    line2_spans.push(Span::styled(time_str, Style::default().fg(Color::Gray)));

    // DNSSEC badge
    line2_spans.push(Span::raw("  "));
    let (dnssec_label, dnssec_color) = match stats.dnssec_status {
        DnssecStatus::Signed => ("DNSSEC:signed", Color::Green),
        DnssecStatus::Partial => ("DNSSEC:partial", Color::Yellow),
        DnssecStatus::Broken => ("DNSSEC:broken", Color::Red),
        DnssecStatus::Unsigned => ("DNSSEC:unsigned", Color::DarkGray),
    };
    line2_spans.push(Span::styled(dnssec_label, Style::default().fg(dnssec_color)));

    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);
    f.render_widget(Paragraph::new(Line::from(line1_spans)), rows[0]);
    f.render_widget(Paragraph::new(Line::from(line2_spans)), rows[1]);
}

fn draw_table(f: &mut Frame, app: &mut App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("#").style(Style::default().fg(Color::DarkGray)),
        Cell::from("Name").style(Style::default().fg(Color::Gray)),
        Cell::from("Type").style(Style::default().fg(Color::Gray)),
        Cell::from("TTL").style(Style::default().fg(Color::Gray)),
        Cell::from("Value").style(Style::default().fg(Color::Gray)),
    ])
    .bottom_margin(0);

    let current_domain = app.current_domain().trim_end_matches('.').to_owned();
    let rows: Vec<Row> = app
        .rows
        .iter()
        .enumerate()
        .map(|(idx, r)| {
            let type_style = to_ratatui_style(r.record_type);
            let type_str: &'static str = r.record_type.into();
            let line_num = Cell::from(format!("{}", idx + 1)).style(Style::default().fg(Color::DarkGray));
            let ttl_str = if app.human_view {
                format_ttl(r.ttl)
            } else {
                r.ttl.to_string()
            };
            let name_display = if r.name.trim_end_matches('.') == current_domain {
                "@".to_string()
            } else {
                r.name.clone()
            };
            if app.human_view {
                let value_lines: Vec<Line> = r
                    .human_value
                    .lines()
                    .map(|line| {
                        if let Some((label, value)) = line.split_once(": ") {
                            Line::from(vec![
                                Span::styled(format!("{label}: "), Style::default().fg(Color::Gray)),
                                Span::raw(value.to_string()),
                            ])
                        } else {
                            Line::raw(line.to_string())
                        }
                    })
                    .collect();
                let height = value_lines.len() as u16;
                Row::new(vec![
                    line_num,
                    Cell::from(name_display.clone()),
                    Cell::from(type_str).style(type_style),
                    Cell::from(ttl_str).style(Style::default().fg(Color::Gray)),
                    Cell::from(Text::from(value_lines)),
                ])
                .height(height)
            } else {
                Row::new(vec![
                    line_num,
                    Cell::from(name_display.clone()),
                    Cell::from(type_str).style(type_style),
                    Cell::from(ttl_str).style(Style::default().fg(Color::Gray)),
                    Cell::from(r.value.as_str()),
                ])
            }
        })
        .collect();

    let widths = [
        Constraint::Length(5),
        Constraint::Min(20),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Percentage(60),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::BOLD).bg(Color::Indexed(236)))
        .highlight_symbol(if is_ascii() { "> " } else { "▸ " });

    f.render_stateful_widget(table, area, &mut app.table_state);

    // Scrollbar
    if !app.rows.is_empty() {
        let selected = app.table_state.selected().unwrap_or(0);
        let mut scrollbar_state = ScrollbarState::new(app.rows.len().saturating_sub(1)).position(selected);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None);
        // Render scrollbar on the inner area (inside the block's top border)
        let scrollbar_area = Rect {
            y: area.y + 1, // skip the top border
            height: area.height.saturating_sub(1),
            ..area
        };
        f.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
    }
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let detail = if let Some(idx) = app.table_state.selected() {
        if let Some(row) = app.rows.get(idx) {
            let mut spans = vec![
                Span::styled(" ", Style::default()),
                Span::styled(format!("{}", row.category), Style::default().fg(Color::Cyan)),
                Span::styled(" | server: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format_nameserver_human(&row.nameserver),
                    Style::default().fg(Color::Yellow),
                ),
            ];
            if let Some(ref target) = row.drill_target {
                spans.push(Span::styled(" | ", Style::default().fg(Color::DarkGray)));
                spans.push(Span::styled(
                    format!("[{}] {target}", if is_ascii() { "->" } else { "\u{2192}" }),
                    Style::default().fg(Color::Green),
                ));
            }
            Line::from(spans)
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
        Mode::Search => Span::styled(
            " SEARCH ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let mut spans = vec![mode_span];

    // Show quit confirmation
    if app.quit_confirm {
        spans.push(Span::styled(
            " Press q again to quit",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
        f.render_widget(Paragraph::new(Line::from(spans)), area);
        return;
    }

    // Show vi count buffer when active
    if !app.count_buffer.is_empty() || app.pending_g.is_some() {
        let mut buf = app.count_buffer.clone();
        if app.pending_g.is_some() {
            buf.push('g');
        }
        spans.push(Span::styled(
            format!(" {buf}"),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }

    match &app.query_state {
        QueryState::Idle => {
            spans.push(Span::styled(
                " Ready — press i to enter a domain, / to filter",
                Style::default().fg(Color::Gray),
            ));
        }
        QueryState::Loading { domain } => {
            spans.push(Span::styled(
                format!(" Loading {domain}..."),
                Style::default().fg(Color::Yellow),
            ));
        }
        QueryState::Querying { domain } => {
            let (completed, total) = app.batch_progress;
            if total > 0 {
                let width = 12;
                let filled = (completed * width) / total;
                let empty = width - filled;
                spans.push(Span::styled(
                    format!(" Querying {domain} "),
                    Style::default().fg(Color::Yellow),
                ));
                let (fill_char, empty_char) = if is_ascii() {
                    ("#", "-")
                } else {
                    ("\u{2588}", "\u{2591}")
                };
                spans.push(Span::styled(fill_char.repeat(filled), Style::default().fg(Color::Cyan)));
                spans.push(Span::styled(
                    empty_char.repeat(empty),
                    Style::default().fg(Color::DarkGray),
                ));
                spans.push(Span::styled(
                    format!(" {completed}/{total}"),
                    Style::default().fg(Color::Yellow),
                ));
            } else {
                spans.push(Span::styled(
                    format!(" Querying {domain}..."),
                    Style::default().fg(Color::Yellow),
                ));
            }
        }
        QueryState::Done {
            record_count,
            total_record_count,
            server_count,
            elapsed,
            ..
        } => {
            let secs = elapsed.as_secs_f64();
            let records_str = if record_count == total_record_count {
                format!("{record_count} records")
            } else {
                format!("{record_count}/{total_record_count} records")
            };
            spans.push(Span::styled(
                format!(" {records_str} | {server_count} servers | {secs:.1}s"),
                Style::default().fg(Color::Gray),
            ));
            if let Some(prev) = app.history.last() {
                spans.push(Span::styled(
                    format!(
                        " [{}] back to {}",
                        if is_ascii() { "<-" } else { "\u{2190}" },
                        prev.domain
                    ),
                    Style::default().fg(Color::DarkGray),
                ));
            }
        }
        QueryState::Error { message, .. } => {
            spans.push(Span::styled(
                format!(" Error: {message}"),
                Style::default().fg(Color::Red),
            ));
        }
    }

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_record_popup(f: &mut Frame, app: &mut App) {
    let (ref_name, ref_rt, ref_value) = match &app.popup {
        Popup::RecordDetail {
            name,
            record_type,
            value,
        } => (name.clone(), *record_type, value.clone()),
        _ => return,
    };
    let row = match app
        .rows
        .iter()
        .find(|r| r.name == ref_name && r.record_type == ref_rt && r.value == ref_value)
    {
        Some(r) => r,
        None => return,
    };

    let (summary, detail, rfc) = record_type_info(row.record_type)
        .map(|(s, d, r)| (s, d, r.unwrap_or("")))
        .unwrap_or(("", "", ""));

    let human = &row.human_value;

    let mut lines: Vec<Line> = vec![
        Line::raw(""),
        Line::from(Span::styled(&row.name, Style::default().add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("Category: ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{}", row.category), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("TTL: ", Style::default().fg(Color::Gray)),
            Span::raw(format_ttl(row.ttl)),
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
        Span::styled(
            format_nameserver_human(&row.nameserver),
            Style::default().fg(Color::Yellow),
        ),
    ]));

    // Subdomain explanation from reference data
    let subdomain_part = extract_subdomain(&row.name, app.current_domain());
    if let Some(sub) = subdomain_part {
        if let Some(reference_data::InfoEntry::Subdomain(sub_info)) = reference_data::find(sub) {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled("Subdomain: ", Style::default().fg(Color::Gray)),
                Span::styled(sub_info.summary.to_string(), Style::default().fg(Color::Cyan)),
            ]));
            if !sub_info.detail.is_empty() {
                lines.push(Line::raw(sub_info.detail.to_string()));
            }
            if let Some(rfc_str) = sub_info.rfc {
                lines.push(Line::from(Span::styled(
                    rfc_str.to_string(),
                    Style::default().fg(Color::Gray),
                )));
            }
        }
    }

    // TXT sub-type explanation
    if row.record_type == RecordType::TXT {
        for txt_info in reference_data::txt_sub_types() {
            if row.value.starts_with(txt_info.prefix) {
                lines.push(Line::raw(""));
                lines.push(Line::from(vec![
                    Span::styled("TXT Type: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{} — {}", txt_info.name, txt_info.summary),
                        Style::default().fg(Color::Cyan),
                    ),
                ]));
                if !txt_info.detail.is_empty() {
                    lines.push(Line::raw(txt_info.detail.to_string()));
                }
                if let Some(rfc_str) = txt_info.rfc {
                    lines.push(Line::from(Span::styled(
                        rfc_str.to_string(),
                        Style::default().fg(Color::Gray),
                    )));
                }
                break;
            }
        }
    }

    if !detail.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::raw(detail.to_string()));
    }

    if !rfc.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(rfc, Style::default().fg(Color::Gray))));
    }

    lines.push(Line::raw(""));
    lines.push(
        Line::from(Span::styled(
            "[Esc] close  [j/k] scroll",
            Style::default().fg(Color::Gray),
        ))
        .right_aligned(),
    );

    // Build title
    let title = if summary.is_empty() {
        format!(" {} Record ", row.record_type)
    } else {
        format!(" {} Record — {} ", row.record_type, summary)
    };

    let area = f.area();
    let popup_area = centered_rect(area, 60, 70, 40, 80);
    render_scrollable_popup(f, popup_area, &title, lines, &mut app.record_detail_scroll);
}

fn draw_help_popup(f: &mut Frame, app: &mut App) {
    let dim = Style::default().fg(Color::Gray);
    let key_style = Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD);

    let help_line = |key: &str, desc: &str| -> Line<'static> {
        Line::from(vec![
            Span::styled(format!("  {key:<14}"), key_style),
            Span::styled(desc.to_string(), dim),
        ])
    };

    let section = |title: &'static str| -> Line<'static> {
        Line::from(Span::styled(title, Style::default().add_modifier(Modifier::BOLD)))
    };

    let lines: Vec<Line> = vec![
        Line::raw(""),
        section("Navigation"),
        help_line("j / k", "Move selection down / up"),
        help_line("gg / G", "Jump to first / last row"),
        help_line("22gg / 22G", "Jump to line 22"),
        help_line("PgUp / PgDn", "Scroll by 10 rows"),
        help_line("Enter", "Drill into subdomain"),
        help_line("l / Right", "Drill into value target"),
        help_line("Left / BS", "Go back in history"),
        Line::raw(""),
        section("Panels"),
        help_line("o", "Record details"),
        help_line("s", "Server response times"),
        help_line("w", "WHOIS for result IPs"),
        help_line("c", "DNS health checks"),
        help_line("d", "Subdomain discovery"),
        Line::raw(""),
        section("Display"),
        help_line("h", "Toggle human-readable view"),
        help_line("S", "Toggle stats panel"),
        help_line("Tab", "Cycle grouping mode"),
        Line::raw(""),
        section("Query"),
        help_line("i", "Enter domain input mode"),
        help_line("/", "Filter results (regex)"),
        help_line("C", "Clear active filter"),
        help_line("r", "Re-run current query"),
        Line::raw(""),
        section("Categories"),
        help_line("1-8", "Toggle (Email, Svc, TLS, ...)"),
        help_line("9, 0", "Toggle Legacy, Gaming"),
        help_line("a / n", "Select all / none"),
        Line::raw(""),
        section("Input Mode"),
        help_line("Enter", "Submit query"),
        help_line("Esc", "Back to normal mode"),
        help_line("Ctrl+W", "Delete word"),
        Line::raw(""),
        section("General"),
        help_line("?", "Show this help"),
        help_line("q", "Quit"),
        help_line("Ctrl+C", "Force quit"),
        Line::raw(""),
        Line::from(Span::styled("[Esc] close  [j/k] scroll", dim)).right_aligned(),
    ];

    let area = f.area();
    let popup_area = centered_rect(area, 50, 70, 38, 60);
    render_scrollable_popup(f, popup_area, " Help ", lines, &mut app.help_scroll);
}

fn draw_servers_popup(f: &mut Frame, app: &mut App) {
    let dim = Style::default().fg(Color::Gray);

    let mut lines: Vec<Line> = vec![Line::raw("")];

    if let Some(lookups) = &app.lookups {
        // Build per-server stats
        struct ServerStats {
            name: String,
            protocol: String,
            responses: usize,
            errors: usize,
            min_ms: Option<u128>,
            max_ms: Option<u128>,
            total_ms: u128,
            time_count: usize,
        }

        let mut server_map: std::collections::HashMap<String, ServerStats> = std::collections::HashMap::new();
        let mut server_order: Vec<String> = Vec::new();

        for lookup in lookups.iter() {
            let raw = lookup.name_server().to_string();
            let entry = server_map.entry(raw.clone()).or_insert_with(|| {
                server_order.push(raw.clone());
                let ns = lookup.name_server();
                let protocol = format!("{:?}", ns.protocol()).to_lowercase();
                let name = format_nameserver_human(&raw);
                ServerStats {
                    name,
                    protocol,
                    responses: 0,
                    errors: 0,
                    min_ms: None,
                    max_ms: None,
                    total_ms: 0,
                    time_count: 0,
                }
            });

            if lookup.result().is_err() {
                entry.errors += 1;
            } else {
                entry.responses += 1;
            }

            if let Some(duration) = lookup.result().response_time() {
                let ms = duration.as_millis();
                entry.min_ms = Some(entry.min_ms.map_or(ms, |m: u128| m.min(ms)));
                entry.max_ms = Some(entry.max_ms.map_or(ms, |m: u128| m.max(ms)));
                entry.total_ms += ms;
                entry.time_count += 1;
            }
        }

        // Sort: by avg latency (fastest first), errors-only last
        server_order.sort_by(|a, b| {
            let sa = &server_map[a];
            let sb = &server_map[b];
            let a_has_time = sa.time_count > 0;
            let b_has_time = sb.time_count > 0;
            // Servers with no response times (all errors) sort last
            b_has_time.cmp(&a_has_time).then_with(|| {
                let avg_a = if sa.time_count > 0 {
                    sa.total_ms / sa.time_count as u128
                } else {
                    u128::MAX
                };
                let avg_b = if sb.time_count > 0 {
                    sb.total_ms / sb.time_count as u128
                } else {
                    u128::MAX
                };
                avg_a.cmp(&avg_b)
            })
        });

        lines.push(Line::from(Span::styled(
            format!(" {} servers used", server_order.len()),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::raw(""));

        // Header
        lines.push(Line::from(vec![
            Span::styled(format!("  {:<3}", "#"), dim),
            Span::styled(format!("{:<28}", "Server"), dim),
            Span::styled(format!("{:<7}", "Proto"), dim),
            Span::styled(format!("{:>4}", "OK"), dim),
            Span::styled(format!("{:>5}", "Err"), dim),
            Span::styled(format!("{:>8}", "Avg"), dim),
            Span::styled(format!("{:>8}", "Min"), dim),
            Span::styled(format!("{:>8}", "Max"), dim),
        ]));

        for (i, key) in server_order.iter().enumerate() {
            let s = &server_map[key];
            let avg_ms = if s.time_count > 0 {
                Some(s.total_ms / s.time_count as u128)
            } else {
                None
            };

            let err_style = if s.errors > 0 {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let ok_style = Style::default().fg(Color::Green);

            let fmt_ms = |v: Option<u128>| -> String {
                match v {
                    Some(ms) => format!("{ms}ms"),
                    None => if is_ascii() { "-" } else { "\u{2013}" }.to_string(),
                }
            };

            // Truncate server name to fit
            let name_display = if s.name.len() > 26 {
                format!("{}..", &s.name[..24])
            } else {
                s.name.clone()
            };

            lines.push(Line::from(vec![
                Span::styled(format!("  {:<3}", i + 1), dim),
                Span::styled(format!("{:<28}", name_display), Style::default().fg(Color::Yellow)),
                Span::styled(format!("{:<7}", s.protocol), dim),
                Span::styled(format!("{:>4}", s.responses), ok_style),
                Span::styled(format!("{:>5}", s.errors), err_style),
                Span::styled(format!("{:>8}", fmt_ms(avg_ms)), Style::default().fg(Color::Cyan)),
                Span::styled(format!("{:>8}", fmt_ms(s.min_ms)), dim),
                Span::styled(format!("{:>8}", fmt_ms(s.max_ms)), dim),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(" No query results yet", dim)));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled("[Esc] close  [j/k] scroll", dim)).right_aligned());

    let area = f.area();
    let popup_area = centered_rect(area, 70, 70, 60, 100);
    render_scrollable_popup(f, popup_area, " Servers ", lines, &mut app.servers_scroll);
}

fn draw_whois_popup(f: &mut Frame, app: &mut App) {
    let dim = Style::default().fg(Color::Gray);

    let mut lines: Vec<Line> = vec![Line::raw("")];

    if let Some(ref error) = app.whois_error {
        lines.push(Line::from(Span::styled(
            format!(" Error: {error}"),
            Style::default().fg(Color::Red),
        )));
    } else if let Some(ref responses) = app.whois_data {
        // Group responses by IP
        let mut ip_order: Vec<ipnetwork::IpNetwork> = Vec::new();
        let mut by_ip: std::collections::HashMap<ipnetwork::IpNetwork, Vec<&WhoisResponse>> =
            std::collections::HashMap::new();
        for resp in responses.iter() {
            let ip = *resp.resource();
            by_ip.entry(ip).or_default().push(resp);
            if !ip_order.contains(&ip) {
                ip_order.push(ip);
            }
        }

        for (i, ip) in ip_order.iter().enumerate() {
            if i > 0 {
                lines.push(Line::raw(""));
            }
            lines.push(Line::from(Span::styled(
                format!(" {ip}"),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )));

            if let Some(resps) = by_ip.get(ip) {
                for resp in resps {
                    match resp {
                        WhoisResponse::NetworkInfo { network_info, .. } => {
                            let asns = network_info.asns().join(", ");
                            let prefix = network_info.prefix();
                            lines.push(Line::from(vec![
                                Span::styled("   Network: ", dim),
                                Span::raw(format!("AS {asns}, Prefix {prefix}")),
                            ]));
                        }
                        WhoisResponse::Whois { whois, .. } => {
                            if let Some(net_name) = whois.net_name() {
                                lines.push(Line::from(vec![
                                    Span::styled("   Net name: ", dim),
                                    Span::raw(net_name.to_string()),
                                ]));
                            }
                            if let Some(org) = whois.organization() {
                                lines.push(Line::from(vec![
                                    Span::styled("   Organization: ", dim),
                                    Span::raw(org.to_string()),
                                ]));
                            }
                            if let Some(country) = whois.country() {
                                lines.push(Line::from(vec![
                                    Span::styled("   Country: ", dim),
                                    Span::raw(country.to_string()),
                                ]));
                            }
                            if let Some(authority) = whois.source() {
                                lines.push(Line::from(vec![
                                    Span::styled("   Authority: ", dim),
                                    Span::raw(format!("{authority}")),
                                ]));
                            }
                        }
                        WhoisResponse::GeoLocation { geo_location, .. } => {
                            for resource in geo_location.located_resources() {
                                for loc in resource.locations() {
                                    lines.push(Line::from(vec![
                                        Span::styled("   Location: ", dim),
                                        Span::raw(format!("{}, {}", loc.city(), loc.country())),
                                    ]));
                                }
                            }
                        }
                        WhoisResponse::Error { err, .. } => {
                            lines.push(Line::from(vec![
                                Span::styled("   Error: ", Style::default().fg(Color::Red)),
                                Span::raw(format!("{err}")),
                            ]));
                        }
                    }
                }
            }
        }

        if ip_order.is_empty() {
            lines.push(Line::from(Span::styled(" No WHOIS data available", dim)));
        }
    } else {
        lines.push(Line::from(Span::styled(
            " Loading WHOIS data...",
            Style::default().fg(Color::Yellow),
        )));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled("[Esc] close  [j/k] scroll", dim)).right_aligned());

    let area = f.area();
    let popup_area = centered_rect(area, 60, 80, 50, 90);
    render_scrollable_popup(f, popup_area, " WHOIS ", lines, &mut app.whois_scroll);
}

fn draw_lints_popup(f: &mut Frame, app: &mut App) {
    let dim = Style::default().fg(Color::Gray);

    let mut lines: Vec<Line> = vec![Line::raw("")];

    if let Some(ref sections) = app.lint_results {
        if sections.is_empty() {
            lines.push(Line::from(Span::styled(" No lint results available", dim)));
        } else {
            for (i, section) in sections.iter().enumerate() {
                if i > 0 {
                    lines.push(Line::raw(""));
                }
                lines.push(Line::from(Span::styled(
                    format!(" {}", section.name),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                )));

                for result in &section.results {
                    let (icon, style, msg): (&str, Style, &str) = match result {
                        CheckResult::Ok(msg) => (
                            if is_ascii() { "+" } else { "\u{2713}" },
                            Style::default().fg(Color::Green),
                            msg.as_str(),
                        ),
                        CheckResult::Warning(msg) => ("!", Style::default().fg(Color::Yellow), msg.as_str()),
                        CheckResult::Failed(msg) => (
                            if is_ascii() { "x" } else { "\u{2717}" },
                            Style::default().fg(Color::Red),
                            msg.as_str(),
                        ),
                        CheckResult::NotFound() => continue,
                    };
                    lines.push(Line::from(vec![
                        Span::styled(format!("   {icon} "), style),
                        Span::raw(msg.to_string()),
                    ]));
                }
            }
        }
    } else {
        lines.push(Line::from(Span::styled(" No query results yet", dim)));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled("[Esc] close  [j/k] scroll", dim)).right_aligned());

    let area = f.area();
    let popup_area = centered_rect(area, 60, 80, 50, 90);
    render_scrollable_popup(f, popup_area, " DNS Health Checks ", lines, &mut app.lint_scroll);
}

fn draw_discovery_popup(f: &mut Frame, app: &mut App) {
    let dim = Style::default().fg(Color::Gray);

    let mut lines: Vec<Line> = vec![Line::raw("")];

    // Wildcard status
    if let Some(ref state) = app.discovery_state {
        let wildcard_line = if state.wildcard_running {
            Line::from(vec![
                Span::styled("  Wildcard: ", dim),
                Span::styled("detecting...", Style::default().fg(Color::Yellow)),
            ])
        } else if state.wildcard_checked {
            if state.wildcard_lookups.is_some() {
                Line::from(vec![
                    Span::styled("  Wildcard: ", dim),
                    Span::styled("detected (filtering enabled)", Style::default().fg(Color::Yellow)),
                ])
            } else {
                Line::from(vec![
                    Span::styled("  Wildcard: ", dim),
                    Span::styled("none detected", Style::default().fg(Color::Green)),
                ])
            }
        } else {
            Line::from(vec![
                Span::styled("  Wildcard: ", dim),
                Span::styled("not checked (runs automatically with Wordlist/Permutation)", dim),
            ])
        };
        lines.push(wildcard_line);
        lines.push(Line::raw(""));

        // Strategy blocks
        for strategy in DiscoveryStrategy::all() {
            let status = state.statuses.get(strategy).cloned().unwrap_or(StrategyStatus::Idle);

            let (icon, status_style, status_text) = match &status {
                StrategyStatus::Idle => (
                    if is_ascii() { "o" } else { "\u{25CB}" },
                    Style::default().fg(Color::DarkGray),
                    "idle".to_string(),
                ),
                StrategyStatus::Running { completed, total } => {
                    if *total > 0 {
                        (
                            if is_ascii() { "*" } else { "\u{25D4}" },
                            Style::default().fg(Color::Yellow),
                            format!("running {completed}/{total}"),
                        )
                    } else {
                        (
                            if is_ascii() { "*" } else { "\u{25D4}" },
                            Style::default().fg(Color::Yellow),
                            "running...".to_string(),
                        )
                    }
                }
                StrategyStatus::Done { found, elapsed } => {
                    let secs = elapsed.as_secs_f64();
                    (
                        if is_ascii() { "@" } else { "\u{25CF}" },
                        Style::default().fg(Color::Green),
                        format!(
                            "done {} {found} found ({secs:.1}s)",
                            if is_ascii() { "--" } else { "\u{2014}" }
                        ),
                    )
                }
                StrategyStatus::Error(msg) => (
                    if is_ascii() { "x" } else { "\u{2717}" },
                    Style::default().fg(Color::Red),
                    format!("error: {msg}"),
                ),
            };

            // Trigger line: [key] Label    status_icon status_text
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  [{}] ", strategy.key()),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<14}", strategy.label()),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{icon} "), status_style),
                Span::styled(status_text, status_style),
            ]));

            // Description line (dimmed, indented)
            lines.push(Line::from(Span::styled(
                format!("      {}", strategy.description()),
                dim,
            )));
            lines.push(Line::raw(""));
        }
    } else {
        lines.push(Line::from(Span::styled(
            if is_ascii() {
                " No query results yet -- run a query first"
            } else {
                " No query results yet \u{2014} run a query first"
            },
            dim,
        )));
        lines.push(Line::raw(""));
    }

    lines.push(
        Line::from(Span::styled(
            "[Esc] close  [j/k] scroll  [c/w/s/t/p] run strategy  [a] run all",
            dim,
        ))
        .right_aligned(),
    );

    let area = f.area();
    let popup_area = centered_rect(area, 65, 80, 60, 100);
    render_scrollable_popup(f, popup_area, " Discovery ", lines, &mut app.discovery_scroll);
}

/// Render a scrollable popup with title, lines, and an optional scrollbar.
/// The `scroll` parameter is clamped to the valid range and updated in place.
fn render_scrollable_popup(f: &mut Frame, popup_area: Rect, title: &str, lines: Vec<Line<'_>>, scroll: &mut u16) {
    let inner_height = popup_area.height.saturating_sub(2);
    let total_lines = lines.len() as u16;
    let max_scroll = total_lines.saturating_sub(inner_height);
    *scroll = (*scroll).min(max_scroll);

    let popup = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((*scroll, 0))
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

    f.render_widget(Clear, popup_area);
    f.render_widget(popup, popup_area);

    if max_scroll > 0 {
        let mut scrollbar_state = ScrollbarState::new(max_scroll as usize).position(*scroll as usize);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None);
        let scrollbar_area = Rect {
            x: popup_area.x,
            y: popup_area.y + 1,
            width: popup_area.width,
            height: popup_area.height.saturating_sub(2),
        };
        f.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
    }
}

/// Returns a centered `Rect` using percentage of the outer area, clamped to min/max width.
fn centered_rect(outer: Rect, pct_width: u16, pct_height: u16, min_width: u16, max_width: u16) -> Rect {
    let popup_w = (outer.width * pct_width / 100).clamp(min_width.min(outer.width), max_width.min(outer.width));
    let popup_h = (outer.height * pct_height / 100).clamp(10.min(outer.height), outer.height);
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

fn format_ttl(ttl: u32) -> String {
    humantime::format_duration(Duration::from_secs(ttl as u64)).to_string()
}

/// Extract the subdomain prefix from a full record name given the queried domain.
/// e.g. "_dmarc.google.com." with domain "google.com" → Some("_dmarc")
fn extract_subdomain<'a>(name: &'a str, domain: &str) -> Option<&'a str> {
    let name = name.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    let prefix = name.strip_suffix(domain)?;
    let prefix = prefix.strip_suffix('.')?;
    if prefix.is_empty() {
        None
    } else {
        Some(prefix)
    }
}
