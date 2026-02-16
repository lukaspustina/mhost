use std::time::Duration;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Table, Wrap,
};
use ratatui::Frame;

use mhost::app::common::styles::{record_type_color, record_type_is_bold};
use mhost::app::common::reference_data;
use mhost::app::modules::check::lints::CheckResult;
use mhost::services::whois::WhoisResponse;
use mhost::RecordType;

use crate::app::{
    category_short_label, format_nameserver_human, record_type_info, App, DiscoveryStrategy,
    Mode, Popup, QueryState, StrategyStatus, TOGGLEABLE_CATEGORIES,
};

pub fn draw(f: &mut Frame, app: &mut App) {
    let stats_height = if app.show_stats && app.stats_data.is_some() { 2 } else { 0 };
    let chunks = Layout::vertical([
        Constraint::Length(3),            // title + input
        Constraint::Length(1),            // category toggles
        Constraint::Length(stats_height), // stats panel (0 or 2)
        Constraint::Min(5),              // results table
        Constraint::Length(1),            // detail line
        Constraint::Length(1),            // status bar
    ])
    .split(f.area());

    draw_input(f, app, chunks[0]);
    draw_category_toggles(f, app, chunks[1]);
    if stats_height > 0 {
        draw_stats(f, app, chunks[2]);
    }
    draw_table(f, app, chunks[3]);
    draw_detail(f, app, chunks[4]);
    draw_status(f, app, chunks[5]);

    match app.popup {
        Popup::RecordDetail(_) => draw_record_popup(f, app),
        Popup::Help => draw_help_popup(f),
        Popup::Servers => draw_servers_popup(f, app),
        Popup::Whois => draw_whois_popup(f, app),
        Popup::Lints => draw_lints_popup(f, app),
        Popup::Discovery => draw_discovery_popup(f, app),
        Popup::None => {}
    }
}

fn draw_input(f: &mut Frame, app: &App, area: Rect) {
    let title_right = " [?]help [/]filter [C]lear [i]nput [r]re-run [d]iscover [s]ervers [w]hois [c]heck [S]tats [h]uman [a]ll [n]one [q]uit ";

    let title_left: Line = if let Some(ref filter) = app.filter {
        Line::from(vec![
            Span::raw(" mdive "),
            Span::styled(
                format!("regex: \"{}\" ", filter.as_str()),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
        ])
    } else {
        Line::from(" mdive ")
    };

    let search_border_color = if app.filter_error { Color::Red } else { Color::Green };

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

    let prompt_style = if app.mode == Mode::Search && app.filter_error {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Gray)
    };

    let input_line = Line::from(vec![
        Span::styled(prompt, prompt_style),
        Span::raw(text),
    ]);

    let paragraph = Paragraph::new(input_line).block(block);
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
    spans.push(Span::raw(" "));

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
        line1_spans.push(Span::styled(
            format!("{type_str}:{count}"),
            to_ratatui_style(*rt),
        ));
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
        (Some(min), Some(max)) => format!("{min}\u{2013}{max}ms"),
        _ => "\u{2013}".to_string(),
    };
    line2_spans.push(Span::styled(time_str, Style::default().fg(Color::Gray)));

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

    let rows: Vec<Row> = app
        .rows
        .iter()
        .enumerate()
        .map(|(idx, r)| {
            let type_style = to_ratatui_style(r.record_type);
            let type_str: &'static str = r.record_type.into();
            let line_num = Cell::from(format!("{}", idx + 1))
                .style(Style::default().fg(Color::DarkGray));
            let ttl_str = if app.human_view {
                format_ttl(r.ttl)
            } else {
                r.ttl.to_string()
            };
            if app.human_view {
                let value_lines: Vec<Line> = r.human_value
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
                    line_num,
                    Cell::from(r.name.as_str()),
                    Cell::from(type_str).style(type_style),
                    Cell::from(ttl_str).style(Style::default().fg(Color::Gray)),
                    Cell::from(Text::from(value_lines)),
                ])
                .height(height)
            } else {
                Row::new(vec![
                    line_num,
                    Cell::from(r.name.as_str()),
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

    f.render_stateful_widget(table, area, &mut app.table_state);

    // Scrollbar
    if !app.rows.is_empty() {
        let selected = app.table_state.selected().unwrap_or(0);
        let mut scrollbar_state = ScrollbarState::new(app.rows.len().saturating_sub(1))
            .position(selected);
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
            Line::from(vec![
                Span::styled(" ", Style::default()),
                Span::styled(
                    format!("{}", row.category),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(" | server: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format_nameserver_human(&row.nameserver),
                    Style::default().fg(Color::Yellow),
                ),
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
        Mode::Search => Span::styled(
            " SEARCH ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let mut spans = vec![mode_span];

    // Show vi count buffer when active
    if !app.count_buffer.is_empty() || app.pending_g {
        let mut buf = app.count_buffer.clone();
        if app.pending_g {
            buf.push('g');
        }
        spans.push(Span::styled(
            format!(" {buf}"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
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
                spans.push(Span::styled(
                    "\u{2588}".repeat(filled),
                    Style::default().fg(Color::Cyan),
                ));
                spans.push(Span::styled(
                    "\u{2591}".repeat(empty),
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

    let human = &row.human_value;

    let mut lines: Vec<Line> = vec![
        Line::raw(""),
        Line::from(Span::styled(
            &row.name,
            Style::default().add_modifier(Modifier::BOLD),
        )),
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
                Span::styled(
                    sub_info.summary.to_string(),
                    Style::default().fg(Color::Cyan),
                ),
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
        lines.push(Line::from(Span::styled(
            rfc,
            Style::default().fg(Color::Gray),
        )));
    }

    lines.push(Line::raw(""));
    lines.push(
        Line::from(Span::styled("[Esc] close", Style::default().fg(Color::Gray)))
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
    let key_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);

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
        help_line("gg / Home", "Jump to first row"),
        help_line("G / End", "Jump to last row"),
        help_line("22gg / 22G", "Jump to line 22"),
        help_line("PgUp / PgDn", "Scroll by 10 rows"),
        help_line("Enter", "Show record details"),
        help_line("h", "Toggle human-readable view"),
        help_line("s", "Show servers used"),
        help_line("w", "Show WHOIS for result IPs"),
        help_line("c", "Show DNS health checks"),
        help_line("S", "Toggle stats panel"),
        help_line("d", "Open discovery panel"),
        Line::raw(""),
        Line::from(Span::styled(
            "Query",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        help_line("i", "Enter domain input mode"),
        help_line("/", "Filter results"),
        help_line("C", "Clear active filter"),
        help_line("r", "Re-run current query"),
        Line::raw(""),
        Line::from(Span::styled(
            "Categories",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        help_line("1-8", "Toggle categories (Email, Svc, TLS, ...)"),
        help_line("9, 0", "Toggle Legacy, Gaming"),
        help_line("a", "Select all categories"),
        help_line("n", "Deselect all categories"),
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
        Line::from(Span::styled("[Esc] close", dim)).right_aligned(),
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

fn draw_servers_popup(f: &mut Frame, app: &App) {
    let dim = Style::default().fg(Color::Gray);

    let mut lines: Vec<Line> = vec![Line::raw("")];

    if let Some(lookups) = &app.lookups {
        // Collect unique servers and sort for stable display
        let mut servers: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for lookup in lookups.iter() {
            let raw = lookup.name_server().to_string();
            if seen.insert(raw.clone()) {
                servers.push(raw);
            }
        }
        servers.sort();

        lines.push(Line::from(Span::styled(
            format!(" {} servers used", servers.len()),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::raw(""));

        for (i, raw) in servers.iter().enumerate() {
            let human = format_nameserver_human(raw);
            lines.push(Line::from(vec![
                Span::styled(format!("  {:>2}  ", i + 1), dim),
                Span::styled(human, Style::default().fg(Color::Yellow)),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            " No query results yet",
            dim,
        )));
    }

    lines.push(Line::raw(""));
    lines.push(
        Line::from(Span::styled("[Esc] close", dim)).right_aligned(),
    );

    let area = f.area();
    let popup_area = centered_rect(area, 50, 70, 40, 70);

    let popup = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(" Servers ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

    f.render_widget(Clear, popup_area);
    f.render_widget(popup, popup_area);
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
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
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
            lines.push(Line::from(Span::styled(
                " No WHOIS data available",
                dim,
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            " Loading WHOIS data...",
            Style::default().fg(Color::Yellow),
        )));
    }

    lines.push(Line::raw(""));
    lines.push(
        Line::from(Span::styled("[Esc] close  [j/k] scroll", dim)).right_aligned(),
    );

    let area = f.area();
    let popup_area = centered_rect(area, 60, 80, 50, 90);
    // Inner height = popup height - 2 (top + bottom border)
    let inner_height = popup_area.height.saturating_sub(2);
    let total_lines = lines.len() as u16;
    let max_scroll = total_lines.saturating_sub(inner_height);
    app.whois_line_count = max_scroll;
    let scroll = app.whois_scroll.min(max_scroll);

    let popup = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0))
        .block(
            Block::default()
                .title(" WHOIS ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

    f.render_widget(Clear, popup_area);
    f.render_widget(popup, popup_area);

    // Scrollbar
    if max_scroll > 0 {
        let mut scrollbar_state = ScrollbarState::new(max_scroll as usize)
            .position(scroll as usize);
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

fn draw_lints_popup(f: &mut Frame, app: &mut App) {
    let dim = Style::default().fg(Color::Gray);

    let mut lines: Vec<Line> = vec![Line::raw("")];

    if let Some(ref sections) = app.lint_results {
        if sections.is_empty() {
            lines.push(Line::from(Span::styled(
                " No lint results available",
                dim,
            )));
        } else {
            for (i, section) in sections.iter().enumerate() {
                if i > 0 {
                    lines.push(Line::raw(""));
                }
                lines.push(Line::from(Span::styled(
                    format!(" {}", section.name),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )));

                for result in &section.results {
                    let (icon, style, msg): (&str, Style, &str) = match result {
                        CheckResult::Ok(msg) => (
                            "\u{2713}",
                            Style::default().fg(Color::Green),
                            msg.as_str(),
                        ),
                        CheckResult::Warning(msg) => (
                            "!",
                            Style::default().fg(Color::Yellow),
                            msg.as_str(),
                        ),
                        CheckResult::Failed(msg) => (
                            "\u{2717}",
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
        lines.push(Line::from(Span::styled(
            " No query results yet",
            dim,
        )));
    }

    lines.push(Line::raw(""));
    lines.push(
        Line::from(Span::styled("[Esc] close  [j/k] scroll", dim)).right_aligned(),
    );

    let area = f.area();
    let popup_area = centered_rect(area, 60, 80, 50, 90);
    let inner_height = popup_area.height.saturating_sub(2);
    let total_lines = lines.len() as u16;
    let max_scroll = total_lines.saturating_sub(inner_height);
    app.lint_line_count = max_scroll;
    let scroll = app.lint_scroll.min(max_scroll);

    let popup = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0))
        .block(
            Block::default()
                .title(" DNS Health Checks ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

    f.render_widget(Clear, popup_area);
    f.render_widget(popup, popup_area);

    // Scrollbar
    if max_scroll > 0 {
        let mut scrollbar_state = ScrollbarState::new(max_scroll as usize)
            .position(scroll as usize);
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
                    Span::styled(
                        "detected (filtering enabled)",
                        Style::default().fg(Color::Yellow),
                    ),
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
                Span::styled(
                    "not checked (runs automatically with Wordlist/Permutation)",
                    dim,
                ),
            ])
        };
        lines.push(wildcard_line);
        lines.push(Line::raw(""));

        // Strategy blocks
        for strategy in DiscoveryStrategy::all() {
            let status = state
                .statuses
                .get(strategy)
                .cloned()
                .unwrap_or(StrategyStatus::Idle);

            let (icon, status_style, status_text) = match &status {
                StrategyStatus::Idle => (
                    "\u{25CB}",
                    Style::default().fg(Color::DarkGray),
                    "idle".to_string(),
                ),
                StrategyStatus::Running { completed, total } => {
                    if *total > 0 {
                        (
                            "\u{25D4}",
                            Style::default().fg(Color::Yellow),
                            format!("running {completed}/{total}"),
                        )
                    } else {
                        (
                            "\u{25D4}",
                            Style::default().fg(Color::Yellow),
                            "running...".to_string(),
                        )
                    }
                }
                StrategyStatus::Done { found, elapsed } => {
                    let secs = elapsed.as_secs_f64();
                    (
                        "\u{25CF}",
                        Style::default().fg(Color::Green),
                        format!("done \u{2014} {found} found ({secs:.1}s)"),
                    )
                }
                StrategyStatus::Error(msg) => (
                    "\u{2717}",
                    Style::default().fg(Color::Red),
                    format!("error: {msg}"),
                ),
            };

            // Trigger line: [key] Label    status_icon status_text
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  [{}] ", strategy.key()),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
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
            " No query results yet \u{2014} run a query first",
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
    let inner_height = popup_area.height.saturating_sub(2);
    let total_lines = lines.len() as u16;
    let max_scroll = total_lines.saturating_sub(inner_height);
    app.discovery_line_count = max_scroll;
    let scroll = app.discovery_scroll.min(max_scroll);

    let popup = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0))
        .block(
            Block::default()
                .title(" Discovery ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

    f.render_widget(Clear, popup_area);
    f.render_widget(popup, popup_area);

    // Scrollbar
    if max_scroll > 0 {
        let mut scrollbar_state =
            ScrollbarState::new(max_scroll as usize).position(scroll as usize);
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
fn centered_rect(
    outer: Rect,
    pct_width: u16,
    pct_height: u16,
    min_width: u16,
    max_width: u16,
) -> Rect {
    let popup_w = (outer.width * pct_width / 100)
        .clamp(min_width.min(outer.width), max_width.min(outer.width));
    let popup_h = (outer.height * pct_height / 100)
        .clamp(10.min(outer.height), outer.height);
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
