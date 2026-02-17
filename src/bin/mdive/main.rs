mod app;
mod discovery;
mod dns;
mod lints;
mod ui;

use std::io;
use std::sync::Arc;

use clap::{Arg, ArgAction, Command};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::event::EventStream;
use crossterm::execute;
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use mhost::app::common::resolver_args::{u64_range, ResolverArgs};

use app::{Action, App, DiscoveryStrategy, Mode, Popup, QueryState, StrategyStatus};

fn create_parser() -> Command {
    Command::new("mdive")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Interactive DNS domain explorer")
        .arg(
            Arg::new("domain")
                .index(1)
                .value_name("DOMAIN")
                .help("Domain name to query on launch"),
        )
        .arg(
            Arg::new("nameservers")
                .short('s')
                .long("nameserver")
                .value_name("HOSTNAME | IP ADDR")
                .action(ArgAction::Append)
                .help("Adds nameserver for lookups"),
        )
        .arg(
            Arg::new("predefined")
                .short('p')
                .long("predefined")
                .action(ArgAction::SetTrue)
                .help("Adds predefined nameservers for lookups"),
        )
        .arg(
            Arg::new("predefined-filter")
                .long("predefined-filter")
                .value_name("PROTOCOL")
                .action(ArgAction::Append)
                .value_delimiter(',')
                .default_value("udp")
                .value_parser(["udp", "tcp", "https", "tls"])
                .help("Filters predefined nameservers by protocol"),
        )
        .arg(
            Arg::new("no-system-lookups")
                .short('S')
                .long("no-system-lookups")
                .action(ArgAction::SetTrue)
                .help("Don't use system nameservers"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .value_name("SECONDS")
                .default_value("5")
                .value_parser(u64_range(1, 30))
                .help("Sets timeout in seconds for responses"),
        )
        .arg(
            Arg::new("ipv4-only")
                .short('4')
                .long("ipv4-only")
                .action(ArgAction::SetTrue)
                .conflicts_with("ipv6-only")
                .help("Only use IPv4 for DNS connections"),
        )
        .arg(
            Arg::new("ipv6-only")
                .short('6')
                .long("ipv6-only")
                .action(ArgAction::SetTrue)
                .conflicts_with("ipv4-only")
                .help("Only use IPv6 for DNS connections"),
        )
        .arg(
            Arg::new("ascii")
                .long("ascii")
                .action(ArgAction::SetTrue)
                .help("Uses only ASCII compatible characters for output"),
        )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = create_parser().get_matches();
    let resolver_args = ResolverArgs::from_matches(&matches);
    let domain = matches.get_one::<String>("domain").cloned();

    if matches.get_flag("ascii") {
        mhost::app::output::styles::ascii_mode();
    }

    // Setup terminal
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    // Install panic hook that restores terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let local = tokio::task::LocalSet::new();
    let result = local.run_until(run(&mut terminal, resolver_args, domain)).await;

    // Restore terminal
    terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    resolver_args: ResolverArgs,
    domain: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut app = App::new(resolver_args);
    if let Some(domain) = domain {
        app.cursor_pos = domain.len();
        app.input = domain.clone();
        app.query_state = QueryState::Loading { domain };
    }
    let (tx, mut rx) = mpsc::channel::<Action>(128);
    let mut event_stream = EventStream::new();

    loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;

        // If Loading, build resolver group (once) and spawn a domain query task
        if let QueryState::Loading { ref domain } = app.query_state {
            let domain = domain.clone();
            let tx = tx.clone();
            let generation = app.query_generation;
            app.query_state = QueryState::Querying {
                domain: domain.clone(),
            };

            // Build resolver group once and cache it
            if app.resolver_group.is_none() {
                match app.resolver_args.build_resolver_group().await {
                    Ok(rg) => {
                        app.resolver_group = Some(Arc::new(rg));
                    }
                    Err(msg) => {
                        app.query_state = QueryState::Error { domain, message: msg };
                        continue;
                    }
                }
            }
            let resolver_group = app.resolver_group.clone().unwrap();
            let handle = dns::spawn_domain_query(domain, resolver_group, tx, generation);
            app.dns_task = Some(handle);
        }

        // If WHOIS popup is open and data needs fetching, spawn the WHOIS query
        if app.needs_whois_fetch() {
            if let Some(ref lookups) = app.lookups {
                let ips = dns::ips_from_lookups(lookups);
                if ips.is_empty() {
                    app.whois_error = Some("No IP addresses found in results".to_string());
                } else {
                    let generation = app.query_generation;
                    dns::spawn_whois_query(ips, tx.clone(), generation);
                    app.whois_loading = true;
                    app.whois_generation = generation;
                }
            }
        }

        tokio::select! {
            Some(event_result) = event_stream.next() => {
                match event_result {
                    Ok(Event::Key(key)) => {
                        if let Some(action) = map_key(key, &app) {
                            app.update(action);
                        }
                    }
                    Ok(_) => {} // ignore mouse, resize, etc.
                    Err(_) => break,
                }
            }
            Some(action) = rx.recv() => {
                app.update(action);
            }
        }

        // If discovery strategies were requested, spawn them
        let pending: Vec<DiscoveryStrategy> = app.pending_strategy_spawns.drain(..).collect();
        if !pending.is_empty() {
            let domain = app.current_domain().to_string();
            let generation = app.discovery_state.as_ref().map_or(0, |s| s.generation);

            // Build resolver group if not yet available
            if app.resolver_group.is_none() {
                match app.resolver_args.build_resolver_group().await {
                    Ok(rg) => {
                        app.resolver_group = Some(Arc::new(rg));
                    }
                    Err(msg) => {
                        if let Some(ref mut state) = app.discovery_state {
                            for &strategy in &pending {
                                state.statuses.insert(strategy, StrategyStatus::Error(msg.clone()));
                            }
                        }
                        continue;
                    }
                }
            }
            let resolver_group = app.resolver_group.clone().unwrap();

            // Check wildcard state once upfront — multiple strategies may need it
            let wildcard_checked = app.discovery_state.as_ref().is_some_and(|s| s.wildcard_checked);
            let wildcard_running = app.discovery_state.as_ref().is_some_and(|s| s.wildcard_running);
            let wildcard_lookups = app.discovery_state.as_ref().and_then(|s| s.wildcard_lookups.clone());
            let needs_wildcard = pending.iter().any(|s| matches!(s, DiscoveryStrategy::Wordlist | DiscoveryStrategy::Permutation));

            if needs_wildcard && !wildcard_checked && !wildcard_running {
                if let Some(ref mut state) = app.discovery_state {
                    state.wildcard_running = true;
                }
                let handle = discovery::spawn_wildcard_check(
                    domain.clone(),
                    Arc::clone(&resolver_group),
                    tx.clone(),
                    generation,
                );
                app.discovery_tasks.push(handle);
            }

            for strategy in pending {
                let rg = Arc::clone(&resolver_group);
                let tx = tx.clone();
                let domain = domain.clone();

                let handle = match strategy {
                    DiscoveryStrategy::CtLogs => {
                        discovery::spawn_ct_logs(domain, rg, tx, generation)
                    }
                    DiscoveryStrategy::Wordlist => {
                        discovery::spawn_wordlist(domain, rg, wildcard_lookups.clone(), tx, generation)
                    }
                    DiscoveryStrategy::SrvProbing => {
                        discovery::spawn_srv_probing(domain, rg, tx, generation)
                    }
                    DiscoveryStrategy::TxtMining => {
                        if let Some(ref lookups) = app.lookups {
                            discovery::spawn_txt_mining(
                                domain,
                                rg,
                                lookups.clone(),
                                tx,
                                generation,
                            )
                        } else {
                            if let Some(ref mut state) = app.discovery_state {
                                state.statuses.insert(
                                    DiscoveryStrategy::TxtMining,
                                    StrategyStatus::Error("No lookup results available yet".to_string()),
                                );
                            }
                            continue;
                        }
                    }
                    DiscoveryStrategy::Permutation => {
                        if let Some(ref lookups) = app.lookups {
                            discovery::spawn_permutation(
                                domain,
                                rg,
                                lookups.clone(),
                                wildcard_lookups.clone(),
                                tx,
                                generation,
                            )
                        } else {
                            if let Some(ref mut state) = app.discovery_state {
                                state.statuses.insert(
                                    DiscoveryStrategy::Permutation,
                                    StrategyStatus::Error("No lookup results available yet".to_string()),
                                );
                            }
                            continue;
                        }
                    }
                };
                app.discovery_tasks.push(handle);
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn map_key(key: KeyEvent, app: &App) -> Option<Action> {
    // Ctrl+C always quits
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Some(Action::Quit);
    }

    // When any popup is open, handle close + scrolling for scrollable popups
    if app.popup != Popup::None {
        let scrollable = matches!(
            app.popup,
            Popup::Whois | Popup::Lints | Popup::Discovery | Popup::RecordDetail { .. } | Popup::Servers | Popup::Help
        );

        // Discovery popup: strategy keys trigger runs, Esc closes
        if app.popup == Popup::Discovery {
            if let KeyCode::Char(c) = key.code {
                if c == 'a' {
                    return Some(Action::RunAllStrategies);
                }
                if let Some(strategy) = DiscoveryStrategy::from_key(c) {
                    return Some(Action::RunStrategy(strategy));
                }
            }
        }

        return match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Some(Action::ClosePopup),
            KeyCode::Enter if !matches!(app.popup, Popup::Discovery) => Some(Action::ClosePopup),
            KeyCode::Char('j') | KeyCode::Down if scrollable => Some(Action::PopupScrollDown),
            KeyCode::Char('k') | KeyCode::Up if scrollable => Some(Action::PopupScrollUp),
            KeyCode::PageDown if scrollable => Some(Action::PopupScrollPageDown),
            KeyCode::PageUp if scrollable => Some(Action::PopupScrollPageUp),
            KeyCode::Char('g') if scrollable => Some(Action::PopupScrollHome),
            KeyCode::Char('G') if scrollable => Some(Action::PopupScrollEnd),
            _ => None,
        };
    }

    match app.mode {
        Mode::Input => map_input_key(key),
        Mode::Search => map_search_key(key),
        Mode::Normal => map_normal_key(key, app),
    }
}

fn map_input_key(key: KeyEvent) -> Option<Action> {
    // Ctrl+W: delete word
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('w') {
        return Some(Action::InputDeleteWord);
    }

    match key.code {
        KeyCode::Esc => Some(Action::ExitInputMode),
        KeyCode::Enter => Some(Action::SubmitQuery),
        KeyCode::Backspace => Some(Action::InputBackspace),
        KeyCode::Left => Some(Action::InputLeft),
        KeyCode::Right => Some(Action::InputRight),
        KeyCode::Home => Some(Action::InputHome),
        KeyCode::End => Some(Action::InputEnd),
        KeyCode::Char(c) => Some(Action::InputChar(c)),
        _ => None,
    }
}

fn map_search_key(key: KeyEvent) -> Option<Action> {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('w') {
        return Some(Action::InputDeleteWord);
    }

    match key.code {
        KeyCode::Esc => Some(Action::ExitSearchMode),
        KeyCode::Enter => Some(Action::ApplyFilter),
        KeyCode::Backspace => Some(Action::InputBackspace),
        KeyCode::Left => Some(Action::InputLeft),
        KeyCode::Right => Some(Action::InputRight),
        KeyCode::Home => Some(Action::InputHome),
        KeyCode::End => Some(Action::InputEnd),
        KeyCode::Char(c) => Some(Action::InputChar(c)),
        _ => None,
    }
}

fn map_normal_key(key: KeyEvent, app: &App) -> Option<Action> {
    match key.code {
        KeyCode::Char('q') => Some(Action::Quit),
        KeyCode::Char('i') => Some(Action::EnterInputMode),
        KeyCode::Char('/') => Some(Action::EnterSearchMode),
        KeyCode::Char('C') if app.filter.is_some() => Some(Action::ClearFilter),
        KeyCode::Esc if app.filter.is_some() => Some(Action::ClearFilter),
        KeyCode::Enter => {
            if app.table_state.selected().is_some() {
                Some(Action::DrillIntoName)
            } else {
                Some(Action::SubmitQuery)
            }
        }
        KeyCode::Char('l') | KeyCode::Right => {
            if app.table_state.selected().is_some() {
                Some(Action::DrillIntoValue)
            } else {
                None
            }
        }
        KeyCode::Left | KeyCode::Backspace => Some(Action::GoBack),
        KeyCode::Char('o') => Some(Action::OpenRecordDetail),
        KeyCode::Char('j') | KeyCode::Down => Some(Action::MoveDown),
        KeyCode::Char('k') | KeyCode::Up => Some(Action::MoveUp),
        KeyCode::Char('g') => Some(Action::PressG),
        KeyCode::Char('G') => Some(Action::PressCapG),
        KeyCode::Home => Some(Action::Home),
        KeyCode::End => Some(Action::End),
        KeyCode::PageUp => Some(Action::PageUp),
        KeyCode::PageDown => Some(Action::PageDown),
        KeyCode::Char('r') => Some(Action::SubmitQuery),
        KeyCode::Char('d') => Some(Action::OpenDiscovery),
        KeyCode::Char('s') => Some(Action::OpenServers),
        KeyCode::Char('w') => Some(Action::OpenWhois),
        KeyCode::Char('c') => Some(Action::OpenLints),
        KeyCode::Char('?') => Some(Action::OpenHelp),
        KeyCode::Char('h') => Some(Action::ToggleHumanView),
        KeyCode::Char('S') => Some(Action::ToggleStats),
        KeyCode::Char('a') => Some(Action::SelectAll),
        KeyCode::Char('n') => Some(Action::SelectNone),
        KeyCode::Tab => Some(Action::CycleGroupMode),
        KeyCode::Char(c @ '0'..='9') => Some(Action::DigitPress(c)),
        _ => None,
    }
}
