mod app;
mod dns;
mod lints;
mod ui;

use std::io;

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

use app::{Action, App, Mode, Popup, QueryState};

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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = create_parser().get_matches();
    let resolver_args = ResolverArgs::from_matches(&matches);
    let domain = matches.get_one::<String>("domain").cloned();

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

    let result = run(&mut terminal, resolver_args, domain).await;

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
    let (tx, mut rx) = mpsc::channel::<Action>(16);
    let mut event_stream = EventStream::new();

    loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;

        // If Loading, spawn a domain query task and transition to Querying
        if let QueryState::Loading { ref domain } = app.query_state {
            let domain = domain.clone();
            let tx = tx.clone();
            let resolver_args = app.resolver_args.clone();
            let generation = app.query_generation;
            app.query_state = QueryState::Querying {
                domain: domain.clone(),
            };
            dns::spawn_domain_query(domain, resolver_args, tx, generation);
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
        return match key.code {
            KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q') => Some(Action::ClosePopup),
            // Scrolling in scrollable popups (WHOIS, Lints)
            KeyCode::Char('j') | KeyCode::Down if app.popup == Popup::Whois || app.popup == Popup::Lints => {
                Some(Action::PopupScrollDown)
            }
            KeyCode::Char('k') | KeyCode::Up if app.popup == Popup::Whois || app.popup == Popup::Lints => {
                Some(Action::PopupScrollUp)
            }
            KeyCode::PageDown if app.popup == Popup::Whois || app.popup == Popup::Lints => Some(Action::PopupScrollPageDown),
            KeyCode::PageUp if app.popup == Popup::Whois || app.popup == Popup::Lints => Some(Action::PopupScrollPageUp),
            KeyCode::Char('g') if app.popup == Popup::Whois || app.popup == Popup::Lints => Some(Action::PopupScrollHome),
            KeyCode::Char('G') if app.popup == Popup::Whois || app.popup == Popup::Lints => Some(Action::PopupScrollEnd),
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
                Some(Action::OpenPopup)
            } else {
                Some(Action::SubmitQuery)
            }
        }
        KeyCode::Char('j') | KeyCode::Down => Some(Action::MoveDown),
        KeyCode::Char('k') | KeyCode::Up => Some(Action::MoveUp),
        KeyCode::Char('g') => Some(Action::PressG),
        KeyCode::Char('G') => Some(Action::PressCapG),
        KeyCode::Home => Some(Action::Home),
        KeyCode::End => Some(Action::End),
        KeyCode::PageUp => Some(Action::PageUp),
        KeyCode::PageDown => Some(Action::PageDown),
        KeyCode::Char('r') => Some(Action::SubmitQuery),
        KeyCode::Char('s') => Some(Action::OpenServers),
        KeyCode::Char('w') => Some(Action::OpenWhois),
        KeyCode::Char('c') => Some(Action::OpenLints),
        KeyCode::Char('?') => Some(Action::OpenHelp),
        KeyCode::Char('h') => Some(Action::ToggleHumanView),
        KeyCode::Char('a') => Some(Action::SelectAll),
        KeyCode::Char('n') => Some(Action::SelectNone),
        KeyCode::Char(c @ '0'..='9') => Some(Action::DigitPress(c)),
        _ => None,
    }
}
