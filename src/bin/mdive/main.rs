mod app;
mod dns;
mod ui;

use std::io;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::event::EventStream;
use crossterm::execute;
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use app::{Action, App, Mode, Popup, QueryState, TOGGLEABLE_TYPES};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let domain = std::env::args().nth(1);
    let result = run(&mut terminal, domain).await;

    // Restore terminal
    terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, domain: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let mut app = App::new();
    if let Some(domain) = domain {
        app.cursor_pos = domain.len();
        app.input = domain.clone();
        app.query_state = QueryState::Loading { domain };
    }
    let (tx, mut rx) = mpsc::channel::<Action>(16);
    let mut event_stream = EventStream::new();

    loop {
        terminal.draw(|f| ui::draw(f, &app))?;

        // If Loading, spawn a DNS query task and transition to Querying
        if let QueryState::Loading { ref domain } = app.query_state {
            let domain = domain.clone();
            let types = app.active_type_list();
            let tx = tx.clone();
            app.query_state = QueryState::Querying {
                domain: domain.clone(),
            };
            dns::spawn_query(domain, types, tx);
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

    // When any popup is open, only allow closing it
    if app.popup != Popup::None {
        return match key.code {
            KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q') => Some(Action::ClosePopup),
            _ => None,
        };
    }

    match app.mode {
        Mode::Input => map_input_key(key),
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

fn map_normal_key(key: KeyEvent, app: &App) -> Option<Action> {
    match key.code {
        KeyCode::Char('q') => Some(Action::Quit),
        KeyCode::Char('/') | KeyCode::Char('i') => Some(Action::EnterInputMode),
        KeyCode::Enter => {
            if app.table_state.selected().is_some() {
                Some(Action::OpenPopup)
            } else {
                Some(Action::SubmitQuery)
            }
        }
        KeyCode::Char('j') | KeyCode::Down => Some(Action::MoveDown),
        KeyCode::Char('k') | KeyCode::Up => Some(Action::MoveUp),
        KeyCode::Char('g') | KeyCode::Home => Some(Action::Home),
        KeyCode::Char('G') | KeyCode::End => Some(Action::End),
        KeyCode::PageUp => Some(Action::PageUp),
        KeyCode::PageDown => Some(Action::PageDown),
        KeyCode::Char('r') => Some(Action::SubmitQuery),
        KeyCode::Char('?') => Some(Action::OpenHelp),
        KeyCode::Char('h') => Some(Action::ToggleHumanView),
        KeyCode::Char('a') => Some(Action::SelectAll),
        KeyCode::Char('n') => Some(Action::SelectNone),
        KeyCode::Char(c @ '1'..='9') => {
            let idx = (c as usize) - ('1' as usize);
            TOGGLEABLE_TYPES
                .get(idx)
                .map(|rt| Action::ToggleRecordType(*rt))
        }
        KeyCode::Char('0') => TOGGLEABLE_TYPES
            .get(9)
            .map(|rt| Action::ToggleRecordType(*rt)),
        _ => None,
    }
}
