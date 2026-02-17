use std::io;

use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use mhost::app::common::resolver_args::ResolverArgs;
use mhost::app::common::styles::ascii_mode;
use mhost::app::mdive;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = mdive::create_parser().get_matches();
    let resolver_args = ResolverArgs::from_matches(&matches);
    let domain = matches.get_one::<String>("domain").cloned();

    if matches.get_flag("ascii") {
        ascii_mode();
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
    let result = local.run_until(mdive::run(&mut terminal, resolver_args, domain)).await;

    // Restore terminal
    terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}
