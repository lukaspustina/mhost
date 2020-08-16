use clap::Shell;
use std::env;
use std::fs;
use std::path::Path;

#[allow(dead_code)]
#[path = "src/app/app.rs"]
mod app;

fn main() {
    let root_dir = env::var_os("CARGO_MANIFEST_DIR")
        .expect("Cargo output directory environment variable is not set.");
    let output_dir = Path::new(&root_dir).join("contrib").join("shell-completions");
    fs::create_dir_all(&output_dir).expect("failed to create output directory");

    // Create Shell completions
    let mut app = app::app();
    app.gen_completions("mhost", Shell::Bash, &output_dir);
    app.gen_completions("mhost", Shell::Fish, &output_dir);
    app.gen_completions("mhost", Shell::Zsh, &output_dir);
}