use clap::{Args, Parser, Subcommand};
use pulsebeam_core::AppOpts;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Token {},
    Verify { jwt: String },
}

pub fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    println!("{cli:?}");

    match &cli.command {
        Some(Commands::Token {}) => {}
        Some(Commands::Verify { jwt }) => {}
        None => {}
    };

    Ok(())
}
