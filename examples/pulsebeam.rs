use anyhow::Context;
use clap::{Parser, Subcommand};
use pulsebeam_core::{App, PeerPolicy, PeerClaims};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Application ID (optional, can also be set with the PULSEBEAM_APP_ID environment variable)
    #[arg(long)]
    app_id: Option<String>,

    /// Application secret (optional, can also be set with the PULSEBEAM_APP_SECRET environment variable)
    #[arg(long)]
    app_secret: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new token
    CreateToken {
        /// Peer ID for the token
        #[arg(long)]
        peer_id: String,

        /// Group ID for the token
        #[arg(long)]
        group_id: String,

        /// Duration of the token in seconds
        #[arg(long, default_value_t = 3600)]
        duration: u32,

        /// Allow connections from group ID and peer ID (format: "group_id:peer_id")
        #[arg(long, value_name = "GROUP_ID:PEER_ID")]
        allow_policy: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Get app_id and app_secret, prioritizing CLI arguments over environment variables
    let app_id = cli
        .app_id
        .or_else(|| std::env::var("PULSEBEAM_APP_ID").ok())
        .context(
            "PULSEBEAM_APP_ID must be provided either as a CLI argument or an environment variable",
        )?;
    let app_secret = cli
        .app_secret
        .or_else(|| std::env::var("PULSEBEAM_APP_SECRET").ok())
        .context("PULSEBEAM_APP_SECRET must be provided either as a CLI argument or an environment variable")?;

    let app = App::new(&app_id, &app_secret);

    match &cli.command {
        Commands::CreateToken {
            peer_id,
            group_id,
            duration,
            allow_policy,
        } => {
            let mut claims = PeerClaims::new(group_id, peer_id);

            // Helper function to parse "group_id:peer_id" strings
            let parse_peer_policy = |s: &String| -> Option<PeerPolicy> {
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() == 2 {
                    Some(PeerPolicy {
                        group_id_policy: parts[0].to_string(),
                        peer_id_policy: parts[1].to_string(),
                    })
                } else {
                    None
                }
            };

            claims.allow_policy = allow_policy.as_ref().and_then(parse_peer_policy);

            let token = app.create_token(&claims, *duration)?;
            println!("{}", token);
        }
    };

    Ok(())
}
