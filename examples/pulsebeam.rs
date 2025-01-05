use anyhow::Context;
use clap::{Parser, Subcommand};
use pulsebeam_core::{App, PeerPolicy, PeerClaims};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// API KEY (required, can also be set with the PULSEBEAM_API_KEY environment variable)
    #[arg(long)]
    api_key: Option<String>,

    /// API SECRET (required, can also be set with the PULSEBEAM_API_SECRET environment variable)
    #[arg(long)]
    api_secret: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new token
    CreateToken {
        /// (required) Peer ID for the token
        #[arg(long)]
        peer_id: String,

        /// (required) Group ID for the token
        #[arg(long)]
        group_id: String,

        /// Duration of the token in seconds
        #[arg(long, default_value_t = 3600)]
        duration: u32,

        /// Allow connections from group ID and peer ID (format: "group_id:peer_id")
        #[arg(long, value_name = "GROUP_ID:PEER_ID", default_value = "*:*")]
        allow_policy: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Get api_key and api_secret, prioritizing CLI arguments over environment variables
    let api_key = cli
        .api_key
        .or_else(|| std::env::var("PULSEBEAM_API_KEY").ok())
        .context(
            "PULSEBEAM_API_KEY must be provided either as a CLI argument or an environment variable",
        )?;
    let api_secret = cli
        .api_secret
        .or_else(|| std::env::var("PULSEBEAM_API_SECRET").ok())
        .context("PULSEBEAM_API_SECRET must be provided either as a CLI argument or an environment variable")?;

    let app = App::new(&api_key, &api_secret);

    match &cli.command {
        Commands::CreateToken {
            peer_id,
            group_id,
            duration,
            allow_policy,
        } => {
            let mut claims: PeerClaims = PeerClaims::new(group_id, peer_id);

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

            claims.allow_policy = parse_peer_policy(allow_policy);

            let token = app.create_token(&claims, *duration)?;
            println!("{}", token);
        }
    };

    Ok(())
}
