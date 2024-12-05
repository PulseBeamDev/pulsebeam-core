use anyhow::Context;
use clap::{Parser, Subcommand};
use pulsebeam_core::{App, FirewallClaims, PeerClaims};

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
        /// Human-readable subject for the token
        #[arg(long)]
        subject: String,

        /// Peer ID for the token
        #[arg(long)]
        peer_id: String,

        /// Group ID for the token
        #[arg(long)]
        group_id: String,

        /// Duration of the token in seconds
        #[arg(long, default_value_t = 3600)]
        duration: u32,

        /// Allow incoming connections from group ID and peer ID (format: "group_id:peer_id")
        #[arg(long, value_name = "GROUP_ID:PEER_ID")]
        allow_incoming_0: Option<String>,

        /// Allow incoming connections from another group ID and peer ID (format: "group_id:peer_id")
        #[arg(long, value_name = "GROUP_ID:PEER_ID")]
        allow_incoming_1: Option<String>,

        /// Allow outgoing connections to group ID and peer ID (format: "group_id:peer_id")
        #[arg(long, value_name = "GROUP_ID:PEER_ID")]
        allow_outgoing_0: Option<String>,

        /// Allow outgoing connections to another group ID and peer ID (format: "group_id:peer_id")
        #[arg(long, value_name = "GROUP_ID:PEER_ID")]
        allow_outgoing_1: Option<String>,
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
            subject,
            peer_id,
            group_id,
            duration,
            allow_incoming_0,
            allow_incoming_1,
            allow_outgoing_0,
            allow_outgoing_1,
        } => {
            let mut claims = PeerClaims::new(group_id, peer_id);
            claims.subject = subject.to_owned();

            // Helper function to parse "group_id:peer_id" strings
            let parse_firewall_claims = |s: &String| -> Option<FirewallClaims> {
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() == 2 {
                    Some(FirewallClaims {
                        group_id: parts[0].to_string(),
                        peer_id: parts[1].to_string(),
                    })
                } else {
                    None
                }
            };

            claims.allow_incoming_0 = allow_incoming_0.as_ref().and_then(parse_firewall_claims);
            claims.allow_incoming_1 = allow_incoming_1.as_ref().and_then(parse_firewall_claims);
            claims.allow_outgoing_0 = allow_outgoing_0.as_ref().and_then(parse_firewall_claims);
            claims.allow_outgoing_1 = allow_outgoing_1.as_ref().and_then(parse_firewall_claims);

            let token = app.create_token(&claims, *duration)?;
            println!("{}", token);
        }
    };

    Ok(())
}
