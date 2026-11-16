//! The self-hostable Weirdnet push server.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Weirdnet push wake-up server (APNs, FCM, relay announcements)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve with a TOML config.
    Serve {
        /// The config file.
        #[arg(short, long, default_value = "/etc/weirdnet-push/config.toml")]
        config: PathBuf,
    },
    /// Check a config: parse it and load the keys.
    Check {
        /// The config file.
        #[arg(short, long, default_value = "/etc/weirdnet-push/config.toml")]
        config: PathBuf,
    },
    /// Make a relay token: give the token to the relay, put the digest in [relay] token_digests.
    RelayToken,
}

fn load(p: &PathBuf) -> Result<weirdnet_push::server::Config, Box<dyn std::error::Error>> {
    Ok(weirdnet_push::server::Config::from_toml(&std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?)?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    match Cli::parse().cmd {
        Cmd::Serve { config } => {
            let c = load(&config)?;
            weirdnet_push::server::serve(c, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
        }
        Cmd::Check { config } => {
            let c = load(&config)?;
            let s = weirdnet_push::server::Service::new(&c)?;
            println!("ok: {} registrations; apns {}, fcm {}, relay {}", s.store().len(), c.apns.is_some(), c.fcm.is_some(), c.relay.is_some());
        }
        Cmd::RelayToken => {
            let t = weirdnet_push::WakeHandle::generate();
            println!("token:  {}", t.as_str());
            println!("digest: {}", weirdnet_push::server::token_digest(t.as_str()));
        }
    }
    Ok(())
}
