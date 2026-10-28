//! Active process session commands for secwet-cli.

use clap::{Args, Subcommand};
use secwet_core::{Error, Result, Secwet};

#[derive(Args, Debug)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub command: SessionSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum SessionSubcommands {
    /// List active process sessions injected with secrets
    List(SessionListArgs),
    /// Stop (terminate) a running process session by ID or PID
    Stop(SessionStopArgs),
}

#[derive(Args, Debug)]
pub struct SessionListArgs {
    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SessionStopArgs {
    /// Target session ID (UUID) or process PID
    pub target: String,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

pub fn execute_session(secwet: &Secwet, args: SessionArgs) -> Result<()> {
    match args.command {
        SessionSubcommands::List(sub) => {
            let sessions = secwet.list_active_sessions()?;
            if sub.json {
                println!("{}", serde_json::to_string_pretty(&sessions).map_err(|_| Error::Storage)?);
            } else if sessions.is_empty() {
                println!("No active secret-injected sessions running.");
            } else {
                println!("{:<38} {:<8} {:<32} {:<12}", "SESSION ID", "PID", "COMMAND", "STARTED");
                println!("{}", "-".repeat(94));
                for s in sessions {
                    println!(
                        "{:<38} {:<8} {:<32} {:<12}",
                        s.session_id,
                        s.pid,
                        truncate_str(&s.command, 30),
                        crate::resolver::format_timestamp(s.started_at)
                    );
                }
            }
            Ok(())
        }
        SessionSubcommands::Stop(sub) => {
            let sessions = secwet.list_active_sessions()?;
            let target_session = if let Ok(pid) = sub.target.parse::<u32>() {
                sessions.into_iter().find(|s| s.pid == pid)
            } else {
                sessions.into_iter().find(|s| s.session_id == sub.target)
            };

            let session = target_session.ok_or(Error::NotFound)?;
            secwet.stop_active_session(&session.session_id)?;

            if sub.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "session_id": session.session_id,
                        "pid": session.pid,
                        "command": session.command,
                        "status": "stopped"
                    })
                );
            } else {
                println!("Stopped session {} (PID: {}, command: '{}')", session.session_id, session.pid, session.command);
            }
            Ok(())
        }
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

