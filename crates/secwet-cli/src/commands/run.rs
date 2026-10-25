use secrecy::ExposeSecret;
use secwet_core::Vault;
use uuid::Uuid;

pub fn execute_run(
    vault: &Vault,
    item_id: Uuid,
    env_id: Option<Uuid>,
    cmd_args: &[String],
) -> Result<i32, String> {
    let (program, args) = cmd_args
        .split_first()
        .ok_or_else(|| "no command specified to run".to_string())?;

    let env_secrets = vault
        .env_for(item_id, env_id)
        .map_err(|e| format!("{e}"))?;

    let mut cmd = std::process::Command::new(program);
    cmd.args(args);

    // Secrets override existing parent environment variables on conflict
    for (k, v) in env_secrets {
        cmd.env(k, v.expose_secret());
    }

    let status = cmd
        .status()
        .map_err(|e| format!("failed to execute '{program}': {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        let code = match status.code() {
            Some(c) => c,
            None => status.signal().map(|s| 128 + s).unwrap_or(1),
        };
        Ok(code)
    }

    #[cfg(not(unix))]
    {
        let code = status.code().unwrap_or(1);
        Ok(code)
    }
}
