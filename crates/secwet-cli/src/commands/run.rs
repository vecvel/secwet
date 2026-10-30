use secrecy::ExposeSecret;
use secwet_core::Secwet;
use uuid::Uuid;

pub fn execute_run(
    secwet: &Secwet,
    item_id: Uuid,
    env_id: Option<Uuid>,
    cmd_args: &[String],
) -> Result<i32, String> {
    let (program, args) = cmd_args
        .split_first()
        .ok_or_else(|| "no command specified to run".to_string())?;

    let (env_secrets, secret_ids) = secwet
        .env_for_with_ids(item_id, env_id)
        .map_err(|e| format!("{e}"))?;

    let mut cmd = std::process::Command::new(program);
    cmd.args(args);

    // Secrets override existing parent environment variables on conflict
    for (k, v) in env_secrets {
        cmd.env(k, v.expose_secret());
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to execute '{program}': {e}"))?;

    let pid = child.id();
    let cmd_str = cmd_args.join(" ");

    // Register active session in local store
    let session = secwet
        .create_active_session(pid, item_id, env_id, &cmd_str, &secret_ids)
        .ok();

    struct SessionGuard<'a> {
        secwet: &'a Secwet,
        session_id: Option<String>,
    }
    impl<'a> Drop for SessionGuard<'a> {
        fn drop(&mut self) {
            if let Some(ref sid) = self.session_id {
                let _ = self.secwet.delete_active_session(sid);
            }
        }
    }
    let guard = SessionGuard {
        secwet,
        session_id: session.map(|s| s.session_id),
    };

    let status = child
        .wait()
        .map_err(|e| format!("failed to wait for '{program}': {e}"))?;

    drop(guard);

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
