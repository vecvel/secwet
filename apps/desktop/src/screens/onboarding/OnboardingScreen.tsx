import { useEffect, useRef, useState } from "react";
import { Button } from "../../components/Button";
import { TextField } from "../../components/Field";
import { BrandMark } from "../../components/Icon";
import { Notice } from "../../components/Notice";
import { isValidEmail } from "../../lib/access";
import { formatUiError } from "../../lib/api";
import { onWindowDragMouseDown } from "../../lib/windowDrag";
import styles from "./OnboardingScreen.module.css";

interface OnboardingScreenProps {
  onCreateWorkspace: (deviceName?: string) => Promise<void> | void;
  onRestoreBackup: () => void;
  defaultDeviceName?: string;
  /** Joins someone else's workspace with an invite link. */
  onJoinWithInvite?: (link: string, email: string, deviceName: string) => Promise<void> | void;
  /** True after joining, while this device waits for the admin to grant access. */
  waitingForAccess?: boolean;
  /** One poll for access; resolves true once shared data arrived. */
  onPollAccess?: () => Promise<boolean>;
  /** Stops waiting and opens the app; shared data keeps arriving through sync. */
  onStopWaiting?: () => void;
  /** Shown after a remote wipe erased this device. */
  wiped?: boolean;
}

const POLL_MS = 3000;

export function OnboardingScreen({
  onCreateWorkspace,
  onRestoreBackup,
  defaultDeviceName = "Desktop",
  onJoinWithInvite,
  waitingForAccess = false,
  onPollAccess,
  onStopWaiting,
  wiped = false,
}: OnboardingScreenProps) {
  const [deviceName, setDeviceName] = useState(defaultDeviceName);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"create" | "join">("create");
  const [inviteLink, setInviteLink] = useState("");
  const [email, setEmail] = useState("");
  const [joinErrors, setJoinErrors] = useState<{ link?: string; email?: string }>({});
  const [joiningNow, setJoiningNow] = useState(false);
  const polling = useRef(false);

  // Poll for access every few seconds while waiting; stops on unmount or when access arrives.
  useEffect(() => {
    if (!waitingForAccess || !onPollAccess) return;
    let stopped = false;
    const tick = async () => {
      if (polling.current || stopped) return;
      polling.current = true;
      try {
        const arrived = await onPollAccess();
        if (arrived) stopped = true;
      } catch {
        // keep waiting; the next poll retries
      } finally {
        polling.current = false;
      }
    };
    tick();
    const timer = setInterval(tick, POLL_MS);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [waitingForAccess, onPollAccess]);

  async function handleJoin() {
    const errs: { link?: string; email?: string } = {};
    const link = inviteLink.trim();
    if (!link) errs.link = "Paste the invite link you were sent.";
    else if (!link.toLowerCase().startsWith("secwet://invite")) errs.link = "Invite links start with secwet://invite.";
    if (!isValidEmail(email)) errs.email = "Enter the email the invite was sent to.";
    setJoinErrors(errs);
    if (errs.link || errs.email || !onJoinWithInvite) return;
    try {
      setJoiningNow(true);
      setError(null);
      await onJoinWithInvite(link, email.trim(), deviceName.trim() || defaultDeviceName);
    } catch (err: unknown) {
      setError(formatUiError(err, "Couldn't join with this invite."));
    } finally {
      setJoiningNow(false);
    }
  }

  async function handleCreate() {
    try {
      setCreating(true);
      setError(null);
      await onCreateWorkspace(deviceName.trim() || undefined);
    } catch (err: unknown) {
      setError(formatUiError(err, "Couldn't create the workspace. Try again."));
    } finally {
      setCreating(false);
    }
  }

  return (
    <div
      className={styles.screen}
      onMouseDown={onWindowDragMouseDown}
      data-tauri-drag-region
    >
      <header
        className={styles.header}
        onMouseDown={onWindowDragMouseDown}
        data-tauri-drag-region
      >
        <span className={styles.brand} aria-hidden="true">
          <BrandMark size={20} />
        </span>
      </header>

      <div className={styles.content}>
        {waitingForAccess ? (
          <>
            <div className={styles.hero}>
              <span className={styles.logoMark} aria-hidden="true">
                <BrandMark size={48} />
              </span>
              <h1 className={styles.title} role="status">
                Waiting for access from the admin…
              </h1>
              <p className={styles.subtitle}>
                This device joined the workspace. What they shared with you appears once their device syncs. Keep Secwet open.
              </p>
            </div>
            <div className={styles.waitActions}>
              <Button variant="secondary" onClick={onStopWaiting}>
                Stop waiting
              </Button>
            </div>
          </>
        ) : (
          <>
            <div className={styles.hero}>
              <span className={styles.logoMark} aria-hidden="true">
                <BrandMark size={48} />
              </span>
              <h1 className={styles.title}>{mode === "join" ? "Join with an invite" : "Welcome to Secwet"}</h1>
              <p className={styles.subtitle}>
                {mode === "join"
                  ? "Paste the link you were sent. This device gets its own key, and you only see what was shared with you."
                  : "Your personal, end-to-end encrypted secret manager. Data stays encrypted on your devices with keys only you control."}
              </p>
            </div>

            {wiped && (
              <div className={styles.errorNotice}>
                <Notice tone="warning" label="Erased">
                  This device was removed and its data erased. Set it up again or join with an invite.
                </Notice>
              </div>
            )}

            {error && (
              <div className={styles.errorNotice}>
                <Notice tone="warning" label={mode === "join" ? "Join error" : "Setup error"}>
                  {error}
                </Notice>
              </div>
            )}

            {mode === "join" ? (
              <div className={styles.card}>
                <TextField
                  label="Invite link"
                  placeholder="secwet://invite?…"
                  autoComplete="off"
                  spellCheck={false}
                  value={inviteLink}
                  error={joinErrors.link}
                  disabled={joiningNow}
                  onChange={(e) => {
                    setInviteLink(e.target.value);
                    if (joinErrors.link) setJoinErrors((p) => ({ ...p, link: undefined }));
                  }}
                />
                <TextField
                  label="Your email"
                  type="email"
                  help="The email address the invite was sent to"
                  placeholder="name@example.com"
                  autoComplete="email"
                  value={email}
                  error={joinErrors.email}
                  disabled={joiningNow}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    if (joinErrors.email) setJoinErrors((p) => ({ ...p, email: undefined }));
                  }}
                />
                <TextField
                  label="Device name"
                  placeholder="e.g. MacBook Pro"
                  value={deviceName}
                  disabled={joiningNow}
                  onChange={(e) => setDeviceName(e.target.value)}
                />
                <div className={styles.actions}>
                  <Button variant="primary" disabled={joiningNow} onClick={handleJoin}>
                    {joiningNow ? "Joining…" : "Join"}
                  </Button>
                  <Button
                    variant="secondary"
                    disabled={joiningNow}
                    onClick={() => {
                      setMode("create");
                      setError(null);
                    }}
                  >
                    Back
                  </Button>
                </div>
              </div>
            ) : (
              <div className={styles.card}>
                <TextField
                  label="Device name"
                  help="Identify this device in your encrypted workspace"
                  placeholder="e.g. MacBook Pro"
                  value={deviceName}
                  disabled={creating}
                  onChange={(e) => setDeviceName(e.target.value)}
                />

                <div className={styles.actions}>
                  <Button variant="primary" disabled={creating} onClick={handleCreate}>
                    {creating ? "Creating workspace…" : "Create workspace"}
                  </Button>
                  <Button variant="secondary" disabled={creating} onClick={onRestoreBackup}>
                    Restore from backup
                  </Button>
                  {onJoinWithInvite && (
                    <Button
                      variant="secondary"
                      disabled={creating}
                      onClick={() => {
                        setMode("join");
                        setError(null);
                      }}
                    >
                      Join with an invite
                    </Button>
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
