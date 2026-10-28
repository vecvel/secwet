import { useEffect, useState } from "react";
import { Badge } from "../../components/Badge";
import { Button, IconButton } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { kindLabels, type Secret } from "../../data/mock";
import { api, type ActiveSession, type SecretMeta } from "../../lib/api";
import { store } from "../../lib/store";
import styles from "./SecretUsageDialog.module.css";

interface Props {
  secret: SecretMeta | Secret;
  activeSession?: ActiveSession | null;
  itemName?: string;
  environmentName?: string;
  onClose: () => void;
}

interface SnippetProps {
  label: string;
  code: string;
  badge: string;
}

function CodeSnippetRow({ label, code, badge }: SnippetProps) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 2000);
    return () => clearTimeout(t);
  }, [copied]);

  const handleCopy = () => {
    api.clipboardCopyText(code).then(() => setCopied(true)).catch(() => {});
  };

  return (
    <div className={styles.snippetContainer}>
      <div className={styles.snippetHeader}>
        <span className={styles.snippetLabel}>{label}</span>
        <Badge tone="neutral">{badge}</Badge>
      </div>
      <div className={styles.snippetCodeBox}>
        <span className={styles.snippetCode}>{code}</span>
        <IconButton
          icon={copied ? "check" : "copy"}
          label={copied ? "Copied" : `Copy ${label}`}
          onClick={handleCopy}
          className={copied ? styles.copied : styles.copyBtn}
        />
      </div>
    </div>
  );
}

export function SecretUsageDialog({ secret, activeSession, itemName, environmentName, onClose }: Props) {
  const [stopping, setStopping] = useState(false);
  const cliItemFlag = itemName ? ` -i "${itemName}"` : "";
  const cliEnvFlag = environmentName ? ` -e "${environmentName}"` : "";
  const cliGetCmd = `secwet get ${secret.name}${cliItemFlag}${cliEnvFlag}`;
  const cliRunCmd = `secwet run${cliItemFlag}${cliEnvFlag} -- <your-command>`;

  const nodeSnippet = `process.env.${secret.name}`;
  const pythonSnippet = `import os\n${secret.name.toLowerCase()} = os.environ.get("${secret.name}")`;
  const goSnippet = `os.Getenv("${secret.name}")`;
  const rustSnippet = `std::env::var("${secret.name}")`;
  const bashSnippet = `"${secret.name}"`;

  const handleStopProcess = async () => {
    if (!activeSession) return;
    setStopping(true);
    try {
      await store.stopActiveSession(activeSession.session_id);
    } catch (e) {
      console.error("Failed to stop process:", e);
    } finally {
      setStopping(false);
    }
  };

  return (
    <Dialog
      title={`Usage: ${secret.name}`}
      description="Commands and language code snippets for reading and injecting this secret."
      onClose={onClose}
      footer={
        <Button variant="secondary" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className={styles.usageModalBody}>
        <div className={styles.badgesRow}>
          <Badge tone="neutral">{kindLabels[secret.kind]}</Badge>
          <Badge tone="accent">{environmentName || "General"}</Badge>
          {itemName && <Badge tone="neutral">{itemName}</Badge>}
          {activeSession && <Badge tone="success">In use</Badge>}
        </div>

        {activeSession && (
          <div className={styles.activeSessionBanner}>
            <div className={styles.activeSessionDetails}>
              <div className={styles.activeSessionTitle}>
                <span className={styles.inUseDot} />
                <span>Running Process Session</span>
              </div>
              <div className={styles.activeSessionMeta}>
                Command: <span className={styles.cmdText}>{activeSession.command}</span> • PID: {activeSession.pid}
              </div>
            </div>
            <Button
              variant="danger"
              icon="stop"
              disabled={stopping}
              onClick={handleStopProcess}
            >
              {stopping ? "Stopping..." : "Stop process"}
            </Button>
          </div>
        )}

        <section className={styles.usageSection}>
          <h3 className={styles.usageSectionTitle}>Terminal & CLI</h3>
          <CodeSnippetRow label="Print secret value to stdout" code={cliGetCmd} badge="CLI" />
          <CodeSnippetRow label="Run application with injected secrets" code={cliRunCmd} badge="CLI" />
        </section>

        <section className={styles.usageSection}>
          <h3 className={styles.usageSectionTitle}>Application Code</h3>
          <CodeSnippetRow label="Node.js / TypeScript" code={nodeSnippet} badge="Node.js" />
          <CodeSnippetRow label="Python" code={pythonSnippet} badge="Python" />
          <CodeSnippetRow label="Go" code={goSnippet} badge="Go" />
          <CodeSnippetRow label="Rust" code={rustSnippet} badge="Rust" />
          <CodeSnippetRow label="Shell / Bash" code={bashSnippet} badge="Bash" />
        </section>
      </div>
    </Dialog>
  );
}
