import { useEffect, useState } from "react";
import { Badge } from "../../components/Badge";
import { IconButton } from "../../components/Button";
import { MoreMenu, type MenuItem } from "../../components/Menu";
import { kindLabels, type Secret } from "../../data/mock";
import { api, type SecretMeta } from "../../lib/api";
import { formatAgo } from "../../lib/format";
import { useStore } from "../../lib/store";
import { SecretUsageDialog } from "./SecretUsageDialog";
import styles from "./SecretRow.module.css";

const MASK = "••••••••••••";

interface Props {
  secret: SecretMeta | Secret;
  itemName?: string;
  environmentName?: string;
  canCopy: boolean;
  onEdit: () => void;
  onCopyToEnvironment: () => void;
  onDelete: () => void;
  /** Member mode and read-only archive: hide edit and delete when the role doesn't allow them. */
  canEdit?: boolean;
  canDelete?: boolean;
}

export function SecretRow({
  secret,
  itemName,
  environmentName,
  canCopy,
  onEdit,
  onCopyToEnvironment,
  onDelete,
  canEdit = true,
  canDelete = true,
}: Props) {
  const [appState, store] = useStore();
  const [revealedValue, setRevealedValue] = useState<string | null>(null);
  const [copiedValue, setCopiedValue] = useState(false);
  const [copiedName, setCopiedName] = useState(false);
  const [showUsage, setShowUsage] = useState(false);
  const revealed = revealedValue !== null;

  const activeSession = appState.activeSessions.find((sess) =>
    sess.secret_ids.includes(secret.id)
  );

  useEffect(() => {
    if (!copiedValue) return;
    const t = setTimeout(() => setCopiedValue(false), 2000);
    return () => clearTimeout(t);
  }, [copiedValue]);

  useEffect(() => {
    if (!copiedName) return;
    const t = setTimeout(() => setCopiedName(false), 2000);
    return () => clearTimeout(t);
  }, [copiedName]);

  // Clean up revealed value on unmount
  useEffect(() => {
    return () => setRevealedValue(null);
  }, []);

  // Listen to secwet://locked to immediately clear revealed secret plaintext
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    api.onSecwetLocked(() => {
      setRevealedValue(null);
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  async function handleToggleReveal() {
    if (revealed) {
      setRevealedValue(null);
    } else {
      try {
        const val = await api.secretReveal(secret.id);
        setRevealedValue(val);
      } catch (e) {
        console.error("Failed to reveal secret:", e);
      }
    }
  }

  async function handleCopy() {
    try {
      // Direct Rust clipboard copy with 30s auto-clear.
      // The webview NEVER touches or receives the secret plaintext!
      await api.secretCopy(secret.id);
      setCopiedValue(true);
    } catch (e) {
      console.error("Failed to copy secret:", e);
    }
  }

  async function handleCopyName() {
    try {
      await api.clipboardCopyText(secret.name);
      setCopiedName(true);
    } catch (e) {
      console.error("Failed to copy secret name:", e);
    }
  }

  const tail =
    ("value_tail" in secret && secret.value_tail)
      ? secret.value_tail
      : ("value" in secret && typeof (secret as any).value === "string")
        ? (secret as any).value.replace(/\s+/g, "").slice(-4)
        : "";

  const updatedAt = secret.updated_at ?? (secret as any).updatedAt ?? Date.now();

  const menu: MenuItem[] = [
    ...(activeSession
      ? [
          {
            label: `Stop process (${activeSession.command})`,
            icon: "stop" as const,
            danger: true,
            onSelect: () => store.stopActiveSession(activeSession.session_id),
          },
        ]
      : []),
    { label: "Usage info & command", icon: "terminal", onSelect: () => setShowUsage(true) },
  ];
  if (canEdit) {
    menu.push({ label: "Edit secret", icon: "pencil", onSelect: onEdit });
  }
  if (canCopy && canEdit) {
    menu.push({ label: "Copy to environment", icon: "layers", onSelect: onCopyToEnvironment });
  }
  if (canDelete) {
    menu.push({ label: "Delete secret", icon: "trash", onSelect: onDelete, danger: true, separator: true });
  }

  return (
    <>
      <li className={styles.row}>
        <div className={styles.identity}>
          <div className={styles.nameRow}>
            <span className={styles.name}>{secret.name?.trim() || "(Untitled secret)"}</span>
            {activeSession && (
              <span className={styles.inUseWrapper}>
                <Badge tone="success">In use</Badge>
                <IconButton
                  icon="stop"
                  label={`Stop process: ${activeSession.command}`}
                  onClick={() => store.stopActiveSession(activeSession.session_id)}
                  className={styles.stopInlineBtn}
                />
              </span>
            )}
            <IconButton
              icon={copiedName ? "check" : "copy"}
              label={copiedName ? "Name copied" : `Copy ${secret.name}`}
              onClick={handleCopyName}
              className={[styles.inlineCopyBtn, copiedName && styles.copied].filter(Boolean).join(" ")}
            />
          </div>
          <span className={styles.meta}>
            {kindLabels[secret.kind]}
            {secret.note ? `, ${secret.note}` : ""}
          </span>
        </div>
        <div className={styles.valueRow}>
          <div className={styles.value} aria-label={revealed ? "Secret value" : "Hidden secret value"}>
            {revealed ? <span className={styles.plain}>{revealedValue}</span> : `${MASK}${tail}`}
          </div>
          <IconButton
            icon={copiedValue ? "check" : "copy"}
            label={copiedValue ? "Value copied" : `Copy ${secret.name} value`}
            onClick={handleCopy}
            className={[styles.inlineCopyBtn, copiedValue && styles.copied].filter(Boolean).join(" ")}
          />
        </div>
        <span className={styles.updated}>{formatAgo(updatedAt)}</span>
        <div className={styles.actions}>
          <IconButton
            icon={revealed ? "eyeOff" : "eye"}
            label={revealed ? `Hide ${secret.name}` : `Reveal ${secret.name}`}
            onClick={handleToggleReveal}
          />
          <MoreMenu label={`Actions for ${secret.name}`} items={menu} />
        </div>
        <span className="visually-hidden" aria-live="polite">
          {copiedValue ? `${secret.name} value copied` : copiedName ? `${secret.name} name copied` : ""}
        </span>
      </li>

      {showUsage && (
        <SecretUsageDialog
          secret={secret}
          activeSession={activeSession}
          itemName={itemName}
          environmentName={environmentName}
          onClose={() => setShowUsage(false)}
        />
      )}
    </>
  );
}
