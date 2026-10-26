import { useEffect, useState } from "react";
import { IconButton } from "../../components/Button";
import { MoreMenu, type MenuItem } from "../../components/Menu";
import { kindLabels, type Secret } from "../../data/mock";
import { api, type SecretMeta } from "../../lib/api";
import { formatAgo } from "../../lib/format";
import styles from "./SecretRow.module.css";

const MASK = "••••••••••••";

interface Props {
  secret: SecretMeta | Secret;
  canCopy: boolean;
  onEdit: () => void;
  onCopyToEnvironment: () => void;
  onDelete: () => void;
}

export function SecretRow({ secret, canCopy, onEdit, onCopyToEnvironment, onDelete }: Props) {
  const [revealedValue, setRevealedValue] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const revealed = revealedValue !== null;

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(t);
  }, [copied]);

  // Clean up revealed value on unmount
  useEffect(() => {
    return () => setRevealedValue(null);
  }, []);

  // Listen to vault://locked to immediately clear revealed secret plaintext
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    api.onVaultLocked(() => {
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
      setCopied(true);
    } catch (e) {
      console.error("Failed to copy secret:", e);
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
    { label: "Edit secret", icon: "pencil", onSelect: onEdit },
    ...(canCopy ? [{ label: "Copy to environment", icon: "layers", onSelect: onCopyToEnvironment } satisfies MenuItem] : []),
    { label: "Delete secret", icon: "trash", onSelect: onDelete, danger: true, separator: true },
  ];

  return (
    <li className={styles.row}>
      <div className={styles.identity}>
        <span className={styles.name}>{secret.name?.trim() || "(Untitled secret)"}</span>
        <span className={styles.meta}>
          {kindLabels[secret.kind]}
          {secret.note ? `, ${secret.note}` : ""}
        </span>
      </div>
      <div className={styles.value} aria-label={revealed ? "Secret value" : "Hidden secret value"}>
        {revealed ? <span className={styles.plain}>{revealedValue}</span> : `${MASK}${tail}`}
      </div>
      <span className={styles.updated}>{formatAgo(updatedAt)}</span>
      <div className={styles.actions}>
        <IconButton
          icon={revealed ? "eyeOff" : "eye"}
          label={revealed ? `Hide ${secret.name}` : `Reveal ${secret.name}`}
          onClick={handleToggleReveal}
        />
        <IconButton
          icon={copied ? "check" : "copy"}
          label={copied ? "Copied" : `Copy ${secret.name}`}
          onClick={handleCopy}
          className={copied ? styles.copied : undefined}
        />
        <MoreMenu label={`More actions for ${secret.name}`} items={menu} />
      </div>
      <span className="visually-hidden" aria-live="polite">
        {copied ? `${secret.name} copied` : ""}
      </span>
    </li>
  );
}
