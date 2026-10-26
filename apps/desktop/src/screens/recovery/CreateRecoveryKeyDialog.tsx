import { useState } from "react";
import { Button } from "../../components/Button";
import { Checkbox } from "../../components/Checkbox";
import { Dialog } from "../../components/Dialog";
import styles from "./CreateRecoveryKeyDialog.module.css";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32, no I, L, O, U

/** 25 random characters in groups of five. Display-only until the Secwet engine derives it. */
function generateKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(25));
  const chars = Array.from(bytes, (b) => ALPHABET[b % 32]).join("");
  return chars.match(/.{5}/g)!.join("-");
}

export function CreateRecoveryKeyDialog({ replacing, onCancel, onDone }: { replacing: boolean; onCancel: () => void; onDone: () => void }) {
  const [key] = useState(generateKey);
  const [stored, setStored] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");

  async function copy() {
    try {
      await navigator.clipboard.writeText(key);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  return (
    <Dialog
      title={replacing ? "Replace recovery key" : "Create recovery key"}
      description="Store this somewhere safe, away from this device: a password manager or on paper. Secwet can't show it again."
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="primary" onClick={onDone} disabled={!stored}>
            {replacing ? "Replace key" : "Done"}
          </Button>
        </>
      }
    >
      <div className={styles.keyBox}>
        <span className={styles.key}>{key}</span>
        <Button variant="secondary" icon={copyState === "copied" ? "check" : "copy"} onClick={copy}>
          {copyState === "copied" ? "Copied" : "Copy"}
        </Button>
      </div>
      {copyState === "failed" && <p className={styles.hint}>Copy isn't available here. Select the key and copy it manually.</p>}
      {replacing && <p className={styles.hint}>Your old recovery key stops working as soon as you replace it. Existing exports still need the old key.</p>}
      <Checkbox label="I have stored my recovery key" checked={stored} onChange={(e) => setStored(e.target.checked)} />
    </Dialog>
  );
}
