import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";
import type { Plan } from "../data/mock";
import styles from "./PlanDialog.module.css";

const plans = [
  {
    id: "free" as const,
    name: "Free",
    summary: "One device, everything local.",
    features: [
      "Unlimited local projects and secrets",
      "Passwords, tokens, API keys, SSH keys, certificates and environment variables",
      "CLI and environment injection",
      "No account, password or cloud dependency",
    ],
  },
  {
    id: "pro" as const,
    name: "Pro",
    summary: "Your vault on every device you approve.",
    features: [
      "Pair and revoke multiple devices",
      "Near real-time encrypted sync through the relay",
      "Offline devices catch up when they reconnect",
      "Vault key rotation after removing a device",
    ],
  },
];

export function PlanDialog({ plan, reason, onClose }: { plan: Plan; reason?: string; onClose: () => void }) {
  return (
    <Dialog
      title="Free and Pro"
      description={reason ?? "Pro adds sync between devices. Your local vault works the same on both plans."}
      onClose={onClose}
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      <div className={styles.plans}>
        {plans.map((p) => (
          <div key={p.id} className={styles.plan}>
            <div className={styles.head}>
              <span className={styles.name}>{p.name}</span>
              {p.id === plan && <span className={styles.current}>Current plan</span>}
            </div>
            <p className={styles.summary}>{p.summary}</p>
            <ul className={styles.features}>
              {p.features.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <p className={styles.note}>If Pro ends, nothing is deleted or locked. Your local vault stays usable and exportable. Subscriptions are not available in this build yet.</p>
    </Dialog>
  );
}
