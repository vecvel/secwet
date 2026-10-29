import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";
import type { Plan } from "../data/mock";
import type { PlanState } from "../lib/api";
import { planEndDate } from "../lib/access";
import { usePlanStatus } from "../lib/usePlan";
import styles from "./PlanDialog.module.css";

const plans = [
  {
    id: "free" as const,
    name: "Free",
    summary: "One device, everything local.",
    features: [
      "Unlimited local projects and secrets",
      "Passwords, tokens, API keys, SSH keys, certificates and environment variables",
      "CLI, environment injection and export",
      "No account, password or cloud dependency. Never contacts the relay",
    ],
  },
  {
    id: "pro" as const,
    name: "Pro",
    summary: "Secwet on every device you approve.",
    features: [
      "Pair and revoke multiple devices",
      "Near real-time encrypted sync through the relay",
      "Share spaces with people, each with their own key",
      "Encryption key rotation after removing a device",
    ],
  },
];

/**
 * Compares Free and Pro. `plan` is the plan the UI acts on (the dev-only
 * simulation may override it); the real plan adds the Pro end date and the
 * paused state.
 */
export function PlanDialog({ plan, reason, onClose }: { plan: Plan | PlanState; reason?: string; onClose: () => void }) {
  const status = usePlanStatus();
  const state: PlanState = plan === "paused" || status?.plan === "paused" ? "paused" : plan;
  const end = planEndDate(status?.expires_at);
  const badge = (id: "free" | "pro") => {
    if (id === "pro" && state === "paused") return end ? `Ended ${end}` : "Ended";
    if (id === state) return id === "pro" && end ? `Current plan, until ${end}` : "Current plan";
    return null;
  };

  return (
    <Dialog
      title="Free and Pro"
      description={reason ?? "Pro adds sync between devices. Your local data works the same on both plans."}
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
              {badge(p.id) && <span className={styles.current}>{badge(p.id)}</span>}
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
      <p className={styles.note}>
        If Pro ends, sync pauses and nothing is deleted or locked. Your local data stays usable and exportable. To get Pro,
        use Check for Pro in Settings &gt; Plan once so the relay knows your Secwet ID, have Pro granted to that ID, then
        check again.
      </p>
    </Dialog>
  );
}
