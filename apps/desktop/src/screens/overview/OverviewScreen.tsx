import { useState, type ReactNode } from "react";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Icon, IconTile } from "../../components/Icon";
import type { Device, Plan, Project, Secret } from "../../data/mock";
import { thisDevice } from "../../data/mock";
import type { SecretMeta } from "../../lib/api";
import { formatAgo, plural } from "../../lib/format";
import { PlanDialog } from "../PlanDialog";
import styles from "./OverviewScreen.module.css";

export const CLI_COMMAND = "secwet run --project payments-api --env production -- npm start";

interface Props {
  projects: Project[];
  secrets: (Secret | SecretMeta)[];
  devices: Device[];
  plan: Plan;
  recoveryKeyCreatedAt?: number;
  pendingRotation?: string;
  cliConnected: boolean;
  onCliCopied: () => void;
  onOpenProject: (projectId: string, environmentId?: string) => void;
  onNewProject: () => void;
  onAddSecret: () => void;
  onOpenDevices: () => void;
  onOpenRecovery: () => void;
}

const initialOf = (name: string) => name.replace(/[^A-Za-z0-9]/g, "").charAt(0).toUpperCase() || "#";

interface Step {
  id: string;
  title: string;
  detail: string;
  done: boolean;
  action?: ReactNode;
}

export function OverviewScreen(props: Props) {
  const { projects, secrets, devices, plan, recoveryKeyCreatedAt, pendingRotation, cliConnected } = props;
  const [comparing, setComparing] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);

  const activeDevices = devices.filter((d) => !d.revokedAt);
  const environments = projects.reduce((n, p) => n + p.environments.length, 0);
  const recent = [...secrets]
    .sort((a, b) => (b.updated_at ?? (b as any).updatedAt ?? 0) - (a.updated_at ?? (a as any).updatedAt ?? 0))
    .slice(0, 5);

  async function copyCli() {
    try {
      await navigator.clipboard.writeText(CLI_COMMAND);
      setCopyFailed(false);
      props.onCliCopied();
    } catch {
      setCopyFailed(true);
    }
  }

  const steps: Step[] = [
    ...(pendingRotation
      ? [
          {
            id: "rotate",
            title: "Rotate the vault key",
            detail: `${pendingRotation} was revoked. Rotating stops it reading changes made from now on.`,
            done: false,
            action: (
              <Button variant="primary" onClick={props.onOpenRecovery}>
                Rotate
              </Button>
            ),
          },
        ]
      : []),
    { id: "vault", title: "Vault created on this device", detail: `${thisDevice.name} holds your device key.`, done: true },
    {
      id: "recovery",
      title: "Create a recovery key",
      detail: recoveryKeyCreatedAt ? "Stored by you, away from this device." : "The only way back in if you lose every device.",
      done: recoveryKeyCreatedAt !== undefined,
      action: (
        <Button variant="primary" onClick={props.onOpenRecovery}>
          Create
        </Button>
      ),
    },
    {
      id: "cli",
      title: "Connect the command line",
      detail: copyFailed ? `Copy isn't available here. Run: ${CLI_COMMAND}` : "Run apps with secrets as environment variables.",
      done: cliConnected,
      action: (
        <Button variant="secondary" icon="copy" onClick={copyCli}>
          Copy command
        </Button>
      ),
    },
    {
      id: "device",
      title: "Add another device",
      detail: plan === "pro" ? "Approve a phone or laptop from this device." : "Needs Pro. Your local vault works the same on Free.",
      done: activeDevices.length > 1 && plan === "pro",
      action:
        plan === "pro" ? (
          <Button variant="secondary" onClick={props.onOpenDevices}>
            Pair a device
          </Button>
        ) : (
          <Button variant="tertiary" onClick={() => setComparing(true)}>
            Compare plans
          </Button>
        ),
    },
  ];
  const remaining = steps.filter((s) => !s.done).length;

  return (
    <div className={styles.screen}>
      <div className={styles.header}>
        <div className={styles.titles}>
          <h1 className={styles.title}>Overview</h1>
          <p className={styles.subtitle}>
            Vault unlocked on {thisDevice.name}. {plan === "pro" ? `Pro plan, ${plural(activeDevices.length, "active device")}.` : "Free plan, sync off."}
          </p>
        </div>
        <div className={styles.actions}>
          <Button variant="secondary" onClick={props.onOpenDevices}>
            Pair a device
          </Button>
          {projects.length > 0 && (
            <Button variant="primary" icon="plus" onClick={props.onAddSecret}>
              Add secret
            </Button>
          )}
        </div>
      </div>

      <div className={styles.stats}>
        <Stat label="Projects" value={projects.length} />
        <Stat label="Secrets" value={secrets.length} />
        <Stat label="Environments" value={environments} />
        <Stat label="Devices" value={activeDevices.length} />
      </div>

      <div className={styles.columns}>
        <div className={styles.column}>
          <section className={styles.card} aria-labelledby="ov-projects">
            <div className={styles.cardHead}>
              <h2 id="ov-projects">Projects</h2>
              <Button variant="tertiary" icon="plus" arrow={false} onClick={props.onNewProject}>
                New project
              </Button>
            </div>
            {projects.length === 0 ? (
              <p className={styles.empty}>No projects yet. Create one to start adding secrets.</p>
            ) : (
              <ul className={styles.list}>
                {projects.map((p) => {
                  const own = secrets.filter((s) => {
                    const pId = "projectId" in s && s.projectId ? s.projectId : s.project_id;
                    return pId === p.id;
                  });
                  const last = own.reduce(
                    (m, s) => Math.max(m, s.updated_at ?? (s as any).updatedAt ?? 0),
                    0
                  );
                  return (
                    <li key={p.id}>
                      <button className={styles.row} onClick={() => props.onOpenProject(p.id)}>
                        <IconTile initial={initialOf(p.name)} />
                        <span className={styles.rowMain}>
                          <span className={styles.rowTitle}>{p.name}</span>
                          <span className={styles.envs}>
                            {p.environments.map((e) => (
                              <span key={e.id}>
                                <b>
                                  {
                                    own.filter((s) => {
                                      const eId = "environmentId" in s && s.environmentId ? s.environmentId : s.environment_id;
                                      return eId === e.id;
                                    }).length
                                  }
                                </b>{" "}
                                {e.name}
                              </span>
                            ))}
                          </span>
                        </span>
                        <span className={styles.rowMeta}>{last ? formatAgo(last) : "Empty"}</span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>

          <section className={styles.card} aria-labelledby="ov-recent">
            <div className={styles.cardHead}>
              <h2 id="ov-recent">Recently changed</h2>
            </div>
            {recent.length === 0 ? (
              <p className={styles.empty}>Secrets you add or edit show up here.</p>
            ) : (
              <ul className={styles.list}>
                {recent.map((s) => {
                  const pId = ("projectId" in s && s.projectId ? s.projectId : s.project_id) ?? "";
                  const eId = "environmentId" in s && s.environmentId ? s.environmentId : s.environment_id;
                  const p = projects.find((x) => x.id === pId);
                  const e = p?.environments.find((x) => x.id === eId);
                  const updatedAt = s.updated_at ?? (s as any).updatedAt ?? 0;
                  return (
                    <li key={s.id}>
                      <button className={styles.row} onClick={() => pId && props.onOpenProject(pId, eId)}>
                        <span className={styles.rowMain}>
                          <span className={styles.rowTitle}>{s.name}</span>
                          <span className={styles.rowSub}>
                            {p?.name} · {e?.name}
                          </span>
                        </span>
                        <span className={styles.rowMeta}>{formatAgo(updatedAt)}</span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>
        </div>

        <section className={styles.card} aria-labelledby="ov-setup">
          <div className={styles.cardHead}>
            <h2 id="ov-setup">Setup and safety</h2>
            {remaining === 0 ? <Badge tone="success">All set</Badge> : <Badge tone="warning">{plural(remaining, "step")} left</Badge>}
          </div>
          <ol className={styles.steps}>
            {steps.map((s, i) => (
              <li key={s.id} className={styles.step}>
                <span className={s.done ? `${styles.num} ${styles.numDone}` : styles.num} aria-hidden="true">
                  {s.done ? <Icon name="check" size={14} /> : i + 1}
                </span>
                <span className={styles.stepText}>
                  <span className={styles.rowTitle}>
                    {s.title}
                    <span className="visually-hidden">{s.done ? ", done" : ", to do"}</span>
                  </span>
                  <span className={styles.rowSub}>{s.detail}</span>
                </span>
                {!s.done && s.action && <span className={styles.stepAction}>{s.action}</span>}
              </li>
            ))}
          </ol>
        </section>
      </div>

      {comparing && <PlanDialog plan={plan} onClose={() => setComparing(false)} />}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className={styles.stat}>
      <span className={styles.statLabel}>{label}</span>
      <span className={styles.statValue}>{value}</span>
    </div>
  );
}
