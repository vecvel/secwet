import { useState, useEffect, type ReactNode } from "react";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import type { Device, Plan, Project, Secret } from "../../data/mock";
import { thisDevice } from "../../data/mock";
import type { SecretMeta } from "../../lib/api";
import { formatAgo, plural } from "../../lib/format";
import { useStore } from "../../lib/store";
import { PlanDialog } from "../PlanDialog";
import styles from "./OverviewScreen.module.css";

export const CLI_COMMAND = "secwet run --project payments-api --env production -- npm start";

interface Props {
  plan: Plan;
  cliConnected: boolean;
  onCliCopied: () => void;
  onOpenDevices: () => void;
  onOpenRecovery: () => void;
  onOpenItem?: (itemId: string, environmentId?: string) => void;
  onOpenGroup?: (groupId: string) => void;
  onOpenLabel?: (labelId: string) => void;
  onNewItem?: () => void;
  onAddSecret?: () => void;
  onOpenSettings?: () => void;
  // Backward compatibility props
  projects?: Project[];
  secrets?: (Secret | SecretMeta)[];
  devices?: Device[];
  recoveryKeyCreatedAt?: number;
  pendingRotation?: string;
  onOpenProject?: (projectId: string, environmentId?: string) => void;
  onNewProject?: () => void;
}

interface Step {
  id: string;
  title: string;
  detail: string;
  done: boolean;
  action?: ReactNode;
}

export function OverviewScreen(props: Props) {
  const [appState] = useStore();
  const { dashboardConfig, settings, items, overview } = appState;

  const [comparing, setComparing] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  const [cliCopiedLocally, setCliCopiedLocally] = useState(false);

  const plan = props.plan;
  const devices = props.devices || [];
  const activeDevices = devices.filter((d) => !d.revokedAt);
  const recoveryKeyCreatedAt = props.recoveryKeyCreatedAt;
  const pendingRotation = props.pendingRotation;

  // Track clipboard state: check on focus, visibility change, and document copy events
  useEffect(() => {
    async function verifyClipboard() {
      try {
        if (navigator.clipboard && navigator.clipboard.readText) {
          const text = await navigator.clipboard.readText();
          setCliCopiedLocally(text.trim() === CLI_COMMAND.trim());
        }
      } catch {
        // Permissions may deny clipboard reading without direct user interaction
      }
    }

    function handleCopyEvent() {
      // If the user copied something else in the page, revert copy state
      setTimeout(verifyClipboard, 50);
    }

    window.addEventListener("focus", verifyClipboard);
    document.addEventListener("visibilitychange", verifyClipboard);
    document.addEventListener("copy", handleCopyEvent);
    const interval = setInterval(verifyClipboard, 2500);
    return () => {
      window.removeEventListener("focus", verifyClipboard);
      document.removeEventListener("visibilitychange", verifyClipboard);
      document.removeEventListener("copy", handleCopyEvent);
      clearInterval(interval);
    };
  }, []);

  const visibleKpis = dashboardConfig.visible_kpis || ["secrets", "assets", "notes", "devices"];
  const widgets = dashboardConfig.widgets || ["recent_secrets", "recent_notes", "quick_actions", "checklist"];

  async function copyCli() {
    try {
      await navigator.clipboard.writeText(CLI_COMMAND);
      setCopyFailed(false);
      setCliCopiedLocally(true);
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
            title: "Rotate encryption key",
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
    {
      id: "device_init",
      title: "Initialized on this device",
      detail: `${settings.device_name || thisDevice.name} holds your device key.`,
      done: true,
    },
    {
      id: "recovery",
      title: "Create a recovery key",
      detail: recoveryKeyCreatedAt
        ? "Stored by you, away from this device."
        : "The only way back in if you lose every device.",
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
      detail: copyFailed
        ? `Copy isn't available here. Run: ${CLI_COMMAND}`
        : "Run apps with secrets as environment variables.",
      done: cliCopiedLocally,
      action: !cliCopiedLocally ? (
        <Button variant="secondary" icon="copy" onClick={copyCli}>
          Copy command
        </Button>
      ) : undefined,
    },
    {
      id: "device",
      title: "Add another device",
      detail:
        plan === "pro"
          ? "Approve a phone or laptop from this device."
          : "Needs Pro. Works the same on local device.",
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

  // Counts for KPIs
  const secretsCount = overview?.secrets_count ?? (props.secrets?.length ?? appState.secrets.length);
  const assetsCount = overview?.assets_count ?? overview?.files_count ?? (appState.assets?.length ?? appState.files?.length ?? 0);
  const notesCount = overview?.notes_count ?? appState.notes.length;
  const devicesCount = overview?.active_devices_count ?? (activeDevices.length || 1);

  // Recent secrets from overview or props
  const recentSecrets = overview?.recent?.length
    ? overview.recent
    : (props.secrets || appState.secrets)
        .slice(0, 5)
        .map((s: any) => ({
          id: s.id,
          name: s.name,
          project_id: s.project_id || s.projectId || s.item_id || "",
          project_name: s.project_name || items.find((i) => i.id === (s.project_id || s.item_id))?.name || "Entry",
          environment_id: s.environment_id || s.environmentId || "",
          environment_name: s.environment_name || "General",
          updated_at: s.updated_at || s.updatedAt || Date.now(),
          item_id: s.item_id || s.project_id || s.projectId,
          item_name: s.item_name || s.project_name,
        }));

  function navigateToItem(itemId?: string, envId?: string) {
    if (!itemId) return;
    if (props.onOpenItem) {
      props.onOpenItem(itemId, envId);
    } else if (props.onOpenProject) {
      props.onOpenProject(itemId, envId);
    }
  }

  return (
    <div className={styles.screen}>
      {visibleKpis.length > 0 && (
        <div className={styles.stats}>
          {visibleKpis.includes("secrets") && <Stat label="Secrets" value={secretsCount} />}
          {(visibleKpis.includes("assets") || visibleKpis.includes("files")) && <Stat label="Assets" value={assetsCount} />}
          {visibleKpis.includes("notes") && <Stat label="Notes" value={notesCount} />}
          {visibleKpis.includes("devices") && <Stat label="Devices" value={devicesCount} />}
        </div>
      )}

      <div className={styles.columns}>
        <div className={styles.column}>
          {widgets.includes("recent_secrets") && (
            <section className={styles.card} aria-labelledby="ov-recent">
              <div className={styles.cardHead}>
                <h2 id="ov-recent">Recently changed secrets</h2>
              </div>
              {recentSecrets.length === 0 ? (
                <p className={styles.empty}>Secrets you add or edit show up here.</p>
              ) : (
                <ul className={styles.list}>
                  {recentSecrets.map((s) => {
                    const targetItemId = s.item_id || s.project_id;
                    const subtitle = [s.item_name || s.project_name, s.environment_name]
                      .filter(Boolean)
                      .join(" · ");
                    return (
                      <li key={s.id}>
                        <button
                          className={styles.row}
                          onClick={() => navigateToItem(targetItemId, s.environment_id)}
                        >
                          <span className={styles.rowMain}>
                            <span className={styles.rowTitle}>{s.name}</span>
                            {subtitle && <span className={styles.rowSub}>{subtitle}</span>}
                          </span>
                          <span className={styles.rowMeta}>{formatAgo(s.updated_at)}</span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>
          )}

          {widgets.includes("quick_actions") && (
            <section className={styles.card} aria-labelledby="ov-quick">
              <div className={styles.cardHead}>
                <h2 id="ov-quick">Quick actions</h2>
              </div>
              <div className={styles.quickActionsGrid}>
                <Button
                  variant="secondary"
                  icon="plus"
                  onClick={props.onNewItem || props.onNewProject}
                >
                  New entry
                </Button>
                <Button
                  variant="secondary"
                  icon="key"
                  onClick={props.onAddSecret || props.onNewItem}
                >
                  Add secret
                </Button>
                <Button variant="secondary" icon="devices" onClick={props.onOpenDevices}>
                  Pair device
                </Button>
                <Button variant="secondary" icon="recovery" onClick={props.onOpenRecovery}>
                  Backup key
                </Button>
              </div>
            </section>
          )}

          {widgets.includes("recent_notes") && (
            <section className={styles.card} aria-labelledby="ov-notes">
              <div className={styles.cardHead}>
                <h2 id="ov-notes">Recent notes</h2>
              </div>
              {appState.notes.length === 0 ? (
                <p className={styles.empty}>Notes you create appear here.</p>
              ) : (
                <ul className={styles.list}>
                  {appState.notes.slice(0, 5).map((n) => {
                    const item = items.find((i) => i.id === n.item_id);
                    return (
                      <li key={n.id}>
                        <button
                          className={styles.row}
                          onClick={() => navigateToItem(n.item_id, n.environment_id ?? undefined)}
                        >
                          <span className={styles.rowMain}>
                            <span className={styles.rowTitle}>{n.title}</span>
                            <span className={styles.rowSub}>
                              {item?.name} {n.snippet ? `— ${n.snippet}` : ""}
                            </span>
                          </span>
                          <span className={styles.rowMeta}>{formatAgo(n.updated_at)}</span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>
          )}
        </div>

        {widgets.includes("checklist") && (
          <section className={styles.card} aria-labelledby="ov-setup">
            <div className={styles.cardHead}>
              <h2 id="ov-setup">Setup and safety</h2>
              {remaining === 0 ? (
                <span className={styles.statusSimple}>
                  <span className={styles.dotSuccess} /> All set
                </span>
              ) : (
                <span className={styles.statusSimple}>
                  <span className={styles.dotWarning} /> {plural(remaining, "step")} left
                </span>
              )}
            </div>
            <ol className={styles.steps}>
              {steps.map((s, i) => (
                <li key={s.id} className={styles.step}>
                  <span
                    className={s.done ? `${styles.num} ${styles.numDone}` : styles.num}
                    aria-hidden="true"
                  >
                    {s.done ? <Icon name="check" size={14} /> : i + 1}
                  </span>
                  <span className={styles.stepText}>
                    <span className={styles.rowTitle}>
                      {s.title}
                      <span className="visually-hidden">
                        {s.done ? ", done" : ", to do"}
                      </span>
                    </span>
                    <span className={styles.rowSub}>{s.detail}</span>
                  </span>
                  {!s.done && s.action && (
                    <span className={styles.stepAction}>{s.action}</span>
                  )}
                </li>
              ))}
            </ol>
          </section>
        )}
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
