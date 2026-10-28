import { useState, useEffect, type ReactNode } from "react";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import type { Device, Plan, Project, Secret } from "../../data/mock";
import { thisDevice } from "../../data/mock";
import { api, type ItemView, type SecretMeta } from "../../lib/api";
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
  onOpenCli?: () => void;
  onOpenItem?: (itemId: string, environmentId?: string) => void;
  onOpenGroup?: (groupId: string) => void;
  onOpenLabel?: (labelId: string) => void;
  onNewItem?: () => void;
  onAddSecret?: () => void;
  /** Member mode and read-only archive: show "New entry" only when creating is allowed. Default true. */
  canCreate?: boolean;
  /** Show "Add secret" only when this device may write somewhere. Default true. */
  canAddSecret?: boolean;
  /** Show pairing actions only when the device is not a read-only archive. Default true. */
  canPair?: boolean;
  onOpenSettings?: () => void;
  items?: ItemView[];
  isSpaceFiltered?: boolean;
  // Backward compatibility props
  projects?: Project[];
  secrets?: (Secret | SecretMeta)[];
  devices?: Device[];
  recoveryKeyCreatedAt?: number;
  /** Reason sentence from key_status when rotation is recommended, for example "iPhone 16 was revoked." */
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
  const canCreate = props.canCreate ?? true;
  const canAddSecret = props.canAddSecret ?? true;
  const canPair = props.canPair ?? true;
  const [appState] = useStore();
  const { dashboardConfig, settings, items, overview } = appState;

  const [comparing, setComparing] = useState(false);
  const [cliReadLocally, setCliReadLocally] = useState(() => {
    return typeof window !== "undefined" && window.localStorage.getItem("secwet:cli_guide_read") === "true";
  });

  useEffect(() => {
    api.cliStatus().then((status) => {
      if (status.installed) {
        setCliReadLocally(true);
        props.onCliCopied();
      }
    }).catch(() => {});
  }, []);

  const isCliDone = props.cliConnected || cliReadLocally;

  function markCliAsRead() {
    if (typeof window !== "undefined") {
      window.localStorage.setItem("secwet:cli_guide_read", "true");
    }
    setCliReadLocally(true);
    props.onCliCopied();
  }

  function handleOpenCli() {
    markCliAsRead();
    if (props.onOpenCli) {
      props.onOpenCli();
    }
  }

  const plan = props.plan;
  const devices = props.devices || [];
  const activeDevices = devices.filter((d) => !d.revokedAt);
  const recoveryKeyCreatedAt = props.recoveryKeyCreatedAt;
  const pendingRotation = props.pendingRotation;

  const visibleKpis = dashboardConfig.visible_kpis || ["secrets", "assets", "notes", "devices"];
  const widgets = dashboardConfig.widgets || ["recent_secrets", "recent_notes", "quick_actions", "checklist"];

  const steps: Step[] = [
    ...(pendingRotation
      ? [
          {
            id: "rotate",
            title: "Rotate encryption key",
            detail: `${pendingRotation} Rotating stops revoked devices reading changes made from now on.`,
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
      detail: "Run apps with secrets as environment variables.",
      done: isCliDone,
      action: (
        <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
          {props.onOpenCli && (
            <Button variant="secondary" onClick={handleOpenCli}>
              CLI Guide
            </Button>
          )}
          <Button variant="tertiary" onClick={markCliAsRead}>
            Mark as read
          </Button>
        </div>
      ),
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
          canPair ? (
            <Button variant="secondary" onClick={props.onOpenDevices}>
              Pair a device
            </Button>
          ) : undefined
        ) : (
          <Button variant="tertiary" onClick={() => setComparing(true)}>
            Compare plans
          </Button>
        ),
    },
  ].filter((step) => step.id !== "device" || canPair);
  const remaining = steps.filter((s) => !s.done).length;

  // Scoped visible items
  const visibleItems = props.items || items;
  const visibleItemIds = new Set(visibleItems.map((i) => i.id));
  const isFiltered = props.isSpaceFiltered ?? Boolean(props.items && props.items.length !== items.length);

  // Counts for KPIs
  const secretsCount = isFiltered
    ? visibleItems.reduce((acc, it) => acc + (it.secrets_count || 0), 0)
    : (overview?.secrets_count ?? (props.secrets?.length ?? appState.secrets.length));
  const assetsCount = isFiltered
    ? visibleItems.reduce((acc, it) => acc + (it.assets_count || it.files_count || 0), 0)
    : (overview?.assets_count ?? overview?.files_count ?? (appState.assets?.length ?? appState.files?.length ?? 0));
  const notesCount = isFiltered
    ? visibleItems.reduce((acc, it) => acc + (it.notes_count || 0), 0)
    : (overview?.notes_count ?? appState.notes.length);
  const devicesCount = overview?.active_devices_count ?? (activeDevices.length || 1);

  // Recent secrets from overview or props
  const rawRecent = overview?.recent?.length
    ? overview.recent
    : (props.secrets || appState.secrets)
        .slice(0, 10)
        .map((s: any) => ({
          id: s.id,
          name: s.name,
          project_id: s.project_id || s.projectId || s.item_id || "",
          project_name: s.project_name || visibleItems.find((i) => i.id === (s.project_id || s.item_id))?.name || "Entry",
          environment_id: s.environment_id || s.environmentId || "",
          environment_name: s.environment_name || "General",
          updated_at: s.updated_at || s.updatedAt || Date.now(),
          item_id: s.item_id || s.project_id || s.projectId,
          item_name: s.item_name || s.project_name,
        }));

  const recentSecrets = (isFiltered
    ? rawRecent.filter((s: any) => {
        const targetItemId = s.item_id || s.project_id;
        return targetItemId ? visibleItemIds.has(targetItemId) : true;
      })
    : rawRecent
  ).slice(0, 5);

  const recentNotes = (isFiltered
    ? appState.notes.filter((n) => visibleItemIds.has(n.item_id))
    : appState.notes
  ).slice(0, 5);

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
                {canCreate && (
                  <Button
                    variant="secondary"
                    icon="plus"
                    onClick={props.onNewItem || props.onNewProject}
                  >
                    New entry
                  </Button>
                )}
                {canAddSecret && (
                  <Button
                    variant="secondary"
                    icon="key"
                    onClick={props.onAddSecret || props.onNewItem}
                  >
                    Add secret
                  </Button>
                )}
                {canPair && (
                  <Button variant="secondary" icon="devices" onClick={props.onOpenDevices}>
                    Pair device
                  </Button>
                )}
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
              {recentNotes.length === 0 ? (
                <p className={styles.empty}>Notes you create appear here.</p>
              ) : (
                <ul className={styles.list}>
                  {recentNotes.map((n) => {
                    const item = visibleItems.find((i) => i.id === n.item_id);
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
