import { useState, useEffect } from "react";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { SelectControl } from "../../components/Field";
import { List, ListRow } from "../../components/List";
import { Notice } from "../../components/Notice";
import { PageHeader, Section } from "../../components/PageHeader";
import { SegmentedTabs, type TabItem } from "../../components/SegmentedTabs";
import type { Device, Plan } from "../../data/mock";
import { initialDevices, thisDevice } from "../../data/mock";
import { api } from "../../lib/api";
import { formatAgo, formatDate } from "../../lib/format";
import { useStore } from "../../lib/store";
import { PairDeviceDialog } from "../devices/PairDeviceDialog";
import { RevokeDeviceDialog } from "../devices/RevokeDeviceDialog";
import { CLI_COMMAND } from "../overview/OverviewScreen";
import { PlanDialog } from "../PlanDialog";
import { CreateRecoveryKeyDialog } from "../recovery/CreateRecoveryKeyDialog";
import { ExportDialog } from "../recovery/ExportDialog";
import { RotateKeyDialog } from "../recovery/RotateKeyDialog";
import styles from "./SettingsScreen.module.css";

export type ThemePreference = "system" | "light" | "dark";
export type SettingsTab = "general" | "security" | "devices" | "recovery" | "sync" | "subscription";

interface Props {
  plan: Plan;
  onPlanChange: (plan: Plan) => void;
  theme: ThemePreference;
  onThemeChange: (t: ThemePreference) => void;
  lockMinutes: number;
  onLockMinutesChange: (m: number) => void;
  onCliCopied: () => void;
  // Optional customizations and integration
  homeLabel?: string;
  onHomeLabelChange?: (label: string) => void;
  deviceName?: string;
  onDeviceNameChange?: (name: string) => void;
  devices?: Device[];
  onPairDevice?: (d: Device) => void;
  onRevokeDevice?: (id: string) => void;
  pendingRotation?: string;
  keyRotatedAt?: number;
  recoveryKeyCreatedAt?: number;
  onRecoveryKeyCreated?: () => void;
  onRotated?: () => void;
  initialTab?: SettingsTab;
}

const SETTINGS_TABS: TabItem[] = [
  { id: "general", label: "General" },
  { id: "security", label: "Security & Encryption" },
  { id: "devices", label: "Devices" },
  { id: "recovery", label: "Recovery & Backups" },
  { id: "sync", label: "Synchronization" },
  { id: "subscription", label: "Subscription & Entitlements" },
];

function deviceMeta(d: Device, _plan?: Plan) {
  if (d.revokedAt) return `${d.platform}, revoked ${formatDate(d.revokedAt)}. Copies it already had stay on it.`;
  if (d.current) return `${d.platform}, added ${formatDate(d.addedAt)}, key ${d.fingerprint}`;
  return `${d.platform}, ${d.lastSyncAt ? `last synced ${formatAgo(d.lastSyncAt)}` : "active"}, key ${d.fingerprint}`;
}

export function SettingsScreen(props: Props) {
  const {
    plan,
    onPlanChange,
    theme,
    onThemeChange,
    lockMinutes,
    onLockMinutesChange,
    onCliCopied,
    pendingRotation,
    keyRotatedAt,
    recoveryKeyCreatedAt,
    onRecoveryKeyCreated,
    onRotated,
  } = props;

  const [appState, store] = useStore();
  const [activeTab, setActiveTab] = useState<SettingsTab>(props.initialTab || "general");

  useEffect(() => {
    if (props.initialTab) {
      setActiveTab(props.initialTab);
    }
  }, [props.initialTab]);

  const [comparing, setComparing] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");

  // Local state for devices if not passed via props
  const [localDevices, setLocalDevices] = useState<Device[]>(props.devices || initialDevices);
  const devices = props.devices || localDevices;
  const activeDevices = devices.filter((d) => !d.revokedAt);
  const revokedDevices = devices.filter((d) => d.revokedAt);

  // Dialog states
  const [pairing, setPairing] = useState(false);
  const [revoking, setRevoking] = useState<Device | null>(null);
  const [openRecoveryModal, setOpenRecoveryModal] = useState<"create" | "export" | "rotate" | null>(null);

  // Editable text values
  const [homeLabelInput, setHomeLabelInput] = useState(
    props.homeLabel ?? appState.settings.home_label ?? "Overview"
  );
  const [deviceNameInput, setDeviceNameInput] = useState(
    props.deviceName ?? appState.settings.device_name ?? thisDevice.name
  );

  // Biometric unlock preference state
  const [biometricUnlock, setBiometricUnlock] = useState(() => {
    return typeof window !== "undefined" && window.localStorage.getItem("secwet:biometric_unlock") !== "false";
  });

  // Sync state
  const [isSyncing, setIsSyncing] = useState(false);
  const [lastSyncResult, setLastSyncResult] = useState<string | null>(null);

  async function copyCli() {
    try {
      await navigator.clipboard.writeText(CLI_COMMAND);
      setCopyState("copied");
      onCliCopied();
    } catch {
      setCopyState("failed");
    }
  }

  async function saveHomeLabel() {
    const trimmed = homeLabelInput.trim() || "Overview";
    setHomeLabelInput(trimmed);
    if (props.onHomeLabelChange) {
      props.onHomeLabelChange(trimmed);
    }
    await store.updateSettings({ home_label: trimmed });
    await store.updateDashboard({ ...appState.dashboardConfig, home_label: trimmed });
  }

  async function saveDeviceName() {
    const trimmed = deviceNameInput.trim() || thisDevice.name;
    setDeviceNameInput(trimmed);
    if (props.onDeviceNameChange) {
      props.onDeviceNameChange(trimmed);
    }
    await store.updateSettings({ device_name: trimmed });
  }

  function handlePair(d: Device) {
    if (props.onPairDevice) {
      props.onPairDevice(d);
    } else {
      setLocalDevices((prev) => [...prev, d]);
    }
    setPairing(false);
  }

  function handleRevoke(id: string) {
    if (props.onRevokeDevice) {
      props.onRevokeDevice(id);
    } else {
      setLocalDevices((prev) =>
        prev.map((d) => (d.id === id ? { ...d, revokedAt: Date.now() } : d))
      );
    }
    setRevoking(null);
  }

  async function handleManualSync() {
    setIsSyncing(true);
    try {
      const report = await api.syncNow();
      setLastSyncResult(
        `Synced just now (pushed: ${report.pushed}, pulled: ${report.pulled})`
      );
    } catch {
      setLastSyncResult("Sync failed. Check relay connection.");
    } finally {
      setIsSyncing(false);
    }
  }

  const hasRecoveryKey = recoveryKeyCreatedAt !== undefined;

  return (
    <div className={styles.screen}>
      <PageHeader
        title="Settings"
        subtitle="Consolidated preferences, security controls, device management, and synchronization."
      />

      <SegmentedTabs
        label="Settings tabs"
        items={SETTINGS_TABS}
        value={activeTab}
        onChange={(id) => setActiveTab(id as SettingsTab)}
      />

      {/* 1. GENERAL TAB */}
      {activeTab === "general" && (
        <>
          <Section title="Appearance & Locking">
            <List>
              <ListRow
                title="Appearance"
                meta="System follows your operating system's light or dark setting."
                trailing={
                  <div className={styles.select}>
                    <SelectControl
                      aria-label="Appearance"
                      value={theme}
                      onChange={(e) => onThemeChange(e.target.value as ThemePreference)}
                    >
                      <option value="system">System</option>
                      <option value="light">Light</option>
                      <option value="dark">Dark</option>
                    </SelectControl>
                  </div>
                }
              />
              <ListRow
                title="Lock Secwet after"
                meta="Idle time before revealed values hide and Secwet locks."
                trailing={
                  <div className={styles.select}>
                    <SelectControl
                      aria-label="Lock Secwet after"
                      value={lockMinutes}
                      onChange={(e) => onLockMinutesChange(Number(e.target.value))}
                    >
                      <option value={5}>5 minutes</option>
                      <option value={15}>15 minutes</option>
                      <option value={30}>30 minutes</option>
                      <option value={60}>1 hour</option>
                    </SelectControl>
                  </div>
                }
              />
            </List>
          </Section>

          <Section title="Workspace & Identity">
            <List>
              <ListRow
                title="Home view title"
                meta="Customize the title displayed in the sidebar and dashboard."
                trailing={
                  <input
                    type="text"
                    aria-label="Home view title"
                    className={styles.input}
                    value={homeLabelInput}
                    onChange={(e) => setHomeLabelInput(e.target.value)}
                    onBlur={saveHomeLabel}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") saveHomeLabel();
                    }}
                  />
                }
              />
              <ListRow
                title="Device name"
                meta="Identify this machine when approving or viewing paired devices."
                trailing={
                  <input
                    type="text"
                    aria-label="Device name"
                    className={styles.input}
                    value={deviceNameInput}
                    onChange={(e) => setDeviceNameInput(e.target.value)}
                    onBlur={saveDeviceName}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") saveDeviceName();
                    }}
                  />
                }
              />
            </List>
          </Section>

          <Section title="Command Line">
            <List>
              <ListRow
                title="Run a command with secrets as environment variables"
                meta={<code className={styles.code}>{CLI_COMMAND}</code>}
                trailing={
                  <Button
                    variant="secondary"
                    icon={copyState === "copied" ? "check" : "copy"}
                    onClick={copyCli}
                  >
                    {copyState === "copied" ? "Copied" : "Copy"}
                  </Button>
                }
              />
            </List>
            {copyState === "failed" && (
              <p className={styles.hint}>
                Copy isn't available here. Select the command and copy it manually.
              </p>
            )}
          </Section>
        </>
      )}

      {/* 2. SECURITY & ENCRYPTION TAB */}
      {activeTab === "security" && (
        <>
          {pendingRotation && (
            <Notice
              tone="warning"
              label="Rotate key"
              action={
                <Button variant="tertiary" onClick={() => setOpenRecoveryModal("rotate")}>
                  Rotate encryption key
                </Button>
              }
            >
              {pendingRotation} was revoked. Rotate the encryption key so it cannot decrypt changes made from now on.
            </Notice>
          )}

          <Section title="Key Rotation">
            <List>
              <ListRow
                title={
                  <>
                    Master encryption key
                    {pendingRotation && <Badge tone="warning">Rotation recommended</Badge>}
                  </>
                }
                meta={
                  pendingRotation
                    ? `${pendingRotation} was revoked. Rotate to unseal future changes under a new epoch.`
                    : keyRotatedAt
                      ? `Last rotated ${formatAgo(keyRotatedAt).toLowerCase()}.`
                      : "Encryption key active under current epoch. Rotation recommended after revoking devices."
                }
                trailing={
                  <Button variant="secondary" onClick={() => setOpenRecoveryModal("rotate")}>
                    Rotate key
                  </Button>
                }
              />
            </List>
          </Section>

          <Section title="Authentication & Presence">
            <List>
              <ListRow
                title="Biometric presence (Touch ID)"
                meta="Prompt for Touch ID or system authentication when unlocking Secwet."
                trailing={
                  <div className={styles.select}>
                    <SelectControl
                      aria-label="Biometric presence"
                      value={biometricUnlock ? "enabled" : "disabled"}
                      onChange={(e) => {
                        const enabled = e.target.value === "enabled";
                        setBiometricUnlock(enabled);
                        if (typeof window !== "undefined") {
                          window.localStorage.setItem("secwet:biometric_unlock", enabled ? "true" : "false");
                        }
                      }}
                    >
                      <option value="enabled">Required</option>
                      <option value="disabled">Disabled</option>
                    </SelectControl>
                  </div>
                }
              />
            </List>
          </Section>

          <Section title="Zeroization & Memory Protection">
            <List>
              <ListRow
                title="Strict zeroization policy"
                meta="All decrypted keys, secrets, notes, and file buffers in memory are actively zeroized using volatile memory wipes whenever Secwet locks or the application shuts down."
                trailing={<Badge tone="success">Enforced</Badge>}
              />
              <ListRow
                title="Storage at rest"
                meta="All database records and file attachments are stored encrypted using XChaCha20-Poly1305 with per-record nonces. No plaintext ever touches disk."
                trailing={<Badge tone="success">XChaCha20</Badge>}
              />
            </List>
          </Section>
        </>
      )}

      {/* 3. DEVICES TAB */}
      {activeTab === "devices" && (
        <>
          <Section
            title="Active Devices"
            action={
              <Button variant="primary" icon="plus" onClick={() => setPairing(true)}>
                Pair a device
              </Button>
            }
          >
            <List label="Active devices">
              {activeDevices.map((d) => (
                <ListRow
                  key={d.id}
                  title={
                    <>
                      {d.name}
                      {d.current && <Badge>This device</Badge>}
                    </>
                  }
                  meta={deviceMeta(d, plan)}
                  trailing={
                    d.current ? (
                      <Badge tone="success">Active</Badge>
                    ) : (
                      <Button
                        variant="tertiary"
                        arrow={false}
                        onClick={() => setRevoking(d)}
                      >
                        Revoke
                      </Button>
                    )
                  }
                />
              ))}
            </List>
          </Section>

          {revokedDevices.length > 0 && (
            <Section title="Revoked Devices">
              <List label="Revoked devices">
                {revokedDevices.map((d) => (
                  <ListRow
                    key={d.id}
                    muted
                    title={d.name}
                    meta={deviceMeta(d, plan)}
                    trailing={<Badge tone="danger">Revoked</Badge>}
                  />
                ))}
              </List>
            </Section>
          )}
        </>
      )}

      {/* 4. RECOVERY & BACKUPS TAB */}
      {activeTab === "recovery" && (
        <>
          <Section title="Recovery">
            <List>
              <ListRow
                title={
                  <>
                    Recovery key
                    {hasRecoveryKey ? (
                      <Badge tone="success">Created</Badge>
                    ) : (
                      <Badge tone="warning">Not created</Badge>
                    )}
                  </>
                }
                meta={
                  hasRecoveryKey
                    ? `Created ${formatDate(recoveryKeyCreatedAt)}. Keep it safe and separate from this device.`
                    : "Without a recovery key, losing all approved devices means losing access to Secwet forever."
                }
                trailing={
                  <Button
                    variant={hasRecoveryKey ? "secondary" : "primary"}
                    onClick={() => setOpenRecoveryModal("create")}
                  >
                    {hasRecoveryKey ? "Replace" : "Create"}
                  </Button>
                }
              />
              <ListRow
                title="Encrypted export"
                meta={
                  hasRecoveryKey
                    ? "Full encrypted backup archive containing all items, secrets, notes, and files."
                    : "Create a recovery key first. The backup archive is encrypted with your recovery key."
                }
                trailing={
                  <Button
                    variant="secondary"
                    onClick={() => setOpenRecoveryModal(hasRecoveryKey ? "export" : "create")}
                  >
                    {hasRecoveryKey ? "Export data" : "Create key first"}
                  </Button>
                }
              />
            </List>
          </Section>

          <Section title="What recovery cannot do">
            <ul className={styles.limits}>
              <li>
                Secwet servers never hold your encryption key; there is no account reset or cloud password recovery.
              </li>
              <li>
                Revoking a device or rotating the key cannot erase secrets a device already copied locally.
              </li>
              <li>
                Ending a Pro subscription never deletes or locks your local data. Backups and exports remain accessible on every plan.
              </li>
            </ul>
          </Section>
        </>
      )}

      {/* 5. SYNCHRONIZATION TAB */}
      {activeTab === "sync" && (
        <>
          <Section title="Relay & Sync Engine">
            <List>
              <ListRow
                title="Relay connection"
                meta="End-to-end encrypted WebSocket connection to sync relay."
                trailing={<Badge tone="success">Connected</Badge>}
              />
              <ListRow
                title="Outbox queue"
                meta="Local changes awaiting sync. All changes are encrypted before transmission."
                trailing={<Badge tone="neutral">0 pending</Badge>}
              />
              <ListRow
                title="Manual sync"
                meta={lastSyncResult || "Trigger an immediate exchange with the sync relay."}
                trailing={
                  <Button
                    variant="secondary"
                    disabled={isSyncing}
                    onClick={handleManualSync}
                  >
                    {isSyncing ? "Syncing..." : "Sync now"}
                  </Button>
                }
              />
            </List>
          </Section>
        </>
      )}

      {/* 6. SUBSCRIPTION & ENTITLEMENTS TAB */}
      {activeTab === "subscription" && (
        <>
          <Section title="Subscription Plan">
            <List>
              <ListRow
                title={
                  <>
                    {plan === "pro" ? "Pro Plan" : "Free Plan"}
                    <Badge tone="accent">Current plan</Badge>
                  </>
                }
                meta={
                  plan === "pro"
                    ? "Real-time encrypted synchronization across all approved devices."
                    : "Local-only. Move to Pro to sync seamlessly with mobile and secondary devices."
                }
                trailing={
                  <Button variant="tertiary" onClick={() => setComparing(true)}>
                    Compare plans
                  </Button>
                }
              />
            </List>
          </Section>

          {import.meta.env.DEV && (
            <Section title="Simulate Plan (Development)">
              <List>
                <ListRow
                  title="Active Tier"
                  meta="Simulate Free vs Pro in development builds to test feature gating."
                  trailing={
                    <div className={styles.select}>
                      <SelectControl
                        aria-label="Simulate plan"
                        value={plan}
                        onChange={(e) => onPlanChange(e.target.value as Plan)}
                      >
                        <option value="free">Free</option>
                        <option value="pro">Pro</option>
                      </SelectControl>
                    </div>
                  }
                />
              </List>
            </Section>
          )}

          <Section title="Entitlements & Policy">
            <ul className={styles.limits}>
              <li>
                <strong>Zero Lock-in:</strong> Ending a Pro subscription never deletes, locks, or revokes your local data.
              </li>
              <li>
                <strong>Backups & Exports:</strong> Recovery keys, local encrypted backups, and data exports remain accessible on every plan.
              </li>
              <li>
                <strong>Multi-device Sync:</strong> Pro activates encrypted relay sync across all paired desktop and mobile devices.
              </li>
            </ul>
          </Section>
        </>
      )}

      {/* Dialogs */}
      {comparing && <PlanDialog plan={plan} onClose={() => setComparing(false)} />}

      {pairing &&
        (plan === "pro" ? (
          <PairDeviceDialog
            onCancel={() => setPairing(false)}
            onApprove={handlePair}
          />
        ) : (
          <PlanDialog
            plan={plan}
            reason="Pairing a second device requires Pro. Everything on this device remains fully functional on Free."
            onClose={() => setPairing(false)}
          />
        ))}

      {revoking && (
        <RevokeDeviceDialog
          device={revoking}
          onCancel={() => setRevoking(null)}
          onConfirm={() => handleRevoke(revoking.id)}
        />
      )}

      {openRecoveryModal === "create" && (
        <CreateRecoveryKeyDialog
          replacing={hasRecoveryKey}
          onCancel={() => setOpenRecoveryModal(null)}
          onDone={() => {
            if (onRecoveryKeyCreated) onRecoveryKeyCreated();
            setOpenRecoveryModal(null);
          }}
        />
      )}

      {openRecoveryModal === "export" && (
        <ExportDialog
          secretCount={appState.secrets.length}
          projectCount={appState.items.length}
          onClose={() => setOpenRecoveryModal(null)}
        />
      )}

      {openRecoveryModal === "rotate" && (
        <RotateKeyDialog
          onCancel={() => setOpenRecoveryModal(null)}
          onConfirm={() => {
            if (onRotated) onRotated();
            setOpenRecoveryModal(null);
          }}
        />
      )}
    </div>
  );
}
