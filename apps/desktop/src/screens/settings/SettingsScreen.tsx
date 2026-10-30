import { useState, useEffect } from "react";
import { Badge } from "../../components/Badge";
import { Button, IconButton } from "../../components/Button";
import { SelectControl } from "../../components/Field";
import { List, ListRow } from "../../components/List";
import { Notice } from "../../components/Notice";
import { PageHeader, Section } from "../../components/PageHeader";
import { SegmentedTabs, type TabItem } from "../../components/SegmentedTabs";
import type { Device, Plan } from "../../data/mock";
import { initialDevices, thisDevice } from "../../data/mock";
import { canPairDevices, canRotateMasterKey, isReadOnly, planEndDate } from "../../lib/access";
import { api, formatUiError, type CliInstallStatus, type RelayStatusDto } from "../../lib/api";
import { reloadPlan, setPlanStatus, usePlanStatus } from "../../lib/usePlan";
import { formatAgo, formatDate } from "../../lib/format";
import { useStore } from "../../lib/store";
import { PairDeviceDialog } from "../devices/PairDeviceDialog";
import { RevokeDeviceDialog } from "../devices/RevokeDeviceDialog";
import { PlanDialog } from "../PlanDialog";
import { CreateRecoveryKeyDialog } from "../recovery/CreateRecoveryKeyDialog";
import { ExportDialog } from "../recovery/ExportDialog";
import { RotateKeyDialog } from "../recovery/RotateKeyDialog";
import { BiometricSection } from "./BiometricSection";
import styles from "./SettingsScreen.module.css";

export type ThemePreference = "system" | "light" | "dark";
export type SettingsTab =
  | "general"
  | "cli"
  | "security"
  | "devices"
  | "recovery"
  | "sync"
  | "subscription";

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
  onRevokeDevice?: (id: string, wipe: boolean) => void;
  recoveryKeyCreatedAt?: number;
  onRecoveryKeyCreated?: () => void;
  onRotated?: () => void;
  initialTab?: SettingsTab;
}

const SETTINGS_TABS: TabItem[] = [
  { id: "general", label: "General" },
  { id: "cli", label: "CLI" },
  { id: "security", label: "Security" },
  { id: "devices", label: "Devices" },
  { id: "recovery", label: "Recovery" },
  { id: "sync", label: "Sync" },
  { id: "subscription", label: "Plan" },
];

function deviceMeta(d: Device, plan?: Plan | "paused") {
  if (d.revokedAt) return `${d.platform}, revoked ${formatDate(d.revokedAt)}.`;
  if (d.current) return `${d.platform}, added ${formatDate(d.addedAt)}, key ${d.fingerprint}`;
  const sync = d.lastSyncAt ? `last synced ${formatAgo(d.lastSyncAt)}` : "active";
  // When Pro ends, the other devices stop syncing.
  return `${d.platform}, ${plan === "paused" ? `sync paused, ${sync}` : sync}, key ${d.fingerprint}`;
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

  const readOnly = isReadOnly(appState.linkStatus);
  const canRotate = canRotateMasterKey(appState.access, readOnly);
  const canPair = canPairDevices(appState.access, readOnly);
  const isOwner = !appState.access || appState.access.is_owner;
  const keyStatus = appState.keyStatus;
  const rotationRecommended = Boolean(keyStatus?.rotation_recommended);
  const rotationReason = keyStatus?.pending_reason?.trim() || "A device was revoked.";
  const tabs = SETTINGS_TABS;


  useEffect(() => {
    if (activeTab === "security" || activeTab === "devices") {
      store.reloadKeyStatus().catch(() => {});
    }
  }, [activeTab, store]);

  const [comparing, setComparing] = useState(false);

  // Local state for devices if not passed via props
  const [localDevices, setLocalDevices] = useState<Device[]>(props.devices || initialDevices);
  const devices = props.devices || localDevices;
  const activeDevices = devices.filter((d) => !d.revokedAt);
  const revokedDevices = devices.filter((d) => d.revokedAt);

  // Dialog states
  const [pairing, setPairing] = useState(false);
  const [revoking, setRevoking] = useState<Device | null>(null);
  const [revokeNotice, setRevokeNotice] = useState<string | null>(null);
  const [openRecoveryModal, setOpenRecoveryModal] = useState<"create" | "export" | "rotate" | null>(null);

  // Editable text values
  const [homeLabelInput, setHomeLabelInput] = useState(
    props.homeLabel ?? appState.settings.home_label ?? "Overview"
  );
  const [deviceNameInput, setDeviceNameInput] = useState(
    props.deviceName ?? appState.settings.device_name ?? thisDevice.name
  );

  // Sync state
  const [isSyncing, setIsSyncing] = useState(false);
  const [lastSyncResult, setLastSyncResult] = useState<string | null>(null);

  // Plan: the real plan from the relay entitlement, cached in the core.
  const planStatus = usePlanStatus();
  const realPlan = planStatus?.plan ?? "free";
  const planEnd = planEndDate(planStatus?.expires_at);
  const [planBusy, setPlanBusy] = useState(false);
  const [planMessage, setPlanMessage] = useState<{ tone: "success" | "warning"; text: string } | null>(null);

  // Relay status state
  const [relayStatus, setRelayStatus] = useState<RelayStatusDto | null>(null);
  const [relayLoading, setRelayLoading] = useState(false);
  const [relayError, setRelayError] = useState<string | null>(null);
  const [relayUrlInput, setRelayUrlInput] = useState("");
  const [relayUrlSaved, setRelayUrlSaved] = useState("");

  const fetchRelayStatus = async () => {
    setRelayLoading(true);
    setRelayError(null);
    try {
      // Free reports the cached plan without contacting the relay.
      const status = await api.relayStatus();
      setRelayStatus(status);
      setRelayUrlSaved(status.relay_url);
      setRelayUrlInput((prev) => prev || status.relay_url);
      reloadPlan();
    } catch (err) {
      setRelayError(formatUiError(err, "Couldn't read the sync status."));
    } finally {
      setRelayLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === "sync" || activeTab === "subscription") {
      fetchRelayStatus();
    }
  }, [activeTab]);

  async function saveRelayUrl() {
    const url = relayUrlInput.trim();
    if (url === relayUrlSaved) return;
    if (url && !/^https?:\/\/[^\s/]+/i.test(url)) {
      setRelayError("Enter the relay address, for example https://relay.example.com.");
      return;
    }
    try {
      await api.relaySetUrl(url);
      setRelayUrlSaved(url);
      setRelayError(null);
      await fetchRelayStatus();
    } catch (err) {
      setRelayError(formatUiError(err, "Couldn't save the relay address."));
    }
  }

  /** Free: "Check for Pro" asks the relay once. Pro and paused: re-read the entitlement. */
  async function handleCheckPlan() {
    setPlanBusy(true);
    setPlanMessage(null);
    try {
      const next = realPlan === "free" ? await api.planActivate() : await api.planRefresh();
      setPlanStatus(next);
      setPlanMessage(
        next.plan === "pro"
          ? { tone: "success", text: "Pro is active. Sync, pairing and sharing are on." }
          : next.plan === "paused"
            ? { tone: "warning", text: "Pro has ended for this Secwet. Sync stays paused; everything here keeps working." }
            : { tone: "warning", text: "This Secwet doesn't have Pro yet. Everything keeps working on this device." }
      );
    } catch (err) {
      setPlanMessage({ tone: "warning", text: formatUiError(err, "Couldn't reach the relay. Try again.") });
    } finally {
      setPlanBusy(false);
    }
  }

  async function copySecwetId() {
    if (!planStatus) return;
    try {
      await api.clipboardCopyText(planStatus.secwet_id);
      setPlanMessage({ tone: "success", text: "Secwet ID copied." });
    } catch (err) {
      setPlanMessage({ tone: "warning", text: formatUiError(err, "Couldn't copy the Secwet ID.") });
    }
  }

  const [copiedSnippet, setCopiedSnippet] = useState<string | null>(null);
  const [cliStatus, setCliStatus] = useState<CliInstallStatus | null>(null);
  const [installingCli, setInstallingCli] = useState(false);
  const [cliActionError, setCliActionError] = useState<string | null>(null);

  useEffect(() => {
    if (activeTab === "cli") {
      api.cliStatus().then(setCliStatus).catch(() => {});
    }
  }, [activeTab]);

  async function handleInstallCli() {
    setInstallingCli(true);
    setCliActionError(null);
    try {
      const res = await api.cliInstall();
      setCliStatus(res);
      onCliCopied();
    } catch (e: any) {
      setCliActionError(e?.message || "Failed to install CLI to PATH");
    } finally {
      setInstallingCli(false);
    }
  }

  async function handleUninstallCli() {
    setInstallingCli(true);
    setCliActionError(null);
    try {
      const res = await api.cliUninstall();
      setCliStatus(res);
    } catch (e: any) {
      setCliActionError(e?.message || "Failed to uninstall CLI from PATH");
    } finally {
      setInstallingCli(false);
    }
  }

  async function copyCommand(key: string, text: string) {
    try {
      await api.clipboardCopyText(text); // Non-secret CLI_COMMAND snippet
      setCopiedSnippet(key);
      setTimeout(() => {
        setCopiedSnippet((prev) => (prev === key ? null : prev));
      }, 2000);
      onCliCopied();
    } catch {
      // clipboard copy failed
    }
  }

  function renderCommandSnippet(key: string, command: string) {
    const isCopied = copiedSnippet === key;
    return (
      <div className={styles.commandBox}>
        <code className={styles.commandCode}>{command}</code>
        <IconButton
          icon={isCopied ? "check" : "copy"}
          label={isCopied ? "Copied" : "Copy command"}
          className={[styles.copyIconBtn, isCopied && styles.copiedIconBtn].filter(Boolean).join(" ")}
          onClick={() => copyCommand(key, command)}
        />
      </div>
    );
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

  /** Throws on failure so the dialog can show the error and stay open. */
  async function handleRevoke(device: Device, wipe: boolean) {
    const result = await api.deviceRevoke(device.id, wipe);
    if (props.onRevokeDevice) {
      props.onRevokeDevice(device.id, wipe);
    } else {
      setLocalDevices((prev) =>
        prev.map((d) => (d.id === device.id ? { ...d, revokedAt: Date.now() } : d))
      );
    }
    setRevoking(null);
    setRevokeNotice(
      result.wipe_requested
        ? `${device.name} was revoked. It erases its keys and local data when it next connects.`
        : `${device.name} was revoked. It keeps a read-only copy of what it had.`
    );
    await store.reloadKeyStatus().catch(() => null);
  }

  async function handleManualSync() {
    setIsSyncing(true);
    try {
      const report = await api.syncNow();
      setLastSyncResult(`Synced just now. Sent ${report.pushed}, received ${report.pulled}.`);
    } catch (err) {
      setLastSyncResult(formatUiError(err, "Sync failed. Check the relay connection."));
    } finally {
      setIsSyncing(false);
      // Every sync re-reads the entitlement, so the plan may have changed.
      reloadPlan();
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
        items={tabs}
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

        </>
      )}

      {/* 2. COMMAND LINE TAB */}
      {activeTab === "cli" && (
        <>
          <Section title="Overview & Setup">
            <List>
              <ListRow
                title="Install 'secwet' command in PATH"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      {cliStatus?.installed
                        ? `Linked to ${cliStatus.path || "PATH"}. You can run 'secwet' anywhere in your terminal.`
                        : "Link the companion CLI to your system shell PATH with 1 click so you can use 'secwet' directly from your terminal."}
                    </span>
                    {cliActionError && (
                      <span style={{ color: "var(--color-danger)", fontSize: "var(--font-size-xs)" }}>
                        {cliActionError}
                      </span>
                    )}
                    {cliStatus?.installed && !cliStatus.in_path && (
                      <span style={{ color: "var(--color-warning)", fontSize: "var(--font-size-xs)" }}>
                        Notice: {cliStatus.path} is linked, but not in your active $PATH. Add its directory to your shell config (~/.zshrc or ~/.bashrc).
                      </span>
                    )}
                  </div>
                }
                trailing={
                  <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
                    {cliStatus?.installed ? (
                      <>
                        <Badge tone="success">Installed in PATH</Badge>
                        <Button
                          variant="tertiary"
                          onClick={handleUninstallCli}
                          disabled={installingCli}
                        >
                          {installingCli ? "Removing..." : "Uninstall"}
                        </Button>
                      </>
                    ) : (
                      <Button
                        variant="primary"
                        onClick={handleInstallCli}
                        disabled={installingCli || !cliStatus?.can_install}
                      >
                        {installingCli ? "Installing..." : "Install to PATH"}
                      </Button>
                    )}
                  </div>
                }
              />
              <ListRow
                title="Verify installation"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>Check if the secwet binary is accessible in your current shell path.</span>
                    {renderCommandSnippet("version", "secwet --version")}
                  </div>
                }
              />
              <ListRow
                title="Manual symlink"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>If you prefer linking manually in your terminal:</span>
                    {renderCommandSnippet("symlink", "ln -sf /Applications/Secwet.app/Contents/MacOS/secwet ~/.local/bin/secwet")}
                  </div>
                }
              />
              <ListRow
                title="Build from source"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>For developers compiling from the workspace repository using Cargo:</span>
                    {renderCommandSnippet("install", "cargo install --path crates/secwet-cli")}
                  </div>
                }
              />
            </List>
          </Section>

          <Section title="AI Agents & Workspace Discovery">
            <List>
              <ListRow
                title="Full Workspace Tree (Single-Call Discovery)"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Prints the complete hierarchical tree (Spaces → Groups → Items → Environments → Secrets with In-use status, Notes, Files).
                    </span>
                    {renderCommandSnippet("tree", "secwet tree")}
                    {renderCommandSnippet("tree-space", 'secwet tree --space "Work"')}
                  </div>
                }
              />
              <ListRow
                title="Machine-Readable JSON Tree (For AI Agents)"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Dumps the entire workspace hierarchy in structured JSON so AI coding assistants never have to guess what exists.
                    </span>
                    {renderCommandSnippet("tree-json", "secwet tree --json")}
                  </div>
                }
              />
              <ListRow
                title="Status & Storage Health"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Displays lock state, active device ID, epoch, active plan, and local database storage path.
                    </span>
                    {renderCommandSnippet("status", "secwet status --json")}
                  </div>
                }
              />
            </List>
          </Section>

          <Section title="Secrets & Execution">
            <List>
              <ListRow
                title="Run command with injected secrets"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Executes any program with decrypted secrets injected in-memory as environment variables and registers the active session.
                    </span>
                    {renderCommandSnippet("run", "secwet run -i <item> -e <env> -- npm start")}
                  </div>
                }
              />
              <ListRow
                title="Get single secret value"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Outputs raw secret value with no trailing newline, perfect for script interpolation $(secwet get ...).
                    </span>
                    {renderCommandSnippet("get", "secwet get DATABASE_URL -i <item> -e <env>")}
                  </div>
                }
              />
              <ListRow
                title="Set or update secret"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Sets or updates a secret across all 7 kinds (supports stdin piping or the --value flag for non-interactive scripting).
                    </span>
                    {renderCommandSnippet("set", 'secwet secret set API_KEY -i <item> -e <env> -k api_key --value "my_token"')}
                  </div>
                }
              />
              <ListRow
                title="List secrets"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Lists all secrets with their kind, tail, update time, and in-use status.
                    </span>
                    {renderCommandSnippet("list", "secwet secret list -i <item> -e <env> --json")}
                  </div>
                }
              />
              <ListRow
                title="Copy secret across environments"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Copies an existing secret to another environment within the same item.
                    </span>
                    {renderCommandSnippet("copy-to-env", "secwet secret copy-to-env STRIPE_KEY --target-env staging -i <item>")}
                  </div>
                }
              />
              <ListRow
                title="Import secrets from .env or stdin"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Bulk imports dotenv files (handling comments, quotes, multiline values). Use '-' to stream from pipe or clipboard.
                    </span>
                    {renderCommandSnippet("import", "secwet import .env -i <item> -e <env>")}
                  </div>
                }
              />
              <ListRow
                title="Export secrets"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Exports secrets to stdout or a file in dotenv or JSON format.
                    </span>
                    {renderCommandSnippet("export", "secwet export -i <item> -e <env> --format dotenv")}
                  </div>
                }
              />
            </List>
          </Section>

          <Section title="Workspace CRUD (GUI Parity)">
            <List>
              <ListRow
                title="Spaces (Top-Level Isolation)"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Manage organizational spaces (Personal, Work, Client Projects, etc.) that partition groups.
                    </span>
                    {renderCommandSnippet("space-list", "secwet space list --json")}
                    {renderCommandSnippet("space-create", 'secwet space create "Work" --icon briefcase')}
                    {renderCommandSnippet("space-rename", 'secwet space rename "Work" "Enterprise"')}
                    {renderCommandSnippet("space-delete", 'secwet space delete "Enterprise"')}
                  </div>
                }
              />
              <ListRow
                title="Groups / Sections"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Manage organizational groups under spaces and custom display ordering.
                    </span>
                    {renderCommandSnippet("group-list", 'secwet group list --space "Work" --json')}
                    {renderCommandSnippet("group-create", 'secwet group create "Backend" --space "Work" --icon server')}
                    {renderCommandSnippet("group-move", 'secwet group move "Backend" --to "Work"')}
                    {renderCommandSnippet("group-rename", 'secwet group rename "Backend" "API Services"')}
                    {renderCommandSnippet("group-delete", 'secwet group delete "Backend"')}
                  </div>
                }
              />
              <ListRow
                title="Items / Entries"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Create, inspect, and delete workspace entries within groups.
                    </span>
                    {renderCommandSnippet("item-list", "secwet item list -g <group> --json")}
                    {renderCommandSnippet("item-create", 'secwet item create "Payment API" -g "Backend" -d "Stripe integration"')}
                    {renderCommandSnippet("item-get", 'secwet item get "Payment API" --json')}
                    {renderCommandSnippet("item-delete", 'secwet item delete "Payment API"')}
                  </div>
                }
              />
              <ListRow
                title="Environments"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Manage multiple environments (e.g. dev, staging, prod) per item.
                    </span>
                    {renderCommandSnippet("env-list", 'secwet env list -i "Payment API"')}
                    {renderCommandSnippet("env-create", 'secwet env create "staging" -i "Payment API"')}
                    {renderCommandSnippet("env-rename", 'secwet env rename "staging" "qa" -i "Payment API"')}
                    {renderCommandSnippet("env-delete", 'secwet env delete "qa" -i "Payment API"')}
                  </div>
                }
              />
              <ListRow
                title="Notes & Documentation"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Store, retrieve, and update encrypted markdown documentation and runbooks.
                    </span>
                    {renderCommandSnippet("note-list", 'secwet note list -i "Payment API"')}
                    {renderCommandSnippet("note-create", 'secwet note create "Runbook" -i "Payment API" --content "Deploy instructions..."')}
                    {renderCommandSnippet("note-get", 'secwet note get "Runbook" -i "Payment API" --raw')}
                  </div>
                }
              />
              <ListRow
                title="Encrypted Files & Certificates"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Attach, download, and manage encrypted credentials, keys, or certs.
                    </span>
                    {renderCommandSnippet("file-list", 'secwet file list -i "Payment API"')}
                    {renderCommandSnippet("file-upload", 'secwet file upload ./cert.pem -i "Payment API"')}
                    {renderCommandSnippet("file-download", 'secwet file download cert.pem -i "Payment API" -o ./cert.pem')}
                  </div>
                }
              />
              <ListRow
                title="Active Process Sessions"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      Inspect running injected processes and stop/cancel them directly from terminal.
                    </span>
                    {renderCommandSnippet("session-list", "secwet session list --json")}
                    {renderCommandSnippet("session-stop", "secwet session stop <session_id|pid>")}
                  </div>
                }
              />
              <ListRow
                title="Full CLI manual"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>
                      View all available commands, global flags, and help text.
                    </span>
                    {renderCommandSnippet("help", "secwet --help")}
                  </div>
                }
              />
            </List>
          </Section>

          <Section title="Project Automation (.secwet.toml)">
            <p className={styles.sectionDesc}>
              Initialize a <code>.secwet.toml</code> file in your repository root with one command, or drop it manually. The CLI traverses up from your working directory to find it, allowing you to run commands without passing <code>-i</code> or <code>-e</code> flags every time.
            </p>
            <div style={{ marginBottom: "var(--space-3)" }}>
              {renderCommandSnippet("init", 'secwet init -i "Payment API" -e development')}
            </div>
            <div className={styles.codeCard}>
              <div className={styles.codeCardHeader}>
                <span className={styles.codeCardTitle}>.secwet.toml</span>
                <IconButton
                  icon={copiedSnippet === "toml" ? "check" : "copy"}
                  label={copiedSnippet === "toml" ? "Copied" : "Copy template"}
                  className={[styles.copyIconBtn, copiedSnippet === "toml" && styles.copiedIconBtn].filter(Boolean).join(" ")}
                  onClick={() => copyCommand("toml", `item = "payments-api"\nenv = "development"`)}
                />
              </div>
              <pre className={styles.codePre}>
{`# .secwet.toml - Safe to commit to version control
item = "payments-api"
env = "development"`}
              </pre>
            </div>
            <p className={styles.hint}>
              Once configured, run <code>secwet run -- npm start</code> or <code>secwet import .env</code> directly.
            </p>
          </Section>

          <Section title="Scripting & CI/CD Recipes">
            <List>
              <ListRow
                title="Docker & Docker Compose"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>Inject decrypted secrets into containers during local development.</span>
                    {renderCommandSnippet("docker", "secwet run -- docker compose up")}
                  </div>
                }
              />
              <ListRow
                title="cURL with Bearer Token"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>Interpolate secret values directly into HTTP requests without leaving tokens in terminal logs.</span>
                    {renderCommandSnippet("curl", 'curl -H "Authorization: Bearer $(secwet get API_TOKEN)" https://api.example.com')}
                  </div>
                }
              />
              <ListRow
                title="Import from Clipboard (macOS)"
                meta={
                  <div className={styles.cliMeta}>
                    <span className={styles.cliDesc}>Pipe .env contents straight from your clipboard into Secwet without saving a file to disk.</span>
                    {renderCommandSnippet("pbpaste", "pbpaste | secwet import -")}
                  </div>
                }
              />
            </List>
          </Section>
        </>
      )}

      {/* 2. SECURITY & ENCRYPTION TAB */}
      {activeTab === "security" && (
        <>
          {rotationRecommended && canRotate && (
            <Notice
              tone="warning"
              label="Rotate key"
              action={
                <Button variant="tertiary" onClick={() => setOpenRecoveryModal("rotate")}>
                  Rotate encryption key
                </Button>
              }
            >
              {rotationReason} Rotate the encryption key so it can't read changes made from now on.
            </Notice>
          )}

          <Section title="Key Rotation">
            <List>
              <ListRow
                title={
                  <>
                    Master encryption key
                    {keyStatus && <Badge tone="neutral">Version {keyStatus.epoch}</Badge>}
                    {rotationRecommended && <Badge tone="warning">Rotation recommended</Badge>}
                  </>
                }
                meta={
                  !isOwner
                    ? "Managed by the workspace owner. Shared spaces use their own keys."
                    : keyStatus?.rotated_at
                      ? `Last rotated ${formatAgo(keyStatus.rotated_at).toLowerCase()}. Rotate after revoking a device.`
                      : "Never rotated. Rotate after revoking a device."
                }
                trailing={
                  isOwner ? (
                    <Button
                      variant={rotationRecommended ? "primary" : "secondary"}
                      disabled={!canRotate}
                      onClick={() => setOpenRecoveryModal("rotate")}
                    >
                      Rotate key
                    </Button>
                  ) : undefined
                }
              />
            </List>
          </Section>

          <BiometricSection />

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
          {revokeNotice && (
            <Notice
              tone="success"
              label="Revoked"
              action={
                <Button variant="tertiary" arrow={false} onClick={() => setRevokeNotice(null)}>
                  Dismiss
                </Button>
              }
            >
              {revokeNotice}
            </Notice>
          )}

          {rotationRecommended && canRotate && (
            <Notice
              tone="warning"
              label="Rotate key"
              action={
                <Button variant="tertiary" onClick={() => setOpenRecoveryModal("rotate")}>
                  Rotate encryption key
                </Button>
              }
            >
              {rotationReason} Rotate the encryption key so it can't read changes made from now on.
            </Notice>
          )}

          <Section
            title="Active Devices"
            action={
              canPair ? (
                <Button variant="primary" icon="plus" onClick={() => setPairing(true)}>
                  Pair a device
                </Button>
              ) : undefined
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
                      {!d.current && realPlan === "paused" && <Badge tone="warning">Paused</Badge>}
                    </>
                  }
                  meta={deviceMeta(d, realPlan === "paused" ? "paused" : plan)}
                  trailing={
                    d.current ? (
                      <Badge tone="success">Active</Badge>
                    ) : readOnly ? undefined : (
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

      {/* MEMBERS TAB (owners and admins) */}

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
          {realPlan === "free" && (
            <Notice
              tone="accent"
              label="Free"
              action={
                <Button variant="tertiary" onClick={() => setActiveTab("subscription")}>
                  See plan
                </Button>
              }
            >
              Sync comes with Pro. On Free, everything stays on this device and Secwet never contacts the relay.
            </Notice>
          )}
          {realPlan === "paused" && (
            <Notice tone="warning" label="Sync paused">
              Pro ended{planEnd ? ` on ${planEnd}` : ""}, so sync is paused on every device. Everything here stays usable
              and exportable. Changes you make now are kept and sent once Pro is renewed.
            </Notice>
          )}
          <Section title="Sync">
            {relayError && (
              <div className={styles.noticeGap}>
                <Notice tone="warning" label="Sync">
                  {relayError}
                </Notice>
              </div>
            )}
            <List>
              <ListRow
                title="Relay address"
                meta="The sync relay this Secwet uses. It only stores encrypted data."
                trailing={
                  <input
                    type="url"
                    aria-label="Relay address"
                    className={styles.input}
                    placeholder="https://relay.example.com"
                    spellCheck={false}
                    autoComplete="off"
                    disabled={readOnly}
                    value={relayUrlInput}
                    onChange={(e) => setRelayUrlInput(e.target.value)}
                    onBlur={saveRelayUrl}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") saveRelayUrl();
                    }}
                  />
                }
              />
              <ListRow
                title="Relay connection"
                meta={
                  realPlan === "free"
                    ? "Not used on Free."
                    : relayUrlSaved
                      ? relayUrlSaved
                      : "Add the relay address to sync."
                }
                trailing={
                  realPlan === "free" ? (
                    <Badge tone="neutral">Off</Badge>
                  ) : relayStatus?.connected ? (
                    <Badge tone="success">Connected</Badge>
                  ) : (
                    <Badge tone="neutral">{relayLoading ? "Checking…" : "Offline"}</Badge>
                  )
                }
              />
              <ListRow
                title="Devices"
                meta={`${planStatus?.active_devices ?? 1} of ${planStatus?.device_limit ?? 1} devices on this plan.`}
                trailing={
                  <Badge
                    tone={(planStatus?.active_devices ?? 1) >= (planStatus?.device_limit ?? 1) ? "warning" : "neutral"}
                  >
                    {`${planStatus?.active_devices ?? 1} / ${planStatus?.device_limit ?? 1}`}
                  </Badge>
                }
              />
              {realPlan !== "free" && (
                <ListRow
                  title="Waiting to sync"
                  meta={
                    realPlan === "paused"
                      ? "Changes made while sync is paused. They are sent once Pro is renewed."
                      : "Local changes not sent yet. Everything is encrypted before it leaves this device."
                  }
                  trailing={<Badge tone="neutral">{`${relayStatus?.pending_outbox_count ?? 0} changes`}</Badge>}
                />
              )}
              <ListRow
                title="Sync now"
                meta={
                  readOnly
                    ? "This device was unlinked from Secwet. Sync is disabled."
                    : realPlan === "free"
                      ? "Needs Pro."
                      : realPlan === "paused"
                        ? lastSyncResult || "Checks whether Pro was renewed, then syncs."
                        : lastSyncResult || "Send and receive changes now."
                }
                trailing={
                  <Button
                    variant="secondary"
                    disabled={isSyncing || readOnly || realPlan === "free" || !relayUrlSaved}
                    onClick={async () => {
                      await handleManualSync();
                      await fetchRelayStatus();
                    }}
                  >
                    {isSyncing ? "Syncing…" : "Sync now"}
                  </Button>
                }
              />
            </List>
          </Section>

          <Section title="What the relay sees">
            <ul className={styles.limits}>
              <li>The relay never sees your master key, secret values, names or notes.</li>
              <li>Every request is signed with this device's own key and protected against replay.</li>
              <li>The relay stores only encrypted data and random IDs.</li>
            </ul>
          </Section>
        </>
      )}

      {/* 6. PLAN TAB */}
      {activeTab === "subscription" && (
        <>
          {planMessage && (
            <Notice
              tone={planMessage.tone}
              label="Plan"
              action={
                <Button variant="tertiary" arrow={false} onClick={() => setPlanMessage(null)}>
                  Dismiss
                </Button>
              }
            >
              {planMessage.text}
            </Notice>
          )}
          <Section title="Plan">
            <List>
              <ListRow
                title={
                  <>
                    {realPlan === "free" ? "Free" : "Pro"}
                    {realPlan === "paused" ? (
                      <Badge tone="warning">Paused</Badge>
                    ) : (
                      <Badge tone="accent">Current plan</Badge>
                    )}
                  </>
                }
                meta={
                  realPlan === "pro"
                    ? `${planStatus?.device_limit ?? 5} devices${planEnd ? `, until ${planEnd}` : ""}. Sync, pairing and sharing are on.`
                    : realPlan === "paused"
                      ? `Pro ended${planEnd ? ` on ${planEnd}` : ""}. Sync is paused. Nothing is deleted or locked, and you can still export.`
                      : "One device, everything local. Secwet never contacts the relay on Free."
                }
                trailing={
                  <Button variant="tertiary" onClick={() => setComparing(true)}>
                    Compare plans
                  </Button>
                }
              />
              <ListRow
                title="Secwet ID"
                meta={planStatus?.secwet_id ?? "Unlock Secwet to see its ID."}
                trailing={
                  <Button variant="tertiary" arrow={false} disabled={!planStatus} onClick={copySecwetId}>
                    Copy
                  </Button>
                }
              />
              <ListRow
                title={realPlan === "free" ? "Check for Pro" : "Check plan"}
                meta={
                  !relayUrlSaved
                    ? "Add the relay address in Settings > Sync first."
                    : realPlan === "free"
                      ? "Check once so the relay knows this Secwet ID, then again after Pro is granted to it. This is the only time a Free device contacts the relay."
                      : planStatus?.checked_at
                        ? `Checked ${formatAgo(planStatus.checked_at).toLowerCase()}. The plan is also checked on every sync.`
                        : "The plan is checked on every sync."
                }
                trailing={
                  <Button
                    variant="secondary"
                    disabled={planBusy || readOnly || !relayUrlSaved}
                    onClick={handleCheckPlan}
                  >
                    {planBusy ? "Checking…" : realPlan === "free" ? "Check for Pro" : "Check now"}
                  </Button>
                }
              />
            </List>
          </Section>

          {import.meta.env.DEV && (
            <Section title="Simulate plan (development)">
              <List>
                <ListRow
                  title="Interface plan"
                  meta="Development builds only. Changes how the interface gates features; the real plan above stays the same."
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

          <Section title="If Pro ends">
            <ul className={styles.limits}>
              <li>Nothing is deleted or locked. Everything on this device stays usable.</li>
              <li>Recovery keys, backups and export work on every plan.</li>
              <li>Sync pauses on every device and resumes when Pro is renewed.</li>
            </ul>
          </Section>
        </>
      )}

      {/* Dialogs */}
      {comparing && <PlanDialog plan={realPlan === "paused" ? "paused" : plan} onClose={() => setComparing(false)} />}

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
          onConfirm={(wipe) => handleRevoke(revoking, wipe)}
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
          onDone={() => {
            if (onRotated) onRotated();
            store.reloadKeyStatus().catch(() => {});
          }}
        />
      )}
    </div>
  );
}
