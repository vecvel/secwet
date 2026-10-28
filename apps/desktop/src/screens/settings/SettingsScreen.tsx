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
import { canManageMembers, canPairDevices, canRotateMasterKey, isReadOnly } from "../../lib/access";
import { api, type CliInstallStatus, type RelayStatusDto } from "../../lib/api";
import { formatAgo, formatDate } from "../../lib/format";
import { useStore } from "../../lib/store";
import { PairDeviceDialog } from "../devices/PairDeviceDialog";
import { RevokeDeviceDialog } from "../devices/RevokeDeviceDialog";
import { PlanDialog } from "../PlanDialog";
import { CreateRecoveryKeyDialog } from "../recovery/CreateRecoveryKeyDialog";
import { ExportDialog } from "../recovery/ExportDialog";
import { RotateKeyDialog } from "../recovery/RotateKeyDialog";
import { MembersSection } from "./MembersSection";
import styles from "./SettingsScreen.module.css";

export type ThemePreference = "system" | "light" | "dark";
export type SettingsTab =
  | "general"
  | "cli"
  | "security"
  | "devices"
  | "members"
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
  { id: "members", label: "Members" },
  { id: "recovery", label: "Recovery" },
  { id: "sync", label: "Sync" },
  { id: "subscription", label: "Plan" },
];

function deviceMeta(d: Device, _plan?: Plan) {
  if (d.revokedAt) return `${d.platform}, revoked ${formatDate(d.revokedAt)}.`;
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
  const showMembers = canManageMembers(appState.access);
  const canRotate = canRotateMasterKey(appState.access, readOnly);
  const canPair = canPairDevices(appState.access, readOnly);
  const isOwner = !appState.access || appState.access.is_owner;
  const keyStatus = appState.keyStatus;
  const rotationRecommended = Boolean(keyStatus?.rotation_recommended);
  const rotationReason = keyStatus?.pending_reason?.trim() || "A device was revoked.";
  const tabs = SETTINGS_TABS.filter((t) => t.id !== "members" || showMembers);

  useEffect(() => {
    if (activeTab === "members" && !showMembers) setActiveTab("general");
  }, [activeTab, showMembers]);

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

  // Biometric unlock preference state
  const [biometricUnlock, setBiometricUnlock] = useState(() => {
    return typeof window !== "undefined" && window.localStorage.getItem("secwet:biometric_unlock") !== "false";
  });

  // Sync state
  const [isSyncing, setIsSyncing] = useState(false);
  const [lastSyncResult, setLastSyncResult] = useState<string | null>(null);

  // Relay status state
  const [relayStatus, setRelayStatus] = useState<RelayStatusDto | null>(null);
  const [relayLoading, setRelayLoading] = useState(false);
  const [relayRegistering, setRelayRegistering] = useState(false);
  const [relayError, setRelayError] = useState<string | null>(null);
  const [relaySuccess, setRelaySuccess] = useState<string | null>(null);

  const fetchRelayStatus = async () => {
    setRelayLoading(true);
    setRelayError(null);
    try {
      const status = await api.relayStatus();
      setRelayStatus(status);
    } catch (err: any) {
      setRelayError(err?.message || "Failed to query relay status");
    } finally {
      setRelayLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === "sync") {
      fetchRelayStatus();
    }
  }, [activeTab]);

  async function handleRegisterWithRelay() {
    setRelayRegistering(true);
    setRelayError(null);
    setRelaySuccess(null);
    try {
      const res = await api.relayRegister();
      setRelaySuccess(`Registered workspace with relay (epoch ${res.current_epoch})`);
      await fetchRelayStatus();
    } catch (err: any) {
      setRelayError(err?.message || "Failed to register with relay");
    } finally {
      setRelayRegistering(false);
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
                    </>
                  }
                  meta={deviceMeta(d, plan)}
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
      {activeTab === "members" && showMembers && <MembersSection />}

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
            {relayError && (
              <div style={{ marginBottom: "1rem" }}>
                <Notice tone="warning" label="Relay Notice">{relayError}</Notice>
              </div>
            )}
            {relaySuccess && (
              <div style={{ marginBottom: "1rem" }}>
                <Notice tone="success" label="Success">{relaySuccess}</Notice>
              </div>
            )}
            <List>
              <ListRow
                title="Relay connection"
                meta={
                  relayStatus
                    ? `Endpoint: ${relayStatus.relay_url}`
                    : "End-to-end encrypted connection to sync relay."
                }
                trailing={
                  relayStatus?.connected ? (
                    <Badge tone="success">Connected</Badge>
                  ) : (
                    <Badge tone="neutral">{relayLoading ? "Checking..." : "Offline"}</Badge>
                  )
                }
              />
              <ListRow
                title="Device slots"
                meta={`${relayStatus?.active_devices ?? 1} of ${relayStatus?.device_limit ?? 1} devices registered.`}
                trailing={
                  <Badge
                    tone={
                      (relayStatus?.active_devices ?? 1) >= (relayStatus?.device_limit ?? 1)
                        ? "warning"
                        : "neutral"
                    }
                  >
                    {relayStatus ? `${relayStatus.active_devices} / ${relayStatus.device_limit}` : "1 / 1"}
                  </Badge>
                }
              />
              <ListRow
                title="Outbox queue"
                meta="Local changes awaiting sync. All changes are encrypted before transmission."
                trailing={<Badge tone="neutral">{relayStatus?.pending_outbox_count ?? 0} pending</Badge>}
              />
              <ListRow
                title="Register with Relay"
                meta="Register this workspace and device public key on the zero-knowledge relay."
                trailing={
                  <Button
                    variant="secondary"
                    disabled={relayRegistering || readOnly}
                    onClick={handleRegisterWithRelay}
                  >
                    {relayRegistering ? "Registering..." : "Register store"}
                  </Button>
                }
              />
              <ListRow
                title="Manual sync"
                meta={
                  readOnly
                    ? "This device was unlinked from Secwet. Sync is disabled."
                    : lastSyncResult || "Trigger an immediate exchange with the sync relay."
                }
                trailing={
                  <Button
                    variant="secondary"
                    disabled={isSyncing || readOnly}
                    onClick={async () => {
                      await handleManualSync();
                      await fetchRelayStatus();
                    }}
                  >
                    {isSyncing ? "Syncing..." : "Sync now"}
                  </Button>
                }
              />
            </List>
          </Section>

          <Section title="Zero-Knowledge Invariants">
            <ul className={styles.limits}>
              <li>
                The sync relay never sees, processes, or stores your master key, secret values, or decrypted metadata.
              </li>
              <li>
                All requests are cryptographically authenticated with your device's Ed25519 signing key and protected against replay attacks.
              </li>
              <li>
                Database records on the relay store only opaque ciphertext payloads and non-identifying IDs.
              </li>
            </ul>
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
