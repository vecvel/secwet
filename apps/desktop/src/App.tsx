import { useEffect, useState } from "react";
import { Button } from "./components/Button";
import { EmptyState } from "./components/EmptyState";
import { SelectControl } from "./components/Field";
import { UnlockScreen } from "./components/UnlockScreen";
import { initialDevices, type Device, type Plan } from "./data/mock";
import { useIdleTimer } from "./hooks/useIdleTimer";
import { BottomTabs } from "./layout/BottomTabs";
import { Sidebar } from "./layout/Sidebar";
import { TopBar } from "./layout/TopBar";
import { destinations, type Route } from "./layout/routes";
import { isLocked, isUnlocked } from "./lib/api";
import { useVault } from "./lib/store";
import { DevicesScreen } from "./screens/devices/DevicesScreen";
import { OverviewScreen } from "./screens/overview/OverviewScreen";
import { NewProjectDialog } from "./screens/projects/NewProjectDialog";
import { RecoveryScreen } from "./screens/recovery/RecoveryScreen";
import { SecretsScreen } from "./screens/secrets/SecretsScreen";
import { SettingsScreen } from "./screens/settings/SettingsScreen";
import styles from "./App.module.css";

export function App() {
  const [route, setRoute] = useState<Route>("overview");
  const [vaultState, store] = useVault();
  const { projects, secrets, status, settings } = vaultState;

  const [creatingProject, setCreatingProject] = useState(false);
  const [pendingAddSecret, setPendingAddSecret] = useState(false);
  const [cliConnected, setCliConnected] = useState(false);
  const [plan, setPlan] = useState<Plan>("free");
  const [devices, setDevices] = useState<Device[]>(initialDevices);
  const [pendingRotation, setPendingRotation] = useState<string>();
  const [vaultKeyRotatedAt, setVaultKeyRotatedAt] = useState<number>();
  const [recoveryKeyCreatedAt, setRecoveryKeyCreatedAt] = useState<number>();

  // Auto-lock Idle Timer
  useIdleTimer({
    timeoutMinutes: settings.lock_minutes,
    onIdle: () => store.lock(),
    enabled: isUnlocked(status),
  });

  // Sync theme to root html element
  useEffect(() => {
    const root = document.documentElement;
    if (settings.theme === "system") delete root.dataset.theme;
    else root.dataset.theme = settings.theme;
  }, [settings.theme]);

  // Falls back to the first project when the selected one was deleted.
  const project = projects.find((p) => p.id === vaultState.selectedProjectId) ?? projects[0];
  const projectId = project?.id;
  const environmentId =
    vaultState.selectedEnvironmentId && project?.environments.some((e) => e.id === vaultState.selectedEnvironmentId)
      ? vaultState.selectedEnvironmentId
      : project?.environments[0]?.id;
  const routeLabel = destinations.find((d) => d.id === route)!.label;

  // When vault is locked, render the UnlockScreen
  if (isLocked(status)) {
    return (
      <div className={styles.shell}>
        <UnlockScreen onUnlock={() => store.unlock()} deviceName={settings.device_name} />
      </div>
    );
  }

  return (
    <div className={styles.shell}>
      <Sidebar
        route={route}
        onNavigate={setRoute}
        projects={projects}
        projectId={projectId}
        onSelectProject={(id) => store.selectProject(id)}
        onNewProject={() => setCreatingProject(true)}
        plan={plan}
      />
      <div className={styles.main}>
        <TopBar>
          {route === "secrets" && project ? (
            <>
              <span className={styles.crumb}>Projects</span>
              <span className={styles.crumbSep} aria-hidden="true">
                /
              </span>
              <span className={styles.crumbCurrent}>{project.name}</span>
              <div className={styles.projectPicker}>
                <SelectControl aria-label="Project" value={projectId} onChange={(e) => store.selectProject(e.target.value)}>
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </SelectControl>
              </div>
            </>
          ) : (
            <span className={styles.crumbCurrent}>{routeLabel}</span>
          )}
        </TopBar>
        <main className={styles.content}>
          {route === "secrets" &&
            (project && environmentId ? (
              <SecretsScreen
                key={project.id}
                project={project}
                projects={projects}
                environmentId={environmentId}
                onEnvironmentChange={(id) => store.selectEnvironment(project.id, id)}
                secrets={secrets}
                dispatch={store.dispatch}
                onNewProject={() => setCreatingProject(true)}
                startAdding={pendingAddSecret}
                onStartedAdding={() => setPendingAddSecret(false)}
              />
            ) : (
              <EmptyState
                icon="folder"
                title="Create your first project"
                body="A project holds the secrets for one app or service, split into environments like Development and Production."
                action={
                  <Button variant="primary" icon="plus" onClick={() => setCreatingProject(true)}>
                    New project
                  </Button>
                }
              />
            ))}
          {route === "overview" && (
            <OverviewScreen
              projects={projects}
              secrets={secrets}
              devices={devices}
              plan={plan}
              recoveryKeyCreatedAt={recoveryKeyCreatedAt}
              pendingRotation={pendingRotation}
              cliConnected={cliConnected}
              onCliCopied={() => setCliConnected(true)}
              onOpenProject={(id, envId) => {
                store.selectProject(id, envId);
                setRoute("secrets");
              }}
              onNewProject={() => setCreatingProject(true)}
              onAddSecret={() => {
                setPendingAddSecret(true);
                setRoute("secrets");
              }}
              onOpenDevices={() => setRoute("devices")}
              onOpenRecovery={() => setRoute("recovery")}
            />
          )}
          {route === "devices" && (
            <DevicesScreen
              devices={devices}
              plan={plan}
              pendingRotation={pendingRotation}
              onPair={(d) => setDevices((all) => [...all, d])}
              onRevoke={(id) => {
                setDevices((all) => all.map((d) => (d.id === id ? { ...d, revokedAt: Date.now() } : d)));
                setPendingRotation(devices.find((d) => d.id === id)?.name);
              }}
              onOpenRecovery={() => setRoute("recovery")}
            />
          )}
          {route === "recovery" && (
            <RecoveryScreen
              recoveryKeyCreatedAt={recoveryKeyCreatedAt}
              vaultKeyRotatedAt={vaultKeyRotatedAt}
              pendingRotation={pendingRotation}
              secretCount={secrets.length}
              projectCount={projects.length}
              onRecoveryKeyCreated={() => setRecoveryKeyCreatedAt(Date.now())}
              onRotated={() => {
                setVaultKeyRotatedAt(Date.now());
                setPendingRotation(undefined);
              }}
            />
          )}
          {route === "settings" && (
            <SettingsScreen
              plan={plan}
              onPlanChange={setPlan}
              theme={settings.theme}
              onThemeChange={(t) => store.updateSettings({ theme: t })}
              lockMinutes={settings.lock_minutes}
              onLockMinutesChange={(m) => store.updateSettings({ lock_minutes: m, lock_timeout_minutes: m })}
              onCliCopied={() => setCliConnected(true)}
            />
          )}
        </main>
      </div>
      <BottomTabs route={route} onNavigate={setRoute} />
      {creatingProject && (
        <NewProjectDialog
          projects={projects}
          onCancel={() => setCreatingProject(false)}
          onCreate={async (p) => {
            const envNames = p.environments.map((e) => e.name);
            const created = await store.createProject(p.name, envNames);
            store.selectProject(created.id, created.environments[0]?.id);
            setRoute("secrets");
            setCreatingProject(false);
          }}
        />
      )}
    </div>
  );
}
