import { useEffect, useState } from "react";
import { Button } from "./components/Button";
import { EmptyState } from "./components/EmptyState";
import { Icon } from "./components/Icon";
import { UnlockScreen } from "./components/UnlockScreen";
import { initialDevices, type Device, type Plan } from "./data/mock";
import { useIdleTimer } from "./hooks/useIdleTimer";
import { BottomTabs } from "./layout/BottomTabs";
import { Sidebar } from "./layout/Sidebar";
import { TopBar } from "./layout/TopBar";
import { type Route } from "./layout/routes";
import { api, isLocked, isUnlocked } from "./lib/api";
import { useStore } from "./lib/store";
import { ItemScreen } from "./screens/items/ItemScreen";
import { GroupScreen } from "./screens/groups/GroupScreen";
import { NewItemDialog } from "./screens/groups/NewItemDialog";
import { NewGroupDialog } from "./screens/groups/NewGroupDialog";
import { OverviewScreen } from "./screens/overview/OverviewScreen";
import { CustomizeDashboardDialog } from "./screens/overview/CustomizeDashboardDialog";
import { SettingsScreen, type SettingsTab } from "./screens/settings/SettingsScreen";
import styles from "./App.module.css";

export function App() {
  const [route, setRoute] = useState<Route>("overview");
  const [appState, store] = useStore();
  const {
    groups,
    items,
    environments,
    secrets,
    assets,
    notes,
    status,
    settings,
    dashboardConfig,
    selectedGroupId,
    selectedItemId,
    selectedEnvironmentId,
  } = appState;

  const [creatingGroup, setCreatingGroup] = useState(false);
  const [creatingItemGroupId, setCreatingItemGroupId] = useState<string | null>(null);
  const [cliConnected, setCliConnected] = useState(false);
  const [plan, setPlan] = useState<Plan>("free");
  const [devices, setDevices] = useState<Device[]>(initialDevices);
  const [pendingRotation, setPendingRotation] = useState<string>();
  const [keyRotatedAt, setKeyRotatedAt] = useState<number>();
  const [recoveryKeyCreatedAt, setRecoveryKeyCreatedAt] = useState<number>();
  const [settingsTab, setSettingsTab] = useState<SettingsTab>("general");

  // Auto-lock Idle Timer
  useIdleTimer({
    timeoutMinutes: settings.lock_minutes || 15,
    onIdle: () => store.lock(),
    enabled: isUnlocked(status),
  });

  // Sync theme to root html element
  useEffect(() => {
    const root = document.documentElement;
    if (settings.theme === "system") {
      delete root.dataset.theme;
    } else {
      root.dataset.theme = settings.theme;
    }
  }, [settings.theme]);

  // Selected entities
  const activeGroup =
    groups.find((g) => g.id === selectedGroupId) ||
    groups[0];
  const activeItem =
    items.find((i) => i.id === selectedItemId) ||
    items.find((i) => (i.group_id ?? i.label_id) === activeGroup?.id) ||
    items[0];
  const activeItemGroup =
    groups.find((g) => g.id === (activeItem?.group_id ?? activeItem?.label_id)) ||
    activeGroup;

  const homeTitle = dashboardConfig.home_label || settings.home_label || "Overview";
  const [customizingDashboard, setCustomizingDashboard] = useState(false);
  const [isEditingHomeTitle, setIsEditingHomeTitle] = useState(false);
  const [homeTitleInput, setHomeTitleInput] = useState(homeTitle);

  async function handleSaveHomeTitle(newTitle: string) {
    setIsEditingHomeTitle(false);
    const trimmed = newTitle.trim() || "Overview";
    setHomeTitleInput(trimmed);
    await store.updateDashboard({
      ...dashboardConfig,
      home_label: trimmed,
    });
    await store.updateSettings({
      home_label: trimmed,
    });
  }

  const [realDeviceName, setRealDeviceName] = useState<string>("");
  useEffect(() => {
    api.systemDeviceName().then((n: string) => {
      if (n && n !== "desktop") setRealDeviceName(n);
    }).catch(() => {});
  }, []);

  const effectiveDeviceName =
    settings.device_name && settings.device_name !== "desktop" && settings.device_name !== "default-device"
      ? settings.device_name
      : (realDeviceName || "Desktop");

  useEffect(() => {
    setDevices((curr) =>
      curr.map((d) => (d.current ? { ...d, name: effectiveDeviceName } : d))
    );
  }, [effectiveDeviceName]);

  // When vault is locked, render the UnlockScreen
  if (isLocked(status)) {
    return (
      <div className={styles.shell}>
        <UnlockScreen
          onUnlock={() => store.unlock()}
          deviceName={effectiveDeviceName}
        />
      </div>
    );
  }

  return (
    <div className={styles.shell}>
      <Sidebar
        route={route}
        onNavigate={(r) => {
          if (r === "settings") setSettingsTab("general");
          setRoute(r);
        }}
        homeLabel={homeTitle}
        groups={groups}
        items={items}
        selectedGroupId={activeGroup?.id ?? null}
        selectedItemId={activeItem?.id ?? null}
        onSelectGroup={(id) => {
          store.selectGroup(id);
          setRoute("group");
        }}
        onSelectItem={(id) => {
          store.selectItem(id);
          setRoute("item");
        }}
        onNewGroup={() => setCreatingGroup(true)}
        onNewItemForGroup={(groupId) => setCreatingItemGroupId(groupId)}
        plan={plan}
        deviceName={effectiveDeviceName}
      />

      <div className={styles.main}>
        <TopBar
          actions={
            route === "overview" ? (
              <div className={styles.topBarActions}>
                <Button
                  variant="secondary"
                  icon="customize"
                  onClick={() => setCustomizingDashboard(true)}
                >
                  Customize
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => {
                    setSettingsTab("devices");
                    setRoute("settings");
                  }}
                >
                  Pair device
                </Button>
                <Button
                  variant="primary"
                  icon="plus"
                  onClick={() => {
                    const targetGroup = activeGroup || groups[0];
                    if (targetGroup) {
                      setCreatingItemGroupId(targetGroup.id);
                    } else {
                      setCreatingGroup(true);
                    }
                  }}
                >
                  New
                </Button>
              </div>
            ) : undefined
          }
        >
          {route === "overview" && (
            isEditingHomeTitle ? (
              <input
                type="text"
                className={styles.titleInput}
                value={homeTitleInput}
                autoFocus
                onChange={(e) => setHomeTitleInput(e.target.value)}
                onBlur={() => handleSaveHomeTitle(homeTitleInput)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSaveHomeTitle(homeTitleInput);
                  if (e.key === "Escape") {
                    setHomeTitleInput(homeTitle);
                    setIsEditingHomeTitle(false);
                  }
                }}
              />
            ) : (
              <span
                className={styles.crumbCurrent}
                onDoubleClick={() => {
                  setHomeTitleInput(homeTitle);
                  setIsEditingHomeTitle(true);
                }}
                title="Double-click to rename"
                style={{ cursor: "pointer" }}
              >
                {homeTitle}
              </span>
            )
          )}

          {route === "group" && activeGroup && (
            <span className={styles.crumbCurrent}>{activeGroup.name}</span>
          )}

          {route === "item" && activeItem && (
            <>
              {activeItemGroup && (
                <>
                  <button
                    className={styles.crumbBtn}
                    onClick={() => {
                      store.selectGroup(activeItemGroup.id);
                      setRoute("group");
                    }}
                  >
                    {activeItemGroup.name}
                  </button>
                  <span className={styles.crumbSep} aria-hidden="true">
                    <Icon name="dot" size={14} />
                  </span>
                </>
              )}
              <span className={styles.crumbCurrent}>{activeItem.name}</span>
            </>
          )}

          {route === "settings" && (
            <span className={styles.crumbCurrent}>Settings</span>
          )}
        </TopBar>

        <main className={styles.content}>
          {route === "overview" && (
            <OverviewScreen
              plan={plan}
              cliConnected={cliConnected}
              onCliCopied={() => setCliConnected(true)}
              onOpenItem={(itemId, envId) => {
                store.selectItem(itemId, envId);
                setRoute("item");
              }}
              onOpenGroup={(groupId) => {
                store.selectGroup(groupId);
                setRoute("group");
              }}
              onOpenLabel={(labelId) => {
                store.selectGroup(labelId);
                setRoute("group");
              }}
              onNewItem={() => {
                if (activeGroup) {
                  setRoute("group");
                } else {
                  setCreatingGroup(true);
                }
              }}
              onAddSecret={() => {
                if (activeItem) {
                  setRoute("item");
                } else if (activeGroup) {
                  setRoute("group");
                } else {
                  setCreatingGroup(true);
                }
              }}
              onOpenDevices={() => {
                setSettingsTab("devices");
                setRoute("settings");
              }}
              onOpenRecovery={() => {
                setSettingsTab("recovery");
                setRoute("settings");
              }}
              onOpenSettings={() => {
                setSettingsTab("general");
                setRoute("settings");
              }}
              devices={devices}
              recoveryKeyCreatedAt={recoveryKeyCreatedAt}
              pendingRotation={pendingRotation}
            />
          )}

          {route === "group" &&
            (activeGroup ? (
              <GroupScreen
                key={activeGroup.id}
                group={activeGroup}
                groups={groups}
                items={items}
                onSelectItem={(itemId) => {
                  store.selectItem(itemId);
                  setRoute("item");
                }}
                onCreateItem={async (name, desc) => {
                  const created = await store.createItem(activeGroup.id, name, desc);
                  await store.selectItem(created.id);
                  setRoute("item");
                }}
                onRenameGroup={(id, name) => store.renameGroup(id, name)}
                onDeleteGroup={async (id) => {
                  await store.deleteGroup(id);
                  setRoute("overview");
                }}
              />
            ) : (
              <EmptyState
                icon="folder"
                title="No sections yet"
                body="Create a section to organize your projects, credentials, and services."
                action={
                  <Button
                    variant="primary"
                    icon="plus"
                    onClick={() => setCreatingGroup(true)}
                  >
                    New
                  </Button>
                }
              />
            ))}

          {route === "item" &&
            (activeItem ? (
              <ItemScreen
                key={activeItem.id}
                item={activeItem}
                group={activeItemGroup}
                environments={environments}
                secrets={secrets}
                assets={assets}
                files={assets}
                notes={notes}
                selectedEnvironmentId={selectedEnvironmentId}
                onSelectEnvironment={(envId) => store.selectEnvironment(envId)}
                onBackToGroup={() => {
                  if (activeItemGroup) store.selectGroup(activeItemGroup.id);
                  setRoute("group");
                }}
                onRenameItem={(id, name, desc) => store.renameItem(id, name, desc)}
                onDeleteItem={async (id) => {
                  await store.deleteItem(id);
                  setRoute("group");
                }}
                onAddEnvironment={(itemId, name) =>
                  store.addEnvironment(itemId, name).then(() => {})
                }
                onRenameEnvironment={(id, name) => store.renameEnvironment(id, name)}
                onDeleteEnvironment={(id, preserve) =>
                  store.deleteEnvironment(id, preserve)
                }
                onAddSecret={(draft) => store.addSecret(draft).then(() => {})}
                onAddSecrets={(drafts) => store.addSecrets(drafts).then(() => {})}
                onUpdateSecret={(id, draft) =>
                  store.updateSecret(id, draft).then(() => {})
                }
                onDeleteSecret={(id: string) => store.deleteSecret(id)}
                onCopySecretToEnvironment={(id: string, envId?: string | null) =>
                  store.copySecretToEnvironment(id, envId).then(() => {})
                }
                onUploadAsset={(name: string, mime: string, bytes: number[] | Uint8Array) =>
                  store.uploadAsset(activeItem.id, selectedEnvironmentId, name, mime, bytes).then(() => {})
                }
                onRenameAsset={(id: string, name: string) => store.renameAsset(id, name).then(() => {})}
                onDeleteAsset={(id: string) => store.deleteAsset(id)}
                onUploadFile={(name: string, mime: string, bytes: number[] | Uint8Array) =>
                  store.uploadAsset(activeItem.id, selectedEnvironmentId, name, mime, bytes).then(() => {})
                }
                onRenameFile={(id: string, name: string) => store.renameAsset(id, name).then(() => {})}
                onDeleteFile={(id: string) => store.deleteAsset(id)}
                onCreateNote={(title: string, content: string) =>
                  store.createNote({
                    item_id: activeItem.id,
                    environment_id: selectedEnvironmentId,
                    title,
                    content,
                  }).then(() => {})
                }
                onUpdateNote={(id: string, title?: string, content?: string) =>
                  store.updateNote(id, { title, content })
                }
                onDeleteNote={(id: string) => store.deleteNote(id)}
              />
            ) : (
              <EmptyState
                icon="folder"
                title="No entry selected"
                body="Select an entry from the section or create a new one."
                action={
                  <Button
                    variant="primary"
                    onClick={() => {
                      if (activeGroup) setRoute("group");
                      else setCreatingGroup(true);
                    }}
                  >
                    View
                  </Button>
                }
              />
            ))}

          {route === "settings" && (
            <SettingsScreen
              plan={plan}
              onPlanChange={setPlan}
              theme={settings.theme}
              onThemeChange={(t) => store.updateSettings({ theme: t })}
              lockMinutes={settings.lock_minutes}
              onLockMinutesChange={(m) =>
                store.updateSettings({ lock_minutes: m, lock_timeout_minutes: m })
              }
              onCliCopied={() => setCliConnected(true)}
              homeLabel={settings.home_label}
              onHomeLabelChange={(hl) => store.updateSettings({ home_label: hl })}
              deviceName={effectiveDeviceName}
              onDeviceNameChange={(dn) => store.updateSettings({ device_name: dn })}
              devices={devices}
              onPairDevice={(d) => setDevices((all) => [...all, d])}
              onRevokeDevice={(id) => {
                setDevices((all) =>
                  all.map((d) => (d.id === id ? { ...d, revokedAt: Date.now() } : d))
                );
                setPendingRotation(devices.find((d) => d.id === id)?.name);
              }}
              pendingRotation={pendingRotation}
              keyRotatedAt={keyRotatedAt}
              recoveryKeyCreatedAt={recoveryKeyCreatedAt}
              onRecoveryKeyCreated={() => setRecoveryKeyCreatedAt(Date.now())}
              onRotated={() => {
                setKeyRotatedAt(Date.now());
                setPendingRotation(undefined);
              }}
              initialTab={settingsTab}
            />
          )}
        </main>
      </div>

      <BottomTabs route={route} onNavigate={setRoute} />

      {creatingGroup && (
        <NewGroupDialog
          onCancel={() => setCreatingGroup(false)}
          onCreate={async (name, icon) => {
            const created = await store.createGroup(name, icon);
            await store.selectGroup(created.id);
            setRoute("group");
            setCreatingGroup(false);
          }}
        />
      )}

      {customizingDashboard && (
        <CustomizeDashboardDialog
          config={dashboardConfig}
          onClose={() => setCustomizingDashboard(false)}
          onSave={async (newConfig) => {
            await store.updateDashboard(newConfig);
            if (newConfig.home_label !== settings.home_label) {
              await store.updateSettings({ home_label: newConfig.home_label });
            }
          }}
        />
      )}

      {creatingItemGroupId && (() => {
        const targetGroup = groups.find((g) => g.id === creatingItemGroupId);
        if (!targetGroup) return null;
        return (
          <NewItemDialog
            groupName={targetGroup.name}
            existingItems={items.filter((it) => (it.group_id ?? it.label_id) === targetGroup.id)}
            onCancel={() => setCreatingItemGroupId(null)}
            onCreate={async (name, desc) => {
              const created = await store.createItem(targetGroup.id, name, desc);
              setCreatingItemGroupId(null);
              await store.selectItem(created.id);
              setRoute("item");
            }}
          />
        );
      })()}
    </div>
  );
}
