import { useEffect, useState } from "react";
import { Button } from "./components/Button";
import { EmptyState } from "./components/EmptyState";
import { Icon } from "./components/Icon";
import { Notice } from "./components/Notice";
import { UnlockScreen } from "./components/UnlockScreen";
import { type Device, type Plan } from "./data/mock";
import { usePlanStatus } from "./lib/usePlan";
import { useIdleTimer } from "./hooks/useIdleTimer";
import { BottomTabs } from "./layout/BottomTabs";
import { Sidebar } from "./layout/Sidebar";
import { TopBar } from "./layout/TopBar";
import { type Route } from "./layout/routes";
import {
  canCreateSpace,
  canManageMembers,
  canPairDevices,
  isShareableSpace,
  canRotateMasterKey,
  isReadOnly,
  permissionsFor,
} from "./lib/access";
import { api, isLocked, isUnlocked, isUninitialized, type DeviceView, type SpaceView, type TreeNodeKind } from "./lib/api";
import { useStore } from "./lib/store";
import { ItemScreen } from "./screens/items/ItemScreen";
import { GroupScreen } from "./screens/groups/GroupScreen";
import { NewItemDialog } from "./screens/groups/NewItemDialog";
import { NewGroupDialog } from "./screens/groups/NewGroupDialog";
import { OverviewScreen } from "./screens/overview/OverviewScreen";
import { CustomizeDashboardDialog } from "./screens/overview/CustomizeDashboardDialog";
import { SettingsScreen, type SettingsTab } from "./screens/settings/SettingsScreen";
import { NewSpaceDialog } from "./screens/spaces/NewSpaceDialog";
import { OnboardingScreen } from "./screens/onboarding/OnboardingScreen";
import { RestoreDialog } from "./screens/recovery/RestoreDialog";
import { ShareDialog } from "./screens/sharing/ShareDialog";
import { MembersDialog } from "./screens/members/MembersDialog";
import styles from "./App.module.css";

function toDevice(d: DeviceView): Device {
  return {
    id: d.id,
    name: d.name,
    platform: d.platform,
    fingerprint: d.fingerprint,
    addedAt: d.added_at,
    lastSyncAt: d.last_seen_at ?? d.last_sync_at ?? undefined,
    revokedAt: d.revoked_at ?? undefined,
    current: Boolean(d.is_current ?? d.current),
  };
}

export function App() {
  const [route, setRoute] = useState<Route>("overview");
  const [appState, store] = useStore();
  const {
    spaces,
    activeSpaceId,
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

  const [creatingSpace, setCreatingSpace] = useState(false);
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [creatingItemGroupId, setCreatingItemGroupId] = useState<string | null>(null);
  const [cliConnected, setCliConnected] = useState(() => {
    return typeof window !== "undefined" && window.localStorage.getItem("secwet:cli_guide_read") === "true";
  });

  function handleCliMarkedRead() {
    if (typeof window !== "undefined") {
      window.localStorage.setItem("secwet:cli_guide_read", "true");
    }
    setCliConnected(true);
  }
  // The real plan comes from the relay entitlement (F13). The "Simulate plan"
  // switch in Settings overrides it in development builds only.
  const planStatus = usePlanStatus();
  const [simulatedPlan, setPlan] = useState<Plan | null>(null);
  const plan: Plan = (import.meta.env.DEV && simulatedPlan) || (planStatus?.plan === "pro" ? "pro" : "free");
  const [devices, setDevices] = useState<Device[]>([]);
  const [membersSpace, setMembersSpace] = useState<SpaceView | null>(null);
  const [sharing, setSharing] = useState<{ spaceId: string; focus?: { kind: TreeNodeKind; id: string } } | null>(
    null
  );
  const [recoveryKeyCreatedAt, setRecoveryKeyCreatedAt] = useState<number>();
  const [restoringBackup, setRestoringBackup] = useState(false);
  const [settingsTab, setSettingsTab] = useState<SettingsTab>("general");

  const effectiveRecoveryKeyCreatedAt = appState.recoveryStatus?.created
    ? (appState.recoveryStatus.createdAt || recoveryKeyCreatedAt || Date.now())
    : recoveryKeyCreatedAt;

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

  // Devices come from the backend (mock in browser preview); refresh on device changes.
  const unlocked = isUnlocked(status);
  useEffect(() => {
    if (!unlocked) return;
    let cancelled = false;
    const load = () =>
      api
        .devicesList()
        .then((list) => {
          if (!cancelled) setDevices(list.map(toDevice));
        })
        .catch(() => {});
    load();
    let unlisten: (() => void) | undefined;
    api
      .onSecwetChanged((e) => {
        if (e.scope === "devices" || e.scope === "all") load();
      })
      .then((fn) => {
        if (cancelled) fn();
        else unlisten = fn;
      });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [unlocked]);

  // After a remote wipe the store is gone: drop screen state so onboarding starts clean.
  const uninitialized = isUninitialized(status);
  useEffect(() => {
    if (!uninitialized) return;
    setRoute("overview");
    setSettingsTab("general");
    setDevices([]);
    setSharing(null);
    setMembersSpace(null);
    setCreatingSpace(false);
    setCreatingGroup(false);
    setCreatingItemGroupId(null);
    setCustomizingDashboard(false);
    setRestoringBackup(false);
    setIsEditingHomeTitle(false);
  }, [uninitialized]);

  // Member mode and read-only archive (M7 / M8)
  const access = appState.access;
  const readOnly = isReadOnly(appState.linkStatus);
  const canPair = canPairDevices(appState.access, readOnly);
  const canManageMembersHere = canManageMembers(appState.access);
  const spacePerms = (spaceId: string | null | undefined) =>
    permissionsFor(access, readOnly, { spaceId: spaceId ?? null });
  const groupPerms = (groupId: string | null | undefined) => {
    const g = groups.find((x) => x.id === groupId);
    return permissionsFor(access, readOnly, { spaceId: g?.space_id ?? null, groupId: groupId ?? null });
  };
  const manageableSpaces = spaces.filter((s) => spacePerms(s.id).canManage);
  const canCreateGroupHere = activeSpaceId ? spacePerms(activeSpaceId).canManage : manageableSpaces.length > 0;
  const canCreateSpaceHere = canCreateSpace(access, readOnly);
  const pendingRotation =
    appState.keyStatus?.rotation_recommended && canRotateMasterKey(access, readOnly)
      ? appState.keyStatus.pending_reason?.trim() || "A device was revoked."
      : undefined;

  // Personal space and active space calculations
  const personalSpace = spaces.find((s) => s.is_default || s.name.toLowerCase() === "personal");

  const visibleGroups = activeSpaceId
    ? groups.filter((g) => g.space_id === activeSpaceId)
    : groups;

  const visibleGroupIds = new Set(visibleGroups.map((g) => g.id));
  const visibleItems = activeSpaceId
    ? items.filter((i) => visibleGroupIds.has(i.group_id ?? i.label_id))
    : items;

  // Selected entities strictly within visible groups & visible items:
  const activeGroup =
    visibleGroups.find((g) => g.id === selectedGroupId) ||
    visibleGroups[0] ||
    null;
  const activeItem =
    visibleItems.find((i) => i.id === selectedItemId) ||
    (activeGroup ? visibleItems.find((i) => (i.group_id ?? i.label_id) === activeGroup.id) : null) ||
    visibleItems[0] ||
    null;
  const activeItemGroup = activeItem
    ? visibleGroups.find((g) => g.id === (activeItem.group_id ?? activeItem.label_id)) || activeGroup
    : activeGroup;
  const activeItemSpace = spaces.find((s) => s.id === activeItemGroup?.space_id) ?? null;

  const newTargetGroupId = activeGroup?.id || visibleGroups[0]?.id || null;
  const canCreateFromTopBar =
    visibleGroups.length === 0 ? canCreateGroupHere : groupPerms(newTargetGroupId).canManage;
  // "Add secret" opens the active item, or a group to pick one: allowed when this device can write there.
  const canAddSecretHere = activeItem
    ? permissionsFor(access, readOnly, {
        spaceId: activeItemGroup?.space_id ?? null,
        groupId: activeItem.group_id ?? activeItem.label_id ?? null,
        itemId: activeItem.id,
        general: true,
      }).canWrite || canCreateFromTopBar
    : canCreateFromTopBar;

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

  // When secwet is uninitialized, render the OnboardingScreen
  if (isUninitialized(status) || (isUnlocked(status) && appState.joining)) {
    return (
      <div className={styles.shell}>
        <OnboardingScreen
          onCreateWorkspace={async (deviceName) => {
            await store.createWorkspace(deviceName);
          }}
          onRestoreBackup={() => setRestoringBackup(true)}
          onJoinWithInvite={async (link, email, deviceName) => {
            await store.acceptInvitation(link, email, deviceName);
          }}
          waitingForAccess={isUnlocked(status) && appState.joining}
          wiped={appState.wipedNotice}
          onPollAccess={() => store.pollJoinedAccess()}
          onStopWaiting={() => {
            store.finishJoining();
          }}
          defaultDeviceName={effectiveDeviceName}
        />
        {restoringBackup && (
          <RestoreDialog
            onClose={() => setRestoringBackup(false)}
            onRestored={() => setRestoringBackup(false)}
            defaultDeviceName={effectiveDeviceName}
          />
        )}
      </div>
    );
  }

  // When secwet is locked, render the UnlockScreen
  if (isLocked(status)) {
    return (
      <div className={styles.shell}>
        <UnlockScreen
          onUnlock={(recoveryKey) => store.unlock(recoveryKey)}
          deviceName={effectiveDeviceName}
          onRestore={() => setRestoringBackup(true)}
        />
        {restoringBackup && (
          <RestoreDialog
            onClose={() => setRestoringBackup(false)}
            onRestored={() => setRestoringBackup(false)}
            defaultDeviceName={effectiveDeviceName}
          />
        )}
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
        spaces={spaces}
        activeSpaceId={activeSpaceId}
        onSelectSpace={(id) => store.selectSpace(id)}
        onNewSpace={canCreateSpaceHere ? () => setCreatingSpace(true) : undefined}
        onRenameSpace={(id, name, icon) => store.renameSpace(id, name, icon)}
        onDeleteSpace={(id) => store.deleteSpace(id)}
        canEditSpaces={canCreateSpaceHere}
        canShareSpace={(s: SpaceView) => isShareableSpace(s) && spacePerms(s.id).canShare}
        onShareSpace={(s: SpaceView) => setSharing({ spaceId: s.id })}
        onOpenMembers={canManageMembersHere ? (s: SpaceView) => setMembersSpace(s) : undefined}
        canCreateGroup={canCreateGroupHere}
        canAddToGroup={(groupId) => groupPerms(groupId).canManage}
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
                {canPair && (
                  <Button
                    variant="secondary"
                    onClick={() => {
                      setSettingsTab("devices");
                      setRoute("settings");
                    }}
                  >
                    Pair device
                  </Button>
                )}
                {canCreateFromTopBar && (
                  <Button
                    variant="primary"
                    icon="plus"
                    onClick={() => {
                      if (visibleGroups.length === 0) {
                        setCreatingGroup(true);
                      } else {
                        setCreatingItemGroupId(newTargetGroupId);
                      }
                    }}
                  >
                    New
                  </Button>
                )}
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
          {readOnly && (
            <div className={styles.banner}>
              <Notice tone="warning" label="Unlinked">
                This device was unlinked from Secwet. Sync is disabled. You can still view and export.
              </Notice>
            </div>
          )}

          {route === "overview" && (
            <OverviewScreen
              plan={plan}
              cliConnected={cliConnected}
              onCliCopied={handleCliMarkedRead}
              items={visibleItems}
              isSpaceFiltered={activeSpaceId !== null}
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
                if (!canCreateFromTopBar) return;
                if (visibleGroups.length === 0) {
                  setCreatingGroup(true);
                } else {
                  setCreatingItemGroupId(newTargetGroupId);
                }
              }}
              onAddSecret={() => {
                if (activeItem) {
                  setRoute("item");
                } else if (activeGroup) {
                  setRoute("group");
                } else if (canCreateGroupHere) {
                  setCreatingGroup(true);
                }
              }}
              canCreate={canCreateFromTopBar}
              canAddSecret={canAddSecretHere}
              canPair={canPair}
              onOpenDevices={() => {
                setSettingsTab("devices");
                setRoute("settings");
              }}
              onOpenRecovery={() => {
                setSettingsTab("recovery");
                setRoute("settings");
              }}
              onOpenSecurity={() => {
                setSettingsTab("security");
                setRoute("settings");
              }}
              onOpenCli={() => {
                setSettingsTab("cli");
                setRoute("settings");
              }}
              onOpenSettings={() => {
                setSettingsTab("general");
                setRoute("settings");
              }}
              devices={devices}
              recoveryKeyCreatedAt={effectiveRecoveryKeyCreatedAt}
              pendingRotation={pendingRotation}
            />
          )}

          {route === "group" &&
            (activeGroup ? (
              <GroupScreen
                key={activeGroup.id}
                group={activeGroup}
                groups={visibleGroups}
                items={visibleItems}
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
                canManage={groupPerms(activeGroup.id).canManage}
              />
            ) : (
              <EmptyState
                icon="folder"
                title="No groups in this space"
                body={
                  canCreateGroupHere
                    ? "Create a group to organize your projects, credentials, and services."
                    : "Nothing in this space is shared with you yet."
                }
                action={
                  canCreateGroupHere ? (
                    <Button
                      variant="primary"
                      icon="plus"
                      onClick={() => setCreatingGroup(true)}
                    >
                      New Group
                    </Button>
                  ) : undefined
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
                onShare={
                  activeItemSpace && isShareableSpace(activeItemSpace)
                    ? (target) => setSharing({ spaceId: activeItemSpace.id, focus: target })
                    : undefined
                }
              />
            ) : (
              <EmptyState
                icon="folder"
                title="No entry selected"
                body="Select an entry from the sidebar or create a new one."
                action={
                  activeGroup || canCreateFromTopBar ? (
                    <Button
                      variant="primary"
                      onClick={() => {
                        if (activeGroup) setRoute("group");
                        else if (visibleGroups.length === 0) {
                          if (canCreateGroupHere) setCreatingGroup(true);
                        } else if (groupPerms(visibleGroups[0].id).canManage) {
                          setCreatingItemGroupId(visibleGroups[0].id);
                        }
                      }}
                    >
                      {activeGroup ? "View group" : "New"}
                    </Button>
                  ) : undefined
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
              onCliCopied={handleCliMarkedRead}
              homeLabel={settings.home_label}
              onHomeLabelChange={(hl) => store.updateSettings({ home_label: hl })}
              deviceName={effectiveDeviceName}
              onDeviceNameChange={(dn) => store.updateSettings({ device_name: dn })}
              devices={devices}
              onPairDevice={(d) => setDevices((all) => [...all.filter((x) => x.id !== d.id), d])}
              onRevokeDevice={(id) => {
                setDevices((all) =>
                  all.map((d) => (d.id === id ? { ...d, revokedAt: Date.now() } : d))
                );
              }}
              recoveryKeyCreatedAt={effectiveRecoveryKeyCreatedAt}
              onRecoveryKeyCreated={() => setRecoveryKeyCreatedAt(Date.now())}
              initialTab={settingsTab}
            />
          )}
        </main>
      </div>

      <BottomTabs route={route} onNavigate={setRoute} />

      {creatingSpace && (
        <NewSpaceDialog
          onCancel={() => setCreatingSpace(false)}
          onCreate={async (name, icon) => {
            const created = await store.createSpace(name, icon);
            store.selectSpace(created.id);
            setCreatingSpace(false);
          }}
        />
      )}

      {creatingGroup && (
        <NewGroupDialog
          spaces={manageableSpaces}
          defaultSpaceId={
            (activeSpaceId && manageableSpaces.some((s) => s.id === activeSpaceId) ? activeSpaceId : null) ||
            (personalSpace && manageableSpaces.some((s) => s.id === personalSpace.id) ? personalSpace.id : null) ||
            manageableSpaces[0]?.id
          }
          onCancel={() => setCreatingGroup(false)}
          onCreate={async (name, icon, spaceId) => {
            const created = await store.createGroup(name, icon, spaceId);
            await store.selectGroup(created.id);
            setRoute("group");
            setCreatingGroup(false);
          }}
        />
      )}

      {membersSpace && <MembersDialog space={membersSpace} onClose={() => setMembersSpace(null)} />}

      {sharing && (
        <ShareDialog
          spaces={spaces}
          initialSpaceId={sharing.spaceId}
          focus={sharing.focus ?? null}
          canShareSpace={(s) => spacePerms(s.id).canShare}
          onClose={() => setSharing(null)}
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

      {creatingItemGroupId && (
        <NewItemDialog
          groups={visibleGroups}
          initialGroupId={creatingItemGroupId}
          existingItems={visibleItems}
          onCancel={() => setCreatingItemGroupId(null)}
          onCreate={async (name, desc, targetGroupId) => {
            const finalGroupId = targetGroupId || creatingItemGroupId || activeGroup?.id || visibleGroups[0]?.id;
            if (!finalGroupId) return;
            const created = await store.createItem(finalGroupId, name, desc);
            setCreatingItemGroupId(null);
            await store.selectItem(created.id);
            setRoute("item");
          }}
        />
      )}
    </div>
  );
}
