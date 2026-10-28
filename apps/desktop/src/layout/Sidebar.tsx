import { BrandMark, Icon, IconTile, type IconName } from "../components/Icon";
import { thisDevice, type Plan } from "../data/mock";
import type { GroupView, ItemView, SpaceView } from "../lib/api";
import { onWindowDragMouseDown } from "../lib/windowDrag";
import { SpaceSwitcher } from "./SpaceSwitcher";
import type { Route } from "./routes";
import styles from "./Sidebar.module.css";

interface Props {
  route: Route;
  onNavigate: (route: Route) => void;
  homeLabel?: string;
  spaces?: SpaceView[];
  activeSpaceId?: string | null;
  onSelectSpace?: (id: string | null) => void;
  onNewSpace?: () => void;
  onRenameSpace?: (id: string, name: string, icon?: string | null) => Promise<unknown> | void;
  onDeleteSpace?: (id: string) => Promise<unknown> | void;
  groups?: GroupView[];
  items?: ItemView[];
  selectedGroupId?: string | null;
  selectedItemId?: string | null;
  onSelectGroup?: (id: string) => void;
  onSelectItem?: (id: string) => void;
  onNewGroup?: () => void;
  onNewItemForGroup?: (groupId: string) => void;
  plan?: Plan;
  deviceName?: string;
  /** Member mode and read-only archive: which create controls to show. Default true. */
  canCreateGroup?: boolean;
  canAddToGroup?: (groupId: string) => boolean;
  canEditSpaces?: boolean;
  canShareSpace?: (space: SpaceView) => boolean;
  onShareSpace?: (space: SpaceView) => void;
}

interface ItemProps {
  label: string;
  icon?: IconName;
  initial?: string;
  active: boolean;
  onClick: () => void;
  className?: string;
}

function NavItem({ label, icon, initial, active, onClick, className }: ItemProps) {
  return (
    <button
      className={[styles.item, active && styles.active, className].filter(Boolean).join(" ")}
      aria-current={active ? "page" : undefined}
      title={label}
      onClick={onClick}
    >
      <IconTile icon={icon} initial={initial} selected={active} />
      <span className={styles.itemLabel}>{label}</span>
    </button>
  );
}

const initialOf = (name: string) =>
  name.replace(/[^A-Za-z0-9]/g, "").charAt(0).toUpperCase() || "#";

/** Redesigned sidebar with Home, Spaces Switcher, user-defined groups, and items under each group. */
export function Sidebar({
  route,
  onNavigate,
  homeLabel,
  spaces = [],
  activeSpaceId,
  onSelectSpace,
  onNewSpace,
  onRenameSpace,
  onDeleteSpace,
  groups = [],
  items = [],
  selectedGroupId,
  selectedItemId,
  onSelectGroup,
  onSelectItem,
  onNewGroup,
  onNewItemForGroup,
  deviceName,
  canCreateGroup = true,
  canAddToGroup = () => true,
  canEditSpaces = true,
  canShareSpace,
  onShareSpace,
}: Props) {
  const displayHome = homeLabel || "Overview";
  const userGroups = activeSpaceId
    ? groups.filter((g) => g.space_id === activeSpaceId)
    : groups;
  const activeGroupId = selectedGroupId ?? null;
  const handleSelectGroup = onSelectGroup || (() => {});
  const handleNewGroup = onNewGroup || (() => {});

  return (
    <aside className={styles.sidebar} aria-label="Main">
      <div className={styles.titleRow} onMouseDown={onWindowDragMouseDown} />
      <div className={styles.brand} onMouseDown={onWindowDragMouseDown}>
        <span className={styles.mark}>
          <BrandMark size={28} />
        </span>
        <span className={styles.brandName}>Secwet</span>
      </div>

      <nav className={styles.nav}>
        {/* Home */}
        <div className={styles.group}>
          <span className={styles.groupLabel}>Home</span>
          <NavItem
            icon="grid"
            label={displayHome}
            active={route === "overview"}
            onClick={() => onNavigate("overview")}
          />
        </div>

        {/* User-defined groups */}
        <div className={styles.groupsContainer} aria-label="Groups">
          {userGroups.map((g) => {
            const groupItems = items.filter((it) => (it.group_id ?? it.label_id) === g.id);
            const isGroupActive = route === "group" && g.id === activeGroupId;
            const canAdd = Boolean(onNewItemForGroup) && canAddToGroup(g.id);

            return (
              <div key={g.id} className={styles.group}>
                <div className={styles.groupLabel}>
                  <button
                    className={[
                      styles.groupTitleBtn,
                      isGroupActive && styles.groupTitleActive,
                    ]
                      .filter(Boolean)
                      .join(" ")}
                    onClick={() => {
                      handleSelectGroup(g.id);
                      onNavigate("group");
                    }}
                    title={`View ${g.name}`}
                  >
                    <span>{g.name}</span>
                  </button>
                  {canAdd && onNewItemForGroup && (
                    <button
                      className={styles.groupAdd}
                      aria-label={`Add to ${g.name}`}
                      title={`Add to ${g.name}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        onNewItemForGroup(g.id);
                      }}
                    >
                      <Icon name="plus" size={13} />
                    </button>
                  )}
                </div>

                {groupItems.map((item) => (
                  <NavItem
                    key={item.id}
                    initial={initialOf(item.name)}
                    label={item.name}
                    active={route === "item" && item.id === selectedItemId}
                    onClick={() => {
                      if (onSelectItem) {
                        onSelectItem(item.id);
                      }
                    }}
                    className={styles.nestedItem}
                  />
                ))}

                {groupItems.length === 0 && canAdd && onNewItemForGroup && (
                  <button
                    className={styles.emptyItemHint}
                    onClick={() => onNewItemForGroup(g.id)}
                    title={`Add to ${g.name}`}
                  >
                    <Icon name="plus" size={11} />
                    <span>Add</span>
                  </button>
                )}
              </div>
            );
          })}

          {canCreateGroup && (
            <div className={styles.newGroupContainer}>
              <button
                className={styles.newGroupBtn}
                onClick={handleNewGroup}
                title="New"
                aria-label="New"
              >
                <span className={styles.newGroupIconWrap}>
                  <Icon name="plus" size={13} />
                </span>
                <span className={styles.newGroupText}>New</span>
              </button>
            </div>
          )}
        </div>
      </nav>

      <div className={styles.footer}>
        {spaces.length > 0 && (
          <SpaceSwitcher
            spaces={spaces}
            activeSpaceId={activeSpaceId ?? null}
            onSelectSpace={onSelectSpace || (() => {})}
            onNewSpace={onNewSpace}
            onRenameSpace={canEditSpaces ? onRenameSpace : undefined}
            onDeleteSpace={canEditSpaces ? onDeleteSpace : undefined}
            canShareSpace={canShareSpace}
            onShareSpace={onShareSpace}
            totalGroupsCount={groups.length}
          />
        )}
        <div className={styles.device}>
          <div className={[styles.deviceInfo, styles.expandedOnly].join(" ")}>
            <span className={styles.deviceName}>
              {deviceName && deviceName !== "desktop" ? deviceName : thisDevice.name}
            </span>
            <span className={styles.deviceMeta}>This device</span>
          </div>
          <button
            className={[styles.settingsBtn, route === "settings" && styles.settingsBtnActive]
              .filter(Boolean)
              .join(" ")}
            onClick={() => onNavigate("settings")}
            title="Settings"
            aria-label="Settings"
          >
            <Icon name="settings" size={16} />
          </button>
        </div>
      </div>
    </aside>
  );
}
