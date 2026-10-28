import { useState, useRef, useEffect, type KeyboardEvent } from "react";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { Icon, type IconName } from "../components/Icon";
import { formatUiError, type SpaceView } from "../lib/api";
import { EditSpaceDialog } from "../screens/spaces/EditSpaceDialog";
import styles from "./SpaceSwitcher.module.css";

interface Props {
  spaces: SpaceView[];
  activeSpaceId: string | null;
  onSelectSpace: (id: string | null) => void;
  /** Omit to hide "New Space" (member mode, read-only archive). */
  onNewSpace?: () => void;
  onRenameSpace?: (id: string, name: string, icon?: string | null) => Promise<unknown> | void;
  onDeleteSpace?: (id: string) => Promise<unknown> | void;
  totalGroupsCount?: number;
  /** Opens the Share dialog for a space. */
  onShareSpace?: (space: SpaceView) => void;
  /** Whether "Share space…" shows for a space. Defaults to every space. */
  canShareSpace?: (space: SpaceView) => boolean;
}

export function SpaceSwitcher({
  spaces,
  activeSpaceId,
  onSelectSpace,
  onNewSpace,
  onRenameSpace,
  onDeleteSpace,
  totalGroupsCount = 0,
  onShareSpace,
  canShareSpace = () => true,
}: Props) {
  const [open, setOpen] = useState(false);
  const [activeMenuSpaceId, setActiveMenuSpaceId] = useState<string | null>(null);
  const [menuPosition, setMenuPosition] = useState<{ top: number; right: number } | null>(null);
  const [editingSpace, setEditingSpace] = useState<SpaceView | null>(null);
  const [deletingSpace, setDeletingSpace] = useState<SpaceView | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const activeSpace = activeSpaceId ? spaces.find((s) => s.id === activeSpaceId) : null;
  const isGlobal = activeSpaceId === null;

  // Click outside to close dropdown and context menu
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      const target = e.target as Node;
      // If clicking inside the floating context menu, let its items handle it
      if (menuRef.current && menuRef.current.contains(target)) {
        return;
      }
      // If clicking the more button, let its onClick toggle the menu
      if ((target as Element).closest?.(`.${styles.moreBtn}`)) {
        return;
      }
      setActiveMenuSpaceId(null);
      if (containerRef.current && !containerRef.current.contains(target)) {
        setOpen(false);
      }
    }
    if (open || activeMenuSpaceId) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [open, activeMenuSpaceId]);

  // Handle keyboard navigation
  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      if (activeMenuSpaceId) {
        setActiveMenuSpaceId(null);
      } else {
        setOpen(false);
      }
    }
  }

  const activeIconName: IconName = isGlobal
    ? "globe"
    : (activeSpace?.icon as IconName) || (activeSpace?.is_default ? "user" : "folder");

  const displayName = isGlobal ? "Global" : activeSpace?.name || "Personal";

  const menuActionsFor = (s: SpaceView) => ({
    edit: Boolean(onRenameSpace),
    share: Boolean(onShareSpace) && canShareSpace(s),
    remove: !s.is_default && Boolean(onDeleteSpace),
  });

  return (
    <>
      <div className={styles.container} ref={containerRef} onKeyDown={handleKeyDown}>
        <button
          type="button"
          className={styles.trigger}
          onClick={() => {
            setOpen((prev) => !prev);
            setActiveMenuSpaceId(null);
          }}
          aria-expanded={open}
          title={`Current space: ${displayName}`}
        >
          <div className={styles.spaceInfo}>
            <span className={styles.spaceIcon}>
              <Icon name={activeIconName} size={15} />
            </span>
            <span className={styles.spaceName}>{displayName}</span>
          </div>
          <span className={[styles.chevron, open && styles.chevronOpen].filter(Boolean).join(" ")}>
            <Icon name="chevronDown" size={14} />
          </span>
        </button>

        {open && (
          <div className={styles.dropdown} role="group" aria-label="Switch space">
            <div className={styles.menuHeader}>Spaces</div>

            {spaces.map((s) => {
              const isSelected = !isGlobal && s.id === activeSpaceId;
              const iconName: IconName = (s.icon as IconName) || (s.is_default ? "user" : "folder");
              const isMenuOpen = activeMenuSpaceId === s.id;
              const actions = menuActionsFor(s);
              const actionCount = Number(actions.edit) + Number(actions.share) + Number(actions.remove);

              return (
                <div
                  key={s.id}
                  className={[styles.spaceRow, isSelected && styles.activeItem].filter(Boolean).join(" ")}
                >
                  <button
                    type="button"
                    aria-current={isSelected ? "true" : undefined}
                    className={styles.spaceSelectBtn}
                    onClick={() => {
                      onSelectSpace(s.id);
                      setOpen(false);
                      setActiveMenuSpaceId(null);
                    }}
                  >
                    <div className={styles.itemLeft}>
                      <span className={styles.spaceRowIcon}>
                        <Icon name={iconName} size={14} />
                      </span>
                      <span className={styles.spaceLabel}>{s.name}</span>
                      <span className={styles.countBadge}>{s.groups_count}</span>
                    </div>
                  </button>

                  {actionCount > 0 && (
                  <div className={styles.itemRight}>
                    <button
                      type="button"
                      className={[styles.moreBtn, isMenuOpen && styles.moreBtnActive].filter(Boolean).join(" ")}
                      title={`Options for ${s.name}`}
                      aria-label={`Options for ${s.name}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        if (isMenuOpen) {
                          setActiveMenuSpaceId(null);
                        } else {
                          const rect = e.currentTarget.getBoundingClientRect();
                          const spaceBelow = window.innerHeight - rect.bottom;
                          const menuHeight = actionCount * 30 + 10;
                          const openUp = spaceBelow < menuHeight + 24;
                          setMenuPosition({
                            top: openUp ? rect.top - menuHeight - 4 : rect.bottom + 4,
                            right: Math.max(12, window.innerWidth - rect.right),
                          });
                          setActiveMenuSpaceId(s.id);
                        }
                      }}
                    >
                      <Icon name="more" size={13} />
                    </button>
                  </div>
                  )}
                </div>
              );
            })}

            <div className={styles.divider} />

            {/* Global Aggregate Option */}
            <button
              type="button"
              aria-current={isGlobal ? "true" : undefined}
              className={[styles.menuItem, isGlobal && styles.activeItem].filter(Boolean).join(" ")}
              onClick={() => {
                onSelectSpace(null);
                setOpen(false);
                setActiveMenuSpaceId(null);
              }}
            >
              <div className={styles.itemLeft}>
                <span className={styles.spaceRowIcon}>
                  <Icon name="globe" size={14} />
                </span>
                <span className={styles.spaceLabel}>Global</span>
                <span className={styles.countBadge}>{totalGroupsCount}</span>
              </div>
            </button>

            {/* New Space Action */}
            {onNewSpace && <div className={styles.divider} />}
            {onNewSpace && (
              <button
                type="button"
                className={styles.newSpaceBtn}
                onClick={() => {
                  setOpen(false);
                  setActiveMenuSpaceId(null);
                  onNewSpace();
                }}
              >
                <Icon name="plus" size={14} />
                <span>New space…</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* Floating 3-dots Context Menu */}
      {activeMenuSpaceId && menuPosition && (
        <div
          ref={menuRef}
          className={styles.rowContextMenu}
          role="menu"
          style={{ top: menuPosition.top, right: menuPosition.right }}
          onMouseDown={(e) => e.stopPropagation()}
          onClick={(e) => e.stopPropagation()}
        >
          {(() => {
            const targetSpace = spaces.find((s) => s.id === activeMenuSpaceId);
            if (!targetSpace) return null;
            const actions = menuActionsFor(targetSpace);
            return (
              <>
                {actions.edit && (
                  <button
                    type="button"
                    role="menuitem"
                    className={styles.contextMenuItem}
                    onClick={() => {
                      setActiveMenuSpaceId(null);
                      setOpen(false);
                      setEditingSpace(targetSpace);
                    }}
                  >
                    <Icon name="pencil" size={13} />
                    <span>Edit space</span>
                  </button>
                )}
                {actions.share && onShareSpace && (
                  <button
                    type="button"
                    role="menuitem"
                    className={styles.contextMenuItem}
                    onClick={() => {
                      setActiveMenuSpaceId(null);
                      setOpen(false);
                      onShareSpace(targetSpace);
                    }}
                  >
                    <Icon name="user" size={13} />
                    <span>Share space…</span>
                  </button>
                )}
                {actions.remove && (
                  <button
                    type="button"
                    role="menuitem"
                    className={[styles.contextMenuItem, styles.dangerMenuItem].filter(Boolean).join(" ")}
                    onClick={() => {
                      setActiveMenuSpaceId(null);
                      setOpen(false);
                      setDeletingSpace(targetSpace);
                    }}
                  >
                    <Icon name="trash" size={13} />
                    <span>Delete space</span>
                  </button>
                )}
              </>
            );
          })()}
        </div>
      )}

      {/* Edit Space Dialog */}
      {editingSpace && (
        <EditSpaceDialog
          space={editingSpace}
          onCancel={() => setEditingSpace(null)}
          onSave={async (name, icon) => {
            if (onRenameSpace) {
              await onRenameSpace(editingSpace.id, name, icon);
            }
            setEditingSpace(null);
          }}
          onDelete={
            !editingSpace.is_default && onDeleteSpace
              ? () => {
                  const toDelete = editingSpace;
                  setEditingSpace(null);
                  setDeletingSpace(toDelete);
                }
              : undefined
          }
        />
      )}

      {/* Confirm Delete Dialog */}
      {deletingSpace && (
        <ConfirmDialog
          title={`Delete ${deletingSpace.name}?`}
          body={
            <>
              <p>
                Its groups move to your {spaces.find((s) => s.is_default)?.name ?? "Personal"} space.
              </p>
              {deleteError && (
                <p className={styles.error} role="alert">
                  {deleteError}
                </p>
              )}
            </>
          }
          confirmLabel="Delete space"
          requireText={deletingSpace.name}
          busy={deleteBusy}
          onConfirm={async () => {
            if (!onDeleteSpace) {
              setDeletingSpace(null);
              return;
            }
            setDeleteBusy(true);
            setDeleteError(null);
            try {
              await onDeleteSpace(deletingSpace.id);
              setDeletingSpace(null);
            } catch (err) {
              setDeleteError(formatUiError(err, "Couldn't delete this space. Try again."));
            } finally {
              setDeleteBusy(false);
            }
          }}
          onCancel={() => {
            setDeleteError(null);
            setDeletingSpace(null);
          }}
        />
      )}
    </>
  );
}
