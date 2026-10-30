import { useState, useMemo } from "react";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { SearchInput } from "../../components/Field";
import { Icon, IconTile } from "../../components/Icon";
import { MoreMenu, type MenuItem } from "../../components/Menu";
import { NameDialog } from "../../components/NameDialog";
import { TopBarActions } from "../../layout/TopBar";
import type { GroupView, ItemView, LabelView } from "../../lib/api";
import { plural } from "../../lib/format";
import { NewItemDialog } from "./NewItemDialog";
import styles from "./GroupScreen.module.css";

interface Props {
  group?: GroupView;
  label?: LabelView;
  groups?: GroupView[];
  labels?: LabelView[];
  items: ItemView[];
  onSelectItem: (itemId: string) => void;
  onCreateItem: (name: string, description?: string) => Promise<void>;
  onRenameGroup?: (id: string, name: string) => Promise<void>;
  onRenameLabel?: (id: string, name: string) => Promise<void>;
  onDeleteGroup?: (id: string) => Promise<void>;
  onDeleteLabel?: (id: string) => Promise<void>;
  /** Admin on this group (member mode) and not a read-only archive. Defaults to true. */
  canManage?: boolean;
}

const initialOf = (name: string) =>
  name.replace(/[^A-Za-z0-9]/g, "").charAt(0).toUpperCase() || "#";

export function GroupScreen(props: Props) {
  const currentGroup = (props.group || props.label)!;
  const allGroups = props.groups || props.labels || [];
  const handleRename = props.onRenameGroup || props.onRenameLabel || (async () => {});
  const handleDelete = props.onDeleteGroup || props.onDeleteLabel || (async () => {});
  const canManage = props.canManage ?? true;

  const [search, setSearch] = useState("");
  const [creatingItem, setCreatingItem] = useState(false);
  const [renamingGroup, setRenamingGroup] = useState(false);
  const [deletingGroup, setDeletingGroup] = useState(false);

  const groupItems = useMemo(() => {
    return props.items.filter((it) => (it.group_id ?? it.label_id) === currentGroup.id);
  }, [props.items, currentGroup.id]);

  const filteredItems = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return groupItems;
    return groupItems.filter(
      (it) =>
        it.name.toLowerCase().includes(q) ||
        (it.description && it.description.toLowerCase().includes(q))
    );
  }, [groupItems, search]);

  const menuItems: MenuItem[] = [
    {
      label: "Rename",
      icon: "pencil",
      onSelect: () => setRenamingGroup(true),
    },
    {
      label: "Delete",
      icon: "trash",
      danger: true,
      onSelect: () => setDeletingGroup(true),
    },
  ];

  return (
    <div className={styles.screen}>
      {canManage && (
        <TopBarActions>
          <Button
            variant="primary"
            icon="plus"
            onClick={() => setCreatingItem(true)}
          >
            New
          </Button>
          <MoreMenu label="Actions" items={menuItems} />
        </TopBarActions>
      )}

      {groupItems.length > 0 && (
        <SearchInput
          className={styles.searchBar}
          placeholder={`Search ${currentGroup.name}...`}
          aria-label={`Search ${currentGroup.name}`}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      )}

      {groupItems.length === 0 ? (
        <EmptyState
          icon="folder"
          title="No entries yet"
          body={
            canManage
              ? "Store secrets, encrypted assets, and notes for your apps and services here."
              : "Nothing here is shared with you yet."
          }
          action={
            canManage ? (
              <Button
                variant="primary"
                icon="plus"
                onClick={() => setCreatingItem(true)}
              >
                New
              </Button>
            ) : undefined
          }
        />
      ) : filteredItems.length === 0 ? (
        <EmptyState
          icon="search"
          title="No entries found"
          body={`No entries matching "${search}".`}
        />
      ) : (
        <ul className={styles.itemsList}>
          {filteredItems.map((item) => (
            <li key={item.id}>
              <button
                className={styles.itemCard}
                onClick={() => props.onSelectItem(item.id)}
              >
                <IconTile initial={initialOf(item.name)} selected={false} />
                <div className={styles.itemMain}>
                  <div className={styles.itemNameRow}>
                    <span className={styles.itemName}>{item.name}</span>
                  </div>
                  {item.description && (
                    <span className={styles.itemDescription}>
                      {item.description}
                    </span>
                  )}
                </div>
                <div className={styles.itemBadges}>
                  {item.environments_count > 0 && (
                    <Badge tone="accent">
                      {plural(item.environments_count, "env")}
                    </Badge>
                  )}
                  <Badge tone="neutral">
                    {plural(item.secrets_count, "secret")}
                  </Badge>
                  {(item.assets_count ?? item.files_count) > 0 && (
                    <Badge tone="neutral">
                      {plural(item.assets_count ?? item.files_count, "asset")}
                    </Badge>
                  )}
                  {item.notes_count > 0 && (
                    <Badge tone="neutral">
                      {plural(item.notes_count, "note")}
                    </Badge>
                  )}
                </div>
                <span className={styles.chevron}>
                  <Icon name="chevronRight" size={16} />
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}

      {creatingItem && (
        <NewItemDialog
          existingItems={groupItems}
          groupName={currentGroup.name}
          labelName={currentGroup.name}
          onCancel={() => setCreatingItem(false)}
          onCreate={async (name, desc) => {
            await props.onCreateItem(name, desc);
            setCreatingItem(false);
          }}
        />
      )}

      {renamingGroup && (
        <NameDialog
          title="Rename"
          label="Name"
          initial={currentGroup.name}
          confirmLabel="Rename"
          validate={(val) => {
            const trimmed = val.trim();
            if (!trimmed) return "Enter a name.";
            if (
              allGroups.some(
                (g) =>
                  g.id !== currentGroup.id &&
                  g.name.toLowerCase() === trimmed.toLowerCase()
              )
            ) {
              return `A category called "${trimmed}" already exists.`;
            }
            return undefined;
          }}
          onSubmit={async (newName) => {
            await handleRename(currentGroup.id, newName);
            setRenamingGroup(false);
          }}
          onCancel={() => setRenamingGroup(false)}
        />
      )}

      {deletingGroup && (
        <ConfirmDialog
          title={`Delete "${currentGroup.name}"?`}
          body={
            <>
              <p>
                Deleting <strong>{currentGroup.name}</strong> will also permanently
                delete all {plural(groupItems.length, "entry")} and their secrets,
                assets, and notes.
              </p>
              <p>This action cannot be undone.</p>
            </>
          }
          confirmLabel="Delete"
          requireText={groupItems.length > 0 ? currentGroup.name : undefined}
          onConfirm={async () => {
            await handleDelete(currentGroup.id);
            setDeletingGroup(false);
          }}
          onCancel={() => setDeletingGroup(false)}
        />
      )}
    </div>
  );
}

export { GroupScreen as LabelScreen };
