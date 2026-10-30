import { useState, useMemo } from "react";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { Dialog } from "../../components/Dialog";
import { EmptyState } from "../../components/EmptyState";
import { SearchInput } from "../../components/Field";
import { Icon } from "../../components/Icon";
import { MoreMenu, type MenuItem } from "../../components/Menu";
import { NameDialog } from "../../components/NameDialog";
import { SegmentedTabs, type TabItem } from "../../components/SegmentedTabs";
import { kindLabels, type SecretKind } from "../../data/mock";
import { TopBarActions } from "../../layout/TopBar";
import type {
  EnvironmentView,
  AssetMetaView,
  FileMetaView,
  GroupView,
  ItemView,
  LabelView,
  NoteMetaView,
  NoteView,
  SecretDraft,
  SecretMeta,
} from "../../lib/api";
import { api } from "../../lib/api";
import { formatAgo } from "../../lib/format";
import { usePermissions } from "../../lib/useAccess";
import { CopySecretDialog } from "../secrets/CopySecretDialog";
import { SecretDialog } from "../secrets/SecretDialog";
import { SecretRow } from "../secrets/SecretRow";
import { AssetManager } from "./AssetManager";
import { EditItemDialog } from "./EditItemDialog";
import { RichTextEditor } from "./RichTextEditor";
import styles from "./ItemScreen.module.css";

interface Props {
  item: ItemView;
  group?: GroupView;
  label?: LabelView;
  environments: EnvironmentView[];
  secrets: SecretMeta[];
  assets?: AssetMetaView[];
  files?: FileMetaView[];
  notes: NoteMetaView[];
  selectedEnvironmentId: string | null;
  onSelectEnvironment: (envId: string | null) => void;
  onBackToGroup?: () => void;
  onBackToLabel?: () => void;
  onRenameItem: (id: string, name: string, description?: string) => Promise<void>;
  onDeleteItem: (id: string) => Promise<void>;
  onAddEnvironment: (itemId: string, name: string) => Promise<void>;
  onRenameEnvironment: (id: string, name: string) => Promise<void>;
  onDeleteEnvironment: (id: string, preserveContent?: boolean) => Promise<void>;
  onAddSecret: (draft: SecretDraft) => Promise<void>;
  onAddSecrets?: (drafts: SecretDraft[]) => Promise<void>;
  onUpdateSecret: (id: string, draft: SecretDraft) => Promise<void>;
  onDeleteSecret: (id: string) => Promise<void>;
  onCopySecretToEnvironment: (id: string, targetEnvId?: string | null) => Promise<void>;
  onUploadAsset?: (name: string, mime: string, bytes: number[] | Uint8Array) => Promise<void>;
  onRenameAsset?: (id: string, name: string) => Promise<void>;
  onDeleteAsset?: (id: string) => Promise<void>;
  onUploadFile?: (name: string, mime: string, bytes: number[] | Uint8Array) => Promise<void>;
  onRenameFile?: (id: string, name: string) => Promise<void>;
  onDeleteFile?: (id: string) => Promise<void>;
  onCreateNote: (title: string, content: string) => Promise<void>;
  onUpdateNote: (id: string, title?: string, content?: string) => Promise<void>;
  onDeleteNote: (id: string) => Promise<void>;
  /** Opens the Share dialog for this item, or for the environment when one is selected. */
  onShare?: (target: { kind: "item" | "environment"; id: string }) => void;
}

type ContentTab = "secrets" | "assets" | "notes";

/**
 * Secret kinds sorted alphabetically by their display label by default:
 * Access token, API key, Certificate, Codes, Environment variable, Password, SSH key.
 */
const ALL_SECRET_KINDS: SecretKind[] = [
  "access_token",
  "api_key",
  "certificate",
  "codes",
  "env_var",
  "password",
  "ssh_key",
];

const SECRET_TYPES_TAB_ORDER_KEY = "secwet:secret-types-tab-order-v2";

function getInitialSecretTypeOrder(): string[] {
  const defaultOrder = ["all", ...ALL_SECRET_KINDS];
  try {
    const saved = localStorage.getItem(SECRET_TYPES_TAB_ORDER_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      if (Array.isArray(parsed) && parsed.length > 0) {
        const validSet = new Set(defaultOrder);
        const filtered = parsed.filter((id) => typeof id === "string" && validSet.has(id));
        const missing = defaultOrder.filter((id) => !filtered.includes(id));
        return [...filtered, ...missing];
      }
    }
  } catch {
    // ignore
  }
  return defaultOrder;
}

export function ItemScreen({
  item,
  group: _group,
  label: _label,
  environments,
  secrets,
  assets,
  files,
  notes,
  selectedEnvironmentId,
  onSelectEnvironment,
  onBackToGroup,
  onBackToLabel,
  onRenameItem,
  onDeleteItem,
  onAddEnvironment,
  onRenameEnvironment,
  onDeleteEnvironment,
  onAddSecret,
  onAddSecrets,
  onUpdateSecret,
  onDeleteSecret,
  onCopySecretToEnvironment,
  onUploadAsset,
  onRenameAsset,
  onDeleteAsset,
  onUploadFile,
  onRenameFile,
  onDeleteFile,
  onCreateNote,
  onUpdateNote,
  onDeleteNote,
  onShare,
}: Props) {
  const [contentTab, setContentTab] = useState<ContentTab>("secrets");
  const [secretSearch, setSecretSearch] = useState("");
  const [selectedKindFilter, setSelectedKindFilter] = useState<SecretKind | "all">("all");
  const [secretTypeOrder, setSecretTypeOrder] = useState<string[]>(getInitialSecretTypeOrder);
  const [noteSearch, setNoteSearch] = useState("");

  const effectiveAssets = useMemo(() => assets ?? files ?? [], [assets, files]);

  // Member mode: the role on the item (containers) and on the open scope (content).
  const groupForPath = _group ?? _label;
  const basePath = {
    spaceId: groupForPath?.space_id ?? null,
    groupId: item.group_id ?? item.label_id ?? groupForPath?.id ?? null,
    itemId: item.id,
  };
  const itemPerms = usePermissions(basePath);
  const scopePerms = usePermissions({
    ...basePath,
    environmentId: selectedEnvironmentId,
    general: !selectedEnvironmentId,
  });

  // Modals for Item
  const [editingItem, setEditingItem] = useState(false);
  const [deletingItem, setDeletingItem] = useState(false);

  // Modals for Environment
  const [addingEnv, setAddingEnv] = useState(false);
  const [renamingEnv, setRenamingEnv] = useState<EnvironmentView | null>(null);
  const [deletingEnv, setDeletingEnv] = useState<EnvironmentView | null>(null);
  const [preserveOnEnvDelete, setPreserveOnEnvDelete] = useState(true);

  // Modals for Secrets
  const [addingSecret, setAddingSecret] = useState(false);
  const [editingSecret, setEditingSecret] = useState<SecretMeta | null>(null);
  const [deletingSecret, setDeletingSecret] = useState<SecretMeta | null>(null);
  const [copyingSecret, setCopyingSecret] = useState<SecretMeta | null>(null);

  // Notes state
  const [activeNote, setActiveNote] = useState<NoteView | null>(null);
  const [isCreatingNote, setIsCreatingNote] = useState(false);
  const [deletingNote, setDeletingNote] = useState<NoteMetaView | null>(null);

  // Filter content by selected environment (null = general)
  const scopedSecrets = useMemo(() => {
    return secrets.filter((s) => {
      if (!selectedEnvironmentId) {
        return environments.length === 0 || !s.environment_id;
      }
      return s.environment_id === selectedEnvironmentId;
    });
  }, [secrets, selectedEnvironmentId, environments.length]);

  const filteredSecrets = useMemo(() => {
    let result = scopedSecrets;
    if (selectedKindFilter !== "all") {
      result = result.filter((s) => s.kind === selectedKindFilter);
    }
    const q = secretSearch.trim().toLowerCase();
    if (!q) return result;
    return result.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        (s.note && s.note.toLowerCase().includes(q))
    );
  }, [scopedSecrets, selectedKindFilter, secretSearch]);

  const secretTypeTabs: TabItem[] = useMemo(() => {
    const tabsMap: Record<string, TabItem> = {
      all: { id: "all", label: "All", count: scopedSecrets.length },
      ...Object.fromEntries(
        ALL_SECRET_KINDS.map((k) => [
          k,
          {
            id: k,
            label: kindLabels[k],
            count: scopedSecrets.filter((s) => s.kind === k).length,
          },
        ])
      ),
    };

    return secretTypeOrder
      .map((id) => tabsMap[id])
      .filter((t): t is TabItem => Boolean(t));
  }, [scopedSecrets, secretTypeOrder]);

  const handleReorderSecretTypes = (newItems: TabItem[]) => {
    const newOrder = newItems.map((item) => item.id);
    setSecretTypeOrder(newOrder);
    try {
      localStorage.setItem(SECRET_TYPES_TAB_ORDER_KEY, JSON.stringify(newOrder));
    } catch {
      // ignore
    }
  };

  const scopedAssets = useMemo(() => {
    return effectiveAssets.filter((a) => {
      if (!selectedEnvironmentId) {
        return environments.length === 0 || !a.environment_id;
      }
      return a.environment_id === selectedEnvironmentId;
    });
  }, [effectiveAssets, selectedEnvironmentId, environments.length]);

  const scopedNotes = useMemo(() => {
    return notes.filter((n) => {
      if (!selectedEnvironmentId) {
        return environments.length === 0 || !n.environment_id;
      }
      return n.environment_id === selectedEnvironmentId;
    });
  }, [notes, selectedEnvironmentId, environments.length]);

  const filteredNotes = useMemo(() => {
    const q = noteSearch.trim().toLowerCase();
    if (!q) return scopedNotes;
    return scopedNotes.filter(
      (n) =>
        n.title.toLowerCase().includes(q) ||
        (n.snippet && n.snippet.toLowerCase().includes(q))
    );
  }, [scopedNotes, noteSearch]);

  const shareTarget = selectedEnvironmentId
    ? ({ kind: "environment", id: selectedEnvironmentId } as const)
    : ({ kind: "item", id: item.id } as const);
  const canShareHere = Boolean(onShare) && (selectedEnvironmentId ? scopePerms.canShare : itemPerms.canShare);

  const itemMenuItems: MenuItem[] = [];
  if (itemPerms.canManage) {
    itemMenuItems.push(
      {
        label: "Rename",
        icon: "pencil",
        onSelect: () => setEditingItem(true),
      },
      {
        label: "Add environment",
        icon: "plus",
        onSelect: () => setAddingEnv(true),
      },
      {
        label: "Delete",
        icon: "trash",
        danger: true,
        onSelect: () => setDeletingItem(true),
      }
    );
  }

  return (
    <>
      <TopBarActions>
        {canShareHere && onShare && (
          <Button
            variant="secondary"
            icon="user"
            title={selectedEnvironmentId ? "Share this environment" : "Share this item"}
            onClick={() => onShare(shareTarget)}
          >
            Share…
          </Button>
        )}
        {itemPerms.canManage && (
          <Button
            variant="secondary"
            icon="plus"
            onClick={() => setAddingEnv(true)}
          >
            Add environment
          </Button>
        )}
        {itemMenuItems.length > 0 && <MoreMenu label="Actions" items={itemMenuItems} />}
      </TopBarActions>

      <div className={styles.screen}>

      {item.description && (
        <p className={styles.itemDescription}>{item.description}</p>
      )}

      {/* Conditional Scope Bar: COMPLETELY HIDDEN if 0 environments */}
      {environments.length > 0 && (
        <div className={styles.envBarRow}>
          <SegmentedTabs
            label="Scope"
            value={selectedEnvironmentId || ""}
            onChange={(val) => onSelectEnvironment(val ? val : null)}
            separatorAfterId=""
            items={[
              { id: "", label: "General" },
              ...environments.map((e) => ({
                id: e.id,
                label: e.name,
              })),
            ]}
            extra={(() => {
              if (!selectedEnvironmentId || !scopePerms.canManage) return null;
              const activeEnv = environments.find((e) => e.id === selectedEnvironmentId);
              if (!activeEnv) return null;
              const envMenu: MenuItem[] = [
                {
                  label: "Rename environment",
                  icon: "pencil",
                  onSelect: () => setRenamingEnv(activeEnv),
                },
                {
                  label: "Delete environment",
                  icon: "trash",
                  danger: true,
                  onSelect: () => {
                    setPreserveOnEnvDelete(true);
                    setDeletingEnv(activeEnv);
                  },
                },
              ];
              return (
                <MoreMenu label={`Actions for ${activeEnv.name}`} items={envMenu} />
              );
            })()}
          />
        </div>
      )}

      {/* Internal Content Tabs */}
      <div className={styles.contentNavRow}>
        <SegmentedTabs
          label="Content tabs"
          value={contentTab}
          onChange={(val) => {
            setContentTab(val as ContentTab);
            setActiveNote(null);
            setIsCreatingNote(false);
          }}
          items={[
            { id: "secrets", label: "Secrets", count: scopedSecrets.length },
            { id: "assets", label: "Assets", count: scopedAssets.length },
            { id: "notes", label: "Notes", count: scopedNotes.length },
          ]}
        />
      </div>

      {/* 1. Secrets Content Section */}
      {contentTab === "secrets" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
          {(scopedSecrets.length > 0 || secretSearch || selectedKindFilter !== "all") && (
            <div className={styles.sectionHeader}>
              <SearchInput
                className={styles.searchBar}
                placeholder="Search secrets..."
                aria-label="Search secrets"
                value={secretSearch}
                onChange={(e) => setSecretSearch(e.target.value)}
              />

              {scopePerms.canWrite && (
                <Button
                  variant="primary"
                  icon="plus"
                  onClick={() => setAddingSecret(true)}
                >
                  Add secret
                </Button>
              )}
            </div>
          )}

          {(scopedSecrets.length > 0 || secretSearch || selectedKindFilter !== "all") && (
            <div className={styles.typeTabsRow}>
              <SegmentedTabs
                label="Secret types"
                value={selectedKindFilter}
                onChange={(val) => setSelectedKindFilter(val as SecretKind | "all")}
                items={secretTypeTabs}
                reorderable
                onReorder={handleReorderSecretTypes}
              />
            </div>
          )}

          {scopedSecrets.length === 0 ? (
            <EmptyState
              icon="key"
              title="No secrets yet"
              body="Secrets are encrypted on this device and sealed with strict record binding."
              action={
                scopePerms.canWrite ? (
                  <Button
                    variant="primary"
                    icon="plus"
                    onClick={() => setAddingSecret(true)}
                  >
                    Add secret
                  </Button>
                ) : undefined
              }
            />
          ) : filteredSecrets.length === 0 ? (
            <EmptyState
              icon="search"
              title="No matching secrets"
              body={
                secretSearch
                  ? `No secrets matching "${secretSearch}"${selectedKindFilter !== "all" ? ` in ${kindLabels[selectedKindFilter]}` : ""}.`
                  : `No ${kindLabels[selectedKindFilter as SecretKind]} secrets found in this environment.`
              }
              action={
                secretSearch || selectedKindFilter !== "all" ? (
                  <Button
                    variant="secondary"
                    onClick={() => {
                      setSecretSearch("");
                      setSelectedKindFilter("all");
                    }}
                  >
                    Clear filter
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <div className={styles.secretsContainer}>
              <ul className={styles.secretsList}>
                {filteredSecrets.map((sec) => (
                  <SecretRow
                    key={sec.id}
                    secret={sec}
                    itemName={item.name}
                    environmentName={environments.find((e) => e.id === selectedEnvironmentId)?.name}
                    canCopy={true}
                    canEdit={scopePerms.canWrite}
                    canDelete={scopePerms.canDelete}
                    onEdit={() => setEditingSecret(sec)}
                    onCopyToEnvironment={() => setCopyingSecret(sec)}
                    onDelete={() => setDeletingSecret(sec)}
                  />
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* 2. Assets Content Section */}
      {contentTab === "assets" && (
        <AssetManager
          itemId={item.id}
          environmentId={selectedEnvironmentId}
          assets={scopedAssets}
          canUpload={scopePerms.canWrite}
          canRename={scopePerms.canWrite}
          canDelete={scopePerms.canDelete}
          onUpload={async (name, mime, bytes) => {
            if (onUploadAsset) {
              await onUploadAsset(name, mime, bytes);
            } else if (onUploadFile) {
              await onUploadFile(name, mime, bytes);
            }
          }}
          onRename={async (id, name) => {
            if (onRenameAsset) {
              await onRenameAsset(id, name);
            } else if (onRenameFile) {
              await onRenameFile(id, name);
            }
          }}
          onDelete={async (id) => {
            if (onDeleteAsset) {
              await onDeleteAsset(id);
            } else if (onDeleteFile) {
              await onDeleteFile(id);
            }
          }}
        />
      )}

      {/* 3. Notes Content Section */}
      {contentTab === "notes" && (
        <div>
          {isCreatingNote || activeNote ? (
            <RichTextEditor
              note={activeNote}
              itemId={item.id}
              environmentId={selectedEnvironmentId}
              readOnly={!scopePerms.canWrite}
              onSave={async (title, content) => {
                if (activeNote) {
                  await onUpdateNote(activeNote.id, title, content);
                } else {
                  await onCreateNote(title, content);
                }
                setActiveNote(null);
                setIsCreatingNote(false);
              }}
              onDelete={
                scopePerms.canDelete
                  ? async (id) => {
                      await onDeleteNote(id);
                      setActiveNote(null);
                      setIsCreatingNote(false);
                    }
                  : undefined
              }
              onClose={() => {
                setActiveNote(null);
                setIsCreatingNote(false);
              }}
            />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
              {(scopedNotes.length > 0 || noteSearch) && (
                <div className={styles.sectionHeader}>
                  <SearchInput
                    className={styles.searchBar}
                    placeholder="Search notes..."
                    aria-label="Search notes"
                    value={noteSearch}
                    onChange={(e) => setNoteSearch(e.target.value)}
                  />

                  {scopePerms.canWrite && (
                    <Button
                      variant="primary"
                      icon="plus"
                      onClick={() => setIsCreatingNote(true)}
                    >
                      New note
                    </Button>
                  )}
                </div>
              )}

              {scopedNotes.length === 0 ? (
                <EmptyState
                  icon="pencil"
                  title="No rich-text notes yet"
                  body="Create formatted notes with headings, tables, code blocks, and lists."
                  action={
                    scopePerms.canWrite ? (
                      <Button
                        variant="primary"
                        icon="plus"
                        onClick={() => setIsCreatingNote(true)}
                      >
                        New note
                      </Button>
                    ) : undefined
                  }
                />
              ) : filteredNotes.length === 0 ? (
                <EmptyState
                  icon="search"
                  title="No matching notes"
                  body={`No notes matching "${noteSearch}".`}
                />
              ) : (
                <ul className={styles.notesGrid}>
                  {filteredNotes.map((n) => (
                    <li key={n.id}>
                      <div
                        className={styles.noteCard}
                        onClick={async () => {
                          const fullNote = await api.noteGet(n.id).catch(() => ({
                            id: n.id,
                            item_id: n.item_id,
                            environment_id: n.environment_id,
                            title: n.title,
                            content: n.snippet,
                            updated_at: n.updated_at,
                            position: n.position,
                          }));
                          setActiveNote(fullNote);
                        }}
                      >
                        <div className={styles.noteCardHeader}>
                          <span className={styles.noteTitle}>{n.title}</span>
                          {scopePerms.canDelete && (
                          <button
                            type="button"
                            className={styles.noteDeleteBtn}
                            title="Delete note"
                            aria-label={`Delete ${n.title}`}
                            onClick={(e) => {
                              e.stopPropagation();
                              setDeletingNote(n);
                            }}
                          >
                            <Icon name="trash" size={14} />
                          </button>
                          )}
                        </div>
                        <p className={styles.noteBody}>{n.snippet || "Empty note"}</p>
                        <div className={styles.noteFooter}>
                          <span className={styles.noteMeta}>
                            Updated {formatAgo(n.updated_at)}
                          </span>
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      )}

      {/* Secret Dialog (Context-Aware: Omits env dropdown when 0 envs exist) */}
      {(addingSecret || editingSecret) && (
        <SecretDialog
          item={item}
          environments={environments}
          defaultEnvironmentId={selectedEnvironmentId}
          existing={secrets}
          initial={editingSecret || undefined}
          onCancel={() => {
            setAddingSecret(false);
            setEditingSecret(null);
          }}
          onSave={async (draftOrDrafts) => {
            const drafts = Array.isArray(draftOrDrafts) ? draftOrDrafts : [draftOrDrafts];
            if (editingSecret) {
              const draft = drafts[0];
              await onUpdateSecret(editingSecret.id, {
                item_id: item.id,
                environment_id: draft.environment_id || null,
                name: draft.name,
                kind: draft.kind,
                value: draft.value,
                note: draft.note || null,
              });
            } else if (drafts.length > 1 && onAddSecrets) {
              await onAddSecrets(
                drafts.map((d) => ({
                  item_id: item.id,
                  environment_id: d.environment_id || null,
                  name: d.name,
                  kind: d.kind,
                  value: d.value,
                  note: d.note || null,
                }))
              );
            } else {
              for (const d of drafts) {
                await onAddSecret({
                  item_id: item.id,
                  environment_id: d.environment_id || null,
                  name: d.name,
                  kind: d.kind,
                  value: d.value,
                  note: d.note || null,
                });
              }
            }
            setAddingSecret(false);
            setEditingSecret(null);
          }}
        />
      )}

      {/* Copy Secret Dialog */}
      {copyingSecret && (
        <CopySecretDialog
          project={{
            id: item.id,
            name: item.name,
            environments: environments.map((e) => ({ id: e.id, name: e.name })),
          }}
          secret={copyingSecret}
          existing={secrets}
          onCancel={() => setCopyingSecret(null)}
          onCopy={async (targetEnvId) => {
            await onCopySecretToEnvironment(copyingSecret.id, targetEnvId);
            setCopyingSecret(null);
          }}
        />
      )}

      {/* Delete Secret Confirmation */}
      {deletingSecret && (
        <ConfirmDialog
          title={`Delete "${deletingSecret.name}"?`}
          body={<p>Are you sure you want to permanently delete this secret?</p>}
          confirmLabel="Delete secret"
          onConfirm={async () => {
            await onDeleteSecret(deletingSecret.id);
            setDeletingSecret(null);
          }}
          onCancel={() => setDeletingSecret(null)}
        />
      )}

      {/* Delete Note Confirmation */}
      {deletingNote && (
        <ConfirmDialog
          title={`Delete "${deletingNote.title}"?`}
          body={<p>Are you sure you want to permanently delete this note?</p>}
          confirmLabel="Delete note"
          onConfirm={async () => {
            await onDeleteNote(deletingNote.id);
            setDeletingNote(null);
          }}
          onCancel={() => setDeletingNote(null)}
        />
      )}

      {/* Edit Item Dialog */}
      {editingItem && (
        <EditItemDialog
          item={item}
          onCancel={() => setEditingItem(false)}
          onSave={async (newName, newDesc) => {
            await onRenameItem(item.id, newName, newDesc);
            setEditingItem(false);
          }}
        />
      )}

      {/* Delete Item Confirmation */}
      {deletingItem && (
        <ConfirmDialog
          title={`Delete "${item.name}"?`}
          body={
            <>
              <p>
                Deleting <strong>{item.name}</strong> will permanently delete
                all environments, secrets, assets, and notes inside it.
              </p>
              <p>This action cannot be undone.</p>
            </>
          }
          confirmLabel="Delete"
          requireText={item.name}
          onConfirm={async () => {
            await onDeleteItem(item.id);
            setDeletingItem(false);
            if (onBackToGroup) {
              onBackToGroup();
            } else if (onBackToLabel) {
              onBackToLabel();
            }
          }}
          onCancel={() => setDeletingItem(false)}
        />
      )}

      {/* Add Environment Dialog */}
      {addingEnv && (
        <NameDialog
          title="Add environment"
          label="Environment name"
          placeholder="e.g. Production, Staging, Development"
          confirmLabel="Add environment"
          validate={(val) => {
            const trimmed = val.trim();
            if (!trimmed) return "Enter an environment name.";
            if (
              environments.some(
                (e) => e.name.toLowerCase() === trimmed.toLowerCase()
              )
            ) {
              return `An environment called "${trimmed}" already exists.`;
            }
            return undefined;
          }}
          onSubmit={async (envName) => {
            await onAddEnvironment(item.id, envName);
            setAddingEnv(false);
          }}
          onCancel={() => setAddingEnv(false)}
        />
      )}

      {/* Rename Environment Dialog */}
      {renamingEnv && (
        <NameDialog
          title="Rename environment"
          label="Environment name"
          initial={renamingEnv.name}
          confirmLabel="Rename"
          validate={(val) => {
            const trimmed = val.trim();
            if (!trimmed) return "Enter an environment name.";
            if (
              environments.some(
                (e) =>
                  e.id !== renamingEnv.id &&
                  e.name.toLowerCase() === trimmed.toLowerCase()
              )
            ) {
              return `An environment called "${trimmed}" already exists.`;
            }
            return undefined;
          }}
          onSubmit={async (newName) => {
            await onRenameEnvironment(renamingEnv.id, newName);
            setRenamingEnv(null);
          }}
          onCancel={() => setRenamingEnv(null)}
        />
      )}

      {/* Delete Environment with Content Preservation Option */}
      {deletingEnv && (
        <Dialog
          title={`Delete "${deletingEnv.name}"?`}
          description="Choose how to handle the secrets, assets, and notes inside this environment."
          onClose={() => setDeletingEnv(null)}
          footer={
            <>
              <Button variant="secondary" onClick={() => setDeletingEnv(null)}>
                Cancel
              </Button>
              <Button
                variant="danger"
                onClick={async () => {
                  await onDeleteEnvironment(deletingEnv.id, preserveOnEnvDelete);
                  setDeletingEnv(null);
                }}
              >
                Delete environment
              </Button>
            </>
          }
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: "var(--space-2)",
                cursor: "pointer",
              }}
            >
              <input
                type="radio"
                name="preserveContent"
                checked={preserveOnEnvDelete}
                onChange={() => setPreserveOnEnvDelete(true)}
              />
              <span>Move secrets, assets, and notes to General (preserve content)</span>
            </label>
            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: "var(--space-2)",
                cursor: "pointer",
              }}
            >
              <input
                type="radio"
                name="preserveContent"
                checked={!preserveOnEnvDelete}
                onChange={() => setPreserveOnEnvDelete(false)}
              />
              <span>Permanently delete all content in this environment</span>
            </label>
          </div>
        </Dialog>
      )}
    </div>
    </>
  );
}
