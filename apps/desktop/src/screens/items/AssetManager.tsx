import { useState, useRef, type DragEvent, type ChangeEvent } from "react";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { Icon, IconTile } from "../../components/Icon";
import { MoreMenu, type MenuItem } from "../../components/Menu";
import { NameDialog } from "../../components/NameDialog";
import { api, type AssetMetaView } from "../../lib/api";
import { formatAgo } from "../../lib/format";
import { AssetPreviewDialog } from "./AssetPreviewDialog";
import styles from "./AssetManager.module.css";

interface Props {
  itemId: string;
  environmentId?: string | null;
  assets?: AssetMetaView[];
  files?: AssetMetaView[];
  onUpload: (name: string, mime: string, bytes: number[] | Uint8Array) => Promise<void>;
  onRename: (id: string, name: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  /** Member mode and read-only archive: hide controls the role doesn't allow. */
  canUpload?: boolean;
  canRename?: boolean;
  canDelete?: boolean;
}

const MAX_ASSET_SIZE = 50 * 1024 * 1024; // 50 MiB

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

export function AssetManager({
  assets: propAssets,
  files: propFiles,
  onUpload,
  onRename,
  onDelete,
  canUpload = true,
  canRename = true,
  canDelete = true,
}: Props) {
  const assets = propAssets ?? propFiles ?? [];
  const [dragOver, setDragOver] = useState(false);
  const [uploadError, setUploadError] = useState<string>();
  const [uploading, setUploading] = useState(false);

  const [previewAsset, setPreviewAsset] = useState<AssetMetaView | null>(null);
  const [renamingAsset, setRenamingAsset] = useState<AssetMetaView | null>(null);
  const [deletingAsset, setDeletingAsset] = useState<AssetMetaView | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  async function handleFiles(fileList: FileList | null) {
    if (!fileList || fileList.length === 0) return;
    setUploadError(undefined);

    for (let i = 0; i < fileList.length; i++) {
      const file = fileList[i];
      if (file.size > MAX_ASSET_SIZE) {
        setUploadError(`"${file.name}" exceeds 50 MiB limit.`);
        return;
      }
    }

    setUploading(true);
    try {
      for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i];
        const arrayBuffer = await file.arrayBuffer();
        const bytes = new Uint8Array(arrayBuffer);
        await onUpload(file.name, file.type || "application/octet-stream", bytes);
      }
    } catch (err: any) {
      setUploadError(err?.message || "Failed to upload asset.");
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  function onDragOver(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragOver(true);
  }

  function onDragLeave(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragOver(false);
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragOver(false);
    handleFiles(e.dataTransfer.files);
  }

  function onFileInputChange(e: ChangeEvent<HTMLInputElement>) {
    handleFiles(e.target.files);
  }

  async function downloadDirect(asset: AssetMetaView) {
    try {
      const res = await api.assetDownload(asset.id);
      const blob = new Blob([new Uint8Array(res.bytes)], {
        type: asset.mime_type || "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = asset.name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setUploadError(err?.message || "Failed to download asset.");
    }
  }

  return (
    <div className={styles.managerContainer}>
      <input
        type="file"
        ref={fileInputRef}
        multiple
        style={{ display: "none" }}
        onChange={onFileInputChange}
      />

      {/* Drag & Drop Upload Zone */}
      {canUpload && (
      <div
        className={[styles.dropzone, dragOver && styles.dropzoneDragOver]
          .filter(Boolean)
          .join(" ")}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        onClick={() => fileInputRef.current?.click()}
        role="button"
        tabIndex={0}
      >
        <Icon name="plus" size={24} />
        <span className={styles.dropzoneTitle}>
          {uploading ? "Uploading encrypted asset..." : "Drop assets here or click to upload"}
        </span>
        <span className={styles.dropzoneSub}>
          Encrypted on-device before storage · Up to 50 MiB per asset
        </span>
      </div>
      )}

      {uploadError && <div className={styles.errorNotice}>{uploadError}</div>}

      {/* Assets List */}
      {assets.length === 0 ? (
        <EmptyState
          icon="folder"
          title="No assets yet"
          body="Upload documents, certificates, PDFs, images, or configurations."
          action={
            canUpload ? (
              <Button
                variant="secondary"
                icon="plus"
                onClick={() => fileInputRef.current?.click()}
              >
                Upload asset
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className={styles.assetsContainer}>
          <ul className={styles.assetsList}>
            {assets.map((asset) => {
              const menuItems: MenuItem[] = [
                {
                  label: "Preview",
                  icon: "eye",
                  onSelect: () => setPreviewAsset(asset),
                },
                {
                  label: "Download",
                  icon: "download",
                  onSelect: () => downloadDirect(asset),
                },
              ];
              if (canRename) {
                menuItems.push({
                  label: "Rename",
                  icon: "pencil",
                  onSelect: () => setRenamingAsset(asset),
                });
              }
              if (canDelete) {
                menuItems.push({
                  label: "Delete",
                  icon: "trash",
                  danger: true,
                  onSelect: () => setDeletingAsset(asset),
                });
              }

              return (
                <li key={asset.id} className={styles.assetCard}>
                  <div
                    className={styles.assetMain}
                    onClick={() => setPreviewAsset(asset)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setPreviewAsset(asset);
                      }
                    }}
                    style={{ cursor: "pointer" }}
                    title={`Preview ${asset.name}`}
                  >
                    <IconTile icon="folder" selected={false} />
                    <div className={styles.assetInfo}>
                      <span className={styles.assetName}>{asset.name}</span>
                      <div className={styles.assetMeta}>
                        <span>{formatBytes(asset.size_bytes)}</span>
                        <span>·</span>
                        <Badge tone="neutral">{asset.mime_type}</Badge>
                        <span>·</span>
                        <span>Uploaded {formatAgo(asset.updated_at)}</span>
                      </div>
                    </div>
                  </div>

                  <div className={styles.assetActions}>
                    <MoreMenu label={`Actions for ${asset.name}`} items={menuItems} />
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {/* Preview Dialog */}
      {previewAsset && (
        <AssetPreviewDialog
          asset={previewAsset}
          onClose={() => setPreviewAsset(null)}
        />
      )}

      {/* Rename Dialog */}
      {renamingAsset && (
        <NameDialog
          title="Rename asset"
          label="Asset name"
          initial={renamingAsset.name}
          confirmLabel="Rename"
          validate={(val) => {
            const trimmed = val.trim();
            if (!trimmed) return "Asset name cannot be empty.";
            return undefined;
          }}
          onSubmit={async (newName) => {
            await onRename(renamingAsset.id, newName);
            setRenamingAsset(null);
          }}
          onCancel={() => setRenamingAsset(null)}
        />
      )}

      {/* Delete Dialog */}
      {deletingAsset && (
        <ConfirmDialog
          title={`Delete "${deletingAsset.name}"?`}
          body={<p>Are you sure you want to permanently delete this asset?</p>}
          confirmLabel="Delete asset"
          onConfirm={async () => {
            await onDelete(deletingAsset.id);
            setDeletingAsset(null);
          }}
          onCancel={() => setDeletingAsset(null)}
        />
      )}
    </div>
  );
}

// Backward compatibility alias
export const FileManager = AssetManager;
