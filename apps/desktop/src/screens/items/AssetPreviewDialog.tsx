import { useEffect, useState, useMemo } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { api, type AssetMetaView } from "../../lib/api";
import { formatAgo } from "../../lib/format";
import styles from "./AssetPreviewDialog.module.css";

interface Props {
  asset: AssetMetaView;
  onClose: () => void;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

/** Simple parser for previewing markdown without third-party dependencies */
function renderMarkdownText(text: string) {
  const lines = text.split("\n");
  return (
    <div className={styles.markdownPreview}>
      {lines.map((line, idx) => {
        if (line.startsWith("# ")) return <h1 key={idx}>{line.slice(2)}</h1>;
        if (line.startsWith("## ")) return <h2 key={idx}>{line.slice(3)}</h2>;
        if (line.startsWith("### ")) return <h3 key={idx}>{line.slice(4)}</h3>;
        if (line.startsWith("- ") || line.startsWith("* ")) {
          return (
            <ul key={idx}>
              <li>{line.slice(2)}</li>
            </ul>
          );
        }
        if (!line.trim()) return <br key={idx} />;
        return <p key={idx}>{line}</p>;
      })}
    </div>
  );
}

export function AssetPreviewDialog({ asset, onClose }: Props) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [assetBytes, setAssetBytes] = useState<Uint8Array | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        setLoading(true);
        const res = await api.assetDownload(asset.id);
        if (active) {
          setAssetBytes(new Uint8Array(res.bytes));
          setLoading(false);
        }
      } catch (err: any) {
        if (active) {
          setError(err?.message || "Failed to download asset for preview.");
          setLoading(false);
        }
      }
    }
    load();
    return () => {
      active = false;
    };
  }, [asset.id]);

  const objectUrl = useMemo(() => {
    if (!assetBytes) return null;
    const blob = new Blob([assetBytes.buffer as ArrayBuffer], { type: asset.mime_type || "application/octet-stream" });
    return URL.createObjectURL(blob);
  }, [assetBytes, asset.mime_type]);

  useEffect(() => {
    return () => {
      if (objectUrl) {
        URL.revokeObjectURL(objectUrl);
      }
    };
  }, [objectUrl]);

  function handleDownload() {
    if (!objectUrl) return;
    const a = document.createElement("a");
    a.href = objectUrl;
    a.download = asset.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  const isImage = asset.mime_type.startsWith("image/");
  const isPdf = asset.mime_type === "application/pdf" || asset.name.endsWith(".pdf");
  const isMarkdown = asset.name.endsWith(".md") || asset.mime_type === "text/markdown";
  const isText =
    asset.mime_type.startsWith("text/") ||
    asset.name.endsWith(".json") ||
    asset.name.endsWith(".csv") ||
    asset.name.endsWith(".env") ||
    asset.name.endsWith(".txt");

  const textContent = useMemo(() => {
    if (!assetBytes || (!isText && !isMarkdown)) return "";
    try {
      return new TextDecoder().decode(assetBytes);
    } catch {
      return "Unable to decode text.";
    }
  }, [assetBytes, isText, isMarkdown]);

  return (
    <Dialog
      title={asset.name}
      description={`${formatBytes(asset.size_bytes)} · Uploaded ${formatAgo(asset.updated_at)}`}
      onClose={onClose}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
          <Button
            variant="primary"
            icon="download"
            disabled={!objectUrl}
            onClick={handleDownload}
          >
            Download
          </Button>
        </>
      }
    >
      <div className={styles.previewContainer}>
        {loading && <p>Loading preview...</p>}
        {error && <p style={{ color: "var(--color-danger)" }}>{error}</p>}
        {!loading && !error && objectUrl && (
          <>
            {isImage && (
              <img src={objectUrl} alt={asset.name} className={styles.imagePreview} />
            )}
            {isPdf && (
              <iframe
                src={objectUrl}
                title={asset.name}
                className={styles.pdfPreview}
              />
            )}
            {isMarkdown && renderMarkdownText(textContent)}
            {!isMarkdown && isText && (
              <pre className={styles.textPreview}>{textContent}</pre>
            )}
            {!isImage && !isPdf && !isText && !isMarkdown && (
              <div className={styles.unsupportedCard}>
                <Icon name="folder" size={36} />
                <p>Preview is not available for this asset format.</p>
                <div className={styles.metaRow}>
                  <span>MIME: {asset.mime_type}</span>
                  <span>·</span>
                  <span>SHA-256: {asset.sha256.slice(0, 16)}...</span>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </Dialog>
  );
}

// Backward compatibility alias
export const FilePreviewDialog = ({ file, onClose }: { file: AssetMetaView; onClose: () => void }) => (
  <AssetPreviewDialog asset={file} onClose={onClose} />
);
