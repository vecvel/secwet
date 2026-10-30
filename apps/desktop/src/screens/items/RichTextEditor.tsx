import { useState, useRef, useEffect, type FormEvent } from "react";
import { Button, IconButton } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { MoreMenu, type MenuItem } from "../../components/Menu";
import { api, copyViaDocument, type NoteView } from "../../lib/api";
import styles from "./RichTextEditor.module.css";

interface Props {
  note?: NoteView | null;
  itemId: string;
  environmentId?: string | null;
  onSave: (title: string, content: string) => Promise<void>;
  onDelete?: (id: string) => Promise<void>;
  onClose: () => void;
  /** Viewer role or read-only archive: show the note without editing controls. */
  readOnly?: boolean;
}

/**
 * Strips HTML tags while preserving meaningful document structure.
 */
export function extractPlainTextFromHtml(html: string): string {
  if (!html) return "";
  const div = document.createElement("div");
  div.innerHTML = html;

  function traverse(node: Node): string {
    if (node.nodeType === Node.TEXT_NODE) {
      return node.textContent || "";
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return "";

    const el = node as HTMLElement;
    const tag = el.tagName.toLowerCase();

    const childText = Array.from(el.childNodes).map(traverse).join("");

    switch (tag) {
      case "h1":
        return `# ${childText.trim()}\n\n`;
      case "h2":
        return `## ${childText.trim()}\n\n`;
      case "h3":
        return `### ${childText.trim()}\n\n`;
      case "p":
        return `${childText.trim()}\n\n`;
      case "li":
        return `• ${childText.trim()}\n`;
      case "tr": {
        const cells = Array.from(el.querySelectorAll("th, td")).map((c) =>
          (c.textContent || "").trim()
        );
        return cells.length ? cells.join(" | ") + "\n" : "";
      }
      case "blockquote":
        return `> ${childText.trim()}\n\n`;
      case "pre":
        return `\`\`\`\n${childText.trim()}\n\`\`\`\n\n`;
      case "br":
        return "\n";
      default:
        return childText;
    }
  }

  return traverse(div).replace(/\n{3,}/g, "\n\n").trim();
}

/**
 * WYSIWYG Rich Text Editor for Notes.
 * Includes formatting toolbar (headings, bold, italic, underline, lists, tables, code)
 * and dedicated "Copy as Plain Text" action.
 */
export function RichTextEditor({ note, itemId: _itemId, environmentId: _environmentId, onSave, onDelete, onClose, readOnly = false }: Props) {
  const [title, setTitle] = useState(note?.title || "");
  const [copiedState, setCopiedState] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string>();
  const [saving, setSaving] = useState(false);

  const editorRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (editorRef.current && note) {
      editorRef.current.innerHTML = note.content;
    } else if (editorRef.current && !note) {
      editorRef.current.innerHTML = "";
    }
  }, [note]);

  function exec(command: string, value: string | undefined = undefined) {
    document.execCommand(command, false, value);
    editorRef.current?.focus();
  }

  function insertTable() {
    const tableHtml =
      "<table><thead><tr><th>Header 1</th><th>Header 2</th></tr></thead><tbody><tr><td>Cell 1</td><td>Cell 2</td></tr></tbody></table><p></p>";
    document.execCommand("insertHTML", false, tableHtml);
    editorRef.current?.focus();
  }

  function insertLink() {
    const url = prompt("Enter link URL:", "https://");
    if (url) {
      exec("createLink", url);
    }
  }

  async function copyAsPlainText() {
    const html = editorRef.current?.innerHTML || "";
    const plainText = extractPlainTextFromHtml(html);
    try {
      if (note?.id) {
        await api.noteCopyPlain(note.id);
      } else {
        await api.clipboardCopyText(plainText);
      }
      setCopiedState(true);
      setTimeout(() => setCopiedState(false), 1500);
    } catch (err) {
      console.error("Failed to copy plain text:", err);
    }
  }

  async function copyWithFormatting() {
    const html = editorRef.current?.innerHTML || "";
    const plainText = extractPlainTextFromHtml(html);
    try {
      copyViaDocument(plainText, html);
      setCopiedState(true);
      setTimeout(() => setCopiedState(false), 1500);
    } catch (err) {
      console.error("Failed to copy formatted text, fallback to plain:", err);
      await api.clipboardCopyText(plainText);
      setCopiedState(true);
      setTimeout(() => setCopiedState(false), 1500);
    }
  }

  const copyMenuItems: MenuItem[] = [
    {
      label: "Plain text",
      icon: "file",
      onSelect: copyAsPlainText,
    },
    {
      label: "Formatted text",
      icon: "document",
      onSelect: copyWithFormatting,
    },
  ];

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (readOnly) return;
    const trimmedTitle = title.trim();
    if (!trimmedTitle) {
      setError("Enter a title for this note.");
      return;
    }
    const content = editorRef.current?.innerHTML || "";
    setSaving(true);
    try {
      await onSave(trimmedTitle, content);
      onClose();
    } catch (err: any) {
      setError(err?.message || "Failed to save note.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className={styles.editorContainer} onSubmit={handleSubmit}>
      <div className={styles.headerRow}>
        <input
          type="text"
          className={styles.titleInput}
          placeholder="Note title..."
          aria-label="Note title"
          value={title}
          readOnly={readOnly}
          autoFocus={!note}
          onChange={(e) => {
            setTitle(e.target.value);
            if (error) setError(undefined);
          }}
        />
        <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
          <MoreMenu
            label={copiedState ? "Copied to clipboard" : "Copy note"}
            icon={copiedState ? "check" : "copy"}
            items={copyMenuItems}
          />
          {note && onDelete && (
            <IconButton
              icon="trash"
              label="Delete note"
              onClick={() => setDeleting(true)}
            />
          )}
        </div>
      </div>

      {error && (
        <p className={styles.error} role="alert">
          {error}
        </p>
      )}

      {/* Formatting Toolbar */}
      {!readOnly && (
      <div className={styles.toolbar} role="toolbar" aria-label="Formatting toolbar">
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Heading 1"
          onClick={() => exec("formatBlock", "<h1>")}
        >
          H1
        </button>
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Heading 2"
          onClick={() => exec("formatBlock", "<h2>")}
        >
          H2
        </button>
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Heading 3"
          onClick={() => exec("formatBlock", "<h3>")}
        >
          H3
        </button>
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Paragraph"
          onClick={() => exec("formatBlock", "<p>")}
        >
          P
        </button>

        <span className={styles.separator} />

        <button
          type="button"
          className={styles.toolbarBtn}
          title="Bold (Ctrl+B)"
          onClick={() => exec("bold")}
        >
          <strong>B</strong>
        </button>
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Italic (Ctrl+I)"
          onClick={() => exec("italic")}
        >
          <em>I</em>
        </button>
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Underline (Ctrl+U)"
          onClick={() => exec("underline")}
        >
          <u>U</u>
        </button>
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Strikethrough"
          onClick={() => exec("strikeThrough")}
        >
          <s>S</s>
        </button>

        <span className={styles.separator} />

        <button
          type="button"
          className={styles.toolbarBtn}
          title="Bulleted list"
          onClick={() => exec("insertUnorderedList")}
        >
          • List
        </button>
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Numbered list"
          onClick={() => exec("insertOrderedList")}
        >
          1. List
        </button>
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Blockquote"
          onClick={() => exec("formatBlock", "<blockquote>")}
        >
          ” Quote
        </button>
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Code block"
          onClick={() => exec("formatBlock", "<pre>")}
        >
          &lt;/&gt; Code
        </button>
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Insert table"
          onClick={insertTable}
        >
          Table
        </button>
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Insert link"
          onClick={insertLink}
        >
          Link
        </button>

        <span className={styles.separator} />

        <button
          type="button"
          className={styles.toolbarBtn}
          title="Undo"
          onClick={() => exec("undo")}
        >
          Undo
        </button>
        <button
          type="button"
          className={styles.toolbarBtn}
          title="Redo"
          onClick={() => exec("redo")}
        >
          Redo
        </button>
      </div>
      )}

      {/* Contenteditable WYSIWYG Area */}
      <div
        ref={editorRef}
        className={styles.contentArea}
        contentEditable={!readOnly}
        role="textbox"
        aria-readonly={readOnly || undefined}
        aria-multiline="true"
        aria-label="Note content"
        suppressContentEditableWarning
      />

      <div className={styles.actionsRow}>
        <Button variant="secondary" type="button" onClick={onClose}>
          {readOnly ? "Close" : "Cancel"}
        </Button>
        {!readOnly && (
          <Button variant="primary" type="submit" disabled={saving}>
            {saving ? "Saving..." : note ? "Save changes" : "Create note"}
          </Button>
        )}
      </div>

      {deleting && note && onDelete && (
        <ConfirmDialog
          title={`Delete "${note.title}"?`}
          body={<p>Are you sure you want to permanently delete this note?</p>}
          confirmLabel="Delete note"
          onConfirm={async () => {
            await onDelete(note.id);
            setDeleting(false);
            onClose();
          }}
          onCancel={() => setDeleting(false)}
        />
      )}
    </form>
  );
}
