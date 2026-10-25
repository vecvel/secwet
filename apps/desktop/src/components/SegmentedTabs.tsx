import type { KeyboardEvent } from "react";
import { IconButton } from "./Button";
import styles from "./SegmentedTabs.module.css";

export interface TabItem {
  id: string;
  label: string;
  count?: number;
}

interface Props {
  label: string;
  items: TabItem[];
  value: string;
  onChange: (id: string) => void;
  /** Optional trailing button, for example "New environment". */
  onAdd?: () => void;
  addLabel?: string;
}

/** Tab list with arrow-key navigation; the selected tab gets a filled tint (weight never changes). */
export function SegmentedTabs({ label, items, value, onChange, onAdd, addLabel = "Add" }: Props) {
  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const i = items.findIndex((t) => t.id === value);
    const next = items[(i + (e.key === "ArrowRight" ? 1 : items.length - 1)) % items.length];
    onChange(next.id);
    e.currentTarget.querySelector<HTMLButtonElement>(`[data-tab="${next.id}"]`)?.focus();
  }

  return (
    <div className={styles.wrap}>
      <div role="tablist" aria-label={label} className={styles.tabs} onKeyDown={onKeyDown}>
        {items.map((t) => {
          const selected = t.id === value;
          return (
            <button
              key={t.id}
              role="tab"
              data-tab={t.id}
              aria-selected={selected}
              tabIndex={selected ? 0 : -1}
              className={[styles.tab, selected && styles.selected].filter(Boolean).join(" ")}
              onClick={() => onChange(t.id)}
            >
              {t.label}
              {t.count !== undefined && <span className={styles.count}>{t.count}</span>}
            </button>
          );
        })}
      </div>
      {onAdd && <IconButton icon="plus" label={addLabel} onClick={onAdd} />}
    </div>
  );
}
