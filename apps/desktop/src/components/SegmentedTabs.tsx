import type { KeyboardEvent, ReactNode } from "react";
import { Fragment } from "react";
import { IconButton } from "./Button";
import styles from "./SegmentedTabs.module.css";
// import { Icon } from "./Icon";

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
  /** If provided, renders a vertical separator right after the tab with this id */
  separatorAfterId?: string;
  /** Optional trailing content aligned to the right (e.g. actions menu) */
  extra?: ReactNode;
}

/** Tab list with arrow-key navigation; minimal style with active bottom indicator line. */
export function SegmentedTabs({
  label,
  items,
  value,
  onChange,
  onAdd,
  addLabel = "Add",
  // separatorAfterId,
  extra,
}: Props) {
  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const i = items.findIndex((t) => t.id === value);
    if (i < 0) return;
    const next = items[(i + (e.key === "ArrowRight" ? 1 : items.length - 1)) % items.length];
    onChange(next.id);
    e.currentTarget.querySelector<HTMLButtonElement>(`[data-tab="${next.id}"]`)?.focus();
  }

  return (
    <div className={styles.wrap}>
      <div role="tablist" aria-label={label} className={styles.tabs} onKeyDown={onKeyDown}>
        {items.map((t, _idx) => { //_idx -> idx
          const selected = t.id === value;
          // const showSeparator =
          //   separatorAfterId !== undefined &&
          //   t.id === separatorAfterId &&
            // idx < items.length - 1;  

          return (
            <Fragment key={t.id}>
              <button
                role="tab"
                data-tab={t.id}
                aria-selected={selected}
                tabIndex={selected ? 0 : -1}
                className={[styles.tab, selected && styles.selected].filter(Boolean).join(" ")}
                onClick={() => onChange(t.id)}
              >
                <span>{t.label}</span>
                {t.count !== undefined && <span className={styles.count}>{t.count}</span>}
              </button>
              {/* {showSeparator && (
            <span className={styles.separator} aria-hidden="true" /> 
              )} */}
            </Fragment>
          );
        })}
      </div>
      {onAdd && <IconButton icon="plus" label={addLabel} onClick={onAdd} />}
      {extra && <div className={styles.extra}>{extra}</div>}
    </div>
  );
}
