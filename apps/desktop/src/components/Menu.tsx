import { Fragment, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { Icon, type IconName } from "./Icon";
import styles from "./Menu.module.css";

export interface MenuItem {
  label: string;
  icon: IconName;
  onSelect: () => void;
  danger?: boolean;
  /** Draws a divider above this item. */
  separator?: boolean;
}

/**
 * "More" button that opens a small action menu. Closes on outside click, Escape or selection.
 * Opens upward when there is no room below. Arrow keys move between items.
 */
export function MoreMenu({ label, items }: { label: string; items: MenuItem[] }) {
  const [open, setOpen] = useState(false);
  const [up, setUp] = useState(false);
  const wrap = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const menu = wrap.current?.querySelector<HTMLElement>('[role="menu"]');
    if (menu && trigger.current) {
      const r = trigger.current.getBoundingClientRect();
      setUp(r.bottom + menu.offsetHeight + 72 > window.innerHeight);
    }
    menu?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
    const onDown = (e: MouseEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        setOpen(false);
        trigger.current?.focus();
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  function onMenuKey(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const all = Array.from(e.currentTarget.querySelectorAll<HTMLElement>('[role="menuitem"]'));
    const i = all.indexOf(document.activeElement as HTMLElement);
    all[(i + (e.key === "ArrowDown" ? 1 : all.length - 1)) % all.length]?.focus();
  }

  return (
    <div className={styles.wrap} ref={wrap}>
      <button
        ref={trigger}
        type="button"
        className={[styles.trigger, open && styles.open].filter(Boolean).join(" ")}
        aria-label={label}
        title={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <Icon name="more" size={18} />
      </button>
      {open && (
        <div role="menu" aria-label={label} className={[styles.menu, up && styles.up].filter(Boolean).join(" ")} onKeyDown={onMenuKey}>
          {items.map((it) => (
            <Fragment key={it.label}>
              {it.separator && <div className={styles.separator} role="separator" />}
              <button
                type="button"
                role="menuitem"
                className={[styles.item, it.danger && styles.danger].filter(Boolean).join(" ")}
                onClick={() => {
                  setOpen(false);
                  it.onSelect();
                }}
              >
                <Icon name={it.icon} />
                <span>{it.label}</span>
              </button>
            </Fragment>
          ))}
        </div>
      )}
    </div>
  );
}
