import type { KeyboardEvent, PointerEvent as ReactPointerEvent, ReactNode } from "react";
import { Fragment, useEffect, useRef, useState } from "react";
import { IconButton } from "./Button";
import styles from "./SegmentedTabs.module.css";
// import { Icon } from "./Icon";

export interface TabItem {
  id: string;
  label: string;
  count?: number;
  draggable?: boolean;
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
  /** When true, tabs can be reordered via drag-and-drop or Alt+Arrow keys */
  reorderable?: boolean;
  /** Callback fired when tabs are reordered */
  onReorder?: (items: TabItem[]) => void;
}

/** Tab list with arrow-key navigation; minimal style with active bottom indicator line. */
export function SegmentedTabs({
  label,
  items,
  value,
  onChange,
  onAdd,
  addLabel = "Add",
  extra,
  reorderable = false,
  onReorder,
}: Props) {
  const tabsRef = useRef<HTMLDivElement>(null);
  const [draggedId, setDraggedId] = useState<string | null>(null);
  const [holdingId, setHoldingId] = useState<string | null>(null);
  const [dropIndicator, setDropIndicator] = useState<{ id: string; position: "before" | "after" } | null>(null);
  const dropIndicatorRef = useRef<{ id: string; position: "before" | "after" } | null>(null);
  const isDragFinishedRef = useRef(false);
  const holdTimerRef = useRef<number | null>(null);

  const dragRef = useRef<{
    id: string;
    startX: number;
    startY: number;
    isDragging: boolean;
    tabRects: { id: string; left: number; right: number; width: number }[];
  } | null>(null);

  useEffect(() => {
    return () => {
      if (holdTimerRef.current) {
        window.clearTimeout(holdTimerRef.current);
      }
      document.body.style.cursor = "";
    };
  }, []);

  function updateDropIndicator(next: { id: string; position: "before" | "after" } | null) {
    dropIndicatorRef.current = next;
    setDropIndicator(next);
  }

  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;

    // Alt+Arrow to reorder active tab when reordering is enabled
    if (reorderable && onReorder && e.altKey) {
      e.preventDefault();
      const i = items.findIndex((t) => t.id === value);
      if (i < 0) return;
      const targetIndex = e.key === "ArrowLeft" ? i - 1 : i + 1;
      if (targetIndex >= 0 && targetIndex < items.length) {
        const nextItems = [...items];
        const [moved] = nextItems.splice(i, 1);
        nextItems.splice(targetIndex, 0, moved);
        onReorder(nextItems);
        setTimeout(() => {
          tabsRef.current?.querySelector<HTMLButtonElement>(`[data-tab="${moved.id}"]`)?.focus();
        }, 0);
      }
      return;
    }

    const i = items.findIndex((t) => t.id === value);
    if (i < 0) return;
    const next = items[(i + (e.key === "ArrowRight" ? 1 : items.length - 1)) % items.length];
    onChange(next.id);
    tabsRef.current?.querySelector<HTMLButtonElement>(`[data-tab="${next.id}"]`)?.focus();
  }

  function handlePointerDown(e: ReactPointerEvent<HTMLButtonElement>, id: string) {
    if (!reorderable || !onReorder) return;
    if (e.button !== 0) return; // Only primary mouse button

    const container = tabsRef.current;
    if (!container) return;

    const tabButtons = Array.from(container.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
    const tabRects = tabButtons.map((btn) => {
      const rect = btn.getBoundingClientRect();
      return {
        id: btn.getAttribute("data-tab") || "",
        left: rect.left,
        right: rect.right,
        width: rect.width,
      };
    });

    dragRef.current = {
      id,
      startX: e.clientX,
      startY: e.clientY,
      isDragging: false,
      tabRects,
    };

    if (holdTimerRef.current) {
      window.clearTimeout(holdTimerRef.current);
    }
    // Only show grab/grabbing cursor after recommended hold delay (160ms), never on quick click
    holdTimerRef.current = window.setTimeout(() => {
      if (dragRef.current) {
        setHoldingId(id);
        document.body.style.cursor = "grabbing";
      }
    }, 160);

    try {
      (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    } catch {
      // ignore
    }
  }

  function handlePointerMove(e: ReactPointerEvent<HTMLButtonElement>) {
    const drag = dragRef.current;
    if (!drag) return;

    const dx = e.clientX - drag.startX;
    const dy = e.clientY - drag.startY;
    const dist = Math.hypot(dx, dy);

    if (!drag.isDragging) {
      if (dist > 4) {
        if (holdTimerRef.current) {
          window.clearTimeout(holdTimerRef.current);
          holdTimerRef.current = null;
        }
        drag.isDragging = true;
        setDraggedId(drag.id);
        setHoldingId(drag.id);
        document.body.style.cursor = "grabbing";
      } else {
        return;
      }
    }

    const clientX = e.clientX;
    let targetId: string | null = null;
    let position: "before" | "after" = "before";

    for (const rect of drag.tabRects) {
      if (clientX >= rect.left && clientX <= rect.right) {
        targetId = rect.id;
        const mid = rect.left + rect.width / 2;
        position = clientX < mid ? "before" : "after";
        break;
      }
    }

    if (!targetId && drag.tabRects.length > 0) {
      if (clientX < drag.tabRects[0].left) {
        targetId = drag.tabRects[0].id;
        position = "before";
      } else if (clientX > drag.tabRects[drag.tabRects.length - 1].right) {
        targetId = drag.tabRects[drag.tabRects.length - 1].id;
        position = "after";
      }
    }

    if (targetId && targetId !== drag.id) {
      updateDropIndicator({ id: targetId, position });
    } else {
      updateDropIndicator(null);
    }
  }

  function handlePointerUp(e: ReactPointerEvent<HTMLButtonElement>) {
    if (holdTimerRef.current) {
      window.clearTimeout(holdTimerRef.current);
      holdTimerRef.current = null;
    }
    document.body.style.cursor = "";
    setHoldingId(null);

    try {
      (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
    } catch {
      // ignore
    }

    const drag = dragRef.current;
    dragRef.current = null;

    if (!drag || !drag.isDragging) {
      isDragFinishedRef.current = false;
      setDraggedId(null);
      updateDropIndicator(null);
      return;
    }

    isDragFinishedRef.current = true;
    setTimeout(() => {
      isDragFinishedRef.current = false;
    }, 100);

    const targetIndicator = dropIndicatorRef.current;
    if (targetIndicator && targetIndicator.id !== drag.id && onReorder) {
      const fromIndex = items.findIndex((t) => t.id === drag.id);
      const targetIndex = items.findIndex((t) => t.id === targetIndicator.id);

      if (fromIndex !== -1 && targetIndex !== -1) {
        let toIndex = targetIndicator.position === "before" ? targetIndex : targetIndex + 1;
        if (fromIndex < toIndex) {
          toIndex -= 1;
        }
        if (toIndex !== fromIndex) {
          const nextItems = [...items];
          const [moved] = nextItems.splice(fromIndex, 1);
          nextItems.splice(toIndex, 0, moved);
          onReorder(nextItems);
        }
      }
    }

    setDraggedId(null);
    updateDropIndicator(null);
  }

  function handlePointerCancel(e: ReactPointerEvent<HTMLButtonElement>) {
    if (holdTimerRef.current) {
      window.clearTimeout(holdTimerRef.current);
      holdTimerRef.current = null;
    }
    try {
      (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
    } catch {
      // ignore
    }
    document.body.style.cursor = "";
    dragRef.current = null;
    isDragFinishedRef.current = false;
    setDraggedId(null);
    setHoldingId(null);
    updateDropIndicator(null);
  }

  return (
    <div className={styles.wrap}>
      <div
        ref={tabsRef}
        role="tablist"
        aria-label={label}
        className={styles.tabs}
        onKeyDown={onKeyDown}
      >
        {items.map((t) => {
          const selected = t.id === value;
          const isItemDraggable = Boolean(reorderable && onReorder && t.draggable !== false);
          const isBeingDragged = draggedId === t.id;
          const isHolding = holdingId === t.id;
          const isDragTarget = dropIndicator?.id === t.id;
          const dropIndicatorClass = isDragTarget
            ? dropIndicator.position === "before"
              ? styles.dropIndicatorBefore
              : styles.dropIndicatorAfter
            : undefined;

          return (
            <Fragment key={t.id}>
              <button
                role="tab"
                data-tab={t.id}
                aria-selected={selected}
                tabIndex={selected ? 0 : -1}
                onPointerDown={isItemDraggable ? (e) => handlePointerDown(e, t.id) : undefined}
                onPointerMove={isItemDraggable ? handlePointerMove : undefined}
                onPointerUp={isItemDraggable ? handlePointerUp : undefined}
                onPointerCancel={isItemDraggable ? handlePointerCancel : undefined}
                className={[
                  styles.tab,
                  selected && styles.selected,
                  isItemDraggable && styles.draggable,
                  isHolding && styles.holding,
                  isBeingDragged && styles.dragging,
                  dropIndicatorClass,
                ]
                  .filter(Boolean)
                  .join(" ")}
                onClick={() => {
                  if (isDragFinishedRef.current) return;
                  onChange(t.id);
                }}
              >
                <span>{t.label}</span>
                {t.count !== undefined && <span className={styles.count}>{t.count}</span>}
              </button>
            </Fragment>
          );
        })}
      </div>
      {onAdd && <IconButton icon="plus" label={addLabel} onClick={onAdd} />}
      {extra && <div className={styles.extra}>{extra}</div>}
    </div>
  );
}
