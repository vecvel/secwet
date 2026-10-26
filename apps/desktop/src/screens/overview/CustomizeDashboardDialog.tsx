import { useState } from "react";
import { Button } from "../../components/Button";
import { Checkbox } from "../../components/Checkbox";
import { Dialog } from "../../components/Dialog";
import { TextField } from "../../components/Field";
import type { DashboardConfig } from "../../lib/api";
import styles from "./CustomizeDashboardDialog.module.css";

interface Props {
  config: DashboardConfig;
  onClose: () => void;
  onSave: (config: DashboardConfig) => void;
}

const ALL_KPIS: { id: string; label: string }[] = [
  { id: "secrets", label: "Secrets" },
  { id: "assets", label: "Assets" },
  { id: "notes", label: "Notes" },
  { id: "devices", label: "Active Devices" },
];

const ALL_WIDGETS: { id: string; label: string }[] = [
  { id: "recent_secrets", label: "Recent Secrets" },
  { id: "recent_notes", label: "Recent Notes" },
  { id: "quick_actions", label: "Quick Actions" },
  { id: "checklist", label: "Setup and Safety Checklist" },
];

export function CustomizeDashboardDialog({ config, onClose, onSave }: Props) {
  const [homeLabel, setHomeLabel] = useState(config.home_label || "Overview");
  const [visibleKpis, setVisibleKpis] = useState<string[]>(() => {
    const raw = config.visible_kpis || [];
    return raw.map((k) => (k === "files" ? "assets" : k));
  });
  const [orderedWidgets, setOrderedWidgets] = useState<string[]>(() => {
    const current = config.widgets || [];
    const missing = ALL_WIDGETS.map((w) => w.id).filter((id) => !current.includes(id));
    return [...current, ...missing];
  });
  const [enabledWidgets, setEnabledWidgets] = useState<Set<string>>(
    () => new Set(config.widgets || ALL_WIDGETS.map((w) => w.id))
  );

  function toggleKpi(id: string) {
    setVisibleKpis((prev) =>
      prev.includes(id) ? prev.filter((k) => k !== id) : [...prev, id]
    );
  }

  function toggleWidget(id: string) {
    setEnabledWidgets((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  function moveWidget(index: number, direction: -1 | 1) {
    const target = index + direction;
    if (target < 0 || target >= orderedWidgets.length) return;
    const copy = [...orderedWidgets];
    const temp = copy[index];
    copy[index] = copy[target];
    copy[target] = temp;
    setOrderedWidgets(copy);
  }

  function handleSave() {
    const activeWidgets = orderedWidgets.filter((w) => enabledWidgets.has(w));
    onSave({
      home_label: homeLabel.trim() || "Overview",
      visible_kpis: visibleKpis,
      widgets: activeWidgets,
    });
    onClose();
  }

  return (
    <Dialog
      title="Customize dashboard"
      description="Tailor the Home title, KPI metrics, and dashboard widgets."
      onClose={onClose}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onClick={handleSave}>
            Save changes
          </Button>
        </>
      }
    >
      <div className={styles.content}>
        <div className={styles.section}>
          <TextField
            label="Home title"
            value={homeLabel}
            onChange={(e) => setHomeLabel(e.target.value)}
            placeholder="e.g. Overview, Workspace, Command Center"
            help="Rename the Home view in the sidebar and top navigation."
          />
        </div>

        <div className={styles.section}>
          <span className={styles.sectionTitle}>Visible KPI metrics</span>
          <div className={styles.kpiGrid}>
            {ALL_KPIS.map((kpi) => (
              <Checkbox
                key={kpi.id}
                label={kpi.label}
                checked={visibleKpis.includes(kpi.id)}
                onChange={() => toggleKpi(kpi.id)}
              />
            ))}
          </div>
        </div>

        <div className={styles.section}>
          <span className={styles.sectionTitle}>Widgets & ordering</span>
          <div className={styles.widgetList}>
            {orderedWidgets.map((widgetId, idx) => {
              const def = ALL_WIDGETS.find((w) => w.id === widgetId);
              if (!def) return null;
              return (
                <div key={widgetId} className={styles.widgetRow}>
                  <Checkbox
                    label={def.label}
                    checked={enabledWidgets.has(widgetId)}
                    onChange={() => toggleWidget(widgetId)}
                  />
                  <div className={styles.widgetActions}>
                    <Button
                      variant="tertiary"
                      disabled={idx === 0}
                      onClick={() => moveWidget(idx, -1)}
                      arrow={false}
                    >
                      Up
                    </Button>
                    <Button
                      variant="tertiary"
                      disabled={idx === orderedWidgets.length - 1}
                      onClick={() => moveWidget(idx, 1)}
                      arrow={false}
                    >
                      Down
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </Dialog>
  );
}
