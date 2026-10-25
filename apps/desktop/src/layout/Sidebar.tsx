import { BrandMark, Icon, IconTile, type IconName } from "../components/Icon";
import { thisDevice, type Plan, type Project } from "../data/mock";
import { onWindowDragMouseDown } from "../lib/windowDrag";
import type { Route } from "./routes";
import styles from "./Sidebar.module.css";

interface Props {
  route: Route;
  onNavigate: (route: Route) => void;
  projects: Project[];
  projectId: string | undefined;
  onSelectProject: (id: string) => void;
  onNewProject: () => void;
  plan: Plan;
}

interface ItemProps {
  label: string;
  icon?: IconName;
  initial?: string;
  active: boolean;
  onClick: () => void;
  className?: string;
}

function NavItem({ label, icon, initial, active, onClick, className }: ItemProps) {
  return (
    <button
      className={[styles.item, active && styles.active, className].filter(Boolean).join(" ")}
      aria-current={active ? "page" : undefined}
      title={label}
      onClick={onClick}
    >
      <IconTile icon={icon} initial={initial} selected={active} />
      <span className={styles.itemLabel}>{label}</span>
    </button>
  );
}

const initialOf = (name: string) => name.replace(/[^A-Za-z0-9]/g, "").charAt(0).toUpperCase() || "#";

/** Expanded: full sidebar with projects. Medium: icon rail with destinations only. */
export function Sidebar({ route, onNavigate, projects, projectId, onSelectProject, onNewProject, plan }: Props) {
  return (
    <aside className={styles.sidebar} aria-label="Main">
      <div className={styles.titleRow} onMouseDown={onWindowDragMouseDown} />
      <div className={styles.brand} onMouseDown={onWindowDragMouseDown}>
        <span className={styles.mark}>
          <BrandMark size={28} />
        </span>
        <span className={styles.brandName}>Secwet</span>
      </div>

      <nav className={styles.nav}>
        <div className={styles.group}>
          <span className={styles.groupLabel}>Home</span>
          <NavItem icon="grid" label="Overview" active={route === "overview"} onClick={() => onNavigate("overview")} />
        </div>
        <NavItem icon="key" label="Secrets" active={route === "secrets"} onClick={() => onNavigate("secrets")} className={styles.railOnly} />

        <div className={[styles.group, styles.expandedOnly].join(" ")}>
          <div className={styles.groupLabel}>
            <span>Projects</span>
            <button className={styles.groupAdd} aria-label="New project" title="New project" onClick={onNewProject}>
              <Icon name="plus" size={14} />
            </button>
          </div>
          {projects.map((p) => (
            <NavItem
              key={p.id}
              initial={initialOf(p.name)}
              label={p.name}
              active={route === "secrets" && p.id === projectId}
              onClick={() => {
                onSelectProject(p.id);
                onNavigate("secrets");
              }}
            />
          ))}
        </div>

        <div className={styles.group}>
          <span className={styles.groupLabel}>Vault</span>
          <NavItem icon="devices" label="Devices" active={route === "devices"} onClick={() => onNavigate("devices")} />
          <NavItem icon="recovery" label="Recovery and backup" active={route === "recovery"} onClick={() => onNavigate("recovery")} />
        </div>
      </nav>

      <div className={styles.footer}>
        <NavItem icon="settings" label="Settings" active={route === "settings"} onClick={() => onNavigate("settings")} />
        <div className={[styles.device, styles.expandedOnly].join(" ")}>
          <span className={styles.deviceName}>{thisDevice.name}</span>
          <span className={styles.deviceMeta}>This device, {plan === "pro" ? "Pro" : "Free"} plan</span>
        </div>
      </div>
    </aside>
  );
}
