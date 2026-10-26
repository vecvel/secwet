import { IconTile } from "../components/Icon";
import { destinations, type Route } from "./routes";
import styles from "./BottomTabs.module.css";

// Overview sits in the center.
const ORDER: Route[] = ["group", "overview", "settings"];

export function BottomTabs({ route, onNavigate }: { route: Route; onNavigate: (r: Route) => void }) {
  const tabs = ORDER.map((id) => destinations.find((d) => d.id === id)!).filter(Boolean);
  return (
    <nav className={styles.bar} aria-label="Main">
      <span className={styles.fade} aria-hidden="true" />
      {tabs.map((d) => {
        const active =
          d.id === route ||
          (d.id === "group" && (route === "group" || route === "item"));
        return (
          <button
            key={d.id}
            className={[styles.tab, active && styles.active].filter(Boolean).join(" ")}
            aria-current={active ? "page" : undefined}
            onClick={() => onNavigate(d.id)}
          >
            <IconTile icon={d.icon} selected={active} />
            <span>{d.label}</span>
          </button>
        );
      })}
    </nav>
  );
}
