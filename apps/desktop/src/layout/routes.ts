import type { IconName } from "../components/Icon";

export type Route = "overview" | "group" | "item" | "settings";

export const destinations: { id: Route; label: string; icon: IconName }[] = [
  { id: "overview", label: "Overview", icon: "grid" },
  { id: "group", label: "Groups", icon: "folder" },
  { id: "settings", label: "Settings", icon: "settings" },
];
