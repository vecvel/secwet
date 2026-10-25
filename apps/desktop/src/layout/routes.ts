import type { IconName } from "../components/Icon";

export type Route = "overview" | "secrets" | "devices" | "recovery" | "settings";

export const destinations: { id: Route; label: string; icon: IconName }[] = [
  { id: "overview", label: "Overview", icon: "grid" },
  { id: "secrets", label: "Secrets", icon: "key" },
  { id: "devices", label: "Devices", icon: "devices" },
  { id: "recovery", label: "Recovery", icon: "recovery" },
  { id: "settings", label: "Settings", icon: "settings" },
];
