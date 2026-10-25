import type { ReactNode } from "react";
import { brandMark } from "./brandMark.generated";

// One outline icon set in the style of SF Symbols: 20 pt grid, 1.5 stroke, round caps and joins.
const paths = {
  grid: (
    <>
      <rect x="3" y="3" width="6" height="6" rx="1.5" />
      <rect x="11" y="3" width="6" height="6" rx="1.5" />
      <rect x="3" y="11" width="6" height="6" rx="1.5" />
      <rect x="11" y="11" width="6" height="6" rx="1.5" />
    </>
  ),
  folder: <path d="M2.75 5.75c0-.83.67-1.5 1.5-1.5h3.4l1.7 1.9h6.4c.83 0 1.5.67 1.5 1.5v7.1c0 .83-.67 1.5-1.5 1.5H4.25c-.83 0-1.5-.67-1.5-1.5z" />,
  key: (
    <>
      <circle cx="6.75" cy="10" r="3.75" />
      <path d="M10.5 10h7M15 10v2.75M17.5 10v2" />
    </>
  ),
  // Laptop screen with a short centered foot; no keyboard, no second device.
  devices: (
    <>
      <rect x="3" y="4" width="14" height="9.5" rx="1.75" />
      <path d="M7.25 16h5.5" />
    </>
  ),
  recovery: (
    <>
      <circle cx="10" cy="10" r="6.75" />
      <circle cx="10" cy="10" r="2.75" />
      <path d="M5.2 5.2l2.85 2.85M11.95 11.95l2.85 2.85M14.8 5.2l-2.85 2.85M8.05 11.95L5.2 14.8" />
    </>
  ),
  settings: (
    <>
      <path d="M3 6h7.5M14.5 6H17M3 14h2.5M9.5 14H17" />
      <circle cx="12.5" cy="6" r="2" />
      <circle cx="7.5" cy="14" r="2" />
    </>
  ),
  plus: <path d="M10 4.5v11M4.5 10h11" />,
  more: (
    <>
      <circle cx="5" cy="10" r="1.1" fill="currentColor" stroke="none" />
      <circle cx="10" cy="10" r="1.1" fill="currentColor" stroke="none" />
      <circle cx="15" cy="10" r="1.1" fill="currentColor" stroke="none" />
    </>
  ),
  pencil: <path d="M13.5 3.75l2.75 2.75L7.5 15.25 4 16l.75-3.5zM11.75 5.5l2.75 2.75" />,
  trash: <path d="M3.75 5.5h12.5M8 5.5V4h4v1.5M5.5 5.5l.75 10.25c.05.7.63 1.25 1.33 1.25h4.84c.7 0 1.28-.55 1.33-1.25l.75-10.25" />,
  layers: <path d="M10 3.5l7 3.75-7 3.75-7-3.75zM3 11l7 3.75L17 11" />,
  search: (
    <>
      <circle cx="8.75" cy="8.75" r="5.25" />
      <path d="M12.6 12.6L16.5 16.5" />
    </>
  ),
  copy: (
    <>
      <rect x="7" y="7" width="9.5" height="9.5" rx="1.75" />
      <path d="M13 7V4.75C13 3.78 12.22 3 11.25 3h-6.5C3.78 3 3 3.78 3 4.75v6.5c0 .97.78 1.75 1.75 1.75H7" />
    </>
  ),
  eye: (
    <>
      <path d="M2 10s3-5.25 8-5.25S18 10 18 10s-3 5.25-8 5.25S2 10 2 10z" />
      <circle cx="10" cy="10" r="2.5" />
    </>
  ),
  eyeOff: (
    <>
      <path d="M2 10s3-5.25 8-5.25S18 10 18 10s-3 5.25-8 5.25S2 10 2 10z" />
      <path d="M3.5 3.5l13 13" />
    </>
  ),
  check: <path d="M4.5 10.5l3.5 3.5 7.5-8.5" />,
  close: <path d="M5 5l10 10M15 5L5 15" />,
  chevronDown: <path d="M6 8l4 4 4-4" />,
  lock: (
    <>
      <rect x="4.5" y="9" width="11" height="8" rx="1.75" />
      <path d="M7 9V6.5a3 3 0 0 1 6 0V9" />
    </>
  ),
  arrowRight: <path d="M4 10h12M11.5 5.5L16 10l-4.5 4.5" />,
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof paths;

export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {paths[name]}
    </svg>
  );
}

/** Splash Twin mark, no background, drawn in the current text color. Paths come from packages/brand (run `pnpm brand`). */
export function BrandMark({ size = 20 }: { size?: number }) {
  const p = size <= brandMark.smallMaxPx ? brandMark.small : brandMark.large;
  return (
    <svg width={size} height={size} viewBox="12 12 40 40" aria-hidden="true">
      <path d={p.back} fill="currentColor" fillOpacity={brandMark.backOpacity} fillRule="evenodd" />
      <path d={p.front} fill="currentColor" fillRule="evenodd" />
    </svg>
  );
}

/** 24 px moss tile holding an icon or a project initial; filled when selected. Same size at every layout width. */
export function IconTile({ icon, initial, selected }: { icon?: IconName; initial?: string; selected?: boolean }) {
  return (
    <span className={selected ? "icon-tile icon-tile-selected" : "icon-tile"} aria-hidden="true">
      {initial ? initial : icon ? <Icon name={icon} size={16} /> : null}
    </span>
  );
}
