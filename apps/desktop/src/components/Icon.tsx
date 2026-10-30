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
  devices: (
    <>
      <rect x="5.5" y="2.5" width="9" height="15" rx="2" />
      <path d="M8.75 4.5h2.5" strokeWidth={1.2} />
      <circle cx="10" cy="14.75" r="0.6" fill="currentColor" stroke="none" />
    </>
  ),
  device: (
    <>
      <rect x="5.5" y="2.5" width="9" height="15" rx="2" />
      <path d="M8.75 4.5h2.5" strokeWidth={1.2} />
      <circle cx="10" cy="14.75" r="0.6" fill="currentColor" stroke="none" />
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
      <circle cx="10" cy="10" r="2.75" />
      <path d="M9.2 3.25h1.6l.35 1.65a5.5 5.5 0 0 1 1.25.72l1.55-.7 1.13 1.13-.7 1.55c.3.38.54.8.72 1.25l1.65.35v1.6l-1.65.35a5.5 5.5 0 0 1-.72 1.25l.7 1.55-1.13 1.13-1.55-.7a5.5 5.5 0 0 1-1.25.72l-.35 1.65H9.2l-.35-1.65a5.5 5.5 0 0 1-1.25-.72l-1.55.7-1.13-1.13.7-1.55a5.5 5.5 0 0 1-.72-1.25L3.25 10.8v-1.6l1.65-.35c.18-.45.42-.87.72-1.25l-.7-1.55 1.13-1.13 1.55.7c.38-.3.8-.54 1.25-.72z" />
    </>
  ),
  customize: (
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
  download: (
    <>
      <path d="M10 3.5v9M6.5 9.5l3.5 3.5 3.5-3.5" />
      <path d="M4 14.5v1.25c0 .69.56 1.25 1.25 1.25h9.5c.69 0 1.25-.56 1.25-1.25V14.5" />
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
  windowMinimize: <path d="M5 10h10" />,
  windowMaximize: <rect x="5" y="5" width="10" height="10" rx="1" />,
  windowRestore: (
    <>
      <rect x="5" y="7" width="8" height="8" rx="1" />
      <path d="M7.5 4.5h7a1 1 0 0 1 1 1v7" />
    </>
  ),
  chevronDown: <path d="M6 8l4 4 4-4" />,
  chevronRight: <path d="M8 6l4 4-4 4" />,
  file: (
    <>
      <path d="M4.5 3.5h7l4 4v9a1.5 1.5 0 0 1-1.5 1.5h-9.5A1.5 1.5 0 0 1 3 16.5v-11.5A1.5 1.5 0 0 1 4.5 3.5z" />
      <path d="M11.5 3.5v4h4" />
    </>
  ),
  document: (
    <>
      <path d="M4.5 3.5h7l4 4v9a1.5 1.5 0 0 1-1.5 1.5h-9.5A1.5 1.5 0 0 1 3 16.5v-11.5A1.5 1.5 0 0 1 4.5 3.5z" />
      <path d="M11.5 3.5v4h4" />
      <path d="M6.5 10.5h7M6.5 13.5h5" />
    </>
  ),
  lock: (
    <>
      <rect x="4.5" y="9" width="11" height="8" rx="1.75" />
      <path d="M7 9V6.5a3 3 0 0 1 6 0V9" />
    </>
  ),
  arrowRight: <path d="M4 10h12M11.5 5.5L16 10l-4.5 4.5" />,
  dot: <circle cx="10" cy="10" r="2.5" fill="currentColor" stroke="none" />,
  info: (
    <>
      <circle cx="10" cy="10" r="7" />
      <path d="M10 9.25v4.5" />
      <circle cx="10" cy="6.6" r="0.9" fill="currentColor" stroke="none" />
    </>
  ),
  terminal: (
    <>
      <path d="M4 6.5l3.5 3.5-3.5 3.5M9.5 13.5h6.5" />
    </>
  ),
  stop: <rect x="5.5" y="5.5" width="9" height="9" rx="1.5" fill="currentColor" stroke="none" />,
  user: (
    <>
      <circle cx="10" cy="7" r="3.25" />
      <path d="M4.5 16.5c0-3 2.5-4.75 5.5-4.75s5.5 1.75 5.5 4.75" />
    </>
  ),
  users: (
    <>
      <circle cx="8" cy="7.25" r="2.75" />
      <path d="M3 16.25c0-2.6 2.2-4.25 5-4.25s5 1.65 5 4.25" />
      <path d="M12.75 4.75a2.6 2.6 0 0 1 0 5" />
      <path d="M14.5 12.1c1.6.4 2.75 1.8 2.75 3.9" />
    </>
  ),
  briefcase: (
    <>
      <rect x="3.5" y="6.5" width="13" height="10" rx="1.5" />
      <path d="M7.5 6.5V4.75c0-.69.56-1.25 1.25-1.25h2.5c.69 0 1.25.56 1.25 1.25V6.5" />
    </>
  ),
  globe: (
    <>
      <circle cx="10" cy="10" r="6.75" />
      <path d="M3.5 10h13M10 3.25c2 2.5 3 4.5 3 6.75s-1 4.25-3 6.75M10 3.25c-2 2.5-3 4.5-3 6.75s1 4.25 3 6.75" />
    </>
  ),
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
