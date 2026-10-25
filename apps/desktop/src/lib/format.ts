const units: [Intl.RelativeTimeFormatUnit, number][] = [
  ["day", 86_400_000],
  ["hour", 3_600_000],
  ["minute", 60_000],
];

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto", style: "short" });

const dateFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });

export function formatDate(timestamp: number): string {
  return dateFmt.format(timestamp);
}

export function formatCountdown(ms: number): string {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/** Random bytes as unpadded base64url, for mock identifiers and keys. */
export function randomToken(bytes: number): string {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

export function formatAgo(timestamp: number, now = Date.now()): string {
  const diff = timestamp - now;
  for (const [unit, ms] of units) {
    if (Math.abs(diff) >= ms) return rtf.format(Math.round(diff / ms), unit);
  }
  return "Just now";
}
