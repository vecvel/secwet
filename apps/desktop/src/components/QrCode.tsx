import { useMemo } from "react";
import { encode } from "uqr";
import styles from "./QrCode.module.css";

/** Always dark modules on white, in both themes, so cameras can read it. */
export function QrCode({ value, size = 168, label }: { value: string; size?: number; label: string }) {
  const { path, n } = useMemo(() => {
    const { data, size: n } = encode(value, { ecc: "M", border: 2 });
    let d = "";
    data.forEach((row, y) => row.forEach((on, x) => on && (d += `M${x} ${y}h1v1h-1z`)));
    return { path: d, n };
  }, [value]);

  return (
    <svg className={styles.qr} width={size} height={size} viewBox={`0 0 ${n} ${n}`} role="img" aria-label={label} shapeRendering="crispEdges">
      <rect width={n} height={n} fill="#FFFFFF" />
      <path d={path} fill="#1A1916" />
    </svg>
  );
}
