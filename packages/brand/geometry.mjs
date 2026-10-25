// Secwet "Splash Twin" mark: two liquid splashes on a diagonal, the back one close behind at 1/phi^2
// opacity, the front one with a wet highlight (a curved shine and a glint) cut out of it.
//
// Each splash outline is a closed Catmull-Rom curve through 10 points whose radius varies with two sine
// harmonics: r(t) = R * (1 + 0.11 sin(3t + p) + 0.06 sin(5t + 2p)). The gap between the splashes and the
// highlight cut-outs are computed as real polygon booleans, so the output is plain path data (no masks)
// that works for SVG, PNG and Android vector drawables.
import polygonClipping from "polygon-clipping";

export const PHI = (1 + Math.sqrt(5)) / 2;
export const TILE = 64;
export const KEYLINE = 40;

const R = 12.5; // splash base radius in construction space
const OFFSET = R * 0.42 + 4; // diagonal distance from back to front splash center
const PHASE_BACK = 2.1;
const PHASE_FRONT = 0.4;
const SAMPLES = 24; // per curve segment
const ARC_SAMPLES = 48;

const r3 = (n) => Math.round(n * 1000) / 1000;

function catmullRom(p0, p1, p2, p3, u) {
  const u2 = u * u;
  const u3 = u2 * u;
  return [0, 1].map(
    (k) => 0.5 * (2 * p1[k] + (-p0[k] + p2[k]) * u + (2 * p0[k] - 5 * p1[k] + 4 * p2[k] - p3[k]) * u2 + (-p0[k] + 3 * p1[k] - 3 * p2[k] + p3[k]) * u3),
  );
}

/** Splash outline as a polygon ring. `grow` pushes the outline outward (used for the gap). */
function splash(cx, cy, phase, grow = 0) {
  const N = 10;
  const ctrl = [];
  for (let i = 0; i < N; i++) {
    const t = (i / N) * Math.PI * 2;
    const r = R * (1 + 0.11 * Math.sin(3 * t + phase) + 0.06 * Math.sin(5 * t + 2 * phase)) + grow;
    ctrl.push([cx + r * Math.sin(t), cy - r * Math.cos(t)]);
  }
  const ring = [];
  for (let i = 0; i < N; i++) {
    const [p0, p1, p2, p3] = [ctrl[(i - 1 + N) % N], ctrl[i], ctrl[(i + 1) % N], ctrl[(i + 2) % N]];
    for (let s = 0; s < SAMPLES; s++) ring.push(catmullRom(p0, p1, p2, p3, s / SAMPLES));
  }
  ring.push(ring[0]);
  return [ring];
}

function circle(cx, cy, r) {
  const ring = [];
  for (let i = 0; i <= ARC_SAMPLES; i++) {
    const a = (i / ARC_SAMPLES) * Math.PI * 2;
    ring.push([cx + r * Math.cos(a), cy + r * Math.sin(a)]);
  }
  return [ring];
}

/** Thick arc with round caps: an annular sector unioned with a circle at each end. */
function arcStroke(cx, cy, radius, a0, a1, width) {
  const outer = [];
  const inner = [];
  for (let i = 0; i <= ARC_SAMPLES; i++) {
    const a = a0 + ((a1 - a0) * i) / ARC_SAMPLES;
    outer.push([cx + (radius + width / 2) * Math.cos(a), cy + (radius + width / 2) * Math.sin(a)]);
    inner.push([cx + (radius - width / 2) * Math.cos(a), cy + (radius - width / 2) * Math.sin(a)]);
  }
  const sector = [[...outer, ...inner.reverse(), outer[0]]];
  const cap = (a) => circle(cx + radius * Math.cos(a), cy + radius * Math.sin(a), width / 2);
  return polygonClipping.union(sector, cap(a0), cap(a1));
}

function bounds(multi) {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const poly of multi) for (const ring of poly) for (const [x, y] of ring) {
    x0 = Math.min(x0, x); y0 = Math.min(y0, y); x1 = Math.max(x1, x); y1 = Math.max(y1, y);
  }
  return { x0, y0, x1, y1 };
}

function toPath(multi, fit) {
  return multi
    .map((poly) =>
      poly
        .map((ring) => {
          const pts = ring.slice(0, -1).map(([x, y]) => [r3(fit.s * x + fit.dx), r3(fit.s * y + fit.dy)]);
          return `M${pts[0][0]} ${pts[0][1]}` + pts.slice(1).map(([x, y]) => `L${x} ${y}`).join("") + "Z";
        })
        .join(""),
    )
    .join("");
}

/**
 * @param {{ small?: boolean }} opts small = optical variant for 32 px and below
 *   (wider gap, bolder shine and glint so they survive rasterising).
 */
export function twin({ small = false } = {}) {
  const gap = small ? 3.2 : 2.2;
  const shineWidth = R * (small ? 0.22 : 0.17);
  const glintRadius = R * (small ? 0.11 : 0.085);

  const B = [25, 25];
  const F = [25 + OFFSET, 25 + OFFSET];

  const frontShape = splash(F[0], F[1], PHASE_FRONT);
  const backRaw = splash(B[0], B[1], PHASE_BACK);
  // Back splash minus the front grown by the gap, so the two never touch.
  const back = polygonClipping.difference(backRaw, splash(F[0], F[1], PHASE_FRONT, gap));

  // Wet highlight: a curved shine at the upper left and a small glint beside it.
  const a0 = Math.atan2(R * 0.05, -R * 0.62);
  const a1 = Math.atan2(-R * 0.62, -R * 0.05) + Math.PI * 2;
  const shine = arcStroke(F[0], F[1], R * 0.62, a0, a1, shineWidth);
  const glint = circle(F[0] + R * 0.22, F[1] - R * 0.6, glintRadius);
  const front = polygonClipping.difference(frontShape, shine, glint);

  // Fit the pair inside the 40-unit keyline, centered on the 64-unit tile.
  const b = bounds([...polygonClipping.union(backRaw, frontShape)]);
  const s = KEYLINE / Math.max(b.x1 - b.x0, b.y1 - b.y0);
  const fit = { s, dx: TILE / 2 - ((b.x0 + b.x1) / 2) * s, dy: TILE / 2 - ((b.y0 + b.y1) / 2) * s };

  return { back: toPath(back, fit), front: toPath(front, fit), backOpacity: r3(1 / PHI ** 2) };
}

/** SVG fragment of the mark in tile space (0 to 64). */
export function markSvg(fill, { small = false } = {}) {
  const t = twin({ small });
  return `<path d="${t.back}" fill="${fill}" fill-opacity="${t.backOpacity}" fill-rule="evenodd"/><path d="${t.front}" fill="${fill}" fill-rule="evenodd"/>`;
}
