// Generates every Secwet icon from geometry.mjs. Run: pnpm brand
//
// Writes:
//   packages/brand/dist/            logo.svg, logo-small.svg, tile-light.svg, tile-dark.svg, favicon.svg
//   apps/desktop/public/            favicon.svg
//   apps/desktop/src/components/    brandMark.generated.ts
//   apps/desktop/src-tauri/icons/   icon.icns, icon.ico, 32x32, 64x64, 128x128, 128x128@2x, icon.png, Windows Store logos
//   apps/mobile/ios/.../AppIcon     1024 default, dark and tinted + Contents.json
//   apps/mobile/android/.../res     adaptive icon (foreground, monochrome, background) + legacy mipmaps
import { mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Resvg } from "@resvg/resvg-js";
import { markSvg, twin } from "./geometry.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
// The mark has no colored background. App icons sit on neutral cream (light) or near-black (dark) squares.
const C = {
  moss: "#3D6A4C", cream: "#F6F4EF", mossLight: "#8FBE9C", deep: "#1A1916", ink: "#26231E", white: "#FFFFFF", black: "#000000",
  plateDarkTop: "#31302E", plateDarkBottom: "#1C1C1B",
};
const SMALL_MAX = 32; // optical small mark at and below this pixel size

function write(path, data) {
  const p = resolve(root, path);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, data);
}

const svg = (body) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">${body}</svg>`;

/** Neutral app-icon square with the mark. rx 14.3 of 64 matches the Apple corner (22.4%); 0 for full-bleed iOS. */
const tile = (bg, fg, { small = false, rx = 14.3 } = {}) => svg(`<rect width="64" height="64" rx="${rx}" fill="${bg}"/>${markSvg(fg, { small })}`);

/** macOS grid: 824 plate on a 1024 canvas, with the standard soft drop shadow. */
function macTile(small, dark = false) {
  // Light: cream. Dark: a dark gradient with only a touch of warmth (also used for Icon.icon's dark base).
  const plate = dark ? "url(#plateDark)" : C.cream;
  const mark = dark ? C.mossLight : C.moss;
  const s = (824 / 1024) * 64;
  const o = (64 - s) / 2;
  const rx = s * 0.2237;

  // In dark tiles: directional top-left-to-right specular rim highlight and subtle ambient bevel
  const darkRim =
    `<linearGradient id="rimGrad" x1="0%" y1="0%" x2="100%" y2="100%">` +
      `<stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.48"/>` +
      `<stop offset="25%" stop-color="#FFFFFF" stop-opacity="0.34"/>` +
      `<stop offset="50%" stop-color="#FFFFFF" stop-opacity="0.18"/>` +
      `<stop offset="75%" stop-color="#FFFFFF" stop-opacity="0.06"/>` +
      `<stop offset="100%" stop-color="#FFFFFF" stop-opacity="0.0"/>` +
    `</linearGradient>` +
    `<linearGradient id="bevelGrad" x1="0%" y1="0%" x2="100%" y2="100%">` +
      `<stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.20"/>` +
      `<stop offset="30%" stop-color="#FFFFFF" stop-opacity="0.12"/>` +
      `<stop offset="60%" stop-color="#FFFFFF" stop-opacity="0.02"/>` +
      `<stop offset="100%" stop-color="#FFFFFF" stop-opacity="0.0"/>` +
    `</linearGradient>`;

  // In light tiles: specular top-left highlight and subtle dark bottom bezel
  const lightRim =
    `<linearGradient id="lightRimGrad" x1="0%" y1="0%" x2="100%" y2="100%">` +
      `<stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.70"/>` +
      `<stop offset="40%" stop-color="#FFFFFF" stop-opacity="0.35"/>` +
      `<stop offset="70%" stop-color="${C.ink}" stop-opacity="0.06"/>` +
      `<stop offset="100%" stop-color="${C.ink}" stop-opacity="0.16"/>` +
    `</linearGradient>`;

  const rimDefs = dark ? darkRim : lightRim;
  const rimStroke = dark ? "url(#rimGrad)" : "url(#lightRimGrad)";
  const bevel = dark
    ? `<rect x="${o + 0.18}" y="${o + 0.18}" width="${s - 0.36}" height="${s - 0.36}" rx="${rx - 0.18}" fill="none" stroke="url(#bevelGrad)" stroke-width="0.36"/>`
    : "";

  return svg(
    `<defs><filter id="sh" x="-20%" y="-20%" width="140%" height="150%"><feDropShadow dx="0" dy="0.6" stdDeviation="0.7" flood-color="#000" flood-opacity="0.28"/></filter>` +
      `<linearGradient id="plateDark" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${C.plateDarkTop}"/><stop offset="1" stop-color="${C.plateDarkBottom}"/></linearGradient>` +
      rimDefs +
    `</defs>` +
      `<rect x="${o}" y="${o}" width="${s}" height="${s}" rx="${rx}" fill="${plate}" filter="url(#sh)"/>` +
      bevel +
      `<rect x="${o + 0.09}" y="${o + 0.09}" width="${s - 0.18}" height="${s - 0.18}" rx="${rx - 0.09}" fill="none" stroke="${rimStroke}" stroke-width="0.19"/>` +
      `<g transform="translate(${o} ${o}) scale(${s / 64})">${markSvg(mark, { small })}</g>`,
  );
}

const glyphOnly = (fg, small = false) => svg(markSvg(fg, { small }));

function png(svgText, size) {
  return new Resvg(svgText, { fitTo: { mode: "width", value: size } }).render().asPng();
}

/** ICO with PNG payloads (supported since Windows Vista). */
function ico(entries) {
  const header = Buffer.alloc(6 + 16 * entries.length);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(entries.length, 4);
  let offset = header.length;
  entries.forEach(({ size, data }, i) => {
    const e = 6 + 16 * i;
    header.writeUInt8(size >= 256 ? 0 : size, e);
    header.writeUInt8(size >= 256 ? 0 : size, e + 1);
    header.writeUInt16LE(1, e + 4);
    header.writeUInt16LE(32, e + 6);
    header.writeUInt32LE(data.length, e + 8);
    header.writeUInt32LE(offset, e + 12);
    offset += data.length;
  });
  return Buffer.concat([header, ...entries.map((e) => e.data)]);
}

/** ICNS with PNG payloads. */
function icns(entries) {
  const chunks = entries.map(({ type, data }) => {
    const h = Buffer.alloc(8);
    h.write(type, 0, "ascii");
    h.writeUInt32BE(data.length + 8, 4);
    return Buffer.concat([h, data]);
  });
  const body = Buffer.concat(chunks);
  const h = Buffer.alloc(8);
  h.write("icns", 0, "ascii");
  h.writeUInt32BE(body.length + 8, 4);
  return Buffer.concat([h, body]);
}

// 1. Brand package outputs
const favicon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="12 12 40 40"><style>.m{fill:${C.moss}}@media (prefers-color-scheme: dark){.m{fill:${C.mossLight}}}</style>${markSvg("currentColor", { small: true }).replaceAll('fill="currentColor"', 'class="m"')}</svg>`;
write("packages/brand/dist/logo.svg", glyphOnly("currentColor"));
write("packages/brand/dist/logo-light.svg", glyphOnly(C.moss));
write("packages/brand/dist/logo-dark.svg", glyphOnly(C.mossLight));
write("packages/brand/dist/logo-small.svg", glyphOnly("currentColor", true));
write("packages/brand/dist/tile-light.svg", tile(C.cream, C.moss));
write("packages/brand/dist/tile-dark.svg", tile(C.deep, C.mossLight));
write("packages/brand/dist/favicon.svg", favicon);
write("apps/desktop/public/favicon.svg", favicon);

// 2. In-app mark for the desktop UI
const big = twin();
const small = twin({ small: true });
write(
  "apps/desktop/src/components/brandMark.generated.ts",
  `// Generated by packages/brand/build.mjs. Do not edit by hand.\n` +
    `export const brandMark = ${JSON.stringify(
      { backOpacity: big.backOpacity, large: { back: big.back, front: big.front }, small: { back: small.back, front: small.front }, smallMaxPx: SMALL_MAX },
      null,
      2,
    )} as const;\n`,
);

// 3. Desktop bundle icons (Tauri)
const iconsDir = "apps/desktop/src-tauri/icons";
for (const name of readdirSync(resolve(root, iconsDir))) rmSync(resolve(root, iconsDir, name), { recursive: true, force: true });
const desk = (size) => png(tile(C.cream, C.moss, { small: size <= SMALL_MAX }), size);
const mac = (size) => png(macTile(size <= SMALL_MAX), size);
write(`${iconsDir}/32x32.png`, desk(32));
write(`${iconsDir}/64x64.png`, desk(64));
write(`${iconsDir}/128x128.png`, desk(128));
write(`${iconsDir}/128x128@2x.png`, desk(256));
write(`${iconsDir}/icon.png`, desk(512));
write(`${iconsDir}/icon.ico`, ico([16, 24, 32, 48, 64, 256].map((size) => ({ size, data: desk(size) }))));
write(
  `${iconsDir}/icon.icns`,
  icns([
    ["icp4", 16], ["icp5", 32], ["icp6", 64], ["ic07", 128], ["ic08", 256], ["ic09", 512], ["ic10", 1024],
    ["ic11", 32], ["ic12", 64], ["ic13", 256], ["ic14", 512],
  ].map(([type, size]) => ({ type, data: mac(size) }))),
);
// macOS 26 adaptive icon (Icon Composer format). The bundler compiles it with actool into Assets.car,
// so the bundled app gets real light, dark and tinted icons. Layers are listed front first.
const srgb = (hex) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  return `srgb:${r.toFixed(5)},${g.toFixed(5)},${b.toFixed(5)},1.00000`;
};
const byAppearance = (light, dark) => [{ value: { solid: srgb(light) } }, { appearance: "dark", value: { solid: srgb(dark) } }];
const iconDir = `${iconsDir}/Icon.icon`;
const layerSvg = (d) => `<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 64 64"><path d="${d}" fill="#000" fill-rule="evenodd"/></svg>`;
write(`${iconDir}/Assets/front.svg`, layerSvg(big.front));
write(`${iconDir}/Assets/back.svg`, layerSvg(big.back));
write(
  `${iconDir}/icon.json`,
  JSON.stringify(
    {
      // Light: cream. Dark: macOS builds its gradient from the subtle warm dark base. Tinted: system background.
      "fill-specializations": [{ value: { solid: srgb(C.cream) } }, { appearance: "dark", value: { "automatic-gradient": srgb(C.plateDarkTop) } }, { appearance: "tinted", value: "automatic" }],
      groups: [
        {
          layers: [
            { "image-name": "front.svg", name: "front", "fill-specializations": byAppearance(C.moss, C.mossLight) },
            { "image-name": "back.svg", name: "back", opacity: big.backOpacity, "fill-specializations": byAppearance(C.moss, C.mossLight) },
          ],
          shadow: { kind: "neutral", opacity: 0.5 },
          translucency: { enabled: false, value: 0.5 },
        },
      ],
      "supported-platforms": { squares: "shared" },
    },
    null,
    2,
  ) + "\n",
);

// Compile Icon.icon into Assets.car here (macOS with Xcode 26+ only). Tauri's bundler copies .icon packages
// without their layer images, which crashes actool, but it accepts a ready-made Assets.car.
if (process.platform === "darwin") {
  const { execFileSync } = await import("node:child_process");
  const { mkdtempSync, copyFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const out = mkdtempSync(join(tmpdir(), "secwet-actool-"));
  try {
    execFileSync("xcrun", [
      "actool", resolve(root, iconDir), "--compile", out, "--output-format", "human-readable-text",
      "--output-partial-info-plist", join(out, "partial.plist"), "--app-icon", "Icon", "--include-all-app-icons",
      "--enable-on-demand-resources", "NO", "--development-region", "en", "--target-device", "mac",
      "--minimum-deployment-target", "10.13", "--platform", "macosx",
    ], { stdio: "pipe" });
    copyFileSync(join(out, "Assets.car"), resolve(root, iconsDir, "Assets.car"));
  } catch (err) {
    console.warn(`brand: skipped Assets.car (needs Xcode 26+ actool): ${String(err.stderr || err.message).split("\n").slice(0, 2).join(" ")}`);
  }
}

// Dock images for the running app: generate ultra-smooth, Apple-grade dithered 1024x1024 Retina images.
const sPlate = (824 / 1024) * 64;
const oPlate = (64 - sPlate) / 2;
const rxPlate = sPlate * 0.2237;

const shadowSvg = svg(
  `<defs><filter id="sh" x="-20%" y="-20%" width="140%" height="150%"><feDropShadow dx="0" dy="0.6" stdDeviation="0.7" flood-color="#000" flood-opacity="0.28"/></filter></defs>` +
    `<rect x="${oPlate}" y="${oPlate}" width="${sPlate}" height="${sPlate}" rx="${rxPlate}" fill="#000" filter="url(#sh)"/>`,
);
const maskSvg = svg(`<rect x="${oPlate}" y="${oPlate}" width="${sPlate}" height="${sPlate}" rx="${rxPlate}" fill="#FFF"/>`);
const fgDarkSvg = svg(
  `<defs>` +
    `<linearGradient id="dockRimGrad" x1="0%" y1="0%" x2="100%" y2="100%">` +
      `<stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.48"/>` +
      `<stop offset="25%" stop-color="#FFFFFF" stop-opacity="0.34"/>` +
      `<stop offset="50%" stop-color="#FFFFFF" stop-opacity="0.18"/>` +
      `<stop offset="75%" stop-color="#FFFFFF" stop-opacity="0.06"/>` +
      `<stop offset="100%" stop-color="#FFFFFF" stop-opacity="0.0"/>` +
    `</linearGradient>` +
    `<linearGradient id="dockBevelGrad" x1="0%" y1="0%" x2="100%" y2="100%">` +
      `<stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.20"/>` +
      `<stop offset="30%" stop-color="#FFFFFF" stop-opacity="0.12"/>` +
      `<stop offset="60%" stop-color="#FFFFFF" stop-opacity="0.02"/>` +
      `<stop offset="100%" stop-color="#FFFFFF" stop-opacity="0.0"/>` +
    `</linearGradient>` +
  `</defs>` +
  `<rect x="${oPlate + 0.18}" y="${oPlate + 0.18}" width="${sPlate - 0.36}" height="${sPlate - 0.36}" rx="${rxPlate - 0.18}" fill="none" stroke="url(#dockBevelGrad)" stroke-width="0.36"/>` +
  `<rect x="${oPlate + 0.09}" y="${oPlate + 0.09}" width="${sPlate - 0.18}" height="${sPlate - 0.18}" rx="${rxPlate - 0.09}" fill="none" stroke="url(#dockRimGrad)" stroke-width="0.19"/>` +
  `<g transform="translate(${oPlate} ${oPlate}) scale(${sPlate / 64})">${markSvg(C.mossLight, { small: false })}</g>`,
);

const { tmpdir } = await import("node:os");
const { mkdtempSync } = await import("node:fs");
const tmpDir = mkdtempSync(join(tmpdir(), "secwet-dock-"));
const shadowPath = join(tmpDir, "shadow.png");
const maskPath = join(tmpDir, "mask.png");
const fgDarkPath = join(tmpDir, "fgDark.png");
const darkDockPath = resolve(root, `${iconsDir}/dock-dark.png`);

writeFileSync(shadowPath, png(shadowSvg, 1024));
writeFileSync(maskPath, png(maskSvg, 1024));
writeFileSync(fgDarkPath, png(fgDarkSvg, 1024));
write(`${iconsDir}/dock-light.png`, png(macTile(false, false), 1024));

try {
  const { execFileSync } = await import("node:child_process");
  execFileSync("python3", [resolve(here, "generate_smooth_dock_icon.py"), shadowPath, maskPath, fgDarkPath, darkDockPath], { stdio: "inherit" });
} catch (err) {
  console.warn("brand: fallback to standard dock images:", err.message);
  write(`${iconsDir}/dock-dark.png`, png(macTile(false, true), 1024));
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}
for (const [name, size] of [["Square30x30Logo", 30], ["Square44x44Logo", 44], ["Square71x71Logo", 71], ["Square89x89Logo", 89], ["Square107x107Logo", 107], ["Square142x142Logo", 142], ["Square150x150Logo", 150], ["Square284x284Logo", 284], ["Square310x310Logo", 310], ["StoreLogo", 50]]) {
  write(`${iconsDir}/${name}.png`, desk(size));
}

// 4. iOS (Flutter Runner). Default is opaque full-bleed; dark and tinted are transparent so iOS draws the backdrop.
const appIcon = "apps/mobile/ios/Runner/Assets.xcassets/AppIcon.appiconset";
for (const name of readdirSync(resolve(root, appIcon))) rmSync(resolve(root, appIcon, name));
write(`${appIcon}/AppIcon-1024.png`, png(tile(C.cream, C.moss, { rx: 0 }), 1024));
write(`${appIcon}/AppIcon-1024-dark.png`, png(glyphOnly(C.mossLight), 1024));
write(`${appIcon}/AppIcon-1024-tinted.png`, png(glyphOnly(C.white), 1024));
write(
  `${appIcon}/Contents.json`,
  JSON.stringify(
    {
      images: [
        { filename: "AppIcon-1024.png", idiom: "universal", platform: "ios", size: "1024x1024" },
        { appearances: [{ appearance: "luminosity", value: "dark" }], filename: "AppIcon-1024-dark.png", idiom: "universal", platform: "ios", size: "1024x1024" },
        { appearances: [{ appearance: "luminosity", value: "tinted" }], filename: "AppIcon-1024-tinted.png", idiom: "universal", platform: "ios", size: "1024x1024" },
      ],
      info: { author: "xcode", version: 1 },
    },
    null,
    2,
  ) + "\n",
);

// 5. Android (Flutter). Adaptive icon: tile space 64 maps to the 72 dp visible area of the 108 dp canvas,
// so the 40-unit keyline becomes 45 dp, inside the 66 dp safe zone.
const res = "apps/mobile/android/app/src/main/res";
const vector = (color, opacityBack) => `<?xml version="1.0" encoding="utf-8"?>
<!-- Generated by packages/brand/build.mjs. Do not edit by hand. -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp" android:height="108dp" android:viewportWidth="108" android:viewportHeight="108">
    <group android:translateX="18" android:translateY="18" android:scaleX="1.125" android:scaleY="1.125">
        <path android:fillColor="${color}" android:fillAlpha="${opacityBack}" android:fillType="evenOdd" android:pathData="${big.back}"/>
        <path android:fillColor="${color}" android:fillType="evenOdd" android:pathData="${big.front}"/>
    </group>
</vector>
`;
write(`${res}/drawable/ic_launcher_foreground.xml`, vector(C.moss, big.backOpacity));
write(`${res}/drawable/ic_launcher_monochrome.xml`, vector(C.black, big.backOpacity));
write(`${res}/values/ic_launcher_background.xml`, `<?xml version="1.0" encoding="utf-8"?>\n<resources>\n    <color name="ic_launcher_background">${C.cream}</color>\n</resources>\n`);
write(
  `${res}/mipmap-anydpi-v26/ic_launcher.xml`,
  `<?xml version="1.0" encoding="utf-8"?>\n<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n    <background android:drawable="@color/ic_launcher_background"/>\n    <foreground android:drawable="@drawable/ic_launcher_foreground"/>\n    <monochrome android:drawable="@drawable/ic_launcher_monochrome"/>\n</adaptive-icon>\n`,
);
for (const [dpi, size] of [["mdpi", 48], ["hdpi", 72], ["xhdpi", 96], ["xxhdpi", 144], ["xxxhdpi", 192]]) {
  write(`${res}/mipmap-${dpi}/ic_launcher.png`, png(tile(C.cream, C.moss, { small: size <= 72 }), size));
}

console.log("brand: wrote desktop, iOS, Android, favicon and in-app assets");
