# @secwet/brand

The Splash Twin mark: two liquid splashes on a diagonal, the front one with a wet highlight cut out of it. No colored background. `geometry.mjs` is the only source; every icon is generated from it.

```bash
pnpm brand
```

## Construction (64-unit tile, 40-unit keyline)

| Part | Value |
| --- | --- |
| Splash outline | Closed Catmull-Rom curve through 10 points, radius r(t) = R (1 + 0.11 sin(3t + p) + 0.06 sin(5t + 2p)), R = 12.5 |
| Pair | Back splash (phase 2.1) and front splash (phase 0.4) on a diagonal, 0.42R + 4 apart; the pair is scaled to fill the 40-unit keyline |
| Gap | Back splash minus the front splash grown by 2.2 (3.2 in the small mark) |
| Back opacity | 1/φ² ≈ 0.38 |
| Wet highlight | A round-capped arc (radius 0.62R, width 0.17R) and a glint (radius 0.085R) cut out of the front splash; 0.22R and 0.11R in the small mark |

Gap and cut-outs are computed with polygon booleans (`polygon-clipping`), so every output is plain path data. The small mark is used at 32 px and below (48 and 72 px on Android legacy icons).

## Outputs

- macOS: adaptive `Icon.icon` (Icon Composer) compiled to `Assets.car` with `actool` (Xcode 26+): cream in light, subtle warm dark gradient in dark, system tint in tinted; plus `icon.icns` fallback and `dock-light.png` / `dock-dark.png` for the unbundled dev app; Windows `icon.ico` (16 to 256, PNG payloads); Linux PNGs; Windows Store logos
- iOS AppIcon: default (opaque), dark and tinted (transparent) at 1024
- Android adaptive icon: foreground, monochrome (themed icons) and background, plus legacy mipmaps
- Favicon SVG that switches with light and dark mode
- `apps/desktop/src/components/brandMark.generated.ts` for the in-app mark

Colors: the mark is Moss `#3D6A4C` in light and `#8FBE9C` in dark, with no colored background. App icons put it on neutral cream `#F6F4EF` (light) or `#1A1916` (iOS dark appearance shows the mint mark on the system's dark backdrop).
