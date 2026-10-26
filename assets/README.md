# Brand Assets

Public-facing identity assets for Secwet. Generated mathematically from [`packages/brand/geometry.mjs`](../packages/brand/geometry.mjs) via `pnpm brand`.

| Asset | Format | Description |
|---|---|---|
| [`icon-dark.png`](icon-dark.png) | 1024×1024 PNG | High-precision Retina macOS squircle dock icon (dark appearance, dithered plate) |
| [`icon-light.png`](icon-light.png) | 1024×1024 PNG | High-precision Retina macOS squircle dock icon (light appearance, cream plate) |
| [`icon.png`](icon.png) | 1024×1024 PNG | Default repository icon (identical to `icon-dark.png`) |
| [`tile-dark.svg`](tile-dark.svg) | SVG | Vector squircle app tile (dark `#1A1916` background with mint mark) |
| [`tile-light.svg`](tile-light.svg) | SVG | Vector squircle app tile (cream `#F6F4EF` background with moss mark) |
| [`mark-dark.svg`](mark-dark.svg) | SVG | Standalone Splash Twin mark in mint (`#8FBE9C`, transparent background) |
| [`mark-light.svg`](mark-light.svg) | SVG | Standalone Splash Twin mark in moss (`#3D6A4C`, transparent background) |
| [`mark.svg`](mark.svg) | SVG | Standalone Splash Twin mark in `currentColor` |
| [`favicon.svg`](favicon.svg) | SVG | Responsive vector favicon that adapts to system dark/light appearance |

To regenerate all brand assets, run:

```bash
pnpm brand
```
