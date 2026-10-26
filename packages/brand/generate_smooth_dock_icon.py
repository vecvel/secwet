#!/usr/bin/env python3
"""
packages/brand/generate_smooth_dock_icon.py

Composites an ultra-smooth, Apple AppStore-grade 1024x1024 dark macOS Dock icon:
1. High-precision 1024x1024 Retina resolution.
2. Apple-style curved lighting (soft diffuse highlight at top-center).
3. TPDF (Triangular Probability Density Function) micro-dithering to eliminate color banding.
4. Composites over the exact macOS squircle drop shadow, with specular inner hairline and Twin mark.
"""

import sys
from pathlib import Path
import numpy as np
from PIL import Image

def create_smooth_dark_plate(width=1024, height=1024, mask=None):
    y, x = np.mgrid[0:height, 0:width].astype(np.float32)

    # Plate boundaries on 1024 canvas
    # s = 824, o = 100
    y_norm = np.clip((y - 100.0) / 824.0, 0.0, 1.0)

    # 1. Non-linear cubic smoothstep curve for natural vertical light falloff
    curve = y_norm * y_norm * (3.0 - 2.0 * y_norm)

    # Base dark gradient tones:
    # Top: rgb(50, 49, 47) = #32312F
    # Bottom: rgb(23, 23, 22) = #171716
    top_color = np.array([50.0, 49.0, 47.0], dtype=np.float32)
    bot_color = np.array([23.0, 23.0, 22.0], dtype=np.float32)
    base_grad = (1.0 - curve[:, :, None]) * top_color + curve[:, :, None] * bot_color

    # 2. Apple-style top-center diffuse radial highlight
    # Soft ambient glow focused at upper-center (x=512, y=210)
    dx = (x - 512.0) / 480.0
    dy = (y - 210.0) / 520.0
    dist = np.sqrt(dx * dx + dy * dy)
    radial = np.clip(1.0 - dist, 0.0, 1.0)
    radial = 0.5 * (1.0 - np.cos(radial * np.pi))  # Cosine smooth curve

    # Add subtle highlight (up to +6.5 units of luminous warmth at center)
    highlight_color = np.array([6.5, 6.2, 5.8], dtype=np.float32)
    base_grad += radial[:, :, None] * highlight_color

    # 3. High-Quality TPDF (Triangular Probability Density Function) Dithering
    # Adding two independent uniform random variables generates triangular noise.
    # Amplitude 0.85 LSB breaks up all color bands while remaining invisible to the eye.
    np.random.seed(1337)
    u1 = np.random.uniform(-0.5, 0.5, size=base_grad.shape)
    u2 = np.random.uniform(-0.5, 0.5, size=base_grad.shape)
    tpdf_dither = (u1 + u2) * 0.85

    dithered_rgb = np.clip(base_grad + tpdf_dither, 0.0, 255.0).astype(np.uint8)

    # Convert to RGBA using the provided alpha mask
    mask_arr = np.array(mask)
    rgba = np.dstack([dithered_rgb, mask_arr])
    return Image.fromarray(rgba, "RGBA")

def composite_icon(shadow_path, mask_path, fg_path, out_path):
    shadow = Image.open(shadow_path).convert("RGBA")
    mask = Image.open(mask_path).convert("L")
    fg = Image.open(fg_path).convert("RGBA")

    width, height = shadow.size
    dark_plate = create_smooth_dark_plate(width, height, mask)

    # Ensure all foreground mark and rim bevel highlight pixels stay strictly
    # within the squircle mask for razor-sharp, pristine anti-aliased edges.
    fg_arr = np.array(fg)
    mask_arr = np.array(mask)
    fg_arr[:, :, 3] = np.minimum(fg_arr[:, :, 3], mask_arr)
    fg_clipped = Image.fromarray(fg_arr, "RGBA")

    # Composite layers:
    # 1. Shadow (bottom)
    # 2. Smooth dithered dark plate (middle)
    # 3. Foreground mark + directional rim bevel highlight (top)
    icon = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    icon = Image.alpha_composite(icon, shadow)
    icon = Image.alpha_composite(icon, dark_plate)
    icon = Image.alpha_composite(icon, fg_clipped)

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    icon.save(out_path, "PNG")
    print(f"Smooth dock icon saved to {out_path} ({width}x{height})")

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: generate_smooth_dock_icon.py <shadow.png> <mask.png> <fg.png> <out.png>")
        sys.exit(1)
    composite_icon(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
