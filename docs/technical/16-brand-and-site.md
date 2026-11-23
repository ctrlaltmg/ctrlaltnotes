---
title: Brand and assets
description: The name, icon and logo, and how every icon variant is generated.
order: 16
---
# Brand and assets

## Name

The product is **CtrlAltNotes** (one word, capital C, A and N). The name and logo are protected by the [trademark policy](https://github.com/ctrlaltmg/ctrlaltnotes/blob/main/TRADEMARKS.md).

## Icon and logo

A white notepad with a folded corner and lines of text on a green `#2f5d50` rounded square. The logo is the icon followed by the name, in a variant for light backgrounds and one for dark backgrounds. The wordmark is converted to outlines, so the logo looks the same without any font installed.

`brand/make_brand.py` generates **every** variant from one SVG definition:

| Output | Used for |
|---|---|
| `app/icons/*` (`icon.icns`, `icon.ico`, PNGs) | macOS, Windows and Linux app icons (Linux uses the PNGs) |
| `ui/icon.svg`, `ui/favicon.*`, `ui/logo.svg`, `ui/logo-dark.svg` | The app UI: lock-screen logo, collapsed-sidebar icon, favicons |

## Colours

| | Light theme | Dark theme |
|---|---|---|
| Accent | `#2f5d50` | `#7fb5a3` |
| Background | `#fbfbfa` | `#161615` |
| Text | `#1c1c1b` | `#e8e8e5` |
