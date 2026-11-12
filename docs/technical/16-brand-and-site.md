---
title: Brand, website and assets
description: How the logo, icons, landing page and animated screenshots are produced and where they live.
order: 16
---
# Brand, website and assets

## Name

The product is **CtrlAltNotes** (one word, capital C, A and N).

## Icon

A white notepad with a folded corner and lines of text on the green `#2f5d50` rounded square. `brand/make_brand.py` generates **every** variant from one SVG definition:

| Output | Used for |
|---|---|
| `app/icons/*` (`icon.icns`, `icon.ico`, PNGs) | macOS, Windows and Linux app icons (Linux uses the PNGs) |
| `ui/icon.svg`, `favicon.*`, `logo*.svg` | The app UI (large logo on lock screens) |
| `site/assets/*` | Website: favicons, Apple touch icon, maskable PWA icons, MS tile, Safari pinned-tab mask, `logo.svg` / `logo-dark.svg`, social card `og-image.png` |

The wordmark is converted to outlines, so the logo looks the same without any font.

## Landing page (`site/`)

Static HTML and CSS. SEO and AI-discovery files: `sitemap.xml`, `robots.txt`, `llms.txt`, `llms-full.txt`, `humans.txt`, `security.txt`, `site.webmanifest`, `browserconfig.xml`, JSON-LD structured data, Open Graph and Twitter cards.

!!! note "Placeholders"
    The domain `https://ctrlaltnotes.example` and the repository URL are placeholders. Replace them with `python3 site/set_domain.py https://your-domain https://github.com/you/repo`.

## Animated screenshots

`python3 tools/make_media.py <path-to>/ctrlaltnotes-web` (run inside `ctrlaltnotes-website/`) drives the real UI with Playwright and writes GIFs and posters to `site/assets/media/`.
