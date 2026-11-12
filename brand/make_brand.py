#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generates every icon / logo file for CtrlAltNotes from one design.
Needs: rsvg-convert (librsvg), Pillow, fontTools.  Run:  python3 brand/make_brand.py
Outputs: ui/ (web app icons), app/icons/ (desktop and mobile app icons), ../ctrlaltnotes-website/site/assets/ (website, if that sibling folder exists)."""
import io, os, subprocess, pathlib
from PIL import Image
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

ROOT = pathlib.Path(__file__).resolve().parent.parent
WEBSITE = ROOT.parent / "ctrlaltnotes-website"          # sibling folder; website assets are written only if it exists
GREEN, GREEN_DARK, PAPER, FOLD = "#2f5d50", "#7fb5a3", "#fafaf8", "#cfe0d9"

def notes_glyph(paper=PAPER, ink=GREEN, fold=FOLD):
    """The notes icon: a page with a folded corner and lines of text (1024 grid)."""
    return f'''<path d="M308 190H614L764 340V786a48 48 0 0 1-48 48H308a48 48 0 0 1-48-48V238a48 48 0 0 1 48-48Z" fill="{paper}"/>
<path d="M614 190V292a48 48 0 0 0 48 48H764Z" fill="{fold}"/>
<rect x="340" y="420" width="232" height="38" rx="19" fill="{ink}"/>
<rect x="340" y="520" width="344" height="30" rx="15" fill="{ink}" opacity=".55"/>
<rect x="340" y="596" width="344" height="30" rx="15" fill="{ink}" opacity=".55"/>
<rect x="340" y="672" width="214" height="30" rx="15" fill="{ink}" opacity=".55"/>'''

def icon_svg(rounded=True, bg=GREEN, scale=1.0):
    rx = 228 if rounded else 0
    g = notes_glyph()
    if scale != 1.0:   # shrink the glyph into a safe zone (maskable icons)
        g = f'<g transform="translate(512 512) scale({scale}) translate(-512 -512)">{g}</g>'
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024"><rect width="1024" height="1024" rx="{rx}" fill="{bg}"/>{g}</svg>'

def png(svg, size):
    out = subprocess.run(["rsvg-convert", "-w", str(size), "-h", str(size)], input=svg.encode(), capture_output=True, check=True).stdout
    return Image.open(io.BytesIO(out)).convert("RGBA")

def text_path(text, font_path, size, x0, y0, colors):
    """Text as outlines (no font needed to display the logo). colors: per-character list."""
    f = TTFont(font_path); gs = f.getGlyphSet(); cmap = f.getBestCmap(); upm = f["head"].unitsPerEm
    s = size / upm; x = x0; parts = []
    for ch, col in zip(text, colors):
        name = cmap[ord(ch)]; pen = SVGPathPen(gs)
        gs[name].draw(TransformPen(pen, (s, 0, 0, -s, x, y0)))
        parts.append(f'<path d="{pen.getCommands()}" fill="{col}"/>')
        x += gs[name].width * s
    return "".join(parts), x

def logo_svg(dark_text=True):
    ink, acc = ("#1c1c1b", GREEN) if dark_text else ("#e8e8e5", GREEN_DARK)
    word = "CtrlAltNotes"
    cols = [ink] * 4 + [acc] * 3 + [ink] * 5
    t, end = text_path(word, "/usr/share/fonts/opentype/inter/Inter-Bold.otf", 150, 330, 230, cols)
    w = int(end + 30)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} 300" width="{w}" height="300" role="img" aria-label="CtrlAltNotes">'
            f'<title>CtrlAltNotes</title><g transform="translate(0 18) scale(.265)">'
            f'<rect width="1024" height="1024" rx="228" fill="{GREEN}"/>{notes_glyph()}</g>{t}</svg>'), w

def write(path, data, mode="wb"):
    if path.startswith("site/"):
        if not WEBSITE.exists(): return
        path = WEBSITE / path
    else:
        path = ROOT / path
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, mode) as f: f.write(data)

# ---------------------------------------------------------------- svg sources
rounded = icon_svg(True)
for p in ("ui/icon.svg", "ui/favicon.svg", "site/assets/favicon.svg", "site/assets/icon.svg"):
    write(p, rounded, "w")
logo, lw = logo_svg(True); logo_d, _ = logo_svg(False)
write("site/assets/logo.svg", logo, "w"); write("site/assets/logo-dark.svg", logo_d, "w")
write("ui/logo.svg", logo, "w"); write("ui/logo-dark.svg", logo_d, "w")
write("site/assets/safari-pinned-tab.svg",
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024"><path fill="#000" d="M308 190H614L764 340V786a48 48 0 0 1-48 48H308a48 48 0 0 1-48-48V238a48 48 0 0 1 48-48Z"/></svg>', "w")

# ---------------------------------------------------------------- desktop app icons (green background + notes icon)
big = png(rounded, 1024)
tauri = ROOT / "app/icons"; tauri.mkdir(parents=True, exist_ok=True)
big.save(tauri / "app-icon.png")
png(rounded, 512).save(tauri / "icon.png")
png(rounded, 256).save(tauri / "128x128@2x.png")
png(rounded, 128).save(tauri / "128x128.png")
png(rounded, 32).save(tauri / "32x32.png")
big.save(tauri / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
big.save(tauri / "icon.icns")

# ---------------------------------------------------------------- website / PWA icons
a = (WEBSITE if WEBSITE.exists() else pathlib.Path(__import__("tempfile").mkdtemp())) / "site/assets"; a.mkdir(parents=True, exist_ok=True)
for s in (16, 32, 48): png(rounded, s).save(a / f"favicon-{s}.png")
big.save(a / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
png(icon_svg(False), 180).convert("RGB").save(a / "apple-touch-icon.png")      # iOS rounds it itself
png(rounded, 192).save(a / "icon-192.png"); png(rounded, 512).save(a / "icon-512.png")
png(icon_svg(False, scale=.8), 512).save(a / "icon-maskable-512.png")            # Android adaptive icons
png(rounded, 150).save(a / "mstile-150.png")
for s in (192, 512): png(rounded, s).save(ROOT / f"ui/icon-{s}.png")
png(rounded, 32).save(ROOT / "ui/favicon.png")
big.save(ROOT / "ui/favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])

# ---------------------------------------------------------------- logo png + social card (1200x630)
logo_png = subprocess.run(["rsvg-convert", "-w", "1400"], input=logo.encode(), capture_output=True, check=True).stdout
(a / "logo.png").write_bytes(logo_png)
card = Image.new("RGB", (1200, 630), "#fbfbfa")
lg = Image.open(io.BytesIO(logo_png)).convert("RGBA"); lg = lg.resize((900, int(900 * lg.height / lg.width)))
card.paste(lg, (150, 150), lg)
from PIL import ImageDraw, ImageFont
d = ImageDraw.Draw(card)
f1 = ImageFont.truetype("/usr/share/fonts/opentype/inter/Inter-Medium.otf", 40)
f2 = ImageFont.truetype("/usr/share/fonts/opentype/inter/Inter-Regular.otf", 28)
d.text((150, 380), "Private, end-to-end encrypted Markdown notes", font=f1, fill="#1c1c1b")
d.text((150, 446), "Folders · live preview · automatic encrypted sync · Mac, Windows & web", font=f2, fill="#7a7a76")
d.rectangle((0, 610, 1200, 630), fill=GREEN)
card.save(a / "og-image.png", optimize=True)
print("brand assets written")
