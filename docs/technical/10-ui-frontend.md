---
title: Front end
description: The vanilla-JS UI, the Markdown renderer and the rules that keep it XSS-safe.
order: 10
---
# Front end

`ui/` has no framework and no build step: `index.html`, `app.css`, and four scripts loaded in order: `md.js`, `api.js`, `quick.js`, `app.js`.

## Rules

1. **No HTML strings.** Every node is made with `createElement` / `textContent`. The `innerHTML` and `eval` strings must not appear (a test greps the served files).
2. **No inline script or style**, so the strict CSP holds.
3. **No remote resources.** No fonts, images or scripts from other origins.
4. The page never holds a file path.

## Markdown renderer (`md.js`)

* Block elements: headings, paragraphs, lists (ordered, unordered, task lists), quotes, fenced code, tables, rules.
* Inline: `**bold**`, `*italic*`, `__bold__`, `_italic_`, `~~strike~~`, `` `code` ``, `++underline++`, `==highlight==`, links.
* Links only for `http:`, `https:`, `mailto:`; a `mailto:` query (cc, bcc, body) is stripped. Images are never loaded; they are shown as links.
* **Work limits**: input shortened above 500,000 characters; lines are hard-wrapped at 4,000; inline text is processed in chunks of 2,000; a per-render regex budget; blockquote depth ≤ 8; tables ≤ 100 columns. This stopped the regular-expression and stack attacks found in the [pentest](14-pentest-report.md).

## Editor

* **Live preview** (default): a side-by-side editor. `.split` holds the Markdown `textarea.ed` on the left and `#preview` on the right; the preview is re-rendered with `renderMarkdown` on every input (DOM nodes only, no HTML strings).
* **Live preview off**: only the textarea is shown.
* **Preview button** (`Ctrl/Cmd+E`): shows only the rendered note with a read-only title; **Edit** returns to the editor.
* **Layout**: the top bar has only **Preview** and **Settings** (plus the status text and, on narrow windows, a menu button). The sidebar has no Note/Folder buttons: right-clicking the sidebar offers New note / New folder. The footer holds the sidebar toggle (`Ctrl/Cmd+B`) and the centred **Lock** button.
* **Sidebar**: the logo keeps the initial 280 px width. The sidebar can be dragged (or resized with the arrow keys on the separator) from 280 px up to the larger of 280 px and a quarter of the window width, and can be collapsed to a thin strip holding the toggle. The state is kept in `localStorage` (`can.side`). Narrow windows (≤ 720 px) keep the overlay menu.
* **Drag and drop**: notes and folders use HTML5 drag and drop. Dropping on a folder moves the item inside; dropping on empty space moves it to the root. `canDrop` refuses a folder dropped on itself or on one of its descendants. The move uses the existing `move` call. The Tauri window sets `dragDropEnabled: false` so the webview receives these events.
* Toolbar actions and shortcuts insert Markdown at the selection of the editor, they do not create rich text.
* Autosave a moment after typing stops; failures are shown in the status line.
* **No scrollbars**: `scrollbar-width:none`, `::-webkit-scrollbar{display:none}`; wheel, trackpad, touch and keyboard still scroll, the caret is followed, and `overscroll-behavior: contain` stops at the ends.

## Screens

Create vault → recovery key → main. Unlock (password, recovery key, security key). Join existing vault (desktop). Settings, export and password dialogs are modal overlays. On the desktop, the create and unlock screens end with a low-contrast footer (`.vaultsw`): **Open a different vault folder…** and, for a chosen vault, its name and **Use the default vault**. After a switch the UI calls `status` and shows the create or unlock screen as appropriate.

## Branding

Lock screens show the large logo (icon, then the name) in a light and a dark variant. The sidebar shows the logo; collapsed, it shows the square app icon at the same position. Colours: accent `#2f5d50` (light) and `#7fb5a3` (dark).

## Theme

`<html data-theme>` is `dark` (default, set in `index.html`), `light` or `system`. `app.css` defines the dark tokens on `:root`, the light tokens under `[data-theme=light]`, and under `[data-theme=system]` inside `@media (prefers-color-scheme: light)`. Logo variants switch through the `--logo-l` / `--logo-d` custom properties. `theme.js` (loaded in `<head>`, external because the CSP forbids inline script) applies the last theme from `localStorage` (`can.theme`) before first paint; the backend value in `status.theme` is authoritative and re-applied on every status refresh.

## Idle behaviour

Calls to `status` and `sync_now{auto:true}` are marked as background and do not extend the idle timer; real user activity sends a throttled `touch`.
