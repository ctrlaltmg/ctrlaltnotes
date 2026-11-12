/* SPDX-License-Identifier: AGPL-3.0-only */
/* CtrlAltNotes UI (shared by the web version and the native apps).
 * No HTML-string injection anywhere: every node is built with createElement / textContent. */
(function () {
  'use strict';
  const api = window.CAN.call;
  const $app = document.getElementById('app');
  const MIN_PW = 15;
  const S = { tree: null, sel: null, note: null, open: new Set(), preview: false, q: '', nav: false,
              sync: null, syncLabel: '', canPick: false, idle: 300, quick: false, theme: 'dark', vaultCustom: false, vaultLabel: '',
              set: { auto_sync: true, sync_interval: 60, live_preview: true, toolbar: true, start_note: 'blank', auto_lock: 300 },
              timer: null, dirty: false, view: '', syncing: false, syncTimer: null, lastEdit: 0 };

  /* Large logo (icon followed by the name) for the lock screens; a light and a dark variant. */
  const brand = () => h('div', { class: 'logo', role: 'img', 'aria-label': 'CtrlAltNotes' },
    h('img', { class: 'logo-l', src: 'logo.svg', alt: '' }), h('img', { class: 'logo-d', src: 'logo-dark.svg', alt: '' }));

  function h(tag, props, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (k === 'class') e.className = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (v === true) e.setAttribute(k, ''); else if (v !== false && v != null) e.setAttribute(k, v);
    }
    for (const c of kids.flat()) if (c != null) e.append(c);
    return e;
  }
  const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };
  function toast(msg) { const t = h('div', { class: 'toast', role: 'status' }, msg); document.body.append(t); setTimeout(() => t.remove(), 3200); }

  /* ---------- theme (dark | light | system); dark is the default ---------- */
  const THEMES = [['dark', 'Dark'], ['light', 'Light'], ['system', 'Match system']];
  function applyTheme(t) {
    if (!THEMES.some(([v]) => v === t)) t = 'dark';
    S.theme = t; document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('can.theme', t); } catch (_) { /* storage unavailable */ }
  }

  /* Every call goes through here: a "locked" answer always returns the user to the unlock screen. */
  async function A(cmd, args) {
    try { return await api(cmd, args); }
    catch (e) { if (e.code === 'locked') { wipe(); showUnlock(); } throw e; }
  }
  function wipe() {            // drop decrypted content from the DOM and from memory
    clearTimeout(S.timer); clearInterval(S.syncTimer); S.dirty = false;
    S.note = null; S.tree = null; S.sel = null; S.preview = false; S.q = '';
    document.querySelectorAll('.ov,.menu,.toast').forEach((n) => n.remove());
    clear($app);
  }

  /* ---------- passwords ---------- */
  const chars = (s) => Array.from(s.normalize('NFKC')).length;
  function strength(pw) {
    const n = chars(pw); const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
    const score = Math.min(1, (Math.min(n, 30) / 30) * 0.8 + classes * 0.05);
    return n < MIN_PW ? Math.min(score, 0.35) : Math.max(score, 0.6);
  }
  const ALPHA = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.!?';   // no look-alikes
  function generate(len) {   // uniform rejection sampling over a CSPRNG
    const out = []; const lim = 256 - (256 % ALPHA.length);
    while (out.length < len) { for (const b of crypto.getRandomValues(new Uint8Array(len * 2))) { if (b < lim && out.length < len) out.push(ALPHA[b % ALPHA.length]); } }
    return out.join('');
  }
  /* A "new password" form block shared by create + change-password: two fields, meter, generator. */
  function newPasswordFields(onChange) {
    const pw = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Choose a password (' + MIN_PW + '+ characters)', 'aria-label': 'New password', autofocus: true });
    const pw2 = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Repeat password', 'aria-label': 'Repeat password' });
    const bar = h('i'); const meter = h('div', { class: 'meter' }, bar);
    const hint = h('div', { class: 'hint' });
    const show = h('button', { type: 'button', class: 'mini' }, 'Show');
    const gen = h('button', { type: 'button', class: 'mini' }, 'Generate');
    const state = { valid: false };
    const check = () => {
      const n = chars(pw.value), same = pw.value === pw2.value && pw2.value.length > 0;
      bar.style.width = Math.round(strength(pw.value) * 100) + '%'; meter.classList.toggle('ok', n >= MIN_PW);
      hint.textContent = !pw.value ? 'Length matters most: use a passphrase of several unrelated words. Spaces and any language are fine.'
        : n < MIN_PW ? (MIN_PW - n) + ' more character(s) needed.' : (pw2.value && !same ? 'Passwords do not match.' : 'Long enough. Very common phrases are rejected.');
      state.valid = n >= MIN_PW && same; onChange(state.valid);
    };
    show.addEventListener('click', () => { const t = pw.type === 'password' ? 'text' : 'password'; pw.type = t; pw2.type = t; show.textContent = t === 'text' ? 'Hide' : 'Show'; });
    gen.addEventListener('click', () => { const g = generate(22); pw.value = g; pw2.value = g; pw.type = 'text'; pw2.type = 'text'; show.textContent = 'Hide'; check(); toast('Generated. Save it in a password manager before continuing.'); });
    pw.addEventListener('input', check); pw2.addEventListener('input', check);
    const node = h('div', { class: 'pwfields' }, pw, pw2, meter, hint, h('div', { class: 'row2' }, show, gen));
    return { node, pw, pw2, state, focus: () => pw.focus(), reset: () => { pw.value = ''; pw2.value = ''; check(); } };
  }

  /* ---------- screens: first run ---------- */
  function showCreate(note) {
    S.view = 'create'; wipe();
    const err = h('div', { class: 'err', role: 'alert' }, note || '');
    const go = h('button', { class: 'go', type: 'submit', disabled: true }, 'Create encrypted vault');
    const f = newPasswordFields((ok) => { go.disabled = !ok; });
    const form = h('form', { onsubmit: async (ev) => {
      ev.preventDefault(); err.textContent = ''; go.disabled = true;
      try { const r = await A('create_vault', { password: f.pw.value }); f.reset(); showRecovery(r.recovery_key, async () => { await showMain(); offerSync(); }); }
      catch (e) { err.textContent = e.message || 'Could not create the vault.'; go.disabled = !f.state.valid; }
    } }, brand(), h('h1', {}, 'Create your vault'), h('div', { class: 'sub' }, 'Everything is encrypted on this device before it is stored or synced.'),
      f.node, go, err,
      S.canPick ? h('button', { type: 'button', class: 'link', onclick: () => showJoin() }, 'I already have a vault in my cloud storage') : null,
      vaultSwitcher(err));
    $app.append(h('div', { class: 'lock' }, form)); f.focus();
  }

  function showRecovery(key, next, title) {
    wipe();
    const copy = h('button', { type: 'button', onclick: async () => { try { await navigator.clipboard.writeText(key); toast('Copied. Clear your clipboard after saving it.'); } catch (_) { toast('Select the key and copy it manually.'); } } }, 'Copy');
    const ok = h('input', { type: 'checkbox', id: 'saved' });
    const go = h('button', { class: 'go', type: 'button', disabled: true, onclick: () => { key = ''; next(); } }, 'Continue');
    ok.addEventListener('change', () => { go.disabled = !ok.checked; });
    $app.append(h('div', { class: 'lock' }, h('div', { class: 'form' },
      brand(), h('h1', {}, title || 'Your recovery key'),
      h('div', { class: 'sub' }, 'If you forget your password, this key is the ONLY way back in. It is shown once and is not stored anywhere. Write it down and keep it somewhere safe and offline.'),
      h('div', { class: 'reckey', 'aria-label': 'Recovery key' }, key), copy,
      h('label', { class: 'chk', for: 'saved' }, ok, 'I have saved my recovery key.'), go)));
  }

  function showJoin(note) {
    S.view = 'join'; wipe();
    const err = h('div', { class: 'err', role: 'alert' }, note || '');
    const pw = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Vault password', 'aria-label': 'Vault password', autofocus: true });
    const go = async (kind) => {
      err.textContent = '';
      try { await A('join_vault', { kind, password: pw.value }); pw.value = ''; await showMain(); }
      catch (e) { pw.value = ''; if (e.code === 'cancelled') return; err.textContent = e.code === 'throttled' ? 'Too many attempts. Wait ' + e.retry + 's.' : (e.message || 'Could not join.'); }
    };
    $app.append(h('div', { class: 'lock' }, h('div', { class: 'form' },
      brand(), h('h1', {}, 'Use an existing vault'),
      h('div', { class: 'sub' }, 'Enter the vault password, then choose where your synced vault is (a cloud-synced folder, or a single vault file).'),
      pw, h('div', { class: 'row2' },
        h('button', { type: 'button', class: 'go', onclick: () => go('folder') }, 'Choose folder…'),
        h('button', { type: 'button', class: 'go', onclick: () => go('bundle') }, 'Choose file…')),
      err, h('button', { type: 'button', class: 'link', onclick: () => showCreate() }, 'Back'))));
    pw.focus();
  }

  /* Right after creating a vault (desktop): sync is on by default once a location is chosen. */
  async function offerSync() {
    if (!S.canPick || S.sync) return;
    const r = await dialog('Sync your notes', [], 'Choose cloud folder…',
      h('div', { class: 'hint' }, 'Pick the folder your cloud service (Proton Drive, iCloud, Dropbox…) keeps in sync. Notes will then sync automatically, always encrypted. You can change this later in Settings.'),
      [['Single file…', 'bundle'], ['Skip', null]]);
    if (!r) return;
    await chooseSync(r.alt || 'folder');
  }

  /* Show whichever screen fits the current vault folder. */
  async function route(note) {
    const st = await refreshStatus();
    if (!st.exists) showCreate(note); else if (!st.unlocked) showUnlock(note); else await showMain();
  }

  /* Quiet footer on the lock screens (desktop only): work in another vault folder instead.
   * The folder is chosen in a native dialog opened by the host; the page never sees a path. */
  function vaultSwitcher(err) {
    if (!S.canPick) return null;
    const pick = async (cmd) => {
      err.textContent = '';
      try { await api(cmd); await route(); }
      catch (e) { if (e.code === 'cancelled') return; err.textContent = e.message || 'Could not open that folder.'; }
    };
    return h('div', { class: 'vaultsw' },
      S.vaultCustom ? h('span', { class: 'vname', title: S.vaultLabel }, 'Vault: ' + S.vaultLabel) : null,
      h('button', { type: 'button', onclick: () => pick('open_vault_folder') }, 'Open a different vault folder…'),
      S.vaultCustom ? h('button', { type: 'button', onclick: () => pick('use_default_vault') }, 'Use the default vault') : null);
  }

  /* ---------- screens: unlock ---------- */
  function showUnlock(note) {
    S.view = 'unlock'; wipe();
    let useRec = false;
    const err = h('div', { class: 'err', role: 'alert' }, note || '');
    const pw = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Password', 'aria-label': 'Password', autofocus: true });
    const alt = h('button', { type: 'button', class: 'alt' }, 'Use recovery key');
    alt.addEventListener('click', () => { useRec = !useRec; pw.type = useRec ? 'text' : 'password'; pw.placeholder = useRec ? 'Recovery key' : 'Password'; pw.setAttribute('aria-label', pw.placeholder); pw.value = ''; alt.textContent = useRec ? 'Use password' : 'Use recovery key'; pw.focus(); });
    const failMsg = (e) => (e.code === 'throttled' ? 'Too many attempts. Wait ' + e.retry + 's.' : null);
    const key = h('button', { type: 'button', class: 'go alt2', hidden: true, onclick: async () => {
      err.textContent = '';
      try { const info = await api('quick_info'); const secret = await window.CANQuick.getSecret(info); await A('unlock_quick', { secret }); await showMain(); }
      catch (e) { err.textContent = failMsg(e) || e.message || 'Could not unlock.'; }
    } }, 'Unlock with security key / fingerprint');
    api('status').then((st) => { if (st.quick && window.CANQuick.supported()) key.hidden = false; }).catch(() => {});
    const form = h('form', { onsubmit: async (ev) => {
      ev.preventDefault(); err.textContent = '';
      try { await A('unlock', useRec ? { recovery: pw.value } : { password: pw.value }); pw.value = ''; await showMain(); }
      catch (e) { pw.value = ''; err.textContent = failMsg(e) || 'Could not unlock.'; }
    } }, brand(), pw, h('button', { class: 'go', type: 'submit' }, 'Unlock'), key, err, alt, vaultSwitcher(err));
    $app.append(h('div', { class: 'lock' }, form)); pw.focus();
  }

  /* ---------- main ---------- */
  async function refreshStatus() {
    const st = await api('status');
    S.sync = st.sync; S.syncLabel = st.sync_label || ''; S.canPick = !!st.can_pick; S.idle = st.idle_lock || 300; S.quick = !!st.quick;
    S.vaultCustom = !!st.vault_custom; S.vaultLabel = st.vault_label || '';
    if (st.theme) applyTheme(st.theme);
    if (st.settings) S.set = st.settings;
    return st;
  }
  async function showMain() {
    const first = S.view !== 'main';
    S.view = 'main'; await refreshStatus(); await loadTree();
    if (first) { S.note = null; S.sel = null; }
    if (first && S.set.start_note === 'last') { const id = latestNoteId(S.tree); if (id) { try { S.note = await A('get_note', { id }); S.sel = id; } catch (_) { /* start blank */ } } }
    draw(); startAutoSync();
  }
  /* Id of the most recently edited note anywhere in the tree (null when there are none). */
  function latestNoteId(node) {
    let best = null;
    const walk = (n) => { for (const x of n.notes || []) if (!best || x.modified > best.modified) best = x; for (const f of n.folders || []) walk(f); };
    walk(node); return best ? best.id : null;
  }
  async function loadTree() { S.tree = await A('tree'); }


  /* ---------- sidebar state, icons, drag and drop helpers ---------- */
  const SVGNS = 'http://www.w3.org/2000/svg';
  function svgIcon(...shapes) {                  // tiny stroke icons built with DOM calls (no HTML strings)
    const svg = document.createElementNS(SVGNS, 'svg');
    for (const [k, v] of Object.entries({ viewBox: '0 0 24 24', width: '18', height: '18', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.8', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) svg.setAttribute(k, v);
    for (const [tag, attrs] of shapes) { const e = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); svg.append(e); }
    return svg;
  }
  const ICON_SIDEBAR = () => svgIcon(['rect', { x: 3, y: 4, width: 18, height: 16, rx: 2.5 }], ['line', { x1: 9, y1: 4, x2: 9, y2: 20 }]);
  const ICON_LOCK = () => svgIcon(['rect', { x: 5, y: 11, width: 14, height: 9, rx: 2 }], ['path', { d: 'M8 11V8a4 4 0 0 1 8 0v3' }]);
  const SIDE_MIN = 280;
  const sideMax = () => Math.max(SIDE_MIN, Math.floor(window.innerWidth / 4));       // at most 1/4 of the window (never below the start width)
  const clampSide = (w) => Math.min(sideMax(), Math.max(SIDE_MIN, Math.round(w)));
  try { const v = JSON.parse(localStorage.getItem('can.side') || '{}'); S.sideW = Number(v.w) || SIDE_MIN; S.sideOpen = v.open !== false; } catch (_) { S.sideW = SIDE_MIN; S.sideOpen = true; }
  function saveSide() { try { localStorage.setItem('can.side', JSON.stringify({ w: S.sideW, open: S.sideOpen })); } catch (_) { /* optional convenience */ } }
  function applySide() {
    const shell = document.querySelector('.shell'); if (!shell) return;
    S.sideW = clampSide(S.sideW);
    shell.style.setProperty('--sw', S.sideW + 'px');
    shell.classList.toggle('collapsed', !S.sideOpen);
    const t = document.getElementById('side-toggle');
    if (t) { const label = S.sideOpen ? 'Hide sidebar' : 'Show sidebar'; t.title = label + ' (Ctrl/Cmd+B)'; t.setAttribute('aria-label', label); t.setAttribute('aria-expanded', String(S.sideOpen)); }
  }
  function toggleSide() { S.sideOpen = !S.sideOpen; applySide(); saveSide(); }
  window.addEventListener('resize', applySide);
  function startResize(e) {
    e.preventDefault(); const x0 = e.clientX, w0 = S.sideW; const bar = e.currentTarget; bar.setPointerCapture?.(e.pointerId);
    document.body.classList.add('resizing');
    const move = (ev) => { S.sideW = clampSide(w0 + ev.clientX - x0); applySide(); };
    const up = () => { bar.removeEventListener('pointermove', move); bar.removeEventListener('pointerup', up); bar.removeEventListener('pointercancel', up); document.body.classList.remove('resizing'); saveSide(); };
    bar.addEventListener('pointermove', move); bar.addEventListener('pointerup', up); bar.addEventListener('pointercancel', up);
  }
  /* where is an item in the tree? -> { item, parent (id or null), kind } */
  function locate(node, id, parent) {
    for (const f of node.folders || []) { if (f.id === id) return { item: f, parent, kind: 'folder' }; const r = locate(f, id, f.id); if (r) return r; }
    for (const n of node.notes || []) if (n.id === id) return { item: n, parent, kind: 'note' };
    return null;
  }
  function insideFolder(folder, id) { return (folder.folders || []).some((f) => f.id === id || insideFolder(f, id)); }
  /* can the dragged item be dropped on this folder (id) or on the top level (null)? */
  function canDrop(target) {
    const d = S.drag; if (!d) return false;
    const here = locate(S.tree, d.id, null); if (!here) return false;
    if (here.parent === target) return false;                              // already there
    if (here.kind === 'folder' && target) { if (target === d.id) return false; if (insideFolder(here.item, target)) return false; }
    return true;
  }
  async function doMove(target) {
    const d = S.drag; S.drag = null; if (!d) return;
    try { await A('move_item', { id: d.id, parent: target }); if (target) S.open.add(target); await refresh(); }
    catch (e) { toast(e.message || 'Could not move it.'); }
  }
  const dragRow = (row, id, kind) => {
    row.draggable = true;
    row.addEventListener('dragstart', (e) => { S.drag = { id, kind }; e.dataTransfer.effectAllowed = 'move'; try { e.dataTransfer.setData('text/plain', id); } catch (_) { /* ok */ } row.classList.add('dragging'); });
    row.addEventListener('dragend', () => { S.drag = null; document.querySelectorAll('.dragging,.drop,.droproot').forEach((x) => x.classList.remove('dragging', 'drop', 'droproot')); });
  };

  function draw() {
    clear($app);
    const q = h('input', { class: 'search', type: 'search', placeholder: 'Search', 'aria-label': 'Search', value: S.q });
    q.addEventListener('input', async () => { S.q = q.value; await renderTree(); q.focus(); });
    const treeBox = h('div', { class: 'tree', id: 'tree', role: 'tree' });
    treeBox.addEventListener('dragover', (e) => {            // dropping on the empty part of the list = top level
      if (!S.drag || !canDrop(null)) return; e.preventDefault(); e.dataTransfer.dropEffect = 'move'; treeBox.classList.add('droproot');
    });
    treeBox.addEventListener('dragleave', (e) => { if (!treeBox.contains(e.relatedTarget)) treeBox.classList.remove('droproot'); });
    treeBox.addEventListener('drop', (e) => { if (!S.drag || !canDrop(null)) return; e.preventDefault(); treeBox.classList.remove('droproot'); doMove(null); });
    const side = h('aside', {},
      h('div', { class: 'sidelogo', role: 'img', 'aria-label': 'CtrlAltNotes' }, h('img', { class: 'logo-l', src: 'logo.svg', alt: '' }), h('img', { class: 'logo-d', src: 'logo-dark.svg', alt: '' }), h('img', { class: 'sidemark', src: 'icon.svg', alt: '' })),
      q, treeBox,
      h('div', { class: 'sfoot' },
        h('button', { id: 'side-toggle', class: 'icon', onclick: toggleSide }, ICON_SIDEBAR()),
        h('button', { class: 'lockbtn', onclick: lockNow, title: 'Ctrl/Cmd+L' }, 'Lock'),
        h('button', { class: 'lockmini icon', onclick: lockNow, 'aria-label': 'Lock', title: 'Lock (Ctrl/Cmd+L)' }, ICON_LOCK()),
        h('span', { class: 'sfoot-sp' })),
      h('div', { class: 'resizer', role: 'separator', 'aria-orientation': 'vertical', 'aria-label': 'Resize sidebar', tabindex: '0',
        onpointerdown: startResize,
        onkeydown: (e) => { if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') { e.preventDefault(); S.sideW = clampSide(S.sideW + (e.key === 'ArrowRight' ? 16 : -16)); applySide(); saveSide(); } } }));
    side.addEventListener('contextmenu', (e) => {              // right-click the sidebar background: create things
      if (e.defaultPrevented || e.target.closest('input,.row,button,.resizer')) return;
      e.preventDefault(); menu(e.clientX, e.clientY, [['New note', () => newItem('note', null)], ['New folder', () => newItem('folder', null)]]);
    });
    const status = h('span', { id: 'status' }, '');
    const top = h('div', { class: 'top' },
      h('button', { class: 'menu-btn', 'aria-label': 'Toggle navigation', onclick: () => { S.nav = !S.nav; document.querySelector('.shell').classList.toggle('nav', S.nav); } }, 'Menu'),
      status, h('span', { class: 'grow' }),
      h('button', { id: 'toggle', onclick: togglePreview, title: 'Ctrl/Cmd+E' }, S.preview ? 'Edit' : 'Preview'),
      h('button', { 'aria-label': 'Settings', onclick: (e) => { e.stopPropagation(); openSettings(); } }, 'Settings'));
    const doc = h('div', { class: 'doc', id: 'doc' });
    $app.append(h('div', { class: 'shell' }, side, h('main', {}, top, doc)));
    applySide(); renderTree(); renderDoc();
  }

  function flat(node, depth, out) { for (const f of node.folders) { out.push([f, depth]); flat(f, depth + 1, out); } return out; }

  async function renderTree() {
    const box = document.getElementById('tree'); if (!box) return; clear(box);
    if (S.q.trim()) {
      const res = await A('search', { query: S.q.trim() });
      if (!res.length) box.append(h('div', { class: 'empty' }, 'No matches'));
      for (const n of res) box.append(noteRow(n));
      return;
    }
    if (!S.tree.folders.length && !S.tree.notes.length) { box.append(h('div', { class: 'empty' }, 'No notes yet.')); return; }
    box.append(...nodeRows(S.tree));
  }
  function nodeRows(node) {
    const rows = [];
    for (const f of node.folders) {
      const open = S.open.has(f.id);
      const frow = h('div', { class: 'row', role: 'treeitem', 'aria-expanded': String(open), tabindex: '0',
        onclick: () => { open ? S.open.delete(f.id) : S.open.add(f.id); renderTree(); },
        onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.currentTarget.click(); } },
        oncontextmenu: (e) => { e.preventDefault(); itemMenu(e.clientX, e.clientY, f, 'folder'); } },
        h('span', { class: 'caret' }, open ? '▾' : '▸'), h('span', { class: 't' }, f.name),
        h('button', { class: 'm', 'aria-label': 'Folder actions', onclick: (e) => { e.stopPropagation(); itemMenu(e.clientX, e.clientY, f, 'folder'); } }, '⋯'));
      dragRow(frow, f.id, 'folder');
      frow.addEventListener('dragover', (e) => { if (!S.drag || !canDrop(f.id)) return; e.preventDefault(); e.stopPropagation(); e.dataTransfer.dropEffect = 'move'; frow.classList.add('drop'); document.getElementById('tree')?.classList.remove('droproot'); });
      frow.addEventListener('dragleave', () => frow.classList.remove('drop'));
      frow.addEventListener('drop', (e) => { if (!S.drag || !canDrop(f.id)) return; e.preventDefault(); e.stopPropagation(); frow.classList.remove('drop'); doMove(f.id); });
      rows.push(frow);
      if (open) rows.push(h('div', { class: 'kids' }, ...nodeRows(f)));
    }
    for (const n of node.notes) rows.push(noteRow(n, node === S.tree ? null : node.id));
    return rows;
  }
  function noteRow(n, parentId) {
    const row = h('div', { class: 'row' + (S.sel === n.id ? ' sel' : ''), role: 'treeitem', tabindex: '0',
      onclick: () => openNote(n.id),
      onkeydown: (e) => { if (e.key === 'Enter') openNote(n.id); },
      oncontextmenu: (e) => { e.preventDefault(); itemMenu(e.clientX, e.clientY, n, 'note'); } },
      h('span', { class: 'caret' }), h('span', { class: 't' }, n.title || 'Untitled'),
      h('button', { class: 'm', 'aria-label': 'Note actions', onclick: (e) => { e.stopPropagation(); itemMenu(e.clientX, e.clientY, n, 'note'); } }, '⋯'));
    dragRow(row, n.id, 'note');
    if (parentId !== undefined) {                                  // dropping on a note = move next to it (same folder)
      row.addEventListener('dragover', (e) => { if (!S.drag || !canDrop(parentId)) return; e.preventDefault(); e.stopPropagation(); e.dataTransfer.dropEffect = 'move'; row.classList.add('drop'); document.getElementById('tree')?.classList.remove('droproot'); });
      row.addEventListener('dragleave', () => row.classList.remove('drop'));
      row.addEventListener('drop', (e) => { if (!S.drag || !canDrop(parentId)) return; e.preventDefault(); e.stopPropagation(); row.classList.remove('drop'); doMove(parentId); });
    }
    return row;
  }

  /* ---------- menus / dialogs ---------- */
  function closeMenus() { document.querySelectorAll('.menu:not(.dlg)').forEach((m) => m.remove()); }
  document.addEventListener('click', closeMenus);
  function menu(x, y, items) {
    closeMenus();
    const m = h('div', { class: 'menu', role: 'menu' }, ...items.map(([label, fn, cls]) => h('button', { role: 'menuitem', class: cls || '', onclick: (e) => { e.stopPropagation(); closeMenus(); fn(); } }, label)));
    m.style.left = Math.max(4, Math.min(x, innerWidth - 200)) + 'px'; m.style.top = Math.max(4, Math.min(y, innerHeight - 40 - items.length * 34)) + 'px';
    document.body.append(m);
  }
  /* Generic modal. fields: [{name,label,type,value}] -> resolves {name:value, alt} or null (cancel).
   * `altButtons` = [[label, value], ...] extra buttons that resolve with out.alt = value. */
  function dialog(title, fields, okLabel, extra, altButtons) {
    return new Promise((res) => {
      const inputs = {};
      const form = h('form', { class: 'dlg', role: 'dialog', 'aria-label': title },
        h('h2', {}, title), extra || null,
        ...fields.map((f) => { inputs[f.name] = h('input', { type: f.type || 'text', value: f.value || '', 'aria-label': f.label, placeholder: f.label, autocomplete: f.type === 'password' ? 'off' : 'on' }); return inputs[f.name]; }),
        h('div', { class: 'btns' }, h('button', { type: 'button', onclick: () => done(null) }, 'Cancel'),
          ...(altButtons || []).map(([l, v]) => h('button', { type: 'button', onclick: () => { const o = {}; for (const k in inputs) o[k] = inputs[k].value; o.alt = v; done(v === null ? null : o); } }, l)),
          h('button', { type: 'submit', class: 'primary' }, okLabel || 'OK')));
      const ov = h('div', { class: 'ov' }, form);
      const done = (v) => { ov.remove(); res(v); };
      form.addEventListener('submit', (e) => { e.preventDefault(); const out = {}; for (const k in inputs) out[k] = inputs[k].value; done(out); });
      ov.addEventListener('keydown', (e) => { if (e.key === 'Escape') done(null); });
      ov.addEventListener('click', (e) => { e.stopPropagation(); });
      document.body.append(ov);
      const first = Object.values(inputs)[0]; if (first) { first.focus(); first.select(); } else { form.querySelector('.primary').focus(); }
    });
  }
  const ask = async (label, initial) => { const r = await dialog(label, [{ name: 'v', label, value: initial }]); return r ? r.v : null; };

  function itemMenu(x, y, item, kind) {
    const items = [];
    if (kind === 'folder') items.push(['New note here', () => newItem('note', item.id)], ['New subfolder', () => newItem('folder', item.id)],
      ['Rename', async () => { const v = await ask('Folder name', item.name); if (v) { await A('rename_folder', { id: item.id, name: v }); await refresh(); } }]);
    else items.push(['Rename', async () => { const v = await ask('Title', item.title); if (v) { await A('update_note', { id: item.id, title: v }); if (S.sel === item.id) await openNote(item.id); else await refresh(); } }]);
    items.push(['Move to…', () => moveMenu(x, y, item)], ['Delete', async () => {
      const v = await ask('Type DELETE to confirm', ''); if (v !== 'DELETE') return;
      await A('delete_item', { id: item.id }); if (S.sel === item.id) { S.sel = null; S.note = null; } await refresh(); renderDoc();
    }, 'del']);
    menu(x, y, items);
  }
  function moveMenu(x, y, item) {
    const dests = [['Top level', null, 0], ...flat(S.tree, 1, []).map(([f, d]) => [f.name, f.id, d])];
    setTimeout(() => menu(x, y, dests.map(([name, id, d]) => ['  '.repeat(d) + name, async () => { try { await A('move_item', { id: item.id, parent: id }); await refresh(); } catch (e) { toast(e.message); } }])), 0);
  }
  async function newItem(kind, parent) {
    const name = await ask(kind === 'note' ? 'Note title' : 'Folder name', ''); if (name === null) return;
    const r = await A(kind === 'note' ? 'create_note' : 'create_folder', kind === 'note' ? { title: name || 'Untitled', parent } : { name: name || 'Untitled', parent });
    if (parent) S.open.add(parent);
    await refresh(); if (kind === 'note') await openNote(r.id);
  }
  async function refresh() { await loadTree(); await renderTree(); }

  /* ---------- settings popup ---------- */
  /* One place that changes a preference: saves it, then repaints what depends on it. */
  async function setPref(key, value) {
    await A('set_settings', { [key]: value }); S.set[key] = value;
    if (key === 'live_preview') draw();
    else if (key === 'toolbar') renderDoc(); else if (key === 'auto_sync') startAutoSync();
  }
  function toggle(label, desc, key, onSet) {
    const sw = h('button', { type: 'button', class: 'sw', role: 'switch', id: 'set-' + key, 'aria-label': label, 'aria-checked': String(!!S.set[key]) });
    const paint = () => sw.setAttribute('aria-checked', String(!!S.set[key]));
    sw.addEventListener('click', async (e) => {
      e.stopPropagation();
      try { await setPref(key, !S.set[key]); if (onSet) onSet(); } catch (err) { toast(err.message || 'Could not save the setting.'); }
      paint();
    });
    return h('div', { class: 'srow' }, h('span', { class: 'stext' }, h('b', {}, label), h('small', {}, desc)), sw);
  }
  const LOCK_CHOICES = [[60, '1 minute'], [120, '2 minutes'], [300, '5 minutes'], [600, '10 minutes'], [900, '15 minutes'], [1800, '30 minutes'], [3600, '1 hour'], [7200, '2 hours'], [0, 'Never']];
  function autoLockRow() {
    const cur = S.set.auto_lock;
    const choices = LOCK_CHOICES.some(([v]) => v === cur) ? LOCK_CHOICES : [[cur, cur % 60 ? cur + ' seconds' : cur / 60 + ' minutes'], ...LOCK_CHOICES].sort((a, b) => (a[0] || 1e9) - (b[0] || 1e9));
    const sel = h('select', { id: 'set-auto_lock', 'aria-label': 'Auto-lock after' }, ...choices.map(([v, l]) => { const o = h('option', { value: String(v) }, l); if (v === cur) o.selected = true; return o; }));
    const small = h('small', {}, cur === 0 ? 'Never locks by itself. Anyone who can use this computer can read your notes until you lock, close the window or quit.' : 'Locks after this much inactivity, when the window closes, and on quit.');
    sel.addEventListener('change', async () => {
      const v = parseInt(sel.value, 10);
      try { await A('set_settings', { auto_lock: v }); S.set.auto_lock = v; S.idle = v; small.textContent = v === 0 ? 'Never locks by itself. Anyone who can use this computer can read your notes until you lock, close the window or quit.' : 'Locks after this much inactivity, when the window closes, and on quit.'; }
      catch (e) { toast(e.message); sel.value = String(S.set.auto_lock); }
    });
    return h('div', { class: 'srow' }, h('span', { class: 'stext' }, h('b', {}, 'Auto-lock after'), small), sel);
  }
  function openSettings() {
    closeMenus();
    document.querySelectorAll('.ov').forEach((n) => n.remove());
    const body = h('div', { class: 'sbody' });
    const close = () => { ov.remove(); };
    const render = () => {
      clear(body);
      /* Appearance (first) */
      const th = h('select', { id: 'set-theme', 'aria-label': 'Theme' }, ...THEMES.map(([v, l]) => { const o = h('option', { value: v }, l); if (v === S.theme) o.selected = true; return o; }));
      th.addEventListener('change', async () => {
        const prev = S.theme; applyTheme(th.value);
        try { await A('set_theme', { theme: th.value }); } catch (e) { applyTheme(prev); th.value = prev; toast(e.message || 'Could not save the setting.'); }
      });
      body.append(h('h3', {}, 'Appearance'),
        h('div', { class: 'srow' }, h('span', { class: 'stext' }, h('b', {}, 'Theme'), h('small', {}, 'Dark, light, or follow the operating system setting.')), th));
      /* Security */
      const quickRow = h('div', { class: 'srow' }, h('span', { class: 'stext' }, h('b', {}, 'Security key / fingerprint unlock'),
        h('small', {}, !window.CANQuick.supported() ? 'Not available in this window. Use a browser with WebAuthn support.' : S.quick ? 'Enabled. Your password and recovery key still work.' : 'Unlock with a YubiKey, Touch ID or Windows Hello instead of typing the password.')),
        window.CANQuick.supported() ? h('button', { onclick: S.quick ? removeQuick : enrollQuick }, S.quick ? 'Remove' : 'Set up…') : null);
      body.append(h('h3', {}, 'Security'),
        h('div', { class: 'srow' }, h('span', { class: 'stext' }, h('b', {}, 'Password'), h('small', {}, 'Changing it issues a new recovery key and removes security-key unlock.')), h('button', { onclick: () => { close(); changePassword(); } }, 'Change…')),
        quickRow,
        autoLockRow(),
        h('h3', {}, 'Sync'),
        toggle('Sync automatically', S.sync ? 'Syncs with “' + S.syncLabel + '” every ' + S.set.sync_interval + ' s while the vault is unlocked.' : 'Takes effect once a sync location is chosen.', 'auto_sync'));
      const iv = h('select', { 'aria-label': 'Sync interval' }, ...[[15, '15 seconds'], [30, '30 seconds'], [60, '1 minute'], [300, '5 minutes'], [900, '15 minutes']].map(([v, l]) => { const o = h('option', { value: String(v) }, l); if (v === S.set.sync_interval) o.selected = true; return o; }));
      iv.addEventListener('change', async () => { try { await A('set_settings', { sync_interval: parseInt(iv.value, 10) }); S.set.sync_interval = parseInt(iv.value, 10); startAutoSync(); } catch (e) { toast(e.message); } });
      body.append(h('div', { class: 'srow' }, h('span', { class: 'stext' }, h('b', {}, 'Sync interval')), iv));
      if (S.canPick) {
        body.append(h('div', { class: 'srow' }, h('span', { class: 'stext' }, h('b', {}, 'Sync location'), h('small', {}, S.sync ? (S.sync === 'folder' ? 'Folder: ' : 'File: ') + S.syncLabel : 'Not set')),
          h('span', { class: 'btnrow' }, h('button', { onclick: () => chooseSync('folder').then(render) }, 'Folder…'), h('button', { onclick: () => chooseSync('bundle').then(render) }, 'File…'),
            S.sync ? h('button', { onclick: async () => { await A('clear_sync'); await refreshStatus(); draw(); render(); } }, 'Stop') : null)));
      }
      /* Editor */
      body.append(h('h3', {}, 'Editor'),
        toggle('Live preview', 'Shows the formatted note next to the Markdown editor and updates it as you type. Off: only the Markdown editor.', 'live_preview'),
        toggle('Formatting toolbar', 'Buttons for bold, italic, underline, headings, lists, tables…', 'toolbar'),
        h('div', { class: 'srow' }, h('span', { class: 'stext' }, h('b', {}, 'When the app opens'), h('small', {}, 'What you see first after unlocking: an empty page, or the note you edited most recently.')),
          (() => {
            const sel = h('select', { id: 'set-start_note', 'aria-label': 'When the app opens' }, ...[['blank', 'Blank page'], ['last', 'Last edited note']].map(([v, l]) => { const o = h('option', { value: v }, l); if (v === S.set.start_note) o.selected = true; return o; }));
            sel.addEventListener('change', async () => { try { await setPref('start_note', sel.value); } catch (e) { toast(e.message); sel.value = S.set.start_note; } });
            return sel;
          })()));
      /* Data */
      body.append(h('h3', {}, 'Data'), h('div', { class: 'srow' }, h('span', { class: 'stext' }, h('b', {}, 'Export to Markdown files'), h('small', {}, S.canPick ? 'Choose which folders and notes to export. Exported files are NOT encrypted.' : 'Choose which folders and notes to export. Your browser saves them to its Downloads folder. They are NOT encrypted.')), h('button', { onclick: () => { close(); exportMd(); } }, 'Export…')));
    };
    async function enrollQuick() {
      const r = await dialog('Set up security key / fingerprint', [{ name: 'pw', label: 'Current password', type: 'password' }, { name: 'label', label: 'Name (e.g. YubiKey)', value: 'Security key' }], 'Continue',
        h('div', { class: 'hint' }, 'You will be asked to touch your key or use your fingerprint.'));
      if (!r) return;
      try {
        const info = await window.CANQuick.enroll();
        await A('quick_enroll', { password: r.pw, secret: info.secret, cred_id: info.cred_id, salt: info.salt, rp_id: info.rp_id, label: r.label || 'Security key' });
        await refreshStatus(); toast('Enabled.'); render();
      } catch (e) { toast(e.message || 'Could not set up.'); }
    }
    async function removeQuick() { try { await A('quick_remove'); await refreshStatus(); render(); toast('Removed.'); } catch (e) { toast(e.message); } }
    const ov = h('div', { class: 'ov' }, h('div', { class: 'dlg wide', role: 'dialog', 'aria-label': 'Settings' },
      h('div', { class: 'dhead' }, h('h2', {}, 'Settings'), h('button', { 'aria-label': 'Close settings', onclick: close }, 'Close')), body));
    ov.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
    ov.addEventListener('click', (e) => { e.stopPropagation(); if (e.target === ov) close(); });
    render(); document.body.append(ov);
  }
  async function chooseSync(kind) {
    try { await A('set_sync', { kind }); await refreshStatus(); draw(); startAutoSync(); toast('Sync location set.'); doSync(true); }
    catch (e) { if (e.code !== 'cancelled') toast(e.message); }
  }
  async function changePassword() {
    await flush();
    const err = h('div', { class: 'err' });
    const old = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Current password', 'aria-label': 'Current password' });
    const go = h('button', { type: 'submit', class: 'primary', disabled: true }, 'Change');
    const f = newPasswordFields((ok) => { go.disabled = !ok; });
    const form = h('form', { class: 'dlg', role: 'dialog', 'aria-label': 'Change password' }, h('h2', {}, 'Change password'), old, f.node, err,
      h('div', { class: 'btns' }, h('button', { type: 'button', onclick: () => ov.remove() }, 'Cancel'), go));
    const ov = h('div', { class: 'ov' }, form);
    ov.addEventListener('click', (e) => e.stopPropagation());
    form.addEventListener('submit', async (e) => {
      e.preventDefault(); err.textContent = '';
      try { const r = await A('change_password', { old: old.value, new: f.pw.value }); ov.remove(); showRecovery(r.recovery_key, async () => { await showMain(); }, 'Your NEW recovery key'); }
      catch (x) { err.textContent = x.message || 'Could not change password.'; }
    });
    document.body.append(ov); old.focus();
  }

  /* Hand a file to the browser's own download (lands in the Downloads folder). */
  function saveDownload(r) {
    const b64 = r.data.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    const bytes = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const url = URL.createObjectURL(new Blob([bytes], { type: r.mime }));
    const a = h('a', { href: url, download: r.name, hidden: true }); document.body.append(a); a.click();
    setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 4000);
  }

  /* ---------- export picker ---------- */
  async function exportMd() {
    await flush(); const tree = await A('tree');
    const picked = new Set(); const boxes = new Map();   // id -> checkbox
    const count = h('span', { class: 'hint' }, 'Nothing selected');
    const go = h('button', { type: 'button', class: 'primary', disabled: true }, S.canPick ? 'Choose destination…' : 'Download');
    const upd = () => { count.textContent = picked.size ? picked.size + ' item(s) selected (folders include everything inside)' : 'Nothing selected'; go.disabled = !picked.size; };
    const setAll = (node, on) => { for (const f of node.folders) { setOne(f.id, on); setAll(f, on); } for (const n of node.notes) setOne(n.id, on); };
    const setOne = (id, on) => { const b = boxes.get(id); if (b) b.checked = on; if (on) picked.add(id); else picked.delete(id); };
    const rows = (node, depth) => {
      const out = [];
      for (const f of node.folders) {
        const cb = h('input', { type: 'checkbox', 'aria-label': 'Folder ' + f.name }); boxes.set(f.id, cb);
        cb.addEventListener('change', () => { setOne(f.id, cb.checked); setAll(f, cb.checked); upd(); });
        out.push(h('label', { class: 'xrow x' + Math.min(depth, 8) }, cb, h('span', { class: 'xf' }, '▾ ' + f.name)), ...rows(f, depth + 1));
      }
      for (const n of node.notes) {
        const cb = h('input', { type: 'checkbox', 'aria-label': 'Note ' + (n.title || 'Untitled') }); boxes.set(n.id, cb);
        cb.addEventListener('change', () => { setOne(n.id, cb.checked); upd(); });
        out.push(h('label', { class: 'xrow x' + Math.min(depth, 8) }, cb, h('span', {}, n.title || 'Untitled')));
      }
      return out;
    };
    const list = h('div', { class: 'xlist' }, ...rows(tree, 0));
    if (!list.firstChild) list.append(h('div', { class: 'empty' }, 'No notes yet.'));
    const all = h('button', { type: 'button', onclick: () => { setAll(tree, true); upd(); } }, 'Select all');
    const none = h('button', { type: 'button', onclick: () => { setAll(tree, false); picked.clear(); upd(); } }, 'Clear');
    const ov = h('div', { class: 'ov' }, h('div', { class: 'dlg wide', role: 'dialog', 'aria-label': 'Export' },
      h('h2', {}, 'Export to Markdown files'), h('div', { class: 'hint' }, 'Exported files are NOT encrypted. Choose what to export:'),
      h('div', { class: 'btnrow' }, all, none), list, count,
      h('div', { class: 'btns' }, h('button', { type: 'button', onclick: () => ov.remove() }, 'Cancel'), go)));
    ov.addEventListener('click', (e) => e.stopPropagation());
    go.addEventListener('click', async () => {
      try {
        if (S.canPick) { const r = await A('export_markdown', { ids: Array.from(picked) }); ov.remove(); toast('Exported ' + r.count + ' note(s). They are unencrypted.'); }
        else { const r = await A('export_download', { ids: Array.from(picked) }); saveDownload(r); ov.remove(); toast('Downloaded ' + r.count + ' note(s) to your Downloads folder. They are unencrypted.'); }
      }
      catch (e) { if (e.code !== 'cancelled') toast(e.message); }
    });
    document.body.append(ov);
  }

  /* ---------- editor ---------- */
  async function openNote(id) {
    await flush();
    S.sel = id; S.note = await A('get_note', { id }); S.preview = false; S.nav = false;
    document.querySelector('.shell')?.classList.remove('nav');
    renderDoc(); renderTree();
  }
  function setStatus(t, ok) { const s = document.getElementById('status'); if (s) { s.textContent = t; s.className = ok ? 'ok' : ''; } }

  /* Toolbar actions edit the Markdown source in the textarea (works on the selection). */
  function edit(ta, fn) {
    const s = ta.selectionStart, e = ta.selectionEnd, v = ta.value;
    const r = fn(v, s, e); ta.value = r.value; ta.focus(); ta.setSelectionRange(r.start, r.end);
    ta.dispatchEvent(new Event('input', { bubbles: true }));
  }
  const wrap = (before, after, ph) => (v, s, e) => {
    const sel = v.slice(s, e) || ph;
    if (v.slice(s - before.length, s) === before && v.slice(e, e + after.length) === after && s !== e)   // toggle off
      return { value: v.slice(0, s - before.length) + sel + v.slice(e + after.length), start: s - before.length, end: e - before.length };
    return { value: v.slice(0, s) + before + sel + after + v.slice(e), start: s + before.length, end: s + before.length + sel.length };
  };
  const prefixLines = (prefix, numbered) => (v, s, e) => {
    const a = v.lastIndexOf('\n', s - 1) + 1; let z = v.indexOf('\n', e); if (z < 0) z = v.length;
    const lines = v.slice(a, z).split('\n'); let n = 0;
    const has = lines.every((l) => (numbered ? /^\d+\.\s/.test(l) : l.startsWith(prefix)));
    const out = lines.map((l) => (has ? (numbered ? l.replace(/^\d+\.\s/, '') : l.slice(prefix.length)) : (numbered ? (++n) + '. ' + l : prefix + l))).join('\n');
    return { value: v.slice(0, a) + out + v.slice(z), start: a, end: a + out.length };
  };
  const block = (text) => (v, s, e) => { const sel = v.slice(s, e); const t = text.replace('$', sel || 'code'); return { value: v.slice(0, s) + t + v.slice(e), start: s + 4, end: s + 4 + (sel || 'code').length }; };
  const insertAt = (text) => (v, s, e) => ({ value: v.slice(0, s) + text + v.slice(e), start: s + text.length, end: s + text.length });
  const link = (v, s, e) => { const sel = v.slice(s, e) || 'link text'; const t = '[' + sel + '](https://)'; return { value: v.slice(0, s) + t + v.slice(e), start: s + sel.length + 3, end: s + sel.length + 11 }; };
  const TOOLS = [
    ['B', 'Bold (Ctrl/Cmd+B)', wrap('**', '**', 'bold'), 'b'], ['I', 'Italic (Ctrl/Cmd+I)', wrap('*', '*', 'italic'), 'i'],
    ['U', 'Underline (Ctrl/Cmd+U)', wrap('++', '++', 'underline'), 'u'], ['S', 'Strikethrough', wrap('~~', '~~', 'text')],
    ['Hi', 'Highlight', wrap('==', '==', 'highlight')], ['</>', 'Inline code', wrap('`', '`', 'code')], null,
    ['H1', 'Heading 1', prefixLines('# ')], ['H2', 'Heading 2', prefixLines('## ')], ['H3', 'Heading 3', prefixLines('### ')], null,
    ['• List', 'Bulleted list', prefixLines('- ')], ['1. List', 'Numbered list', prefixLines('', true)], ['☑ Task', 'Task list', prefixLines('- [ ] ')], ['❝', 'Quote', prefixLines('> ')], null,
    ['Link', 'Link (Ctrl/Cmd+K)', link, 'k'], ['Code block', 'Code block', block('\n```\n$\n```\n')],
    ['Table', 'Table', insertAt('\n| Column 1 | Column 2 |\n|---|---|\n| Cell | Cell |\n')], ['―', 'Horizontal rule', insertAt('\n\n---\n\n')]];

  function renderDoc() {
    const doc = document.getElementById('doc'); if (!doc) return; clear(doc);
    const t = document.getElementById('toggle'); if (t) t.textContent = S.preview ? 'Edit' : 'Preview';
    if (!S.note) { doc.append(h('div', { class: 'empty' }, 'Select or create a note.')); setStatus(''); return; }
    const live = S.set.live_preview;
    const title = h('input', { class: 'title', value: S.note.title, 'aria-label': 'Title', placeholder: 'Untitled', readonly: S.preview ? '' : null });
    title.addEventListener('input', () => { S.note.title = title.value; queueSave(); });
    const page = h('div', { class: 'page' + (live && !S.preview ? ' wide' : '') }, title);
    const md = h('div', { class: 'md', id: 'preview', 'aria-label': 'Preview' });
    const paint = () => {
      clear(md);
      try { md.append(window.renderMarkdown(S.note.body)); }
      catch (_) { md.append(h('p', { class: 'muted' }, 'This note could not be previewed.')); }   // never break the editor
    };
    if (S.preview) { paint(); page.append(md); doc.append(page); return; }        // Preview button: only the formatted text

    const ta = h('textarea', { class: 'ed', 'aria-label': 'Markdown', spellcheck: 'true', placeholder: 'Write in Markdown…' }); ta.value = S.note.body;
    let timer = null;
    ta.addEventListener('input', (e) => {
      S.note.body = ta.value; queueSave();
      if (!live) return;
      clearTimeout(timer);
      const ch = e.data || '';
      if (e.inputType === 'insertLineBreak' || /[\s*_`~=+\])>#|-]/.test(ch)) paint();   // a space, newline or closing mark renders at once
      else timer = setTimeout(paint, 250);
    });
    ta.addEventListener('keydown', (e) => {
      if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
      const tool = TOOLS.find((x) => x && x[3] === e.key.toLowerCase());
      if (tool) { e.preventDefault(); edit(ta, tool[2]); }
    });
    if (S.set.toolbar) page.append(h('div', { class: 'tbar', role: 'toolbar', 'aria-label': 'Formatting' }, ...TOOLS.map((x) => (x ? h('button', { type: 'button', title: x[1], 'aria-label': x[1], onmousedown: (e) => e.preventDefault(), onclick: () => edit(ta, x[2]) }, x[0]) : h('span', { class: 'sep' })))));
    if (live) { paint(); page.append(h('div', { class: 'split' }, ta, md)); } else page.append(ta);
    S.activeTa = ta; doc.append(page); setTimeout(() => ta.focus(), 0);
  }
  function togglePreview() { S.preview = !S.preview; renderDoc(); }
  function queueSave() { S.dirty = true; S.lastEdit = Date.now(); setStatus('Editing…'); clearTimeout(S.timer); S.timer = setTimeout(flush, 700); }
  async function flush() {
    clearTimeout(S.timer); if (!S.dirty || !S.note) return; S.dirty = false;
    const { id, title, body } = S.note;
    try { await A('update_note', { id, title, body }); setStatus('Saved · encrypted', true); await loadTree(); renderTree(); }
    catch (e) { S.dirty = true; if (e.code !== 'locked') setStatus('Could not save'); }
  }

  /* ---------- sync ---------- */
  async function doSync(silent) {
    if (S.syncing || !S.sync) return; S.syncing = true;
    if (!silent) { await flush(); setStatus('Syncing…'); }
    try {
      // `auto` calls do not count as user activity, so they never keep an idle vault unlocked
      const r = await A('sync_now', silent ? { auto: true } : {}); const changed = r.pulled > 0 || r.conflicts > 0;
      if (changed || !silent) {
        await loadTree();
        if (S.sel && !S.dirty) { try { const n = await A('get_note', { id: S.sel }); if (!S.note || n.modified !== S.note.modified) { S.note = n; if (!silent) draw(); else { renderDoc(); } } } catch (_) { S.sel = null; S.note = null; } }
        if (silent) renderTree(); else draw();
      }
      setStatus('Synced ' + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), true);
      if (!silent) toast('Pushed ' + r.pushed + ', pulled ' + r.pulled + (r.conflicts ? ', ' + r.conflicts + ' conflict copy' : '') + (r.errors ? ', ' + r.errors + ' rejected file(s)' : ''));
    } catch (e) { if (e.code !== 'locked') { setStatus('Sync failed'); if (!silent) toast(e.message); } }
    finally { S.syncing = false; }
  }
  function startAutoSync() {
    clearInterval(S.syncTimer);
    if (S.view !== 'main' || !S.sync || !S.set.auto_sync) return;
    S.syncTimer = setInterval(() => { if (S.view === 'main' && !S.dirty && Date.now() - S.lastEdit > 3000) doSync(true); }, Math.max(15, S.set.sync_interval) * 1000);
    doSync(true);
  }
  async function lockNow() { await flush(); try { await api('lock'); } catch (_) { /* already locked */ } showUnlock(); }

  document.addEventListener('keydown', (e) => {
    if (!(e.ctrlKey || e.metaKey) || S.view !== 'main') return;
    if (e.key === 'l' || e.key === 'L') { e.preventDefault(); lockNow(); }
    if ((e.key === 'b' || e.key === 'B') && !e.target.closest?.('textarea,input')) { e.preventDefault(); toggleSide(); }
    if (e.key === 'e' || e.key === 'E') { e.preventDefault(); togglePreview(); }
  });
  window.addEventListener('blur', () => { if (S.view === 'main') flush(); });

  /* Activity keeps the vault open; polling `status` and automatic sync never do. */
  let lastTouch = 0;
  function activity() {
    if (S.view !== 'main') return;
    const now = Date.now(); if (now - lastTouch < 5000) return; lastTouch = now;
    api('touch').catch(() => {});
  }
  ['keydown', 'pointerdown', 'input', 'wheel'].forEach((ev) => document.addEventListener(ev, activity, { passive: true }));

  /* Backend auto-lock (or lock elsewhere) -> clear the screen promptly. */
  setInterval(async () => {
    if (S.view !== 'main') return;
    try { const st = await api('status'); if (!st.unlocked) { wipe(); showUnlock('Locked after inactivity.'); } }
    catch (_) { /* transient */ }
  }, 3000);

  (async () => {
    try {
      await route();
    } catch (e) { clear($app); $app.append(h('div', { class: 'empty' }, window.CAN.native ? 'Could not start.' : 'Open the link printed by ctrlaltnotes-web (it contains a one-time access token).')); }
  })();
})();
