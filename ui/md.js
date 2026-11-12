/* SPDX-License-Identifier: AGPL-3.0-only */
/* Minimal, XSS-safe Markdown renderer.
 * Builds DOM nodes with createElement/textContent ONLY. There is no HTML-string injection, no raw HTML
 * pass-through, no remote images (tracking), and links are limited to http(s)/mailto. */
(function (root) {
  'use strict';
  const el = (tag, text) => { const e = document.createElement(tag); if (text != null) e.textContent = text; return e; };

  function safeHref(u) {
    try {
      const url = new URL(u.trim());
      if (!['http:', 'https:', 'mailto:'].includes(url.protocol)) return null;
      // a mailto: link may carry ?cc=&bcc=&body= that silently addresses/pre-fills a message:
      // keep only the recipient
      if (url.protocol === 'mailto:') { url.search = ''; url.hash = ''; }
      return url.href;
    } catch (_) { return null; }
  }

  const INLINE = /(`+)([\s\S]*?[^`])\1(?!`)|(!?)\[([^\]]*)\]\(([^)\s]*)(?:\s+"[^"]*")?\)|\*\*([\s\S]+?)\*\*|(?<![A-Za-z0-9_])__(?=\S)([\s\S]+?)(?<=\S)__(?![A-Za-z0-9_])|~~([\s\S]+?)~~|\*([^*\s][^*]*?)\*|(?<![A-Za-z0-9_])_(?=[^\s_])([^_]*?)(?<=[^\s_])_(?![A-Za-z0-9_])|\+\+(?=\S)([\s\S]+?)(?<=\S)\+\+|==(?=\S)([\s\S]+?)(?<=\S)==/;

  // Work limits: the inline regex is super-linear on adversarial input (e.g. a long run of
  // backticks), so text is processed in bounded pieces and a render has an overall budget.
  const CHUNK = 2000, MAX_SRC = 500000, MAX_BQ_DEPTH = 8, MAX_LINE = 4000;
  let budget = 0;

  function inline(parent, s, depth) {
    depth = depth || 0;
    if (depth === 0 && s.length > CHUNK) {
      while (s.length > CHUNK) {
        let cut = s.lastIndexOf(' ', CHUNK); if (cut < CHUNK / 2) cut = CHUNK;
        inline(parent, s.slice(0, cut), 0); s = s.slice(cut);
      }
    }
    while (s.length) {
      const m = (depth < 6 && budget-- > 0) ? INLINE.exec(s) : null;
      if (!m) { parent.appendChild(document.createTextNode(s)); return; }
      if (m.index) parent.appendChild(document.createTextNode(s.slice(0, m.index)));
      if (m[1]) parent.appendChild(el('code', m[2].trim()));
      else if (m[5] !== undefined) {
        const href = safeHref(m[5]);
        const label = m[4] || m[5];
        if (m[3] === '!') {                       // images are never loaded; show as a link
          const a = el('a'); a.append(document.createTextNode('[image: ' + label + ']'));
          if (href) { a.href = href; a.rel = 'noopener noreferrer'; a.target = '_blank'; }
          parent.appendChild(a);
        } else if (href) {
          const a = el('a'); a.href = href; a.rel = 'noopener noreferrer'; a.target = '_blank'; a.title = href;
          inline(a, label, depth + 1); parent.appendChild(a);
        } else { parent.appendChild(document.createTextNode(m[0])); }
      } else {
        const body = m[6] ?? m[7] ?? m[8] ?? m[9] ?? m[10] ?? m[11] ?? m[12];
        const tag = (m[6] !== undefined || m[7] !== undefined) ? 'strong' : m[8] !== undefined ? 'del'
          : m[11] !== undefined ? 'u' : m[12] !== undefined ? 'mark' : 'em';
        const e = el(tag); inline(e, body, depth + 1); parent.appendChild(e);
      }
      s = s.slice(m.index + m[0].length);
    }
  }

  function trimHeading(t) {              // strip an optional closing run of #, without a regex
    t = t.trimEnd(); let j = t.length;
    while (j > 0 && t[j - 1] === '#') j--;
    if (j < t.length && (j === 0 || t[j - 1] === ' ' || t[j - 1] === '\t')) t = t.slice(0, j).trimEnd();
    return t;
  }

  function render(src, qd) {
    qd = qd || 0;
    if (qd === 0) budget = 20000;
    const frag = document.createDocumentFragment();
    src = String(src);
    let cut = false;
    if (src.length > MAX_SRC) { src = src.slice(0, MAX_SRC); cut = true; }
    const lines = [];
    for (const l of src.replace(/\r\n?/g, '\n').split('\n')) {     // bound every line
      if (l.length <= MAX_LINE) lines.push(l);
      else for (let k = 0; k < l.length; k += MAX_LINE) lines.push(l.slice(k, k + MAX_LINE));
    }
    let i = 0;
    const isBlank = (l) => /^\s*$/.test(l);
    const cells = (l) => l.trim().replace(/^\|/, '').replace(/\|$/, '').split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, '|'));
    const isSep = (l) => /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/.test(l) && l.includes('-');
    const startsBlock = (l) => /^(#{1,6}\s|```|>\s?|\s*([-*+]|\d+[.)])\s|\s*([-*_])(\s*\3){2,}\s*$)/.test(l);
    while (i < lines.length) {
      const line = lines[i];
      if (isBlank(line)) { i++; continue; }
      let m;
      if ((m = /^```+\s*([\w-]*)\s*$/.exec(line))) {
        const buf = []; i++;
        while (i < lines.length && !/^```+\s*$/.test(lines[i])) buf.push(lines[i++]);
        i++;
        const pre = el('pre'); pre.appendChild(el('code', buf.join('\n'))); frag.appendChild(pre); continue;
      }
      if ((m = /^(#{1,6})\s+(.*)$/.exec(line))) {
        const h = el('h' + m[1].length); inline(h, trimHeading(m[2])); frag.appendChild(h); i++; continue;
      }
      if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { frag.appendChild(el('hr')); i++; continue; }
      if (line.includes('|') && i + 1 < lines.length && isSep(lines[i + 1]) && cells(line).length === cells(lines[i + 1]).length && cells(line).length <= 100) {
        const aligns = cells(lines[i + 1]).map((c) => (/^:-+:$/.test(c) ? 'c' : /^-+:$/.test(c) ? 'r' : /^:-+$/.test(c) ? 'l' : ''));
        const table = el('table'), thead = el('thead'), tbody = el('tbody');
        const row = (src, tag, parent) => { const tr = el('tr'); cells(src).forEach((c, k) => { const cell = el(tag); if (aligns[k]) cell.className = 'al-' + aligns[k]; inline(cell, c); tr.appendChild(cell); }); parent.appendChild(tr); };
        row(line, 'th', thead); i += 2;
        while (i < lines.length && !isBlank(lines[i]) && lines[i].includes('|')) row(lines[i++], 'td', tbody);
        table.appendChild(thead); table.appendChild(tbody); frag.appendChild(table); continue;
      }
      if (qd < MAX_BQ_DEPTH && /^>\s?/.test(line)) {
        const buf = [];
        while (i < lines.length && /^>\s?/.test(lines[i])) buf.push(lines[i++].replace(/^>\s?/, ''));
        const bq = el('blockquote'); bq.appendChild(render(buf.join('\n'), qd + 1)); frag.appendChild(bq); continue;
      }
      if ((m = /^(\s*)([-*+]|\d+[.)])\s+/.exec(line))) {
        const ordered = /\d/.test(m[2]);
        const list = el(ordered ? 'ol' : 'ul');
        while (i < lines.length && (m = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/.exec(lines[i])) && /\d/.test(m[2]) === ordered) {
          const li = el('li'); let t = m[3]; const task = /^\[([ xX])\]\s+(.*)$/.exec(t);
          if (task) { const cb = el('input'); cb.type = 'checkbox'; cb.disabled = true; cb.checked = task[1] !== ' '; li.appendChild(cb); t = task[2]; }
          inline(li, t); list.appendChild(li); i++;
        }
        frag.appendChild(list); continue;
      }
      const buf = [];
      while (i < lines.length && !isBlank(lines[i]) && (buf.length === 0 || !startsBlock(lines[i]))) buf.push(lines[i++]);
      const p = el('p'); inline(p, buf.join('\n')); frag.appendChild(p);
    }
    if (cut) frag.appendChild(el('p', '[preview shortened: the note is very long]'));
    return frag;
  }
  root.renderMarkdown = render;
  root.safeHref = safeHref;
})(window);
