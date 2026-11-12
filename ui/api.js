/* SPDX-License-Identifier: AGPL-3.0-only */
/* Transport abstraction. The UI is identical in both hosts:
 *   - Native desktop app (Tauri):  invoke('rpc', {cmd, args})  -> Rust Service::dispatch
 *   - Web version:                  POST /api/<cmd> (Bearer launch token) -> Rust Service::dispatch
 * Neither transport can carry a file-system path: the host opens native dialogs itself. */
(function (root) {
  'use strict';
  const tauri = root.__TAURI__ && root.__TAURI__.core && root.__TAURI__.core.invoke;
  let token = '';
  if (!tauri) {
    token = location.hash.slice(1);
    history.replaceState(null, '', location.pathname + location.search); // token only in memory from here on
  }

  function fail(wire, status) {
    const e = new Error(String(wire));
    e.code = 'error'; e.retry = 0;
    if (wire === 'locked') e.code = 'locked';
    else if (wire === 'cancelled') e.code = 'cancelled';
    else if (/^throttled:\d+$/.test(wire)) { e.code = 'throttled'; e.retry = parseInt(wire.slice(10), 10); }
    e.status = status || 0;
    return e;
  }

  async function call(cmd, args) {
    args = args || {};
    if (tauri) {
      try { return await tauri('rpc', { cmd, args }); }
      catch (err) { throw fail(typeof err === 'string' ? err : 'internal error'); }
    }
    let r;
    try {
      r = await fetch('api/' + cmd, { method: 'POST', cache: 'no-store',
        headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
        body: JSON.stringify(args) });
    } catch (_) { throw fail('connection lost'); }
    let data = {}; try { data = await r.json(); } catch (_) { /* empty */ }
    if (!r.ok) throw fail(data.error || 'error', r.status);
    return data;
  }
  root.CAN = { call, native: !!tauri };
})(window);
