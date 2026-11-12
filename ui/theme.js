/* SPDX-License-Identifier: AGPL-3.0-only */
/* Applies the saved colour theme before the first paint (no light/dark flash on start).
 * This is only a cache for speed: the backend's `status.theme` is the source of truth and
 * app.js re-applies it. External file because the CSP forbids inline script. */
(function () {
  'use strict';
  var t = 'dark';
  try { t = localStorage.getItem('can.theme') || 'dark'; } catch (_) { /* storage unavailable */ }
  if (t !== 'dark' && t !== 'light' && t !== 'system') t = 'dark';
  document.documentElement.setAttribute('data-theme', t);
})();
