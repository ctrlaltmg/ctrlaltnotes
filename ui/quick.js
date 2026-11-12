/* SPDX-License-Identifier: AGPL-3.0-only */
/* Unlock with a hardware security key or a platform authenticator (fingerprint / Face / Windows
 * Hello) using the WebAuthn "PRF" extension (CTAP2 hmac-secret). The authenticator derives a
 * 32-byte secret that only it can produce, after user verification. The backend wraps the vault
 * key under it; the secret itself is never stored anywhere. */
(function (root) {
  'use strict';
  const enc = (buf) => { let s = ''; const b = new Uint8Array(buf); for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  const dec = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const r = atob(s); const b = new Uint8Array(r.length); for (let i = 0; i < r.length; i++) b[i] = r.charCodeAt(i); return b; };
  const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

  function supported() {
    return !!(root.PublicKeyCredential && navigator.credentials && root.isSecureContext && root.crypto && crypto.getRandomValues);
  }
  function explain(e) {
    if (e && e.name === 'NotAllowedError') return 'Cancelled, timed out, or not allowed by this window.';
    if (e && e.name === 'NotSupportedError') return 'This authenticator or window does not support it.';
    if (e && e.name === 'SecurityError') return 'This window cannot use security keys here.';
    return (e && e.message) || 'Security key unlock failed.';
  }

  async function getSecret(info) {
    if (info.rp_id !== location.hostname) throw new Error('This unlock method was set up in a different app/address.');
    let cred;
    try {
      cred = await navigator.credentials.get({ publicKey: {
        challenge: rand(32), rpId: info.rp_id, timeout: 60000, userVerification: 'required',
        allowCredentials: [{ type: 'public-key', id: dec(info.cred_id) }],
        extensions: { prf: { eval: { first: dec(info.salt) } } } } });
    } catch (e) { throw new Error(explain(e)); }
    const ext = cred && cred.getClientExtensionResults();
    const first = ext && ext.prf && ext.prf.results && ext.prf.results.first;
    if (!first || first.byteLength !== 32) throw new Error('This authenticator did not return a secret (PRF not supported).');
    return enc(first);
  }

  /* Create a credential and derive its secret. Returns what the backend needs. */
  async function enroll() {
    const salt = rand(32);
    let cred;
    try {
      cred = await navigator.credentials.create({ publicKey: {
        rp: { id: location.hostname, name: 'CtrlAltNotes' },
        user: { id: rand(16), name: 'ctrlaltnotes', displayName: 'CtrlAltNotes' },
        challenge: rand(32), timeout: 60000, attestation: 'none',
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { userVerification: 'required', residentKey: 'discouraged' },
        extensions: { prf: { eval: { first: salt } } } } });
    } catch (e) { throw new Error(explain(e)); }
    const ext = cred.getClientExtensionResults();
    if (!ext.prf || !ext.prf.enabled) throw new Error('This authenticator or browser does not support the PRF extension needed for unlocking.');
    const info = { cred_id: enc(cred.rawId), salt: enc(salt), rp_id: location.hostname };
    const first = ext.prf.results && ext.prf.results.first;
    info.secret = (first && first.byteLength === 32) ? enc(first) : await getSecret(info); // some keys only answer on get()
    return info;
  }

  root.CANQuick = { supported, enroll, getSecret };
})(window);
