/* pkvault — 端末の部品：サーバーとのやりとり・パスキー（PRF）・データ鍵を開く／包む・復旧・本人確認・アカウントの操作
   画面は持たない（画面は pkvault-ui.js か、アプリが自分で作る）。先に pkvault-crypto.js を読み込む。

   使い方：
     const pkv = PKVClient.create({ api: '/api', header: 'X-PKV' });
     const st = await pkv.state();                 // ログインしているか（暗号のラベルの頭もサーバーから受け取る）
     if (st.ok) { const v = await pkv.openVault(); if (!v.ok) await pkv.unlock(); }
     else { await pkv.signIn(); await pkv.openVault(); }
     // ここから pkv.vault（PKVCrypto）で暗号化・復号できる。記録の同期は pkvault-store.js */
'use strict';

(function (root) {
  const Crypto = root.PKVCrypto || (typeof require !== 'undefined' ? require('./pkvault-crypto.js') : null);

  /* ------------------------------------------------------------ 利用者に見せる文 */
  const TEXT = {
    prfUnsupported: 'この端末（ブラウザ）は、データの暗号化に必要な機能に対応していないため使えません。新しい OS やブラウザ、またはほかの端末でお試しください。',
    noWrap: 'このパスキーには、まだデータの鍵が登録されていません。鍵を登録したパスキーでログインしてください。',
    cannotOpen: 'データの鍵を開けませんでした。ログインし直してください。',
    noLocalKey: 'この端末にデータの鍵がありません。ログインし直してから、もう一度お試しください',
    needRecoveryKey: '復旧キーがないと、データの鍵を開けません',
    wrongRecovery: 'ユーザーIDか復旧キーが違います',
    cancelled: 'キャンセルされたか、時間切れになりました',
    exists: 'この端末にはすでにこのアカウントのパスキーがあります',
    failed: 'パスキーを使えませんでした',
    network: '通信できませんでした。つながっているか確かめてください',
    server: 'うまくいきませんでした。少し待ってからもう一度お試しください',
  };
  function userError(message) { const e = new Error(message); e.user = true; return e; }

  /* ------------------------------------------------------------ WebAuthn の JSON とバイナリの変換 */
  const b2u = buf => Crypto.b64u(new Uint8Array(buf));
  const u2b = s => Crypto.unb64u(s);
  function toCreateOptions(o) {
    return { ...o, challenge: u2b(o.challenge), user: { ...o.user, id: u2b(o.user.id) },
      excludeCredentials: (o.excludeCredentials || []).map(c => ({ ...c, id: u2b(c.id) })) };
  }
  function toGetOptions(o, hint) {
    const out = { ...o, challenge: u2b(o.challenge), allowCredentials: (o.allowCredentials || []).map(c => ({ ...c, id: u2b(c.id) })) };
    if (hint) out.hints = [hint];  // 'hybrid' なら最初から QR コードを出す（対応ブラウザ）
    return out;
  }
  function credToJSON(c) {
    const r = c.response;
    const out = { id: c.id, rawId: b2u(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment || undefined,
      clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
      response: { clientDataJSON: b2u(r.clientDataJSON) } };
    // PRF の出力は秘密（データ鍵の包みを開ける材料）。サーバーには絶対に送らない
    if (out.clientExtensionResults && out.clientExtensionResults.prf) {
      out.clientExtensionResults = { ...out.clientExtensionResults };
      delete out.clientExtensionResults.prf;
    }
    if (r.attestationObject) {
      out.response.attestationObject = b2u(r.attestationObject);
      out.response.transports = r.getTransports ? r.getTransports() : [];
    } else {
      out.response.authenticatorData = b2u(r.authenticatorData);
      out.response.signature = b2u(r.signature);
      if (r.userHandle) out.response.userHandle = b2u(r.userHandle);
    }
    return out;
  }
  const prfOutput = cred => { const r = cred?.getClientExtensionResults?.().prf; return r?.results?.first ? new Uint8Array(r.results.first) : null; };
  const prfEnabled = cred => { const r = cred?.getClientExtensionResults?.().prf; return !!(r && (r.enabled === true || r.results?.first)); };

  function create(opts = {}) {
    const API = opts.api || '/api';
    const HEADER = opts.header || 'X-PKV';
    const doFetch = opts.fetch || ((...a) => globalThis.fetch(...a));
    const creds = opts.credentials || (typeof navigator !== 'undefined' ? navigator.credentials : null);
    // 試験だけ：パスキーの代わりに決まった PRF の出力を使う（本番では渡さない）
    const testPrf = opts.testPrf || null;
    let vault = opts.vault || null;
    let auth = null;          // 最後に受け取った /auth の答え
    let recoveryMem = null;   // 復旧モードで入力した復旧キー（このページの中だけ。新しい鍵を預けたら消す）
    let lastPrf = null;       // 直前のパスキー操作で得た PRF の出力（{ out, credId }）。鍵を開いたらすぐ消す

    /* ---------------------------------------------------------- サーバーとのやりとり */
    // サーバーが混み合っている（503）ときは、少し待って3回まで送り直す（503 のときサーバーは何も書いていない）
    async function request(method, path, body) {
      let r;
      for (let i = 0; ; i++) {
        try {
          r = await doFetch(API + path, { method, cache: 'no-store', credentials: 'same-origin',
            headers: { [HEADER]: '1', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
            body: body !== undefined ? JSON.stringify(body) : undefined });
        } catch { throw userError(TEXT.network); }
        if (r.status !== 503 || i >= 3) break;
        await new Promise(res => setTimeout(res, [400, 1000, 2000][i] + Math.random() * 300));
      }
      const d = await r.json().catch(() => ({}));
      if (!r.ok) {
        const msg = typeof d.error === 'string' ? d.error : '';
        const e = new Error(d.message || msg || 'http ' + r.status);
        e.status = r.status;
        e.data = d;
        e.code = /^[a-z_]+$/.test(msg) ? msg : '';     // reauth・recovery・unauthorized など（英字の印）
        e.user = /[^\x00-\x7f]/.test(e.message);       // サーバーが利用者に向けて書いた日本語の文は、そのまま見せる
        throw e;
      }
      return d;
    }
    const get = p => request('GET', p);

    async function state() {
      auth = await get('/auth');
      if (!vault) vault = Crypto.create({ prefix: auth.kit?.prefix, ...(opts.cryptoOptions || {}) });
      return auth;
    }
    const ensureVault = async () => { if (!vault) await state(); return vault; };
    const supported = () => !!(testPrf || (typeof window !== 'undefined' && window.PublicKeyCredential && creds && window.isSecureContext));

    /* ---------------------------------------------------------- パスキー */
    async function prfExtension() { return { prf: { eval: { first: await (await ensureVault()).prfSalt() } } }; }
    // パスキーで PRF の出力だけを得る（サーバーには送らない。鍵を開く・包むためだけ）
    async function prfFromPasskey(credId, hint) {
      if (testPrf) return { out: testPrf, credId };
      const publicKey = { challenge: vault.random(32), userVerification: 'required', extensions: await prfExtension(),
        allowCredentials: credId ? [{ type: 'public-key', id: vault.unb64u(credId) }] : [] };
      if (hint) publicKey.hints = [hint];
      const cred = await creds.get({ publicKey });
      const out = prfOutput(cred);
      if (!out) throw userError(TEXT.prfUnsupported);
      return { out, credId: cred.id };
    }
    // ログイン（すでにログインしているときは「本人確認」になる）
    async function signIn(hint) {
      await ensureVault();
      const o = await request('POST', '/auth/passkey/options');
      const publicKey = toGetOptions(o, hint);
      publicKey.extensions = { ...(publicKey.extensions || {}), ...(await prfExtension()) };
      const cred = await creds.get({ publicKey });
      const out = testPrf || prfOutput(cred);
      const r = await request('POST', '/auth/passkey/verify', { credential: credToJSON(cred) });
      lastPrf = out ? { out, credId: cred.id } : null;
      return r;
    }
    // パスキーを作る。PRF に対応していないパスキー・端末では、登録の前に止める（アカウントやパスキーを作らない）
    async function passkeyCreate(optionsPath, body, finishPath, extra = {}) {
      await ensureVault();
      const o = await request('POST', optionsPath, body);
      const publicKey = toCreateOptions(o);
      if (!testPrf) publicKey.extensions = { ...(publicKey.extensions || {}), ...(await prfExtension()) };
      const cred = await creds.create({ publicKey });
      if (!testPrf && !prfEnabled(cred)) throw userError(TEXT.prfUnsupported);
      const r = await request('POST', finishPath, { ...extra, credential: credToJSON(cred) });
      return { ...r, cred_id: r.cred_id || cred.id, prf: testPrf || prfOutput(cred) };
    }
    // 作ったばかりのパスキーの PRF の出力（作るときに返さない端末では、もう一度パスキーを使ってもらう）
    const prfOfNew = async r => (r.prf ? { out: r.prf, credId: r.cred_id } : prfFromPasskey(r.cred_id));

    /* ---------------------------------------------------------- データ鍵 */
    const vaultState = () => get('/vault/state');
    async function localDataKeyRaw(st) {
      st = st || await vaultState();
      if (!st.device) return null;
      try { return await vault.loadLocal(st.user, vault.unb64u(st.device.share)); } catch { return null; }
    }
    // 初めての鍵の用意：データ鍵と復旧キーを端末で作り、パスキーと復旧キーで包んで預ける。復旧キーを返す（画面に1回だけ出す）
    async function vaultSetup(st, prf) {
      const raw = vault.newDataKeyRaw(), rk = vault.newRecoveryKey();
      try {
        await request('POST', '/vault/setup', { cred_id: st.cred_id, passkey_wrap: await vault.wrapForPasskey(raw, prf, st.user, st.cred_id),
          recovery_wrap: await vault.wrapForRecovery(raw, rk, st.user), recovery_auth: await vault.recoveryAuth(rk) });
        await vault.storeLocal(raw, st.user, st.device.id, vault.unb64u(st.device.share));
        await vault.activate(raw, st.user);
      } finally { vault.wipe(raw); }
      return rk;
    }
    /* ログインのあと、またはアプリを開いたとき：データ鍵をこの端末で使えるようにする。
       返す値：{ ok: true } / { ok: true, recovery_key }（初めて用意したとき） / { ok: false }（パスキーでの確認が要る → unlock） */
    async function openVault(prf) {
      await ensureVault();
      const st = await vaultState();
      prf = prf || lastPrf || (testPrf ? { out: testPrf, credId: st.cred_id } : null);
      lastPrf = null;
      if (!st.has_vault) {
        if (!prf) return { ok: false };
        return { ok: true, recovery_key: await vaultSetup(st, prf.out) };
      }
      const local = await localDataKeyRaw(st);
      if (local) {
        // この端末にはもう鍵がある。今のパスキーに包みがなければ、ついでに包んで預ける
        if (prf && !st.wrap && st.cred_id && prf.credId === st.cred_id) {
          await request('PUT', '/vault/passkey', { cred_id: st.cred_id, blob: await vault.wrapForPasskey(local, prf.out, st.user, st.cred_id) }).catch(() => {});
        }
        await vault.activate(local, st.user);
        vault.wipe(local);
        return { ok: true };
      }
      if (!prf) return { ok: false };
      if (!st.wrap) throw userError(TEXT.noWrap);
      let raw;
      try { raw = await vault.unwrapWithPasskey(st.wrap, prf.out, st.user, st.cred_id); } catch { throw userError(TEXT.cannotOpen); }
      try {
        await vault.storeLocal(raw, st.user, st.device.id, vault.unb64u(st.device.share));
        await vault.activate(raw, st.user);
      } finally { vault.wipe(raw); }
      return { ok: true };
    }
    // ログインはしているが、この端末に鍵がないとき（端末の控えを消した・割符が変わった）：このログインのパスキーで開く
    async function unlock(hint) {
      const st = await vaultState();
      return openVault(await prfFromPasskey(st.cred_id || undefined, hint));
    }
    // データ鍵を、このパスキーでも包んで預ける（この端末に鍵があるときだけ）
    async function wrapForCredential(credId, prf) {
      const st = await vaultState();
      const raw = await localDataKeyRaw(st);
      if (!raw) throw userError(TEXT.noLocalKey);
      try { await request('PUT', '/vault/passkey', { cred_id: credId, blob: await vault.wrapForPasskey(raw, prf, st.user, credId) }); }
      finally { vault.wipe(raw); }
    }
    // 一覧で「鍵がない」パスキー（物理キーの1本目など）に、鍵を包んで預ける
    async function registerVaultKey(credId) { await wrapForCredential(credId, (await prfFromPasskey(credId)).out); }

    /* ---------------------------------------------------------- 登録・ログアウト */
    // 新規登録：パスキーを作り、そのまま鍵を用意する。{ user_id, recovery_key } を返す（両方を本人に控えてもらう）
    async function register(name, { hint, device, agree, extra } = {}) {
      const r = await passkeyCreate('/auth/register/options', { name, hint, agree, ...(extra || {}) }, '/auth/register/finish', { device });
      const prf = await prfOfNew(r);
      const v = await openVault(prf);
      return { user_id: r.user_id, recovery_key: v.recovery_key, user: r.user };
    }
    async function logout() {
      try { const st = await vaultState(); await vault.forget(st.user); } catch { /* 消せなくても、割符がないので開けない */ }
      vault?.lock();
      await request('POST', '/auth/logout');
    }

    /* ---------------------------------------------------------- 作業証明・復旧 */
    // サーバーが出した課題に対して、SHA-256 の先頭 bits ビットが 0 になる数を探す。正規の利用者は1回だけなので1〜数秒
    async function solvePow(onProgress) {
      const { token, bits } = await get('/auth/pow');
      const te = new TextEncoder();
      const ok = d => {
        let need = bits;
        for (let i = 0; need > 0; i++) {
          if (need >= 8) { if (d[i] !== 0) return false; need -= 8; } else return (d[i] >> (8 - need)) === 0;
        }
        return true;
      };
      for (let base = 0; ; base += 512) {
        const batch = await Promise.all(Array.from({ length: 512 }, (_, i) => globalThis.crypto.subtle.digest('SHA-256', te.encode(`${token}:${base + i}`))));
        const hit = batch.findIndex(d => ok(new Uint8Array(d)));
        if (hit >= 0) return { pow_token: token, pow_nonce: String(base + hit) };
        if (base % 8192 === 0) onProgress?.();
      }
    }
    // ユーザーID＋復旧キーで「復旧モード」に入る（このあと finishRecovery で新しいパスキーを登録する）
    async function recover(userId, key, onProgress) {
      await ensureVault();
      const proof = await solvePow(onProgress);
      if (!vault.recoveryValid(key)) throw userError(TEXT.wrongRecovery);
      const r = await request('POST', '/auth/recover', { user_id: userId, auth: await vault.recoveryAuth(key), ...proof });
      recoveryMem = key;
      return r;
    }
    /* 復旧モードで：新しいパスキーを作り、復旧キーで開いたデータ鍵をそのパスキーと新しい復旧キーで包み直す。
       askKey …… ページを読み直したなどで復旧キーを覚えていないとき、入力してもらう関数（文字列か null を返す）
       返す値：{ user_id, recovery_key }（新しい復旧キー。画面に1回だけ出す） */
    async function finishRecovery({ hint, device, askKey } = {}) {
      await ensureVault();
      const w = await get('/vault/recovery-wrap');
      let raw = null;
      if (w.wrap) {  // まだ鍵を用意していないアカウントなら、パスキーの登録のあとで用意する
        for (;;) {
          const key = recoveryMem || (askKey ? await askKey() : null);
          if (key === null || key === undefined) throw userError(TEXT.needRecoveryKey);
          try { raw = await vault.unwrapWithRecovery(w.wrap, key, w.user); break; } catch { recoveryMem = null; if (!askKey) throw userError(TEXT.wrongRecovery); }
        }
      }
      try {
        const r = await passkeyCreate('/account/passkeys/options', { hint }, '/account/passkeys', { device });
        const prf = (await prfOfNew(r)).out;
        const st = await vaultState();
        let rk;
        if (raw) {
          // 使った復旧キーはサーバーでもう使えなくなっている。新しいパスキーと、新しい復旧キー（端末で作る）で包み直す
          await request('PUT', '/vault/passkey', { cred_id: r.cred_id, blob: await vault.wrapForPasskey(raw, prf, st.user, r.cred_id) });
          rk = vault.newRecoveryKey();
          await request('PUT', '/vault/recovery', { auth: await vault.recoveryAuth(rk), blob: await vault.wrapForRecovery(raw, rk, st.user) });
          await vault.storeLocal(raw, st.user, st.device.id, vault.unb64u(st.device.share));
          await vault.activate(raw, st.user);
        } else {
          rk = await vaultSetup(st, prf);
        }
        recoveryMem = null;
        return { user_id: r.user_id, recovery_key: rk, cred_id: r.cred_id };
      } finally { if (raw) vault.wipe(raw); }
    }
    function cancelRecovery() { recoveryMem = null; return request('POST', '/auth/logout'); }

    /* ---------------------------------------------------------- 本人確認が要る操作 */
    // 重要な操作は、直近の本人確認が要る（403 reauth）。onReauth（画面で「パスキーで確認」を出す関数）を呼んで、やり直す
    let onReauth = opts.onReauth || (() => signIn());
    async function withReauth(fn) {
      try { return await fn(); } catch (e) {
        if (e.code !== 'reauth') throw e;
        await onReauth();
        lastPrf = null;
        return fn();
      }
    }
    async function addPasskey({ hint, device } = {}) {
      return withReauth(async () => {
        const r = await passkeyCreate('/account/passkeys/options', { hint }, '/account/passkeys', { device });
        if (!r.pending) await wrapForCredential(r.cred_id, (await prfOfNew(r)).out);
        return r;  // r.pending … 物理キーの1本目（続けて2本目を登録する）。r.activated … 2本目で使えるようになった1本目
      });
    }
    async function regenRecovery() {
      return withReauth(async () => {
        const st = await vaultState();
        const raw = await localDataKeyRaw(st);
        if (!raw) throw userError(TEXT.noLocalKey);
        try {
          const rk = vault.newRecoveryKey();
          const r = await request('POST', '/account/recovery', { auth: await vault.recoveryAuth(rk), blob: await vault.wrapForRecovery(raw, rk, st.user) });
          return { user_id: r.user_id, recovery_key: rk };
        } finally { vault.wipe(raw); }
      });
    }
    async function withdraw() {
      const r = await withReauth(() => request('POST', '/account/withdraw', { confirm: 'delete', agree: true }));
      try { await vault.forget((await vaultState()).user); } catch { /* ログアウト済み */ }
      vault?.lock();
      return r;
    }

    /* ---------------------------------------------------------- パスキーの失敗の文 */
    function errorText(e, fallback = TEXT.server) {
      if (e?.name === 'NotAllowedError') return TEXT.cancelled;
      if (e?.name === 'InvalidStateError') return TEXT.exists;
      if (e?.name === 'AbortError') return '';
      if (e?.user) return e.message;
      if (e?.name && /Error$/.test(e.name) && e.name !== 'Error') return TEXT.failed;  // ブラウザーの英語の文は出さない
      return fallback;
    }

    return {
      get vault() { return vault; }, get auth() { return auth; },
      set onReauth(fn) { onReauth = fn; },
      request, get, state, supported,
      signIn, register, logout, openVault, unlock, registerVaultKey, prfFromPasskey,
      recover, finishRecovery, cancelRecovery, get inRecovery() { return auth?.scope === 'recovery'; },
      withReauth, reauth: hint => signIn(hint).then(() => { lastPrf = null; }),
      addPasskey, regenRecovery, withdraw,
      account: () => get('/account'),
      recoveryView: () => get('/account/recovery-view'),
      log: () => get('/account/log'),
      rename: name => request('PUT', '/account/name', { name }),
      setSessionDays: days => withReauth(() => request('PUT', '/account/session', { days })),
      renamePasskey: (id, name) => request('PUT', `/account/passkeys/${encodeURIComponent(id)}`, { name }),
      deletePasskey: id => withReauth(() => request('DELETE', `/account/passkeys/${encodeURIComponent(id)}`)),
      deleteSecurityKeys: () => withReauth(() => request('DELETE', '/account/security-keys')),
      devices: () => get('/account/devices'),
      logoutDevice: id => request('DELETE', `/account/devices/${encodeURIComponent(id)}`),
      logoutAll: () => request('POST', '/account/logout-all'),
      agreeTerms: () => request('POST', '/account/terms', { agree: true }),
      errorText, userError, TEXT,
    };
  }

  const api = { create, toCreateOptions, toGetOptions, credToJSON };
  root.PKVClient = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
