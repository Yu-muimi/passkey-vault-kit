/* pkvault — 暗号の土台（端末の中だけで動く）
   鍵の整理（① パスキー ② ユーザーID ③ 復旧キー ④ データ鍵 ⑤ 包み ⑥ 端末鍵 ⑦ サーバーの割符）
   - ④ データ鍵：中身を暗号化・復号する唯一の鍵（AES-256-GCM）。読める形では保存しない
   - ⑤ 包み：④を、①の PRF から作った鍵か、③から作った鍵で暗号化したもの。サーバーに預ける
   - ③ 復旧キー：端末で作る。サーバーには「確認用の値」だけを送り、「包みを開ける値」は端末から出さない
   - ⑥ 端末鍵：この端末の中だけにある取り出せない鍵。⑦と二重にかけて、端末に④を置いておく
   すべて WebCrypto（ブラウザーの標準の暗号）で行い、自前の暗号は書かない。

   使い方：const vault = PKVCrypto.create({ prefix: 'memo/v1' })
     prefix … 暗号のラベルの頭（サーバーの Config.crypto_prefix と同じにする。あとから変えると、預けた暗号文が開けなくなる）
     dbName … 端末鍵などを置く IndexedDB の名前（標準は prefix の最初の部分＋'-vault'）
     kv     … 試験用：IndexedDB の代わりの入れ物 { get(k), put(k, v), del(k) } */
'use strict';

(function (root) {
  const ID_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const RECOVERY_LEN = 24;  // 32文字種×24文字 = 120ビット
  const PAD = 256;          // 暗号文の大きさから長さが分からないよう、256 バイト単位に切り上げる
  const VERSION = 1;

  /* ------------------------------------------------------------ 小さな道具（鍵に関係しない） */
  const b64u = bytes => {
    let s = '';
    const a = new Uint8Array(bytes);
    for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode(...a.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const unb64u = s => {
    if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('bad encoding');
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  };
  const hex = bytes => [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, '0')).join('');
  const random = n => globalThis.crypto.getRandomValues(new Uint8Array(n));
  const wipe = a => { if (a instanceof Uint8Array) a.fill(0); };

  /* IndexedDB の小さな入れ物（キー → 値）。CryptoKey も「取り出せない鍵」のまま入れられる */
  function idbKv(name) {
    function idb(mode, fn) {
      return new Promise((resolve, reject) => {
        const req = indexedDB.open(name, 1);
        req.onupgradeneeded = () => req.result.createObjectStore('kv');
        req.onerror = () => reject(req.error);
        req.onsuccess = () => {
          const db = req.result, tx = db.transaction('kv', mode), st = tx.objectStore('kv');
          let out;
          Promise.resolve(fn(st)).then(v => { out = v; }, reject);
          tx.oncomplete = () => { db.close(); resolve(out); };
          tx.onerror = () => { db.close(); reject(tx.error); };
        };
      });
    }
    const reqP = r => new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    return {
      get: k => idb('readonly', st => reqP(st.get(k))),
      put: (k, v) => idb('readwrite', st => reqP(st.put(v, k))),
      del: k => idb('readwrite', st => reqP(st.delete(k))),
    };
  }
  function memoryKv() {
    const m = new Map();
    return { get: async k => m.get(k), put: async (k, v) => { m.set(k, v); }, del: async k => { m.delete(k); } };
  }

  function create(opts = {}) {
    const prefix = opts.prefix || 'pkvault/v1';
    if (!/^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/.test(prefix)) throw new Error('prefix は英数字と . _ - / だけにしてください');
    const subtle = globalThis.crypto.subtle;
    const enc = new TextEncoder(), dec = new TextDecoder();
    const SALT = enc.encode(prefix);
    const kv = opts.kv || (typeof indexedDB !== 'undefined' ? idbKv(opts.dbName || `${prefix.split('/')[0]}-vault`) : memoryKv());

    // 鍵の材料（PRF の出力・復旧キー・割符）から、用途ごとに別の鍵を作る（HKDF-SHA256）。作った鍵は取り出せない
    async function derive(ikm, label, usages = ['encrypt', 'decrypt']) {
      const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey', 'deriveBits']);
      return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: SALT, info: enc.encode(label) }, base, { name: 'AES-GCM', length: 256 }, false, usages);
    }
    async function deriveBits(ikm, label) {
      const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
      return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: SALT, info: enc.encode(label) }, base, 256));
    }

    // 暗号化：版(1バイト)＋ノンス(12バイト・毎回新しい乱数)＋暗号文。aad（何の・誰の・どの版か）も封に入れる
    async function seal(key, bytes, aad) {
      const iv = random(12);
      const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, bytes));
      const out = new Uint8Array(1 + 12 + ct.length);
      out[0] = VERSION;
      out.set(iv, 1);
      out.set(ct, 13);
      return b64u(out);
    }
    // 復号：形・版・封（aad）のどれかが違えば失敗する（取り替え・改ざんは、ここで見つかる）
    async function open(key, blob, aad) {
      const a = unb64u(blob);
      if (a.length < 1 + 12 + 16 || a[0] !== VERSION) throw new Error('bad blob');
      return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: a.subarray(1, 13), additionalData: enc.encode(aad) }, key, a.subarray(13)));
    }

    /* ---------------------------------------------------------- ④ データ鍵 */
    const newDataKeyRaw = () => random(32);
    const importDataKey = raw => subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

    /* ---------------------------------------------------------- ① パスキー（PRF） */
    // PRF に渡す値：サイトで1つの決まった値（秘密ではない。出力はパスキーごとの秘密から作られる）
    let prfSaltCache = null;
    async function prfSalt() {
      prfSaltCache = prfSaltCache || new Uint8Array(await subtle.digest('SHA-256', enc.encode(`${prefix}/prf`)));
      return prfSaltCache;
    }
    const passkeyAad = (uid, credId) => `${prefix}/wrap/passkey|${uid}|${credId}`;
    const wrapForPasskey = async (raw, prfOut, uid, credId) => seal(await derive(prfOut, 'wrap/passkey'), raw, passkeyAad(uid, credId));
    const unwrapWithPasskey = async (blob, prfOut, uid, credId) => open(await derive(prfOut, 'wrap/passkey'), blob, passkeyAad(uid, credId));

    /* ---------------------------------------------------------- ③ 復旧キー */
    function newRecoveryKey() {
      // 32文字種から偏りなく選ぶ（256 は 32 で割り切れるので、余りで選んでも偏らない）
      const r = random(RECOVERY_LEN);
      const s = [...r].map(x => ID_ALPHABET[x % 32]).join('');
      wipe(r);
      return s.match(/.{4}/g).join('-');
    }
    const normRecovery = s => (typeof s === 'string' ? s.toUpperCase().replace(/[^A-Z0-9]/g, '') : '');
    const recoveryValid = s => new RegExp(`^[${ID_ALPHABET}]{${RECOVERY_LEN}}$`).test(normRecovery(s));
    const recoveryAad = uid => `${prefix}/wrap/recovery|${uid}`;
    // サーバーに送る確認用の値（ここから復旧キーや「開ける値」は計算できない）
    const recoveryAuth = async key => hex(await deriveBits(enc.encode(normRecovery(key)), 'recovery/auth'));
    const wrapForRecovery = async (raw, key, uid) => seal(await derive(enc.encode(normRecovery(key)), 'recovery/wrap'), raw, recoveryAad(uid));
    const unwrapWithRecovery = async (blob, key, uid) => open(await derive(enc.encode(normRecovery(key)), 'recovery/wrap'), blob, recoveryAad(uid));

    /* ---------------------------------------------------------- ⑥ 端末鍵 ＋ ⑦ サーバーの割符 */
    async function deviceKey(uid) {
      let k = await kv.get(`device:${uid}`);
      if (!k) {
        k = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        await kv.put(`device:${uid}`, k);
      }
      return k;
    }
    const localAad = (uid, deviceId, layer) => `${prefix}/local/${layer}|${uid}|${deviceId}`;
    // 端末に④を置く：端末鍵⑥と割符⑦の二重にかける。割符はサーバーがログイン中の端末にだけ渡す
    async function storeLocal(raw, uid, deviceId, share) {
      const inner = await seal(await deviceKey(uid), raw, localAad(uid, deviceId, 'device'));
      const outer = await seal(await derive(share, 'local/share'), enc.encode(inner), localAad(uid, deviceId, 'share'));
      await kv.put(`dek:${uid}`, { deviceId, blob: outer });
    }
    async function loadLocal(uid, share) {
      const rec = await kv.get(`dek:${uid}`);
      if (!rec) return null;
      const inner = dec.decode(await open(await derive(share, 'local/share'), rec.blob, localAad(uid, rec.deviceId, 'share')));
      return open(await deviceKey(uid), inner, localAad(uid, rec.deviceId, 'device'));
    }
    // ログアウト・退会のとき：端末の控えと端末鍵を消す（割符がなくても開けないが、残さない）
    async function forget(uid) { await kv.del(`dek:${uid}`); await kv.del(`device:${uid}`); await kv.del(`cache:${uid}`); session = null; }
    // 暗号文の控え（サーバーから受け取った暗号文のまま）。入れ物が使えなければ控えない
    const cacheGet = async uid => { try { return await kv.get(`cache:${uid}`); } catch { return null; } };
    const cachePut = async (uid, v) => { try { await kv.put(`cache:${uid}`, v); } catch { /* 控えられなくても動く */ } };

    /* ---------------------------------------------------------- 1件ずつの暗号化 */
    const recordAad = (uid, kind, id, ver) => `${prefix}/rec|${uid}|${kind}|${id}|${ver}`;
    async function sealRecord(dataKey, obj, uid, kind, id, ver) {
      const body = enc.encode(JSON.stringify(obj));
      const size = Math.ceil((body.length + 4) / PAD) * PAD;  // 先頭4バイトに本当の長さ、残りは0で埋める
      const buf = new Uint8Array(size);
      new DataView(buf.buffer).setUint32(0, body.length);
      buf.set(body, 4);
      return seal(dataKey, buf, recordAad(uid, kind, id, ver));
    }
    async function openRecord(dataKey, blob, uid, kind, id, ver) {
      const buf = await open(dataKey, blob, recordAad(uid, kind, id, ver));
      const n = new DataView(buf.buffer, buf.byteOffset).getUint32(0);
      if (n > buf.length - 4) throw new Error('bad record');
      return JSON.parse(dec.decode(buf.subarray(4, 4 + n)));
    }

    /* ---------------------------------------------------------- 使える状態のデータ鍵（このページの中だけ） */
    // 記録の番号に使う鍵（名前など、中身から決まる番号をサーバーに読めない形にする HMAC）
    async function idKeyOf(raw) {
      const base = await subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
      return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: SALT, info: enc.encode('record/id') }, base,
        { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']);
    }
    let session = null;  // { uid, dataKey, idKey }。どちらの鍵も取り出せない形
    async function activate(raw, uid) { session = { uid, dataKey: await importDataKey(raw), idKey: await idKeyOf(raw) }; }
    function need() { if (!session) throw new Error('locked'); return session; }
    async function recordId(text) {
      const mac = new Uint8Array(await subtle.sign('HMAC', need().idKey, enc.encode(text)));
      return b64u(mac.subarray(0, 16));
    }
    const seal1 = (kind, id, ver, obj) => sealRecord(need().dataKey, obj, need().uid, kind, id, ver);
    const open1 = (kind, id, ver, blob) => openRecord(need().dataKey, blob, need().uid, kind, id, ver);
    // 操作の記録の説明（題名など）：本人の画面でだけ開ける
    const sealAct = text => seal1('act', '0', 0, { t: String(text || '') });
    async function openAct(blob) { try { return (await open1('act', '0', 0, blob)).t; } catch { return null; } }

    return {
      prefix,
      activate, recordId, sealAct, openAct, seal: seal1, open: open1,
      get session() { return session; },
      lock() { session = null; },
      b64u, unb64u, hex, random, wipe, prfSalt,
      newDataKeyRaw, importDataKey,
      wrapForPasskey, unwrapWithPasskey,
      newRecoveryKey, normRecovery, recoveryValid, recoveryAuth, wrapForRecovery, unwrapWithRecovery,
      storeLocal, loadLocal, forget, cacheGet, cachePut,
      sealRecord, openRecord,
    };
  }

  const api = { create, memoryKv, b64u, unb64u };
  root.PKVCrypto = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
