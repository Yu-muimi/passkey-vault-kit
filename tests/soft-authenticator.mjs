// 試験用：ブラウザーのパスキー（navigator.credentials）の代わり。WebCrypto で ES256 の鍵を作り、本物と同じ形の答えを返す。
// PRF（パスキーから鍵の材料を作る機能）も返す（パスキーごとの秘密と、渡された値から決まる値）。
// synced=true なら「同期するパスキー」（同じ鍵を、ほかの端末の試験でも使い回せる）
const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();

// ---- 最小の CBOR（整数・バイト列・文字列・マップだけ）
function cborHead(major, n) {
  if (n < 24) return [major << 5 | n];
  if (n < 256) return [major << 5 | 24, n];
  if (n < 65536) return [major << 5 | 25, n >> 8, n & 255];
  return [major << 5 | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
}
function cbor(v) {
  if (typeof v === 'number') return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  if (v instanceof Uint8Array) return [...cborHead(2, v.length), ...v];
  if (typeof v === 'string') { const b = te.encode(v); return [...cborHead(3, b.length), ...b]; }
  if (v instanceof Map) {
    const out = cborHead(5, v.size);
    for (const [k, x] of v) out.push(...cbor(k), ...cbor(x));
    return out;
  }
  throw new Error('cbor: unsupported');
}
const bytes = a => new Uint8Array(a);
const cat = (...xs) => { const n = xs.reduce((s, x) => s + x.length, 0), out = new Uint8Array(n); let i = 0; for (const x of xs) { out.set(x, i); i += x.length; } return out; };
const sha256 = async b => bytes(await subtle.digest('SHA-256', b));
const toB64u = x => { const a = x instanceof Uint8Array ? x : new Uint8Array(x); let s = ''; for (const c of a) s += String.fromCharCode(c); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const u2b = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
const ab = u8 => u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);

// WebCrypto の署名（r||s の 64 バイト）を、WebAuthn が使う DER の形にする
function der(sig) {
  const int = b => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.subarray(i); return b[0] & 0x80 ? cat(bytes([0]), b) : b; };
  const r = int(sig.subarray(0, 32)), s = int(sig.subarray(32));
  return cat(bytes([0x30, r.length + s.length + 4, 0x02, r.length]), r, bytes([0x02, s.length]), s);
}

export class SoftAuthenticator {
  constructor({ origin, synced = true, securityKey = false, prf = true } = {}) {
    this.origin = origin;
    this.synced = synced;
    this.sk = securityKey;
    this.prf = prf;
    this.creds = new Map();  // id(b64u) → { key, rp, handle, count, secret, rawId }
  }

  async create({ publicKey: o }) {
    const key = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const raw = bytes(await subtle.exportKey('raw', key.publicKey));  // 0x04 | x | y
    const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, raw.subarray(1, 33)], [-3, raw.subarray(33, 65)]]);
    const rawId = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const rp = o.rp.id;
    for (const c of o.excludeCredentials || []) if (this.creds.has(toB64u(c.id))) { const e = new Error('exists'); e.name = 'InvalidStateError'; throw e; }
    const flags = 0x45 | (this.synced && !this.sk ? 0x18 : 0);  // UP・UV・AT（同期するなら BE・BS）
    const auth = cat(await sha256(te.encode(rp)), bytes([flags, 0, 0, 0, 0]), new Uint8Array(16),
      bytes([0, rawId.length]), rawId, bytes(cbor(cose)));
    const cd = te.encode(JSON.stringify({ type: 'webauthn.create', challenge: toB64u(o.challenge), origin: this.origin }));
    const id = toB64u(rawId);
    const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
    this.creds.set(id, { key, rp, handle: bytes(o.user.id), count: 0, secret, rawId });
    const ext = this.prf && o.extensions?.prf ? { prf: { enabled: true } } : {};
    return {
      id, rawId: ab(rawId), type: 'public-key', authenticatorAttachment: this.sk ? 'cross-platform' : 'platform',
      getClientExtensionResults: () => ext,
      response: { clientDataJSON: ab(cd), attestationObject: ab(bytes(cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', auth]])))),
        getTransports: () => (this.sk ? ['usb', 'nfc'] : ['internal', 'hybrid']) },
    };
  }

  async get({ publicKey: o }) {
    const allow = (o.allowCredentials || []).map(c => toB64u(c.id));
    const id = allow.length ? allow.find(x => this.creds.has(x)) : [...this.creds.keys()][0];
    if (!id) { const e = new Error('no credential'); e.name = 'NotAllowedError'; throw e; }
    const c = this.creds.get(id);
    c.count += this.synced ? 0 : 1;  // 同期するパスキーは回数を数えない（0 のまま）
    const auth = cat(await sha256(te.encode(c.rp)), bytes([0x05 | (this.synced && !this.sk ? 0x18 : 0), c.count >>> 24, (c.count >> 16) & 255, (c.count >> 8) & 255, c.count & 255]));
    const challenge = o.challenge instanceof Uint8Array || o.challenge instanceof ArrayBuffer ? toB64u(o.challenge) : o.challenge;
    const cd = te.encode(JSON.stringify({ type: 'webauthn.get', challenge, origin: this.origin }));
    const sig = der(bytes(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, c.key.privateKey, cat(auth, await sha256(cd)))));
    let ext = {};
    if (this.prf && o.extensions?.prf?.eval?.first) {
      const k = await subtle.importKey('raw', c.secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      ext = { prf: { results: { first: await subtle.sign('HMAC', k, bytes(o.extensions.prf.eval.first)) } } };
    }
    return {
      id, rawId: ab(c.rawId), type: 'public-key', authenticatorAttachment: 'platform',
      getClientExtensionResults: () => ext,
      response: { clientDataJSON: ab(cd), authenticatorData: ab(auth), signature: ab(sig), userHandle: ab(c.handle) },
    };
  }

  // 同期するパスキー：同じパスキーを、ほかの端末（別のクッキー）からも使えるようにする
  shareWith(other) { other.creds = this.creds; return other; }
}

// 端末ごとのクッキー入れ（試験の「端末」1台ぶん）
export function browserFetch(base, { tamper } = {}) {
  const jar = new Map();
  return async (path, init = {}) => {
    const headers = { ...(init.headers || {}) };
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    let r = await fetch(base + path, { ...init, headers, redirect: 'manual' });
    for (const line of r.headers.getSetCookie()) {
      const [kv, ...attrs] = line.split(';');
      const i = kv.indexOf('='), name = kv.slice(0, i).trim(), val = kv.slice(i + 1).trim();
      const expired = attrs.some(a => /^\s*expires=/i.test(a) && new Date(a.split('=')[1]) < new Date()) || attrs.some(a => /^\s*max-age=0/i.test(a));
      if (!val || expired) jar.delete(name); else jar.set(name, val);
    }
    if (tamper) r = await tamper(path, init, r);
    return r;
  };
}
export { u2b, toB64u };
