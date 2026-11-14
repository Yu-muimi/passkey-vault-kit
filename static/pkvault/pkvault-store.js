/* pkvault — 暗号化した記録の同期（端末の部品）
   アプリのデータを「種類／番号 → 中身（JSON にできるオブジェクト）」の記録として持ち、1件ずつ端末で暗号化してサーバーと同期する。
   サーバーには暗号文だけが届く。読める形は、このページのメモリの中だけ（端末の控えも暗号文のまま）。

   使い方（データ鍵を開いたあとで）：
     const store = PKVStore.create({ client: pkv });
     await store.load();                          // 控え（暗号文）＋サーバーの差分から作る
     store.put('note', store.newId(), { title: 'はじめて', body: '…' });  // 少し待ってまとめて送る（flush）
     store.list('note')                           // → [{ id, data }]
     store.on('change', e => draw());             // ほかの端末の変更を受け取ったとき（60秒おき・画面に戻ったとき）

   同時に直したとき（重なり）：項目ごとに、自分だけが変えた項目は自分の値、相手だけが変えた項目は相手の値。
   両方が違う値に変えた項目は、相手の値を残す（onConflict で決め方を変えられる）。消したほうを優先する。
   サーバーが前の状態に戻った（すり替えられた）ときは、前に見た版より古い版を受け付けずに止まる。 */
'use strict';

(function (root) {
  const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
  const KIND_RE = /^[a-z][a-z0-9_]{0,31}$/;
  const PUSH_MAX = 500;

  const same = (x, y) => JSON.stringify(x ?? null) === JSON.stringify(y ?? null);
  // 3者の突き合わせ（元・自分・相手）。オブジェクトでなければ、まるごと相手の値
  function mergeFields(base, mine, theirs) {
    const fields = [];
    if (!mine || !theirs || typeof mine !== 'object' || typeof theirs !== 'object' || Array.isArray(mine) || Array.isArray(theirs)) {
      return { merged: theirs, fields: same(mine, theirs) ? [] : ['*'] };
    }
    const out = {}, keys = new Set([...Object.keys(mine), ...Object.keys(theirs)]);
    for (const k of keys) {
      const bv = base ? base[k] : undefined, mv = mine[k], tv = theirs[k];
      let v;
      if (same(mv, bv)) v = tv;
      else if (same(tv, bv) || same(mv, tv)) v = mv;
      else { v = tv; fields.push(k); }
      if (v !== undefined) out[k] = v;
    }
    return { merged: out, fields };
  }

  function create(opts = {}) {
    const client = opts.client;
    if (!client) throw new Error('client（PKVClient）を渡してください');
    const interval = opts.interval ?? 60000;
    const debounce = opts.debounce ?? 400;
    const onConflict = opts.onConflict || null;  // ({ kind, id, base, mine, theirs, merged, fields }) → 残す中身
    const V = () => { const v = client.vault; if (!v?.session) throw new Error('locked'); return v; };
    const uid = () => V().session.uid;

    let items = new Map();  // 今の中身：種類/番号 → 中身
    let base = new Map();   // 最後に同期した状態：種類/番号 → { ver, json }
    let enc = new Map();    // 同じ状態の暗号文（端末の控えに書く）：種類/番号 → { kind, id, ver, blob }
    let dirty = new Set();  // まだ送っていない変更（送れたら消す。送れないあいだは控えにも暗号化して残す）
    const wrote = new Set();  // このページで書いて送った記録（ほかの端末で消されたときに知らせる）
    let rev = 0, loaded = false;
    const listeners = {};
    const emit = (type, detail) => (listeners[type] || []).forEach(fn => { try { fn(detail); } catch (e) { console.error(e); } });
    const key = (kind, id) => `${kind}/${id}`;
    const split = k => { const i = k.indexOf('/'); return [k.slice(0, i), k.slice(i + 1)]; };
    const check = (kind, id) => {
      if (!loaded) throw new Error('先に load() してください');
      if (!KIND_RE.test(kind) || !ID_RE.test(String(id))) throw new Error('bad kind or id');
    };

    // 一度にひとつずつ（読み込み・送る・受け取るが重ならないように）
    let queue = Promise.resolve();
    const serial = fn => { const p = queue.then(fn); queue = p.catch(() => {}); return p; };

    /* ---------------------------------------------------------- 端末の控え（暗号文のまま） */
    let saving = null;
    function saveCache() {
      if (saving) return;
      saving = setTimeout(() => { saving = null; writeCache().catch(() => {}); }, 300);
    }
    async function writeCache() {
      const v = V(), pending = [];
      // まだ送っていない変更も、暗号化して控えておく（送る前にページを閉じても失わない）
      for (const k of dirty) {
        const [kind, id] = split(k);
        pending.push(items.has(k) ? { kind, id, blob: await v.seal(kind, id, 'pending', items.get(k)) } : { kind, id, deleted: true });
      }
      await v.cachePut(uid(), { rev, records: [...enc.values()], pending });
    }

    /* ---------------------------------------------------------- 読み込み */
    function load() { return serial(loadNow); }
    async function loadNow() {
      const v = V();
      let cached = await v.cacheGet(uid());
      let r = await client.get(`/vault/sync?since=${cached?.rev || 0}`), recs, list;
      // サーバーの変更番号が控えより前に戻っている（サーバーを前の状態に戻した）なら、控えは使わずに全部を受け取り直す
      if (cached && r.rev < cached.rev) { cached = null; r = await client.get('/vault/sync?since=0'); }
      for (let tries = 0; ; tries++) {
        if (cached && !r.full) {
          const m = new Map(cached.records.map(x => [key(x.kind, x.id), x]));
          for (const x of r.records) {
            const k = key(x.kind, x.id), old = m.get(k);
            if (old && x.ver < old.ver) throw new Error('rollback');  // 前に見た版より古い版は受け付けない（すり替えを防ぐ）
            if (x.deleted) m.delete(k); else m.set(k, x);
          }
          recs = [...m.values()];
        } else recs = r.records;
        try {
          list = [];
          for (const x of recs) list.push({ ...x, data: await v.open(x.kind, x.id, x.ver, x.blob) });
          break;
        } catch (e) {
          // 控えが今の鍵で開けない（ほかのアカウントや前の鍵の控え）：控えを捨てて、全部を受け取り直す。それでも開けなければ止める
          if (!cached || tries) throw e;
          cached = null;
          r = await client.get('/vault/sync?since=0');
        }
      }
      enc = new Map(recs.map(x => [key(x.kind, x.id), { kind: x.kind, id: x.id, ver: x.ver, blob: x.blob }]));
      base = new Map(list.map(x => [key(x.kind, x.id), { ver: x.ver, json: JSON.stringify(x.data) }]));
      items = new Map(list.map(x => [key(x.kind, x.id), x.data]));
      dirty = new Set();
      // 送る前に閉じた変更を戻す（開けないものは捨てる）
      for (const p of cached?.pending || []) {
        const k = key(p.kind, p.id);
        try {
          if (p.deleted) items.delete(k); else items.set(k, await v.open(p.kind, p.id, 'pending', p.blob));
          dirty.add(k);
        } catch { /* 前の鍵の控え */ }
      }
      rev = r.rev;
      loaded = true;
      saveCache();
      if (dirty.size) await flushNow();
      emit('change', { keys: [...items.keys()], remote: true, loaded: true });
    }

    /* ---------------------------------------------------------- 読む・書く（すぐに返る。送るのは少しあと） */
    const clone = x => (x === undefined ? undefined : JSON.parse(JSON.stringify(x)));
    function get(kind, id) { return clone(items.get(key(kind, id))); }
    function list(kind) {
      const out = [];
      for (const [k, data] of items) { const [kd, id] = split(k); if (kd === kind) out.push({ id, data: clone(data) }); }
      return out;
    }
    let timer = null;
    function schedule() { clearTimeout(timer); timer = setTimeout(() => flush().catch(e => emit('error', e)), debounce); }
    function put(kind, id, data) {
      check(kind, id);
      if (data === undefined || data === null) throw new Error('data が空です');
      items.set(key(kind, id), clone(data));
      dirty.add(key(kind, id));
      saveCache();
      schedule();
      emit('change', { keys: [key(kind, id)], remote: false });
    }
    function remove(kind, id) {
      check(kind, id);
      if (!items.has(key(kind, id))) return;
      items.delete(key(kind, id));
      dirty.add(key(kind, id));
      saveCache();
      schedule();
      emit('change', { keys: [key(kind, id)], remote: false });
    }
    const newId = () => client.vault.b64u(client.vault.random(16));  // 推測できない番号（128ビット）
    const idFor = text => V().recordId(text);                            // 中身から決まる番号（サーバーには読めない形）

    /* ---------------------------------------------------------- 送る（変わった記録だけ・1件ずつ暗号化） */
    const acts = [];
    // 操作の記録（サーバーの Config.acts にある種類だけ）。説明は暗号化して、本人の画面でだけ開ける
    function act(event, detail) { acts.push({ event, detail }); schedule(); }
    function flush() { clearTimeout(timer); return serial(flushNow); }
    async function flushNow() {
      if (!loaded) return;
      const v = V();
      for (let round = 0; round < 4; round++) {
        const changes = [];
        for (const k of dirty) {
          const b = base.get(k), now = items.has(k) ? JSON.stringify(items.get(k)) : null;
          if (now !== null && (!b || b.json !== now)) changes.push({ k, json: now, base: b ? b.ver : 0 });
          else if (now === null && b && b.json !== null) changes.push({ k, deleted: true, base: b.ver });
          else dirty.delete(k);  // 結局、同期した状態と同じ（戻した・作ってすぐ消した）
        }
        const sealedActs = [];
        for (const a of acts.splice(0)) sealedActs.push({ event: a.event, detail: a.detail ? await v.sealAct(a.detail) : '' });
        if (!changes.length && !sealedActs.length) { saveCache(); return; }
        const conflicts = [];
        for (let i = 0; i < Math.max(changes.length, 1); i += PUSH_MAX) {
          const part = changes.slice(i, i + PUSH_MAX), payload = [];
          for (const c of part) {
            const [kind, id] = split(c.k);
            payload.push(c.deleted ? { kind, id, base: c.base, deleted: true } : { kind, id, base: c.base, blob: await v.seal(kind, id, c.base + 1, JSON.parse(c.json)) });
          }
          const r = await client.request('POST', '/vault/push', { changes: payload, acts: i === 0 ? sealedActs : [] });
          for (const a of r.applied) {
            const k = key(a.kind, a.id), c = part.find(x => x.k === k), sent = payload.find(x => x.kind === a.kind && x.id === a.id);
            base.set(k, { ver: a.ver, json: c.deleted ? null : c.json });
            if (c.deleted) enc.delete(k); else enc.set(k, { kind: a.kind, id: a.id, ver: a.ver, blob: sent.blob });
            if (!c.deleted) wrote.add(k);  // この端末で書いて送った記録（あとでほかの端末で消されたら、書いた中身を知らせるため）
            // 送ったあとにまた直していなければ、送り終わり
            const now = items.has(k) ? JSON.stringify(items.get(k)) : null;
            if (now === (c.deleted ? null : c.json)) dirty.delete(k);
          }
          // 足したものが自分の変更 rev+1… と連続しているときだけ、受け取り済みの番号を進める
          // （あいだにほかの端末の変更が挟まっていたら進めずにおき、次の受け取りでまとめて受け取る）
          const mine = r.applied.map(a => a.rev).sort((x, y) => x - y);
          if (r.rev === rev + mine.length && mine.every((x, j) => x === rev + 1 + j)) rev = r.rev;
          conflicts.push(...r.conflicts);
        }
        saveCache();
        if (!conflicts.length) { emit('saved', {}); return; }
        await resolve(conflicts);
      }
      throw new Error('同期を終えられませんでした');
    }
    // 重なった記録を、サーバーの今の版と突き合わせる。直した結果は、次の回でその版を元にして送る
    async function resolve(conflicts) {
      const v = V(), changed = [];
      for (const c of conflicts) {
        const k = key(c.kind, c.id);
        const b = base.get(k), bdata = b?.json ? JSON.parse(b.json) : null;
        const theirs = c.deleted || !c.blob ? null : await v.open(c.kind, c.id, c.ver, c.blob);
        base.set(k, { ver: c.ver, json: theirs ? JSON.stringify(theirs) : null });
        if (theirs) enc.set(k, { kind: c.kind, id: c.id, ver: c.ver, blob: c.blob }); else enc.delete(k);
        const mine = items.has(k) ? items.get(k) : null;
        if (!theirs) {  // ほかの端末で消していた：消したほうを優先する。自分の中身は知らせて、写せるようにする
          if (mine) { items.delete(k); emit('notice', { type: 'deleted', kind: c.kind, id: c.id, mine: clone(mine) }); changed.push(k); }
          dirty.delete(k);
          continue;
        }
        if (!mine) continue;  // こちらで消した：消したほうを優先（次の回で、今の版に対して消す。dirty に残っている）
        let { merged, fields } = mergeFields(bdata, mine, theirs);
        if (onConflict && fields.length) merged = (await onConflict({ kind: c.kind, id: c.id, base: clone(bdata), mine: clone(mine), theirs: clone(theirs), merged: clone(merged), fields })) ?? merged;
        else if (fields.length) emit('notice', { type: 'conflict', kind: c.kind, id: c.id, fields, mine: clone(mine), theirs: clone(theirs) });
        items.set(k, merged);
        changed.push(k);
      }
      if (changed.length) emit('change', { keys: changed, remote: true });
    }

    /* ---------------------------------------------------------- 受け取る（ほかの端末の変更） */
    function pull() { return serial(pullNow); }
    async function pullNow() {
      if (!loaded || !client.vault?.session) return false;
      const v = V();
      const r = await client.get(`/vault/sync?since=${rev}`);
      if (r.full || r.rev < rev) { await loadNow(); return true; }  // 古すぎる・サーバーが前の状態に戻ったときは、全部を受け取り直す
      for (const x of r.records) { const old = base.get(key(x.kind, x.id)); if (old && x.ver < old.ver) throw new Error('rollback'); }
      if (!r.records.length) { rev = r.rev; return false; }
      const opened = [];
      for (const x of r.records) opened.push({ ...x, data: x.deleted ? null : await v.open(x.kind, x.id, x.ver, x.blob) });
      const changed = [];
      for (const x of opened) {
        const k = key(x.kind, x.id), old = base.get(k);
        if (old && old.ver >= x.ver) continue;  // 自分が送った版（受け取り済み）
        const bdata = old?.json ? JSON.parse(old.json) : null;
        base.set(k, { ver: x.ver, json: x.data ? JSON.stringify(x.data) : null });
        if (x.data) enc.set(k, { kind: x.kind, id: x.id, ver: x.ver, blob: x.blob }); else enc.delete(k);
        if (dirty.has(k)) {
          // まだ送っていない自分の変更がある：消したほうを優先、それ以外は項目ごとに混ぜる（送るのは次の flush）
          const mine = items.has(k) ? items.get(k) : null;
          if (!x.data) { if (mine) emit('notice', { type: 'deleted', kind: x.kind, id: x.id, mine: clone(mine) }); items.delete(k); dirty.delete(k); }
          else if (mine) {
            let { merged, fields } = mergeFields(bdata, mine, x.data);
            if (onConflict && fields.length) merged = (await onConflict({ kind: x.kind, id: x.id, base: clone(bdata), mine: clone(mine), theirs: clone(x.data), merged: clone(merged), fields })) ?? merged;
            else if (fields.length) emit('notice', { type: 'conflict', kind: x.kind, id: x.id, fields, mine: clone(mine), theirs: clone(x.data) });
            items.set(k, merged);
          }
        } else if (x.data) items.set(k, x.data);
        else {
          // この端末で書いて送った記録が、あとでほかの端末で消された：消したほうを優先し、書いた中身は知らせる（写せるように）
          if (wrote.has(k) && items.has(k)) emit('notice', { type: 'deleted', kind: x.kind, id: x.id, mine: clone(items.get(k)) });
          items.delete(k);
        }
        changed.push(k);
      }
      rev = r.rev;
      saveCache();
      if (dirty.size) schedule();
      if (changed.length) emit('change', { keys: changed, remote: true });
      return changed.length > 0;
    }

    // 画面が見えているあいだは決まった間隔で、画面に戻ったときはすぐに、ほかの端末の変更を確かめる。隠れるときは送っておく
    let ticker = null;
    const tick = () => { if (typeof document === 'undefined' || document.visibilityState === 'visible') pull().catch(e => emit('error', e)); };
    const onVis = () => { if (document.visibilityState === 'hidden') flush().catch(() => {}); else tick(); };
    function start() {
      if (ticker || typeof window === 'undefined') return;
      if (interval) ticker = setInterval(tick, interval);
      document.addEventListener('visibilitychange', onVis);
      window.addEventListener('focus', tick);
    }
    function stop() {
      clearInterval(ticker);
      ticker = null;
      if (typeof window !== 'undefined') { document.removeEventListener('visibilitychange', onVis); window.removeEventListener('focus', tick); }
    }
    // ログアウトの前に：送り終えてから止める
    async function close() { stop(); try { await flush(); } catch { /* 送れなかった分は、控え（暗号文）に残る */ } await writeCache().catch(() => {}); }

    return {
      load, get, list, put, remove, newId, idFor, act, flush, pull, start, stop, close,
      on(type, fn) { (listeners[type] = listeners[type] || []).push(fn); return () => { listeners[type] = listeners[type].filter(f => f !== fn); }; },
      get rev() { return rev; },
      get pending() { return dirty.size; },
      get size() { return items.size; },
    };
  }

  const api = { create, mergeFields };
  root.PKVStore = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
