// 端末の部品の通しの試験：本物のサーバー（tests/serve.py）に、試験用のパスキーを持った「端末」を何台もつないで確かめる
//   node tests/test_e2e.mjs
// 登録・鍵の用意・ログイン・別の端末での同期・同時に直したとき・消したとき・送る前に閉じたとき・すり替え・復旧・パスキーの追加・
// 復旧キーの作り直し・ログアウト、最後にランダムな操作を重ねて全端末が同じ中身にそろうか（収束）を見る
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SoftAuthenticator, browserFetch } from './soft-authenticator.mjs';

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..');
globalThis.PKVCrypto = require('../static/pkvault/pkvault-crypto.js');
const PKVClient = require('../static/pkvault/pkvault-client.js');
const PKVStore = require('../static/pkvault/pkvault-store.js');

let passed = 0;
function check(cond, label) { if (!cond) { console.error('FAIL -', label); process.exitCode = 1; throw new Error(label); } passed++; console.log('ok -', label); }
async function rejects(p, re, label) { try { await p; } catch (e) { check(re.test(String(e.message || e.code)), `${label}（${e.message}）`); return; } check(false, label + '（失敗しなかった）'); }

// ---- サーバーを起動
const PORT = 18000 + Math.floor(Math.random() * 1000);
const py = path.join(ROOT, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
const srv = spawn(py, [path.join(HERE, 'serve.py'), String(PORT)], { stdio: ['ignore', 'pipe', 'pipe'] });
let dataDir = '';
await new Promise((res, rej) => {
  srv.stdout.on('data', d => { const m = String(d).match(/READY \d+ (\S+)/); if (m) { dataDir = m[1]; res(); } });
  srv.on('exit', c => rej(new Error('server exited ' + c)));
  setTimeout(() => rej(new Error('server timeout')), 20000);
});
const BASE = `http://localhost:${PORT}`;
let ipN = 1;
function device(authn, opts = {}) {
  const ip = `203.0.113.${ipN++}`;
  const f = browserFetch(BASE, opts);
  const fetchIp = (p, init = {}) => f(p, { ...init, headers: { ...(init.headers || {}), 'X-Test-IP': ip } });
  const client = PKVClient.create({ fetch: fetchIp, credentials: authn });
  return { client, authn, fetch: fetchIp };
}
const store = (d, o = {}) => PKVStore.create({ client: d.client, interval: 0, debounce: 5, ...o });
const sleep = ms => new Promise(r => setTimeout(r, ms));

try {
  // ------------------------------------------------------------ 登録と鍵の用意
  const keyA = new SoftAuthenticator({ origin: BASE });
  const A = device(keyA);
  let st = await A.client.state();
  check(st.ok === false && st.kit.prefix === 'test/v1', '最初はログインしていない・暗号のラベルの頭はサーバーの設定');
  const reg = await A.client.register('tester', { device: '試験の端末' });
  check(/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(reg.user_id), '登録するとユーザーIDが出る');
  check(A.client.vault.recoveryValid(reg.recovery_key), '登録すると復旧キーが出る（端末で作ったもの）');
  check(!!A.client.vault.session, '登録の直後からデータ鍵が使える');
  const vs = await A.client.get('/vault/state');
  check(vs.has_vault && vs.has_recovery && vs.wrap, 'サーバーには包みと復旧キーの照合の値だけが預けられた');

  // ------------------------------------------------------------ 記録の保存と暗号化
  const sA = store(A);
  await sA.load();
  const n1 = sA.newId();
  sA.put('note', n1, { title: '秘密のタイトル', body: '本文ひみつ', tags: ['a'] });
  await sA.flush();
  check(sA.pending === 0 && sA.rev === 1, '保存すると送られる（変更番号 1）');
  const raw = await A.client.get('/vault/sync?since=0');
  check(raw.records.length === 1 && !raw.records[0].blob.includes('秘密'), 'サーバーに届くのは暗号文だけ');
  const dbBytes = readFileSync(path.join(dataDir, 'pkvault.db'));
  check(!dbBytes.includes(Buffer.from('秘密のタイトル')) && !dbBytes.includes(Buffer.from('本文ひみつ')), 'サーバーの DB のファイルにも中身は残らない');

  // ------------------------------------------------------------ 別の端末（同期するパスキー）でログイン
  const B = device(keyA.shareWith(new SoftAuthenticator({ origin: BASE })));
  await B.client.state();
  await B.client.signIn();
  let v = await B.client.openVault();
  check(v.ok && !v.recovery_key, '別の端末：パスキーの PRF で包みを開けた');
  const sB = store(B);
  await sB.load();
  check(sB.get('note', n1)?.title === '秘密のタイトル', '別の端末でも同じ中身が読める');

  // ------------------------------------------------------------ 同時に直したとき
  sA.put('note', n1, { ...sA.get('note', n1), title: 'Aが直した題' });
  sB.put('note', n1, { ...sB.get('note', n1), body: 'Bが直した本文' });
  await sA.flush();
  await sB.flush();
  await sA.pull();
  check(JSON.stringify(sA.get('note', n1)) === JSON.stringify(sB.get('note', n1)), '違う項目を同時に直すと、両方の変更が残って同じ中身にそろう');
  check(sB.get('note', n1).title === 'Aが直した題' && sB.get('note', n1).body === 'Bが直した本文', '混ぜた結果が正しい');
  const notices = [];
  sB.on('notice', e => notices.push(e));
  sA.put('note', n1, { ...sA.get('note', n1), title: '同じ項目A' });
  sB.put('note', n1, { ...sB.get('note', n1), title: '同じ項目B' });
  await sA.flush();
  await sB.flush();
  await sA.pull();
  check(sB.get('note', n1).title === '同じ項目A' && sA.get('note', n1).title === '同じ項目A', '同じ項目を同時に直すと、先に保存したほうが残る');
  check(notices.some(n => n.type === 'conflict' && n.fields.includes('title') && n.mine.title === '同じ項目B'), '負けたほうには、自分の値を知らせる（写せるように）');

  // ------------------------------------------------------------ 消したのと直したのが重なったとき
  const n2 = sA.newId();
  sA.put('note', n2, { title: '消すメモ' });
  await sA.flush();
  await sB.pull();
  sA.remove('note', n2);
  sB.put('note', n2, { title: '消す前に直した' });
  await sA.flush();
  await sB.flush();
  check(sB.get('note', n2) === undefined && notices.some(n => n.type === 'deleted' && n.mine.title === '消す前に直した'), '消したほうを優先し、直した側には書いた中身を知らせる');
  // 逆の順：ほかの端末が先に直して送ったあとに、それを知らない端末が消す（栞で見つかった重なり方）
  const n3 = sA.newId();
  sA.put('note', n3, { title: '先に直される' });
  await sA.flush();
  await sB.pull();
  sB.put('note', n3, { title: 'Bが先に直して送った' });
  await sB.flush();
  sA.remove('note', n3);  // A は B の変更をまだ受け取っていない
  await sA.flush();
  await sA.pull();
  await sB.pull();
  const n3rec = (await A.client.get('/vault/sync?since=0')).records.find(r => r.id === n3);
  check(sA.get('note', n3) === undefined && sB.get('note', n3) === undefined && !n3rec,
    '先に直して送ったあとに古い端末で消しても、消したほうが残る（どちらの端末にも戻ってこない）');
  check(notices.some(n => n.type === 'deleted' && n.mine.title === 'Bが先に直して送った'), '直して送った側には、あとで消されたときに書いた中身を知らせる');
  // 受け取る前に、ほかの端末の変更がまだ送っていない自分の変更と重なったとき
  const sBs = store(B, { debounce: 100000 });  // 自動では送らない端末
  await sBs.load();
  sBs.put('note', n1, { ...sBs.get('note', n1), body: 'B送る前' });
  sA.put('note', n1, { ...sA.get('note', n1), title: 'A先に送った' });
  await sA.flush();
  await sBs.pull();
  check(sBs.get('note', n1).title === 'A先に送った' && sBs.get('note', n1).body === 'B送る前' && sBs.pending === 1, '受け取ったときも、送る前の自分の変更と混ぜる');
  await sBs.flush();
  await sA.pull();
  check(sA.get('note', n1).body === 'B送る前', '混ぜたものを送り、相手にも届く');

  // ------------------------------------------------------------ 送る前にページを閉じたとき
  const sA2 = store(A, { debounce: 100000 });
  await sA2.load();
  sA2.put('note', 'offline1', { title: '送る前に閉じた' });
  sA2.stop();
  await sleep(400);  // 控え（暗号文）への書き込みを待つ
  const cache = await A.client.vault.cacheGet(A.client.vault.session.uid);
  check(cache.pending.length === 1 && !JSON.stringify(cache).includes('送る前に閉じた'), '送っていない変更も、暗号化して端末に控える');
  const sA3 = store(A);
  await sA3.load();
  check(sA3.get('note', 'offline1')?.title === '送る前に閉じた' && sA3.pending === 0, '開き直すと、控えた変更を戻して送る');

  // ------------------------------------------------------------ サーバーが古い版を返したとき（すり替え）
  const C = device(keyA.shareWith(new SoftAuthenticator({ origin: BASE })), {
    tamper: async (p, init, r) => {
      if (!globalThis.__tamper || !p.startsWith('/api/vault/sync')) return r;
      const d = await r.json();
      d.records = d.records.map(x => ({ ...x, ver: 1 }));
      d.rev += 100;
      return new Response(JSON.stringify(d), { status: 200, headers: { 'Content-Type': 'application/json' } });
    },
  });
  await C.client.state();
  await C.client.signIn();
  await C.client.openVault();
  const sC = store(C);
  await sC.load();
  sA.put('note', n1, { ...sA.get('note', n1), title: 'すり替え前' });
  await sA.flush();
  globalThis.__tamper = true;
  await rejects(sC.pull(), /rollback/, '前に見た版より古い版を返されたら、受け付けずに止まる');
  globalThis.__tamper = false;

  // ------------------------------------------------------------ ログアウトと、端末に置いた鍵
  await C.client.logout();
  st = await C.client.state();
  check(st.ok === false && !C.client.vault.session, 'ログアウトすると、ログインも使える鍵もなくなる');
  check((await C.client.vault.cacheGet(1)) === undefined, 'ログアウトすると、端末の控えも消える');

  // ------------------------------------------------------------ 開き直し（アプリを開いたとき）
  const A2 = { ...A, client: PKVClient.create({ fetch: A.fetch, credentials: keyA, vault: A.client.vault }) };
  await A2.client.state();
  v = await A2.client.openVault();
  check(v.ok, '開き直したときは、端末に置いた鍵（端末鍵＋割符）で、パスキーを使わずに開ける');

  // ------------------------------------------------------------ パスキーを追加して、そのパスキーだけで別の端末から入る
  const keyNew = new SoftAuthenticator({ origin: BASE, synced: false });
  const A3 = { ...A, client: PKVClient.create({ fetch: A.fetch, credentials: keyNew, vault: A.client.vault }) };
  await A3.client.state();
  A3.client.onReauth = () => A.client.reauth();
  const added = await A3.client.addPasskey({ device: '2本目' });
  check(added.ok && !added.pending, '本人確認のあと、パスキーを追加して鍵を包んで預けた');
  const E = device(keyNew.shareWith(new SoftAuthenticator({ origin: BASE, synced: false })));
  await E.client.state();
  await E.client.signIn();
  v = await E.client.openVault();
  const sE = store(E);
  await sE.load();
  check(v.ok && sE.get('note', n1)?.title === 'すり替え前', '追加したパスキーだけで、別の端末から中身を開ける');

  // ------------------------------------------------------------ 復旧キーの作り直し
  A.client.onReauth = () => A.client.reauth();
  const regen = await A.client.regenRecovery();
  check(A.client.vault.recoveryValid(regen.recovery_key) && regen.recovery_key !== reg.recovery_key, '復旧キーを作り直した');

  // ------------------------------------------------------------ 復旧（パスキーをなくした端末）
  const D = device(new SoftAuthenticator({ origin: BASE }));
  await D.client.state();
  await rejects(D.client.recover(reg.user_id, reg.recovery_key), /違います/, '作り直す前の復旧キーは使えない');
  const rec = await D.client.recover(reg.user_id, regen.recovery_key);
  check(rec.scope === 'recovery', 'ユーザーID＋復旧キーで復旧モードに入る');
  await rejects(D.client.get('/vault/sync?since=0'), /recovery|先に/, '復旧モードでは、記録は読めない');
  const fin = await D.client.finishRecovery({ device: '復旧した端末' });
  check(A.client.vault.recoveryValid(fin.recovery_key) && fin.recovery_key !== regen.recovery_key, '新しいパスキーを登録すると、新しい復旧キーが出る');
  const sD = store(D);
  await sD.load();
  check(sD.get('note', n1)?.title === 'すり替え前', '復旧した端末で、前の中身がそのまま開ける');
  st = await A.client.state();
  check(st.ok === false, '復旧すると、ほかの端末はすべてログアウトされる');
  const D2 = device(new SoftAuthenticator({ origin: BASE }));
  await D2.client.state();
  await rejects(D2.client.recover(reg.user_id, regen.recovery_key), /違います/, '使った復旧キーは、もう使えない');

  // ------------------------------------------------------------ 収束：3台でランダムに直して、最後に全台がそろうか
  const devs = [D];
  for (let i = 0; i < 2; i++) {
    const d = device(D.authn.shareWith(new SoftAuthenticator({ origin: BASE })));
    await d.client.state();
    await d.client.signIn();
    await d.client.openVault();
    devs.push(d);
  }
  const stores = [];
  for (const d of devs) { const s = store(d, { debounce: 100000 }); await s.load(); stores.push(s); }
  const ids = ['f1', 'f2', 'f3', 'f4', 'f5'];
  let seed = Number(process.env.SEED || 12345);
  const rnd = n => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  for (let step = 0; step < 300; step++) {
    const s = stores[rnd(3)], id = ids[rnd(ids.length)], op = rnd(10);
    try {
      if (op < 5) s.put('note', id, { ...(s.get('note', id) || {}), ['k' + rnd(3)]: `v${step}` });
      else if (op < 6) s.remove('note', id);
      else if (op < 8) await s.flush();
      else await s.pull();
    } catch (e) { check(false, '途中の操作で失敗しない：' + e.message); }
  }
  for (let r = 0; r < 3; r++) for (const s of stores) { await s.flush(); await s.pull(); }
  const dump = s => JSON.stringify(ids.map(id => s.get('note', id) ?? null));
  check(stores.every(s => dump(s) === dump(stores[0]) && s.pending === 0), 'ランダムに300回操作しても、全端末が同じ中身にそろう');
  const fresh = store(devs[1]);
  devs[1].client.vault.cachePut(devs[1].client.vault.session.uid, null);
  await fresh.load();
  check(dump(fresh) === dump(stores[0]), 'サーバーから全部を受け取り直しても、同じ中身');

  // ------------------------------------------------------------ 退会
  const W = devs[2];
  W.client.onReauth = () => W.client.reauth();
  const wd = await W.client.withdraw();
  check(!!wd.delete_after && !W.client.vault.session, '退会すると、ログアウトして端末の鍵も消える');
  st = await devs[1].client.state();
  check(st.ok === false, '退会すると、ほかの端末もログアウトされる');
  const back = device(D.authn.shareWith(new SoftAuthenticator({ origin: BASE })));
  await back.client.state();
  const again = await back.client.signIn();
  check(again.withdraw_cancelled === true, '退会手続き中にパスキーでログインすると、退会は取り消される');

  console.log(`\n${passed} checks passed`);
} catch (e) {
  console.error(e);
  process.exitCode = 1;
} finally {
  srv.kill();
}
