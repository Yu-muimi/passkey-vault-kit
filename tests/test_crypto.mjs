// 暗号の部品の試験：改ざん・取り替えの検出、長さを隠す切り上げ、復旧キーの形、端末鍵＋割符、
// そして栞（shiori）の vault.js と互いに開けるか（ラベルの頭を 'shiori/v1' にしたとき。栞を部品に移す日のため）
//   node tests/test_crypto.mjs          （栞の vault.js の場所を SHIORI_VAULT に入れたときだけ、互換も確かめる）
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const K = require('../static/pkvault/pkvault-crypto.js');
let passed = 0;
const check = (c, l) => { if (!c) { console.error('FAIL -', l); process.exit(1); } passed++; console.log('ok -', l); };
const fails = async p => { try { await p; return false; } catch { return true; } };

const v = K.create({ prefix: 'test/v1', kv: K.memoryKv() });
const raw = v.newDataKeyRaw();
await v.activate(raw, 7);
const dk = v.session.dataKey;
const b = await v.sealRecord(dk, { t: 'あ' }, 7, 'note', 'x', 1);
check((await v.openRecord(dk, b, 7, 'note', 'x', 1)).t === 'あ', '暗号化して開ける');
check(await fails(v.openRecord(dk, b, 8, 'note', 'x', 1)), 'ほかの人の記録としては開けない');
check(await fails(v.openRecord(dk, b, 7, 'note', 'y', 1)), 'ほかの番号の記録としては開けない（取り替えの検出）');
check(await fails(v.openRecord(dk, b, 7, 'note', 'x', 2)), 'ほかの版としては開けない');
const t = K.unb64u(b); t[20] ^= 1;
check(await fails(v.openRecord(dk, K.b64u(t), 7, 'note', 'x', 1)), '1ビットの改ざんでも開けない');
const short = await v.sealRecord(dk, { t: 'a' }, 7, 'n', '1', 1), long = await v.sealRecord(dk, { t: 'a'.repeat(200) }, 7, 'n', '1', 1);
check(short.length === long.length, '長さの近い中身は、同じ大きさの暗号文になる（長さを隠す）');
check(b !== await v.sealRecord(dk, { t: 'あ' }, 7, 'note', 'x', 1), '同じ中身でも毎回ちがう暗号文');
const w = K.create({ prefix: 'other/v1', kv: K.memoryKv() });
await w.activate(raw, 7);
check(await fails(w.openRecord(w.session.dataKey, b, 7, 'note', 'x', 1)), 'ラベルの頭がちがうアプリでは、同じ鍵でも開けない');
const rk = v.newRecoveryKey();
check(v.recoveryValid(rk) && v.recoveryValid(rk.toLowerCase().replace(/-/g, ' ')) && !v.recoveryValid('ABCD'), '復旧キーの形（小文字・区切りなしでも通る）');
const rw = await v.wrapForRecovery(raw, rk, 7);
check(K.b64u(await v.unwrapWithRecovery(rw, rk, 7)) === K.b64u(raw) && await fails(v.unwrapWithRecovery(rw, v.newRecoveryKey(), 7)), '復旧キーで包んで開ける・違うキーでは開けない');
check((await v.recoveryAuth(rk)) !== (await v.recoveryAuth(v.newRecoveryKey())) && /^[0-9a-f]{64}$/.test(await v.recoveryAuth(rk)), 'サーバーに送る確認用の値');
const prf = v.random(32);
const pw = await v.wrapForPasskey(raw, prf, 7, 'cred1');
check(await fails(v.unwrapWithPasskey(pw, prf, 7, 'cred2')) && await fails(v.unwrapWithPasskey(pw, v.random(32), 7, 'cred1')), 'パスキーの包みは、そのパスキーの PRF でだけ開く');
const share = v.random(32);
await v.storeLocal(raw, 7, 'dev1', share);
check(K.b64u(await v.loadLocal(7, share)) === K.b64u(raw) && await fails(v.loadLocal(7, v.random(32))), '端末に置いた鍵は、サーバーの割符がないと開けない');
await v.forget(7);
check((await v.loadLocal(7, share)) === null && !v.session, '忘れると、端末の鍵も使える鍵もなくなる');
check((() => { try { K.create({ prefix: 'bad prefix!' }); return false; } catch { return true; } })(), '変なラベルの頭は断る');

const SHIORI = process.env.SHIORI_VAULT || '';  // 栞の vault.js の場所（指定したときだけ互換を確かめる）
if (SHIORI && existsSync(SHIORI)) {
  const S = require(SHIORI);
  const k = K.create({ prefix: 'shiori/v1', kv: K.memoryKv() });
  await k.activate(raw, 3);
  await S.activate(raw, 3);
  const a = await k.sealRecord(k.session.dataKey, { body: '互換' }, 3, 'note', '5', 2);
  check((await S.openRecord(S.session.dataKey, a, 3, 'note', '5', 2)).body === '互換', '栞：部品で暗号化した記録を、栞の vault.js で開ける');
  const c = await S.sealRecord(S.session.dataKey, { body: '逆' }, 3, 'note', '5', 2);
  check((await k.openRecord(k.session.dataKey, c, 3, 'note', '5', 2)).body === '逆', '栞：栞の記録を、部品で開ける');
  check(await k.recoveryAuth(rk) === await S.recoveryAuth(rk) && K.b64u(await S.unwrapWithRecovery(await k.wrapForRecovery(raw, rk, 3), rk, 3)) === K.b64u(raw), '栞：復旧キーの確認用の値と包みが同じ');
  check(K.b64u(await S.unwrapWithPasskey(await k.wrapForPasskey(raw, prf, 3, 'c'), prf, 3, 'c')) === K.b64u(raw) && K.b64u(await k.prfSalt()) === K.b64u(await S.prfSalt()), '栞：パスキーの包みと PRF に渡す値が同じ');
  check(await k.recordId('concept|読書') === await S.recordId('concept|読書'), '栞：中身から決まる番号が同じ');
} else console.log('（栞の vault.js が見つからないので、互換の確認は飛ばしました）');
console.log(`\n${passed} checks passed`);
