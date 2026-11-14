/* 見本アプリ：暗号メモ。ログイン・鍵は pkvault-ui.js、同期は pkvault-store.js に任せ、ここはメモの画面だけ */
'use strict';

const pkv = PKVClient.create({ api: '/api', header: 'X-PKV' });
const esc = PKVUI.esc;
const $ = s => document.querySelector(s);
let store = null, openId = null;

const ui = PKVUI.create({
  client: pkv, appName: '暗号メモ', root: $('#auth'),
  onReady: start,
  beforeLogout: () => store?.close(),
  eventLabels: { 'act:note:add': 'メモを追加', 'act:note:delete': 'メモを削除' },
});
ui.boot();

async function start() {
  $('#app').hidden = false;
  store = PKVStore.create({ client: pkv });
  store.on('change', e => { drawList(); if (e.remote && openId && e.keys.includes(`note/${openId}`)) drawEditor(false); });
  store.on('saved', drawSync);
  store.on('error', () => { $('#sync').textContent = '送れませんでした（あとで送り直します）'; });
  // 重なったとき：負けた側の中身を、写しのメモとして残す（消えないように）
  store.on('notice', n => {
    if (n.kind !== 'note' || !n.mine) return;
    const id = store.newId();
    store.put('note', id, { ...n.mine, title: `${n.mine.title || '無題'}（写し）`, updated: new Date().toISOString() });
    ui.toast(n.type === 'deleted' ? 'ほかの端末で消されたメモを、写しとして残しました' : 'ほかの端末と同時に直したため、こちらの内容を写しとして残しました');
  });
  await store.load();
  store.start();
  drawList();
}

function drawSync() { $('#sync').textContent = store.pending ? `送信待ち ${store.pending}件` : '保存済み（暗号化）'; }

function drawList() {
  const q = $('#q').value.trim().toLowerCase();
  const notes = store.list('note')
    .filter(n => !q || `${n.data.title} ${n.data.body}`.toLowerCase().includes(q))
    .sort((a, b) => String(b.data.updated).localeCompare(String(a.data.updated)));
  $('#list').innerHTML = notes.map(n => `<li><button type="button" data-id="${esc(n.id)}" ${n.id === openId ? 'aria-current="true"' : ''}>
    <b>${esc(n.data.title || '無題')}</b><span>${esc((n.data.body || '').slice(0, 60))}</span></button></li>`).join('');
  $('#empty').hidden = store.list('note').length > 0;
  drawSync();
}

function drawEditor(focus = true) {
  const n = openId && store.get('note', openId);
  $('#editor').hidden = !n;
  if (!n) return;
  const t = $('#title'), b = $('#body');
  if (document.activeElement !== t) t.value = n.title || '';
  if (document.activeElement !== b) b.value = n.body || '';
  const d = new Date(n.updated);
  $('#stamp').textContent = isNaN(d) ? '' : `更新 ${d.toLocaleString('ja-JP', { dateStyle: 'short', timeStyle: 'short' })}`;
  if (focus) t.focus();
}

function save() {
  if (!openId) return;
  const n = store.get('note', openId) || {};
  store.put('note', openId, { ...n, title: $('#title').value, body: $('#body').value, updated: new Date().toISOString() });
}

$('#list').addEventListener('click', e => { const b = e.target.closest('[data-id]'); if (!b) return; openId = b.dataset.id; drawList(); drawEditor(); });
$('#new').onclick = () => {
  openId = store.newId();
  const now = new Date().toISOString();
  store.put('note', openId, { title: '', body: '', created: now, updated: now });
  store.act('note:add');
  drawList();
  drawEditor();
};
$('#title').oninput = save;
$('#body').oninput = save;
$('#q').oninput = drawList;
$('#del').onclick = async () => {
  if (!openId || !await ui.confirm('メモを削除', 'このメモを削除します。ほかの端末からも消えます。', '削除する', true)) return;
  store.remove('note', openId);
  store.act('note:delete');
  openId = null;
  drawEditor();
};
document.querySelectorAll('[data-view]').forEach(b => {
  b.onclick = () => {
    document.querySelectorAll('[data-view]').forEach(x => x.removeAttribute('aria-current'));
    b.setAttribute('aria-current', 'page');
    $('#notes').hidden = b.dataset.view !== 'notes';
    $('#settings').hidden = b.dataset.view !== 'settings';
    if (b.dataset.view === 'settings') ui.securityPanel($('#security'));
  };
});
