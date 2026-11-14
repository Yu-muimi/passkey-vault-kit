/* pkvault — 画面の部品（使わなくてもよい。アプリが自分で画面を作るなら pkvault-client.js だけで足りる）
   ログイン・新規登録・復旧・復旧モード・ユーザーIDと復旧キーの表示・鍵を開く・本人確認・セキュリティの設定。
   ほかのライブラリは使わない（アイコンも中に持つ）。見た目は pkvault-ui.css（色は --pkv-* の変数で変えられる）。

   使い方：
     const ui = PKVUI.create({ client: pkv, appName: 'メモ帳', root: document.getElementById('auth'),
       onReady: () => startApp(), terms: { url: '/terms' },
       eventLabels: { 'act:note:add': 'メモを追加' } });   // アプリの操作の記録の名前（任意）
     ui.boot();                                   // ログインしていなければログインの画面、していれば鍵を開いて onReady
     ui.securityPanel(document.getElementById('settings'));   // 設定の画面に「パスキー・復旧キー・端末・退会」を出す */
'use strict';

(function (root) {
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const svg = d => `<svg class="pkv-ic" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
  const IC = {
    key: svg('<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3m-3 3 3 3m-6 0 2 2"/>'),
    qr: svg('<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20h.01M17 20h4v-3"/>'),
    phone: svg('<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/>'),
    desktop: svg('<rect x="2" y="4" width="20" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>'),
    usb: svg('<path d="M9 3h6v6H9zM7 9h10v8a5 5 0 0 1-10 0z"/>'),
    ring: svg('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="m5.6 5.6 3.6 3.6m5.6 5.6 3.6 3.6m0-12.8-3.6 3.6m-5.6 5.6-3.6 3.6"/>'),
    x: svg('<path d="M6 6l12 12M18 6 6 18"/>'),
    copy: svg('<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>'),
    eye: svg('<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>'),
    lock: svg('<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'),
    info: svg('<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>'),
    back: svg('<path d="M15 6l-6 6 6 6"/>'),
  };
  const isPhone = () => typeof navigator !== 'undefined' && /iPhone|iPad|Android/.test(navigator.userAgent);
  const finePointer = () => typeof matchMedia !== 'undefined' && matchMedia('(pointer: fine)').matches;
  const focusSoft = el => { if (el && finePointer()) el.focus(); };  // タッチ端末では、キーボードが勝手に開かないように

  // 記録の種類（サーバーの log_event の名前）→ 画面の言葉
  const EVENTS = {
    'login:passkey': 'ログイン', 'login:recovery': '復旧モードに入った', 'reauth': '本人確認', 'logout': 'ログアウト', 'register': '登録',
    'rename': '名前を変更', 'session:days': 'ログインを保つ期間を変更', 'passkey:add': 'パスキーを追加', 'passkey:add:pending': 'セキュリティキー（1本目）',
    'passkey:delete': 'パスキーを削除', 'recovery:regen': '復旧キーを作り直した', 'recovery:start': '復旧を始めた', 'recovery:done': '復旧した',
    'device:logout': '端末をログアウト', 'logout-all': 'ほかの端末をすべてログアウト', 'withdraw': '退会', 'withdraw:cancel': '退会を取り消した',
    'vault:setup': 'データの鍵を用意', 'login:blocked': 'ログインを止めた', 'limit:push': '保存の回数の上限',
  };
  const DAY_LABEL = d => (d === 0 ? '毎回' : `${d}日`);
  const fmtTime = s => (s ? String(s).slice(0, 16).replace('T', ' ') : '');
  // 「2026年11月12日」の形（サーバーの時刻は端末と同じ地域の時刻として読む）
  const fmtDay = s => { const d = new Date(s); return isNaN(d) ? '' : `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日`; };
  // 「たった今・3分前・2時間前・5日前」の形
  const ago = s => {
    const d = new Date(s);
    if (isNaN(d)) return '';
    const m = Math.max(0, Math.floor((Date.now() - d) / 60000));
    return m < 1 ? 'たった今' : m < 60 ? `${m}分前` : m < 1440 ? `${Math.floor(m / 60)}時間前` : `${Math.floor(m / 1440)}日前`;
  };
  const uaShort = ua => { ua = ua || ''; for (const [k, n] of [['iPhone', 'iPhone'], ['iPad', 'iPad'], ['Android', 'Android'], ['Macintosh', 'Mac'], ['Windows', 'Windows'], ['CrOS', 'Chromebook'], ['Linux', 'Linux']]) if (ua.includes(k)) return n; return '不明な端末'; };

  function create(opts) {
    const pkv = opts.client;
    const appName = opts.appName || 'アプリ';
    const rootEl = opts.root || document.body;
    const onReady = opts.onReady || (() => {});
    const terms = opts.terms || null;   // { url, privacyUrl }（規約がある場合の案内先）
    const T = { ...(opts.texts || {}) };
    const t = (k, d) => T[k] ?? d;

    /* ---------------------------------------------------------- 小さな道具 */
    const $ = (s, el) => (el || document).querySelector(s);
    const $$ = (s, el) => [...(el || document).querySelectorAll(s)];
    // フォームの送信でページが読み直されないように（CSP があると、属性に書く onsubmit="…" は動かない）
    const noSubmit = el => $$('form', el).forEach(f => f.addEventListener('submit', e => e.preventDefault()));
    function busy(btn, label) {
      if (!btn) return () => {};
      const html = btn.innerHTML;
      btn.disabled = true;
      btn.classList.add('is-busy');
      btn.innerHTML = `<span class="pkv-spin" aria-hidden="true"></span>${esc(label)}`;
      return () => { btn.disabled = false; btn.classList.remove('is-busy'); btn.innerHTML = html; };
    }
    let toastTimer = null;
    function toast(text) {
      let el = $('#pkv-toast');
      if (!el) { el = document.createElement('div'); el.id = 'pkv-toast'; el.className = 'pkv-toast'; el.setAttribute('role', 'status'); document.body.appendChild(el); }
      el.textContent = text;
      el.hidden = false;
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
    }
    // 小窓（閉じたときに resolve する値を返す）
    // sticky：Esc でも外を押しても閉じない（復旧キーの表示など、決まったボタンでしか閉じない画面）
    function modal(html, setup, { sticky = false } = {}) {
      return new Promise(resolve => {
        const back = document.createElement('div');
        back.className = 'pkv pkv-modal-back';
        back.innerHTML = `<div class="pkv-card pkv-modal" role="dialog" aria-modal="true">${html}</div>`;
        const prev = document.activeElement;
        // sticky のあいだは、ページを離れる・読み直すときにブラウザーの確認を出す（閉じると二度と出ない画面を、うっかり消さないように）
        const onLeave = e => { e.preventDefault(); e.returnValue = ''; };
        if (sticky) window.addEventListener('beforeunload', onLeave);
        const close = v => { back.remove(); document.removeEventListener('keydown', onKey); window.removeEventListener('beforeunload', onLeave); prev?.focus?.(); resolve(v); };
        const onKey = e => { if (e.key === 'Escape' && !sticky) close(null); };
        document.addEventListener('keydown', onKey);
        back.addEventListener('click', e => { if (e.target === back && !sticky) close(null); });
        document.body.appendChild(back);
        noSubmit(back);
        $$('[data-close]', back).forEach(b => { b.onclick = () => close(null); });
        setup?.(back, close);
      });
    }
    const head = title => `<div class="pkv-modal-h"><h2>${title}</h2><button type="button" class="pkv-icon-btn" data-close aria-label="閉じる">${IC.x}</button></div>`;
    const confirmBox = (title, html, ok = 'OK', danger = false) => modal(`${head(esc(title))}<div class="pkv-body">${html}</div>
      <div class="pkv-modal-f"><button type="button" class="pkv-btn" data-close>やめる</button><button type="button" class="pkv-btn ${danger ? 'danger' : 'primary'}" data-ok>${esc(ok)}</button></div>`,
      (m, close) => { $('[data-ok]', m).onclick = () => close(true); }).then(v => v === true);
    const promptBox = (title, text, { value = '', mono = false, placeholder = '', ok = 'OK', max = 80 } = {}) => modal(`${head(esc(title))}
      <form class="pkv-body"><p>${esc(text)}</p><input class="pkv-input${mono ? ' mono' : ''}" name="v" maxlength="${max}" value="${esc(value)}" placeholder="${esc(placeholder)}" autocomplete="off" spellcheck="false">
      <div class="pkv-modal-f"><button type="button" class="pkv-btn" data-close>やめる</button><button class="pkv-btn primary">${esc(ok)}</button></div></form>`,
      (m, close) => { const f = $('form', m); f.onsubmit = e => { e.preventDefault(); close(f.v.value); }; focusSoft(f.v); });
    const errText = e => pkv.errorText(e);
    // 記録の名前：アプリの操作（act:…）は opts.eventLabels で名前を付けられる。付けていなければ「操作」
    const eventLabel = ev => opts.eventLabels?.[ev] || EVENTS[ev] || (ev.startsWith('act:') ? '操作' : ev);

    // 保存先を選ぶボタン：この端末 / ほかの端末（QR：Bluetooth で近くにあるか確かめる）
    const saveTargets = (prefix = '') => `<div class="pkv-targets">
      <button type="button" class="pkv-btn primary big" data-hint="client-device">${isPhone() ? IC.phone : IC.desktop}${prefix}この端末に保存</button>
      <button type="button" class="pkv-btn big" data-hint="hybrid">${IC.qr}${prefix}ほかの端末に保存（QRコード）</button></div>`;
    const deviceField = () => `<label class="pkv-label" for="pkv-device">このパスキーの名前（任意）</label>
      <input class="pkv-input" id="pkv-device" name="device" maxlength="40" placeholder="例：自分のスマホ、自宅のPC（空欄なら自動）" autocomplete="off">`;
    const noPasskey = () => `<div class="pkv-note">${IC.info}<div>パスキーは <b>https の独自ドメイン</b>（開発中は localhost）で開いたときに使えます。この端末やブラウザーが対応していないこともあります。</div></div>`;

    function shell(inner) {
      rootEl.hidden = false;
      rootEl.innerHTML = `<div class="pkv pkv-auth"><div class="pkv-card pkv-auth-card">${opts.logo ? `<img class="pkv-logo" src="${esc(opts.logo)}" alt="" width="56" height="56">` : ''}
        <h1 class="pkv-title">${esc(appName)}</h1>${inner}</div></div>`;
      noSubmit(rootEl);
      return rootEl.firstElementChild;
    }
    function done() { rootEl.innerHTML = ''; rootEl.hidden = true; onReady(); }

    /* ---------------------------------------------------------- 起動 */
    async function boot() {
      pkv.onReauth = reauth;
      let st;
      try { st = await pkv.state(); } catch (e) { shell(`<div class="pkv-err" role="alert">${esc(errText(e))}</div><button class="pkv-btn primary big" data-retry>もう一度</button>`).querySelector('[data-retry]').onclick = boot; return; }
      if (st.ok && st.scope === 'recovery') return showRecoveryMode();
      if (st.ok) {
        let v;
        try { v = await pkv.openVault(); } catch (e) { return showUnlock(errText(e)); }
        if (!v.ok) return showUnlock();
        if (v.recovery_key) return showKeys({ recovery_key: v.recovery_key }, afterLogin);
        return afterLogin();
      }
      showLogin();
    }
    async function afterLogin() {
      if (pkv.auth?.terms_update) {
        const ok = await confirmBox('規約を改定しました', `利用規約・プライバシーポリシーを改定しました。${terms?.url ? `<a href="${esc(terms.url)}" target="_blank" rel="noopener">内容を確かめる</a>` : ''}`, '確かめた');
        if (ok) await pkv.agreeTerms().catch(() => {});
      }
      done();
    }

    /* ---------------------------------------------------------- ログイン */
    function showLogin() {
      const ok = pkv.supported() && pkv.auth?.passkey;
      const a = shell(`<p class="pkv-sub">パスキーでログイン</p>
        ${ok ? `<div class="pkv-targets"><button type="button" class="pkv-btn primary big" data-pk>${IC.key}パスキーでログイン</button>
          <button type="button" class="pkv-btn big" data-pk="hybrid">${IC.qr}ほかの端末のパスキー（QRコード）</button></div>` : noPasskey()}
        <div class="pkv-err" role="alert"></div>
        <div class="pkv-links">${pkv.auth?.register ? '<button type="button" class="pkv-link" data-register>はじめての方（新規登録）</button>' : ''}
          <button type="button" class="pkv-link" data-recover>パスキーをなくしたとき（復旧）</button></div>`);
      const err = $('.pkv-err', a);
      $$('[data-pk]', a).forEach(b => { b.onclick = async () => {
        err.textContent = '';
        const restore = busy(b, 'パスキーを確かめています…');
        try {
          const r = await pkv.signIn(b.dataset.pk || undefined);
          const v = await pkv.openVault();
          if (!v.ok) return showUnlock();
          if (r.withdraw_cancelled) toast('退会の手続きを取り消しました');
          if (v.recovery_key) return showKeys({ recovery_key: v.recovery_key }, afterLogin);
          afterLogin();
        } catch (e) { restore(); err.textContent = errText(e); }
      }; });
      $('[data-register]', a)?.addEventListener('click', showRegister);
      $('[data-recover]', a).onclick = showRecover;
    }

    /* ---------------------------------------------------------- 新規登録 */
    function showRegister() {
      const ok = pkv.supported() && pkv.auth?.passkey;
      const needTerms = !!pkv.auth?.terms;
      const a = shell(`<p class="pkv-sub">新規登録</p>
        <form class="pkv-form" autocomplete="off">
          <label class="pkv-label" for="pkv-name">名前</label>
          <input class="pkv-input" id="pkv-name" name="name" maxlength="40" required autocapitalize="off" spellcheck="false">
          <p class="pkv-help">${esc(t('nameHelp', 'ほかの人と同じ名前でもかまいません。あとから変えられます。'))}</p>
          ${deviceField()}
          ${needTerms ? `<label class="pkv-check"><input type="checkbox" name="agree"> <span>${terms?.url ? `<a href="${esc(terms.url)}" target="_blank" rel="noopener">利用規約</a>` : '利用規約'}${terms?.privacyUrl ? `・<a href="${esc(terms.privacyUrl)}" target="_blank" rel="noopener">プライバシーポリシー</a>` : ''}に同意する</span></label>` : ''}
          <div class="pkv-note">${IC.lock}<div>パスワードは使いません。この端末か、ほかの端末に<b>パスキー</b>を作ります。書いた中身は端末で暗号化され、運営者にも読めません。</div></div>
          ${ok ? saveTargets('パスキーを') : noPasskey()}
          <div class="pkv-err" role="alert"></div>
        </form>
        <div class="pkv-links"><button type="button" class="pkv-link" data-back>${IC.back}ログインに戻る</button></div>`);
      const f = $('form', a), err = $('.pkv-err', a);
      f.onsubmit = e => e.preventDefault();
      focusSoft(f.name);
      $('[data-back]', a).onclick = showLogin;
      $$('[data-hint]', a).forEach(b => { b.onclick = async () => {
        err.textContent = '';
        if (!f.name.value.trim()) { err.textContent = '名前を入れてください'; return; }
        if (needTerms && !f.agree.checked) { err.textContent = '同意のチェックが必要です'; return; }
        const restore = busy(b, 'パスキーを作っています…');
        try {
          const r = await pkv.register(f.name.value.trim(), { hint: b.dataset.hint, device: f.device.value.trim(), agree: needTerms ? true : undefined });
          showKeys({ user_id: r.user_id, recovery_key: r.recovery_key, first: true }, afterLogin);
        } catch (e) { restore(); err.textContent = errText(e); }
      }; });
    }

    /* ---------------------------------------------------------- ユーザーIDと復旧キー（1回だけ表示） */
    // 「控えました」→ キーを隠して、控えた場所を見ながら最後の4文字を入れてもらう（画面を見ただけでは入れられないので、控えたことを確かめられる）
    const confirmHTML = label => `<div class="pkv-confirm" hidden>
        <p class="pkv-body">控えたことを確かめます。<b>控えた場所を見て</b>、復旧キーの<b>最後の4文字</b>を入れてください（この画面にはもう表示していません）。</p>
        <label class="pkv-label" for="pkv-last">復旧キーの最後の4文字</label>
        <input class="pkv-input mono" id="pkv-last" maxlength="8" placeholder="XXXX" autocomplete="off" autocapitalize="characters" spellcheck="false">
        <div class="pkv-note warn pkv-ng" role="alert" hidden>${IC.info}<div><b>最後の4文字が一致しません。</b>
          控えた復旧キーが、正しく書き写せていない可能性があります。このままでは、いざというときにアカウントを取り戻せません。
          「もう一度表示する」で見比べて、<b>正しく控え直してから</b>確かめてください。</div></div>
        <div class="pkv-modal-f"><button type="button" class="pkv-btn" data-again>もう一度表示する</button><button type="button" class="pkv-btn primary" data-check disabled>確認する</button></div></div>
      <div class="pkv-done" hidden>
        <p class="pkv-done-h"><b>確認できました</b></p>
        <p class="pkv-body">復旧キーが正しく控えられていることを確かめました。控えは、ほかの人に見られない場所に大切に保管してください。</p>
        <div class="pkv-modal-f"><button type="button" class="pkv-btn primary" data-done>${label}</button></div></div>`;
    function wireConfirm(scope, recovery_key, done) {
      const norm = v => String(v || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
      const want = norm(recovery_key).slice(-4);
      // 4文字を入れるまで「確認する」は押せない。一致しなければ目立つ注意、一致したら「確認できました」を見せてから進む
      const show = $('.pkv-show', scope), box = $('.pkv-confirm', scope), inp = $('#pkv-last', box), ng = $('.pkv-ng', box), btn = $('[data-check]', box);
      const doneBox = $('.pkv-done', scope);
      const ready = () => { btn.disabled = norm(inp.value).length < 4; };
      inp.oninput = () => { ng.hidden = true; ready(); };
      $('[data-saved]', scope).onclick = () => { show.hidden = true; box.hidden = false; inp.value = ''; ng.hidden = true; ready(); inp.focus(); };
      $('[data-again]', box).onclick = () => { box.hidden = true; show.hidden = false; };
      const check = () => {
        const v = norm(inp.value);
        if (v.length < 4) return;
        if (v.slice(-4) !== want) { ng.hidden = false; inp.select(); return; }
        box.hidden = true; doneBox.hidden = false; $('[data-done]', doneBox).focus();
      };
      btn.onclick = check;
      inp.onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); check(); } };
      $('[data-done]', doneBox).onclick = () => done();
    }
    function showKeys({ user_id, recovery_key, first, recovered }, then) {
      const row = (label, value, name) => `<div class="pkv-keyrow"><div class="pkv-keylabel">${label}</div>
        <div class="pkv-keyval"><code class="pkv-mono" data-v="${name}">${esc(value)}</code>
        <button type="button" class="pkv-icon-btn" data-copy="${name}" aria-label="${label}をコピー">${IC.copy}</button></div></div>`;
      const a = shell(`<p class="pkv-sub">${recovered ? '復旧しました' : first ? '登録しました' : '新しい復旧キー'}</p>
        <div class="pkv-show">
        <div class="pkv-note warn">${IC.info}<div><b>復旧キーは、この画面を閉じると二度と表示されません。</b>
          パスキーをすべてなくしたときは、${user_id ? '<b>ユーザーID</b>と' : ''}<b>復旧キー</b>だけがアカウントを取り戻す手段です。
          データは端末で暗号化しているため、<b>パスキーと復旧キーを両方なくすと、運営者にもアカウントは復旧できず、中身も二度と読めなくなります。</b></div></div>
        <p class="pkv-body">パスワードマネージャーに保存するか、紙に書いて安全な場所に保管してください。スクリーンショットだけで残すのは、なくしやすいのでおすすめしません。</p>
        <form class="pkv-keys" autocomplete="on">
          ${user_id ? `<input type="text" name="username" value="${esc(user_id)}" autocomplete="username" hidden>` : ''}
          <input type="password" name="password" value="${esc(recovery_key)}" autocomplete="new-password" hidden>
          ${user_id ? row('ユーザーID', user_id, 'uid') : ''}${row('復旧キー', recovery_key, 'rk')}
        </form>
        <button type="button" class="pkv-btn primary big" data-saved>控えました</button>
        </div>${confirmHTML('はじめる')}`);
      $$('[data-copy]', a).forEach(b => { b.onclick = async () => {
        try { await navigator.clipboard.writeText($(`[data-v="${b.dataset.copy}"]`, a).textContent); toast('コピーしました'); } catch { toast('コピーできませんでした。書き写してください'); }
      }; });
      wireConfirm(a, recovery_key, () => then());
    }

    /* ---------------------------------------------------------- 鍵を開く（ログイン中だが、この端末に鍵がない） */
    function showUnlock(message) {
      const a = shell(`<p class="pkv-sub">データの鍵を開く</p>
        <p class="pkv-body">この端末でデータを開くため、ログインに使ったパスキーで確認します。</p>
        <div class="pkv-targets"><button type="button" class="pkv-btn primary big" data-pk>${IC.key}パスキーで開く</button>
          <button type="button" class="pkv-btn big" data-pk="hybrid">${IC.qr}ほかの端末のパスキー（QRコード）</button></div>
        <div class="pkv-err" role="alert">${esc(message || '')}</div>
        <div class="pkv-links"><button type="button" class="pkv-link" data-logout>ログアウト</button></div>`);
      const err = $('.pkv-err', a);
      $$('[data-pk]', a).forEach(b => { b.onclick = async () => {
        err.textContent = '';
        const restore = busy(b, 'パスキーを確かめています…');
        try {
          const v = await pkv.unlock(b.dataset.pk || undefined);
          if (!v.ok) { restore(); err.textContent = 'データの鍵を開けませんでした'; return; }
          if (v.recovery_key) return showKeys({ recovery_key: v.recovery_key }, afterLogin);
          afterLogin();
        } catch (e) { restore(); err.textContent = errText(e); }
      }; });
      $('[data-logout]', a).onclick = async () => { await pkv.logout().catch(() => {}); showLogin(); };
    }

    /* ---------------------------------------------------------- 復旧 */
    function showRecover() {
      const a = shell(`<p class="pkv-sub">${IC.ring}アカウントの復旧</p>
        <p class="pkv-body">登録したときに表示された<b>ユーザーID</b>と<b>復旧キー</b>を入力してください。パスワードマネージャーに保存していれば自動で入ります。</p>
        <form class="pkv-form" autocomplete="on">
          <label class="pkv-label" for="pkv-uid">ユーザーID</label>
          <input class="pkv-input mono" id="pkv-uid" name="user_id" placeholder="XXXX-XXXX-XXXX" autocomplete="username" autocapitalize="characters" spellcheck="false" required>
          <label class="pkv-label" for="pkv-rk">復旧キー</label>
          <div class="pkv-pw"><input class="pkv-input mono" id="pkv-rk" type="password" name="key" placeholder="24文字（区切りは自由）" autocomplete="current-password" autocapitalize="characters" spellcheck="false" required>
            <button type="button" class="pkv-icon-btn" data-reveal aria-label="表示する">${IC.eye}</button></div>
          <button class="pkv-btn primary big">復旧を始める</button>
          <div class="pkv-err" role="alert"></div>
        </form>
        <div class="pkv-links"><button type="button" class="pkv-link" data-back>${IC.back}ログインに戻る</button></div>`);
      const f = $('form', a), err = $('.pkv-err', a);
      $('[data-back]', a).onclick = showLogin;
      $('[data-reveal]', a).onclick = () => { f.key.type = f.key.type === 'password' ? 'text' : 'password'; };
      f.onsubmit = async e => {
        e.preventDefault();
        err.textContent = '';
        const restore = busy($('button.primary', f), '安全確認をしています…');
        try { await pkv.recover(f.user_id.value, f.key.value); showRecoveryMode(); } catch (ex) { restore(); err.textContent = errText(ex); }
      };
    }
    async function showRecoveryMode() {
      let acc;
      try { acc = await pkv.recoveryView(); } catch { return showLogin(); }
      const ok = pkv.supported() && acc.passkey;
      const a = shell(`<div class="pkv-note warn">${IC.ring}<div><b>復旧モード</b>（${esc(acc.user.account)}）<br>
          15分以内に<b>新しいパスキー</b>を登録してください。登録が終わるまで、中身は表示されません。</div></div>
        <form class="pkv-form">${ok ? deviceField() + saveTargets('新しいパスキーを') : noPasskey()}</form>
        <div class="pkv-err" role="alert"></div>
        <div class="pkv-links"><button type="button" class="pkv-link" data-cancel>${IC.x}やめる</button></div>`);
      const err = $('.pkv-err', a);
      const askKey = () => promptBox('復旧キーをもう一度', 'データの鍵を開くため、復旧キーをもう一度入力してください。', { mono: true, placeholder: '24文字（区切りは自由）', ok: '開く' })
        .then(v => (v === null ? null : v));
      $$('[data-hint]', a).forEach(b => { b.onclick = async () => {
        err.textContent = '';
        const restore = busy(b, 'パスキーを作っています…');
        try {
          const r = await pkv.finishRecovery({ hint: b.dataset.hint, device: $('[name=device]', a)?.value.trim(), askKey });
          showKeys({ user_id: r.user_id, recovery_key: r.recovery_key, recovered: true }, afterLogin);
        } catch (e) { restore(); err.textContent = errText(e); }
      }; });
      $('[data-cancel]', a).onclick = async () => { await pkv.cancelRecovery().catch(() => {}); showLogin(); };
    }

    /* ---------------------------------------------------------- 本人確認（重要な操作の前） */
    function reauth() {
      return new Promise((resolve, reject) => {
        let finished = false;
        modal(`${head('本人確認')}<p class="pkv-body">大切な設定を変えるため、パスキーでもう一度確認します。</p>
          <div class="pkv-targets"><button type="button" class="pkv-btn primary big" data-pk>${IC.key}パスキーで確認</button>
            <button type="button" class="pkv-btn big" data-pk="hybrid">${IC.qr}ほかの端末で確認（QRコード）</button></div>
          <div class="pkv-err" role="alert"></div>`, (m, close) => {
          $$('[data-pk]', m).forEach(b => { b.onclick = async () => {
            const restore = busy(b, 'パスキーを確かめています…');
            try { await pkv.reauth(b.dataset.pk || undefined); finished = true; close(true); resolve(); } catch (e) { restore(); $('.pkv-err', m).textContent = errText(e); }
          }; });
        }).then(() => { if (!finished) reject(pkv.userError('本人確認をキャンセルしました')); });
      });
    }

    /* ---------------------------------------------------------- セキュリティの設定 */
    async function securityPanel(el) {
      el.classList.add('pkv');
      el.innerHTML = '<div class="pkv-loading"><span class="pkv-spin" aria-hidden="true"></span>読み込んでいます…</div>';
      let acc, devs;
      try { [acc, devs] = await Promise.all([pkv.account(), pkv.devices()]); } catch (e) { el.innerHTML = `<div class="pkv-err" role="alert">${esc(errText(e))}</div>`; return; }
      const redraw = () => securityPanel(el);
      const run = async (fn, okText) => { try { await fn(); if (okText) toast(okText); redraw(); } catch (e) { const m = errText(e); if (m) toast(m); } };
      const choices = acc.session_choices || [0, 1, 7, 30];
      el.innerHTML = `
        <section class="pkv-sec"><h3>アカウント</h3>
          <div class="pkv-row"><div><div class="pkv-k">名前</div><div class="pkv-v">${esc(acc.user.account)}</div></div><button type="button" class="pkv-btn small" data-rename>変更</button></div>
          <div class="pkv-row"><div><div class="pkv-k">ユーザーID（復旧に使う）</div><div class="pkv-v pkv-mono">${esc(acc.user_id)}</div></div></div>
        </section>
        <section class="pkv-sec"><h3>ログインを保つ期間</h3>
          <p class="pkv-help">使わないままこの期間がたつと、ログアウトします（すべての端末）。「毎回」はブラウザーを閉じるとログアウトします。長くするときは本人確認が要ります。</p>
          <div class="pkv-seg" role="radiogroup" aria-label="ログインを保つ期間">${choices.map(d => `<button type="button" role="radio" aria-checked="${d === acc.session_days}" data-days="${d}">${DAY_LABEL(d)}</button>`).join('')}</div>
        </section>
        <section class="pkv-sec"><h3>パスキー</h3>
          <ul class="pkv-list">${acc.passkeys.map(p => `<li><div class="pkv-li-main"><div class="pkv-v">${esc(p.name || 'パスキー')}${p.id === acc.current_cred ? '<span class="pkv-badge">このログイン</span>' : ''}</div>
              <div class="pkv-k">${esc([p.provider, p.kind === 'security-key' ? 'セキュリティキー' : '', p.backed_up ? '同期する' : '', `追加 ${fmtTime(p.created)}`].filter(Boolean).join('・'))}</div>
              ${p.vault ? '' : `<div class="pkv-k warn">データの鍵が未登録 <button type="button" class="pkv-link" data-vault="${esc(p.id)}">登録する</button></div>`}</div>
              <div class="pkv-li-act"><button type="button" class="pkv-btn small" data-pkname="${esc(p.id)}">名前</button>
              <button type="button" class="pkv-btn small danger-ghost" data-pkdel="${esc(p.id)}" ${acc.passkeys.length < 2 ? 'disabled title="最後のパスキーは削除できません"' : ''}>削除</button></div></li>`).join('')}</ul>
          <div class="pkv-targets row"><button type="button" class="pkv-btn" data-add="client-device">${isPhone() ? IC.phone : IC.desktop}この端末に追加</button>
            <button type="button" class="pkv-btn" data-add="hybrid">${IC.qr}ほかの端末に追加</button>
            <button type="button" class="pkv-btn" data-add="security-key">${IC.usb}セキュリティキー</button></div>
        </section>
        <section class="pkv-sec"><h3>復旧キー</h3>
          <p class="pkv-help">${acc.has_recovery ? `作った日：${esc(fmtTime(acc.recovery_created))}。キーそのものはサーバーに残りません。なくしたときは作り直してください。` : '<b>復旧キーがありません。</b>作っておいてください。'}</p>
          <button type="button" class="pkv-btn" data-regen>${IC.ring}復旧キーを作り直す</button>
        </section>
        <section class="pkv-sec"><h3>ログイン中の端末</h3>
          <ul class="pkv-list scroll">${devs.map(d => `<li><div class="pkv-li-main"><div class="pkv-v">${esc(uaShort(d.ua))}${d.current ? '<span class="pkv-badge">この端末</span>' : ''}</div>
            <div class="pkv-k">${esc(fmtDay(d.created))} · 最終アクセス ${esc(ago(d.last_seen))}</div></div>
            <div class="pkv-li-act">${d.current ? '' : `<button type="button" class="pkv-btn small" data-devout="${esc(d.id)}">ログアウト</button>`}</div></li>`).join('')}</ul>
          ${devs.length > 1 ? '<button type="button" class="pkv-btn" data-outall>ほかの端末をすべてログアウト</button>' : ''}
        </section>
        <section class="pkv-sec"><h3>最近の記録</h3>
          <ul class="pkv-list compact scroll">${acc.log.slice(0, 30).map(l => `<li><div class="pkv-li-main"><div class="pkv-v">${esc(eventLabel(l.event))}</div>
            <div class="pkv-k">${esc(fmtTime(l.at))}・${esc(uaShort(l.ua))}${l.cred ? '・' + esc(l.cred) : ''}</div></div></li>`).join('')}</ul>
        </section>
        <section class="pkv-sec"><h3>ログアウト・退会</h3>
          <div class="pkv-targets row"><button type="button" class="pkv-btn" data-logout>ログアウト</button><button type="button" class="pkv-btn danger-ghost" data-withdraw>退会する</button></div>
        </section>`;

      $('[data-rename]', el).onclick = async () => {
        const v = await promptBox('名前を変更', t('renameHelp', '自由に設定できます。'), { value: acc.user.account, max: 40 });
        if (v !== null && v.trim()) run(() => pkv.rename(v.trim()), '名前を変えました');
      };
      $$('[data-days]', el).forEach(b => { b.onclick = () => run(() => pkv.setSessionDays(+b.dataset.days), 'ログインを保つ期間を変えました'); });
      $$('[data-pkname]', el).forEach(b => { b.onclick = async () => {
        const p = acc.passkeys.find(x => x.id === b.dataset.pkname);
        const v = await promptBox('パスキーの名前', '見分けやすい名前を付けてください。', { value: p?.name || '', max: 40 });
        if (v !== null) run(() => pkv.renamePasskey(b.dataset.pkname, v.trim()), '名前を変えました');
      }; });
      $$('[data-pkdel]', el).forEach(b => { b.onclick = async () => {
        const p = acc.passkeys.find(x => x.id === b.dataset.pkdel);
        if (!await confirmBox('パスキーを削除', `「${esc(p?.name || 'パスキー')}」を削除します。このパスキーではログインできなくなります。<br><span class="pkv-help">パスキーの保存先（端末のパスワードの設定など）からも消しておいてください。</span>`, '削除する', true)) return;
        run(async () => {
          try { await pkv.deletePasskey(b.dataset.pkdel); } catch (e) {
            if (!e.data?.sk_pair) throw e;
            if (await confirmBox('セキュリティキー', `${esc(e.message)}<br>セキュリティキーをまとめて削除しますか？`, 'まとめて削除', true)) await pkv.deleteSecurityKeys(); else throw pkv.userError('');
          }
        }, 'パスキーを削除しました');
      }; });
      $$('[data-vault]', el).forEach(b => { b.onclick = () => run(() => pkv.registerVaultKey(b.dataset.vault), 'データの鍵を登録しました'); });
      $$('[data-add]', el).forEach(b => { b.onclick = async () => {
        const hint = b.dataset.add;
        const name = await promptBox('パスキーを追加', hint === 'security-key' ? 'セキュリティキーは、なくしたときに備えて2本続けて登録します。名前（任意）' : 'このパスキーの名前（任意。空欄なら自動）', { max: 40, ok: '次へ' });
        if (name === null) return;
        run(async () => {
          const r = await pkv.addPasskey({ hint, device: name.trim() });
          if (r.pending) {
            if (!await confirmBox('2本目のセキュリティキー', '1本目を受け付けました。<b>別のセキュリティキー</b>に差し替えて「登録する」を押してください。<br><span class="pkv-help">2本目を登録するまで、1本目は使えません（30分で取り消されます）。</span>', '登録する')) return;
            const r2 = await pkv.addPasskey({ hint, device: name.trim() ? `${name.trim()}（2本目）` : '' });
            if (!r2.pending) toast('セキュリティキーを2本登録しました。1本目は一覧の「登録する」でデータの鍵を登録してください');
          }
        }, 'パスキーを追加しました');
      }; });
      $('[data-regen]', el).onclick = async () => {
        if (!await confirmBox('復旧キーを作り直す', '新しい復旧キーを作ります。<b>今までの復旧キーは使えなくなります。</b>', '作り直す')) return;
        try { const r = await pkv.regenRecovery(); keysModal(r); } catch (e) { const m = errText(e); if (m) toast(m); }
      };
      $$('[data-devout]', el).forEach(b => { b.onclick = () => run(() => pkv.logoutDevice(b.dataset.devout), '端末をログアウトしました'); });
      $('[data-outall]', el)?.addEventListener('click', async () => {
        if (await confirmBox('ほかの端末をログアウト', 'この端末以外のすべての端末でログアウトします。', 'ログアウトする')) run(() => pkv.logoutAll(), 'ほかの端末をログアウトしました');
      });
      $('[data-logout]', el).onclick = async () => { await opts.beforeLogout?.(); await pkv.logout().catch(() => {}); location.reload(); };
      $('[data-withdraw]', el).onclick = async () => {
        const days = opts.withdrawDays ?? 30;
        const ok = await modal(`${head('退会')}<div class="pkv-body"><p>すぐにすべての端末でログアウトし、<b>${days}日後</b>にアカウントと預けたデータをすべて消します。それまでにパスキーでログインすれば取り消せます。</p>
          <label class="pkv-label" for="pkv-del">確かめるため <b>delete</b> と入力してください</label><input class="pkv-input mono" id="pkv-del" autocomplete="off" spellcheck="false">
          <label class="pkv-check"><input type="checkbox" data-agree> <span>消えることを理解しました</span></label></div>
          <div class="pkv-modal-f"><button type="button" class="pkv-btn" data-close>やめる</button><button type="button" class="pkv-btn danger" data-ok disabled>退会する</button></div>`, (m, close) => {
          const okBtn = $('[data-ok]', m), inp = $('#pkv-del', m), ag = $('[data-agree]', m);
          const upd = () => { okBtn.disabled = !(inp.value.trim() === 'delete' && ag.checked); };
          inp.oninput = upd; ag.onchange = upd;
          okBtn.onclick = () => close(true);
        });
        if (!ok) return;
        try { await opts.beforeLogout?.(); await pkv.withdraw(); location.reload(); } catch (e) { const m = errText(e); if (m) toast(m); }
      };
    }
    function keysModal({ user_id, recovery_key }) {
      modal(`<div class="pkv-modal-h"><h2>新しい復旧キー</h2></div><div class="pkv-show"><div class="pkv-body"><div class="pkv-note warn">${IC.info}<div><b>この画面を閉じると二度と表示されません。</b>今までのキーは使えなくなりました。パスキーと復旧キーを両方なくすと、運営者にもアカウントは復旧できず、中身も読めなくなります。</div></div>
        <form autocomplete="on"><input type="text" name="username" value="${esc(user_id)}" autocomplete="username" hidden><input type="password" name="password" value="${esc(recovery_key)}" autocomplete="new-password" hidden></form>
        <div class="pkv-keyrow"><div class="pkv-keylabel">ユーザーID</div><div class="pkv-keyval"><code class="pkv-mono">${esc(user_id)}</code></div></div>
        <div class="pkv-keyrow"><div class="pkv-keylabel">復旧キー</div><div class="pkv-keyval"><code class="pkv-mono" data-rk>${esc(recovery_key)}</code>
          <button type="button" class="pkv-icon-btn" data-copy aria-label="復旧キーをコピー">${IC.copy}</button></div></div></div>
        <div class="pkv-modal-f"><button type="button" class="pkv-btn primary" data-saved>控えました</button></div></div>${confirmHTML('閉じる')}`, (m, close) => {
        wireConfirm(m, recovery_key, () => close(null));
        $('[data-copy]', m).onclick = async () => { try { await navigator.clipboard.writeText(recovery_key); toast('コピーしました'); } catch { toast('コピーできませんでした'); } };
      }, { sticky: true });
    }

    return { boot, showLogin, showRegister, showRecover, reauth, securityPanel, toast, confirm: confirmBox, prompt: promptBox };
  }

  root.PKVUI = { create, esc };
})(typeof globalThis !== 'undefined' ? globalThis : this);
