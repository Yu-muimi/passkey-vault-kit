# passkey-vault-kit（pkvault）

**パスキーだけでログインし、中身は端末で暗号化して預かる仕組み**を、ほかのアプリに組み込むための開発用の部品です。
栞（shiori）で作って確かめた仕組みを、アプリに依存しない形に取り出しました。

- パスワードなし：ログインはパスキー（生体認証や PIN）だけ。
- サーバーは中身を読めない：記録は1件ずつ端末で暗号化（AES-256-GCM）し、サーバーには暗号文だけを預けます。
  - 暗号化の鍵（データ鍵）はパスキーの PRF で包んで預けます。運営者も DB を盗んだ人も開けません。
- なくしても戻せる：ユーザーID と復旧キー（端末で作る。サーバーは照合用の値しか持たない）で、新しいパスキーを登録し直せます。
- 何台でも同期：差分だけを受け渡し、同時に直したら項目ごとに混ぜます。消したほうを優先し、古い版へのすり替えは受け付けません。

> 位置づけ：**開発用の部品**です。そのまま単独のサービスとして動かすものではなく、アプリに組み込んで使います。
> 第三者によるセキュリティ監査は受けていません。使う前に「守れること・守れないこと」を読んでください。

**English summary** — A drop-in kit for Flask web apps: passwordless sign-in with passkeys only, and end-to-end
encrypted user data. Each record is encrypted in the browser (AES-256-GCM) with a per-user data key that is wrapped by the
passkey's WebAuthn PRF output, so the server only ever stores ciphertext. Includes account recovery (user ID + recovery key),
multi-device sync with conflict merging and rollback protection, ready-made UI, and tests. Documentation is in Japanese.
MIT licensed. Not independently audited.

使っている例：読書メモの [栞 - Reading Notes](https://shiori.muimiapps.com/about)（この部品の元になったアプリ）

---

## 中身

| 場所 | 役目 |
|---|---|
| `pkvault/` | サーバーの部品（Flask）。ログイン・復旧・アカウント・鍵の包み・暗号文の同期・DB |
| `static/pkvault/pkvault-crypto.js` | 暗号の土台（WebCrypto だけ。自前の暗号は書かない） |
| `static/pkvault/pkvault-client.js` | サーバーとのやりとり・パスキー・鍵を開く／包む・復旧・本人確認（画面なし） |
| `static/pkvault/pkvault-store.js` | 暗号化した記録の同期（差分・重なりの混ぜ方・すり替えの拒否・端末の控え） |
| `static/pkvault/pkvault-ui.js` `.css` | 画面の部品（ログイン・登録・復旧・設定）。使わずに自分で作ってもよい |
| `sample/` | 見本：暗号化されたメモ帳 |
| `tests/` | 試験（サーバー71項目・通し40項目・暗号15項目＋栞との互換5項目） |

DB の表：`users` `credentials` `auth_log` `pow_used` `vault_keys` `devices` `records` `settings`（`pkvault/store.py`）。

---

## 使える環境

- サーバー：Python 3.10 以上（Flask）。試験は Node.js 22 以上も使います。
- ブラウザー：パスキーと **PRF 拡張**に対応したもの。目安は、新しい iOS / iPadOS / macOS の Safari、Android の Chrome（Google パスワードマネージャー）、新しい Chrome・Edge。
  - PRF が使えない組み合わせ（古い OS、PRF に対応していないパスキーの保存先など）では、アカウントを作る前に知らせて、作らずに止めます。

## はじめかた

```bash
python -m venv .venv
```

Windows：

```bash
.venv/Scripts/python -m pip install -r requirements.txt
```

```bash
.venv/Scripts/python sample/app.py
```

macOS・Linux：

```bash
.venv/bin/python -m pip install -r requirements.txt
```

```bash
.venv/bin/python sample/app.py
```

`http://localhost:5180` を開きます。パスキーは https の独自ドメインか、開発中の localhost で使えます。

### サーバーに組み込む

```python
from flask import Flask
from pkvault import PasskeyVault, Config

app = Flask(__name__)
pkv = PasskeyVault(app, Config(
    app_name="メモ帳",                 # パスキーの画面に出る名前
    crypto_prefix="memo/v1",           # このアプリの暗号のラベル（決めたら変えない）
    record_kinds={"note": 5000},       # 預かる記録の種類 → 1人あたりの「件数」の上限（容量の上限は user_bytes_max）
    data_dir="data",
))

@app.get("/api/usage")
@pkv.login_required                    # ログインしている本人だけ。pkv.user_id() が本人の番号
def usage():
    return {"user": pkv.user_id()}
```

組み込むと、`/api/auth…` `/api/account…` `/api/vault…` が増えます。
`/api/` の下の変更系の要求には、ヘッダー `X-PKV: 1` が必須になります（CSRF 対策。アプリ自身の API も守られます）。

### 画面に組み込む

```html
<link rel="stylesheet" href="/pkvault/pkvault-ui.css">
<div id="auth" hidden></div>
<script src="/pkvault/pkvault-crypto.js"></script>
<script src="/pkvault/pkvault-client.js"></script>
<script src="/pkvault/pkvault-store.js"></script>
<script src="/pkvault/pkvault-ui.js"></script>
<script>
const pkv = PKVClient.create();
const ui = PKVUI.create({ client: pkv, appName: 'メモ帳', root: document.getElementById('auth'), onReady: start });
ui.boot();                        // ログイン → 鍵を開く → start()

async function start() {
  const store = PKVStore.create({ client: pkv });
  await store.load();
  store.put('note', store.newId(), { title: 'はじめて', body: '…' });  // 少し待ってまとめて送る
  store.list('note');             // → [{ id, data }]
  store.on('change', draw);       // ほかの端末の変更（60秒おき・画面に戻ったとき）
  store.start();
  ui.securityPanel(document.getElementById('settings'));  // パスキー・復旧キー・端末・退会の設定
}
</script>
```

アプリのデータの形は、アプリが決めます（記録の中身は JSON にできるオブジェクトなら何でもよい）。

---

## 設定（`Config`）のおもなもの

| 名前 | 標準 | 意味 |
|---|---|---|
| `app_name` | `"My App"` | パスキーの画面に出る名前 |
| `rp_id` | `None` | 本番のドメイン。決めると、ほかの名前で来た要求を断り、クッキーに Secure を付ける |
| `crypto_prefix` | `"pkvault/v1"` | 暗号のラベルの頭。**あとから変えると、預けた暗号文が開けなくなる** |
| `record_kinds` | `{"item": 10000}` | 記録の種類と、1人あたりの件数の上限 |
| `blob_max` / `user_bytes_max` | 400KB / 100MB | 1件・1人あたりの暗号文の大きさの上限 |
| `session_days` | `(0, 1, 7, 30)` | 本人が選べる「ログインを保つ期間」（0＝毎回） |
| `terms_version` | `None` | 利用規約の版。決めると登録に同意が必須になり、改定したら知らせる |
| `open_registration` / `register_check` | `True` / `None` | だれでも登録できるか／招待コードなどの追加の確認 |
| `client_ip_header` | `None` | 前に置いた中継が付ける接続元（例 `"CF-Connecting-IP"`）。**中継がないのに決めると偽られる** |
| `require_ip_header` | `False` | 上のヘッダーのない要求（中継を通らない直接の接続）を断る |
| `acts` | 空 | 操作の記録として受け付ける種類（説明は暗号化され、本人の画面でだけ開ける） |
| `extra_schema` / `on_delete_user` / `on_migrated` | | アプリの表を同じ DB に置くとき（起動時に設計どおりへ移し替える） |
| `messages` | | サーバーが返す文の差し替え（`pkvault/messages.py` のキー） |

回数制限（復旧・登録・ログインの失敗）や作業証明の難しさも、すべて `Config` で変えられます。

---

## 本番に出すとき

- [ ] `rp_id` に本番のドメインを決める（HTTPS で動かす）。
- [ ] Cloudflare Tunnel などの中継の後ろに置く場合：
  - `client_ip_header="CF-Connecting-IP"`
  - `country_header="CF-IPCountry"`
  - `require_ip_header=True`
  - サーバーは 127.0.0.1 だけで待ち受ける。
- [ ] `ProxyFix` で元の https を戻す（`app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)`）。
- [ ] 画面に CSP を付ける（見本の `security_headers` を参照）。
  - 画面の部品は、属性に書くスクリプトや外のライブラリを使わないので、`script-src 'self'` で動きます。
- [ ] `data/` は本人だけが読めるようにする（`secret.key` と DB は 600 で作られる）。
  - `secret.key` をなくすと、ユーザーID と復旧キーの照合ができなくなります。DB とは別に安全に控えてください。
- [ ] `crypto_prefix` を決めて、以後変えない。
- [ ] 前に置く中継（Cloudflare など）で、受け付ける TLS の最小の版を 1.2 にする（1.0・1.1 は古く、弱点がある）。
  - Cloudflare なら、ダッシュボードの「SSL/TLS → エッジ証明書 → 最小 TLS バージョン」。
- [ ] 部品の版は `requirements.txt` で固定している（`==`）。サーバーを作り直しても同じ版が入る。
  - 版を上げるときは、試験を全部通してから書き換える。`requirements.txt` には日本語を書かない（Windows の pip が読めずに止まる）。
- [ ] データ（DB と `secret.key`）を、別のコンピューターへ定期的に控える。
  - 動いている DB をそのままコピーすると、書き込みの途中で壊れた写しになることがある。SQLite のバックアップ機能で写したもの（`data/backups/` の中や、自分で写したもの）を取る。

---

## 仕組みの要点

| 鍵 | どこにあるか |
|---|---|
| データ鍵 | 中身を暗号化する唯一の鍵。読める形ではどこにも保存しない |
| パスキーの包み | データ鍵を、パスキーの PRF から作った鍵で暗号化したもの。パスキーごとにサーバーへ預ける |
| 復旧キーの包み | データ鍵を、復旧キーから作った鍵で暗号化したもの。復旧モードのあいだだけ本人に渡す |
| 端末の控え | 端末鍵（取り出せない鍵・IndexedDB）とサーバーの割符の二重にかけたデータ鍵 |

- 端末の控えは、開き直すたびにパスキーを使わなくて済むためのものです。
  - ログアウトすると割符が消えるので、控えは開けなくなります。
- 記録の封（AAD）には「だれの・どの種類の・どの番号の・どの版か」を入れます。
  - そのため、サーバーが記録を取り替えたり、古い版を返したりすると、開けないか、受け付けません。
- 暗号文は 256 バイト単位に切り上げます（中身の長さを分かりにくくする）。

---

## 守れること・守れないこと

**守れること**

- サーバーの DB やバックアップが漏れても、記録の中身は読めません（鍵はサーバーにない）。
- サーバーが記録を取り替えたり、古い版を返したりしても、端末が見つけて受け付けません。
- パスワードを持たないので、パスワードの漏えいや使い回しの被害がありません。

**守れないこと（この作りの限界）**

- **配るスクリプトが書き換えられた場合**：ブラウザーで暗号化する仕組みは、サーバー（または配る途中）が悪意のあるスクリプトを配ると、鍵や中身を盗まれます。ウェブで端末暗号化をするときに共通の限界です。
  - 対策の例：スクリプトは自分のサーバーからだけ配る（CSP）、HTTPS、サーバーの改ざんの見張り。
- **端末そのものが乗っ取られている場合**（マルウェア、ロックしていない端末を他人が使うなど）。
- **中身以外の情報**：アカウントの名前、ログインの記録（IP アドレス・日時・ブラウザーの種類）、記録の数・大きさ・種類・更新の時刻は、サーバーから見えます。
- **パスキーと復旧キーを両方なくした場合**：運営者にも戻せません（設計どおり）。

---

## 試験

```bash
.venv/Scripts/python tests/test_server.py
```

```bash
node tests/test_e2e.mjs
```

```bash
node tests/test_crypto.mjs
```

- `test_server.py`：71項目。
  - CSRF・チャレンジの使い回し・別のサイトの答え・ほかの人の記録・上限・版
  - 本人確認・ログインの期間・端末のログアウト・物理キー
  - 復旧の総当たり対策（作業証明・ID ごと・ネットワークごと・IPv6 /64）・送り元の偽装・ホスト名
  - 退会と掃除・設計の移し替え・8台の同時保存
- `test_e2e.mjs`：40項目。本物のサーバーに、試験用のパスキーを持った端末を何台もつないで確かめます。
  - 登録 → 同期 → 重なり → 削除 → 送る前に閉じた変更 → すり替え → 追加 → 復旧 → 退会
  - ランダムな操作を300回重ねても全端末がそろうか（`SEED=…` で乱数を変えられる）
- `test_crypto.mjs`：15項目。改ざんの検出など。
  - 環境変数 `SHIORI_VAULT` に栞の `vault.js` の場所を入れると、栞と互いに開けるか（`crypto_prefix="shiori/v1"` のとき）も確かめます（5項目）。

---

## 入れていないもの（v1）

- 管理の画面（利用停止は `pkv.set_block(uid, banned=True)` で行えます）。
- 端末の中の SQLite（栞の検索・集計のような仕組み）。必要ならアプリが `store.list()` から作ります。
- 共有（ほかの人と同じデータを読む）。データ鍵が1人に1つの設計のためです。

---

## ライセンス

MIT License（[LICENSE](LICENSE)）。作者：Yu-muimi

セキュリティの問題は、公開の Issue ではなく [SECURITY.md](SECURITY.md) の方法で知らせてください。
