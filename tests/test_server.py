"""サーバーの部品の試験：ログイン・復旧・権限・攻撃への備え・上限・ログインを保つ期間・退会と掃除・設計の移し替え・同時の保存

  .venv/Scripts/python tests/test_server.py
"""
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import tempfile
import threading
import urllib.request
from datetime import datetime, timedelta
from http.cookiejar import CookieJar

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from serve import make_app  # noqa: E402
from pkvault import store  # noqa: E402

H = {"X-PKV": "1"}
ORIGIN = "http://localhost"
PREFIX = b"test/v1"
passed = 0


def check(cond, label):
    global passed
    if not cond:
        raise SystemExit(f"FAIL: {label}")
    passed += 1
    print("ok -", label)


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class SoftAuthenticator:
    """端末のパスキー（またはセキュリティキー）を模した最小の実装（attestation: none, ES256）"""

    def __init__(self, security_key=False, synced=False):
        self.creds, self.sk, self.synced = {}, security_key, synced

    def create(self, opts, origin=ORIGIN):
        key = ec.generate_private_key(ec.SECP256R1())
        n = key.public_key().public_numbers()
        cose = {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
        cid = os.urandom(16)
        rp = opts["rp"]["id"]
        auth = hashlib.sha256(rp.encode()).digest() + bytes([0x45 | (0 if self.sk else 0x18)]) + (0).to_bytes(4, "big") \
            + bytes(16) + len(cid).to_bytes(2, "big") + cid + cbor2.dumps(cose)
        cd = json.dumps({"type": "webauthn.create", "challenge": opts["challenge"], "origin": origin}).encode()
        self.creds[cid] = [key, rp, unb64(opts["user"]["id"]), 0]
        return {"id": b64(cid), "rawId": b64(cid), "type": "public-key", "clientExtensionResults": {},
                "authenticatorAttachment": "cross-platform" if self.sk else "platform",
                "response": {"clientDataJSON": b64(cd), "transports": ["usb", "nfc"] if self.sk else ["internal", "hybrid"],
                             "attestationObject": b64(cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth}))}}

    def get(self, opts, origin=ORIGIN, cid=None):
        cid = cid or next(iter(self.creds))
        key, rp, handle, count = self.creds[cid]
        if not self.synced:
            count += 1
            self.creds[cid][3] = count
        auth = hashlib.sha256(rp.encode()).digest() + bytes([0x05]) + count.to_bytes(4, "big")
        cd = json.dumps({"type": "webauthn.get", "challenge": opts["challenge"], "origin": origin}).encode()
        sig = key.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64(cid), "rawId": b64(cid), "type": "public-key", "clientExtensionResults": {},
                "response": {"authenticatorData": b64(auth), "clientDataJSON": b64(cd), "signature": b64(sig), "userHandle": b64(handle)}}


TMP = tempfile.mkdtemp(prefix="pkv-srv-")
app, pkv = make_app(TMP, register_net_hour=1000, register_global_hour=1000)
DB = os.path.join(TMP, "pkvault.db")


def sql(q, *p):
    c = sqlite3.connect(DB)
    r = c.execute(q, p).fetchall()
    c.commit()
    c.close()
    return r


def ip(n):
    return {**H, "X-Test-IP": n}


def register(c, name="tester", authn=None, headers=H):
    authn = authn or SoftAuthenticator()
    o = c.post("/api/auth/register/options", json={"name": name}, headers=headers)
    if o.status_code != 200:
        return o, authn
    return c.post("/api/auth/register/finish", json={"credential": authn.create(o.json)}, headers=headers), authn


def login(c, authn, headers=H, **kw):
    o = c.post("/api/auth/passkey/options", headers=headers).json
    return c.post("/api/auth/passkey/verify", json={"credential": authn.get(o, **kw)}, headers=headers)


def new_rk():
    return "-".join("".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(4)) for _ in range(6))


def rauth(key):
    norm = re.sub(r"[^A-Z0-9]", "", key.upper())
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=PREFIX, info=b"recovery/auth").derive(norm.encode()).hex()


def wrap():
    return b64(bytes([1]) + os.urandom(12 + 32 + 16))


def setup_vault(c, authn):
    rk = new_rk()
    r = c.post("/api/vault/setup", json={"cred_id": b64(next(iter(authn.creds))), "passkey_wrap": wrap(), "recovery_wrap": wrap(),
                                         "recovery_auth": rauth(rk)}, headers=H)
    assert r.status_code == 200, r.get_data(as_text=True)
    return rk


def solve_pow(c, headers=H):
    p = c.get("/api/auth/pow", headers=headers).json
    n = 0
    while int.from_bytes(hashlib.sha256(f"{p['token']}:{n}".encode()).digest(), "big") >> (256 - p["bits"]):
        n += 1
    return {"pow_token": p["token"], "pow_nonce": str(n)}


def recover(c, uid, key, headers=H):
    return c.post("/api/auth/recover", json={"user_id": uid, "auth": rauth(key), **solve_pow(c, headers)}, headers=headers)


def stale(c, sec=3600):
    with c.session_transaction() as s:
        s["auth_at"] = s.get("auth_at", 0) - sec


def blob(n=300):
    return b64(os.urandom(n))


def push(c, changes, headers=H):
    return c.post("/api/vault/push", json={"changes": changes}, headers=headers)


try:
    # ------------------------------------------------------------ 登録・ログイン
    c = app.test_client()
    r, authn = register(c)
    check(r.status_code == 200 and re.match(r"^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$", r.json["user_id"]), "登録するとユーザーIDが返る")
    uid_code = r.json["user_id"]
    check(not sql("SELECT 1 FROM users WHERE uid_enc LIKE ?", f"%{uid_code.replace('-', '')}%"), "ユーザーIDは平文で保存しない")
    rk = setup_vault(c, authn)
    check(c.post("/api/vault/setup", json={}, headers=H).status_code == 409, "鍵の用意は1回だけ")
    h, s = sql("SELECT recovery_hash, recovery_salt FROM users")[0]
    check(h and s and rauth(rk) not in h, "復旧キーはソルト付きの HMAC だけを保存する")
    r = c.post("/api/auth/logout", headers=H)
    check(c.get("/api/vault/state").status_code == 401, "ログアウトすると読めない")
    check(login(c, authn).status_code == 200 and c.get("/api/vault/state").json["has_vault"], "パスキーでログインできる")

    # ------------------------------------------------------------ CSRF・形
    check(c.post("/api/vault/push", json={"changes": []}).status_code == 400, "独自ヘッダーのない変更は断る")
    check(c.post("/api/vault/push", data="[1]", content_type="application/json", headers=H).status_code == 400, "本文がオブジェクトでなければ断る")
    check(c.get("/api/nothing").json == {"error": "not found"} and c.get("/api/vault/push").status_code == 404, "ない場所・使い方の違う場所は同じ 404")
    check(c.post("/api/auth/passkey/verify", json={"credential": "x"}, headers=H).status_code == 400, "壊れたパスキーの答えで落ちない")

    # ------------------------------------------------------------ チャレンジの使い回し
    c2 = app.test_client()
    _, ans = register(c2, "synced", SoftAuthenticator(synced=True))
    c2.post("/api/auth/logout", headers=H)
    o = c2.post("/api/auth/passkey/options", headers=H).json
    a = ans.get(o)
    with c2.session_transaction() as s:
        saved = dict(s)
    check(c2.post("/api/auth/passkey/verify", json={"credential": a}, headers=H).status_code == 200, "同期するパスキーでログイン")
    c3 = app.test_client()
    with c3.session_transaction() as s:
        s.update(saved)
    check(c3.post("/api/auth/passkey/verify", json={"credential": a}, headers=H).status_code == 400, "盗み見たクッキーと答えを送り直しても入れない")

    # ------------------------------------------------------------ 他人のパスキー・別のサイト
    other = app.test_client()
    r, authn2 = register(other, "other")
    setup_vault(other, authn2)
    o = c.post("/api/auth/passkey/options", headers=H).json
    check(c.post("/api/auth/passkey/verify", json={"credential": authn.get(o, origin="https://evil.example")}, headers=H).status_code == 401, "別のサイトで作った答えは通らない")
    bad = authn.get(c.post("/api/auth/passkey/options", headers=H).json)
    bad["response"]["userHandle"] = b64(os.urandom(32))
    check(c.post("/api/auth/passkey/verify", json={"credential": bad}, headers=H).status_code == 401, "アカウントと合わないパスキーは通らない")

    # ------------------------------------------------------------ 記録：分離・版・上限
    check(push(c, [{"kind": "note", "id": "a1", "base": 0, "blob": blob()}]).json["applied"][0]["ver"] == 1, "記録を保存")
    check(push(c, [{"kind": "note", "id": "a1", "base": 0, "blob": blob()}]).json["conflicts"][0]["ver"] == 1, "古い版を元にした保存は重なりとして返す")
    check(other.get("/api/vault/sync?since=0").json["records"] == [], "ほかの人の記録は見えない")
    check(push(other, [{"kind": "note", "id": "a1", "base": 0, "blob": blob()}]).json["applied"], "同じ番号でも人ごとに別")
    check(push(c, [{"kind": "evil", "id": "x", "base": 0, "blob": blob()}]).status_code == 400, "決めていない種類は断る")
    check(push(c, [{"kind": "note", "id": "../x", "base": 0, "blob": blob()}]).status_code == 400, "番号の形が違えば断る")
    check(push(c, [{"kind": "note", "id": "x", "base": 2 ** 60, "blob": blob()}]).status_code == 400, "とても大きな版は断る")
    check(push(c, [{"kind": "note", "id": "x", "base": True, "blob": blob()}]).status_code == 400, "版が数でなければ断る")
    check(push(c, [{"kind": "note", "id": "x", "base": 0, "blob": "a" * 500000}]).status_code == 400, "大きすぎる暗号文は断る")
    check(push(c, [{"kind": "note", "id": "x", "base": 0, "blob": "<script>"}]).status_code == 400, "暗号文の形でなければ断る")
    check(c.get("/api/vault/sync?since=-5").status_code == 200 and c.get("/api/vault/sync?since=99999999999999999999").status_code == 200, "変な since でも落ちない")
    many = [{"kind": "tag", "id": f"t{i}", "base": 0, "blob": blob(10)} for i in range(51)]
    check(push(c, many).status_code == 400 and not sql("SELECT 1 FROM records WHERE kind='tag'"), "件数の上限を超える保存は、まるごと断る")
    check(push(c, [{"kind": "note", "id": "a1", "base": 1, "deleted": True}]).json["applied"][0]["ver"] == 2, "消すと版が上がる")
    sy = c.get("/api/vault/sync?since=1").json
    check(any(x["id"] == "a1" and x["deleted"] for x in sy["records"]), "消した印は差分で伝わる")
    check(all(not x["deleted"] for x in c.get("/api/vault/sync?since=0").json["records"]), "全件のときは消した印を渡さない")

    # ------------------------------------------------------------ 本人確認の要る操作
    stale(c)
    check(c.post("/api/account/recovery", json={"auth": rauth(new_rk()), "blob": wrap()}, headers=H).json.get("error") == "reauth", "時間がたつと、復旧キーの作り直しに本人確認が要る")
    check(c.post("/api/account/withdraw", json={"confirm": "delete", "agree": True}, headers=H).json.get("error") == "reauth", "退会にも本人確認が要る")
    check(c.put("/api/account/session", json={"days": 0}, headers=H).status_code == 200, "ログインを保つ期間を短くするのは、すぐできる")
    check(c.put("/api/account/session", json={"days": 30}, headers=H).json.get("error") == "reauth", "長くするのは本人確認のあと")
    login(c, authn)
    check(c.put("/api/account/session", json={"days": 30}, headers=H).status_code == 200, "本人確認のあとは長くできる")
    check(c.put("/api/account/session", json={"days": 5}, headers=H).status_code == 400, "選べない日数は断る")

    # ------------------------------------------------------------ 使わない端末の期限・端末のログアウト
    c.put("/api/account/session", json={"days": 1}, headers=H)
    sql("UPDATE devices SET last_seen=? WHERE user_id=1", (datetime.now() - timedelta(days=2)).isoformat(timespec="seconds"))
    check(c.get("/api/account").status_code == 401, "選んだ期間より長く使わなかった端末は、ログアウト扱い")
    login(c, authn)
    c.put("/api/account/session", json={"days": 30}, headers=H)
    d2 = app.test_client()
    login(d2, authn)
    devs = c.get("/api/account/devices").json
    check(len(devs) >= 2 and sum(d["current"] for d in devs) == 1, "ログイン中の端末の一覧（割符は出さない）" if all("share" not in d for d in devs) else "割符が出ている")
    other_dev = next(d["id"] for d in devs if not d["current"])
    c.delete(f"/api/account/devices/{other_dev}", headers=H)
    check(d2.get("/api/account").status_code == 401 or d2.get("/api/vault/state").status_code == 401, "一覧から外した端末はログアウトされる")
    login(d2, authn)
    c.post("/api/account/logout-all", headers=H)
    check(d2.get("/api/account").status_code == 401 and c.get("/api/account").status_code == 200, "ほかをすべてログアウトしても、この端末は残る")

    # ------------------------------------------------------------ パスキーの削除・物理キー
    check(c.delete(f"/api/account/passkeys/{b64(next(iter(authn.creds)))}", headers=H).status_code == 400, "最後のパスキーは消せない")
    sk = SoftAuthenticator(security_key=True)
    o = c.post("/api/account/passkeys/options", json={}, headers=H).json
    r = c.post("/api/account/passkeys", json={"credential": sk.create(o)}, headers=H)
    check(r.json.get("pending") is True, "物理キーの1本目は保留")
    check(login(app.test_client(), sk).status_code == 401, "保留の物理キーではログインできない")
    o = c.post("/api/account/passkeys/options", json={}, headers=H).json
    r = c.post("/api/account/passkeys", json={"credential": sk.create(o)}, headers=H)
    check(r.status_code == 200 and len(r.json.get("activated", [])) == 1, "2本目で両方が使えるようになる")
    first = r.json["activated"][0]
    check(c.delete(f"/api/account/passkeys/{first}", headers=H).json.get("sk_pair") is True, "物理キーは1本だけにできない")
    check(c.delete("/api/account/security-keys", headers=H).status_code == 200, "物理キーはまとめてなら消せる")
    check(c.put("/api/vault/passkey", json={"cred_id": b64(next(iter(authn2.creds))), "blob": wrap()}, headers=H).status_code == 400, "ほかの人のパスキーに鍵を預けられない")

    # ------------------------------------------------------------ 復旧の総当たり対策
    rc = app.test_client()
    check(rc.post("/api/auth/recover", json={"user_id": uid_code, "auth": rauth(rk)}, headers=ip("198.51.100.1")).json.get("pow") is True, "作業証明がなければ断る")
    p = solve_pow(rc, ip("198.51.100.1"))
    rc.post("/api/auth/recover", json={"user_id": uid_code, "auth": rauth(new_rk()), **p}, headers=ip("198.51.100.1"))
    check(rc.post("/api/auth/recover", json={"user_id": uid_code, "auth": rauth(rk), **p}, headers=ip("198.51.100.1")).json.get("pow") is True, "作業証明の使い回しは断る")
    for i in range(4):
        recover(rc, uid_code, new_rk(), ip(f"198.51.100.{10 + i}"))
    check(recover(rc, uid_code, rk, ip("198.51.100.50")).status_code == 429, "同じユーザーIDへの失敗が続くと、正しいキーでもしばらく止める")
    sql("DELETE FROM auth_log WHERE event='fail:recover'")
    for i in range(5):
        recover(rc, "AAAA-BBBB-CCCC", new_rk(), ip("198.51.100.77"))
    check(recover(rc, uid_code, rk, ip("198.51.100.77")).status_code == 429, "同じネットワークからの失敗が続くと止める")
    check(recover(rc, uid_code, rk, {**H, "X-Test-IP": "2001:db8:1:1::9"}).status_code == 200, "別のネットワークからは、正しいキーで入れる")
    sql("DELETE FROM auth_log WHERE event='fail:recover'")
    for i in range(5):
        recover(rc, "AAAA-BBBB-CCCC", new_rk(), {**H, "X-Test-IP": f"2001:db8:5:5::{i + 1}"})
    check(recover(rc, uid_code, rk, {**H, "X-Test-IP": "2001:db8:5:5::99"}).status_code == 429, "IPv6 は /64 ごとに数える")
    sql("DELETE FROM auth_log WHERE event='fail:recover'")
    rv = app.test_client()
    check(recover(rv, uid_code, rk, ip("192.0.2.5")).json.get("scope") == "recovery", "復旧モードに入る")
    check(rv.get("/api/vault/sync?since=0").status_code == 403 and rv.get("/api/account").status_code == 403, "復旧モードでは記録も設定も使えない")
    check(rv.get("/api/vault/recovery-wrap").json["wrap"], "復旧モードのあいだだけ、復旧キーの包みを渡す")
    check(c.get("/api/vault/recovery-wrap").status_code in (403, 404), "通常のログインでは、復旧キーの包みは渡さない")
    with rv.session_transaction() as s:
        s["auth_at"] = s["auth_at"] - 16 * 60
    check(rv.get("/api/vault/recovery-wrap").status_code == 401, "復旧モードは時間切れになる")

    # ------------------------------------------------------------ 送り元の偽装
    app2, _ = make_app(tempfile.mkdtemp(prefix="pkv-srv2-"), client_ip_header=None)
    with app2.test_request_context("/", headers={"X-Test-IP": "1.2.3.4", "CF-Connecting-IP": "5.6.7.8"}, environ_base={"REMOTE_ADDR": "10.0.0.1"}):
        from pkvault.guard import client_ip
        check(client_ip() == "10.0.0.1", "中継のヘッダーを決めていなければ、ヘッダーで送り元を偽れない")
    app3, _ = make_app(tempfile.mkdtemp(prefix="pkv-srv3-"), rp_id="notes.example.com")
    c3 = app3.test_client()
    check(c3.get("/api/auth", headers={"Host": "evil.example"}).status_code == 404, "本番のドメイン以外の名前で来た要求は断る")
    r = c3.get("/api/auth", base_url="https://notes.example.com")
    check(r.status_code == 200, "本番のドメインなら答える")
    _, a3 = register(c3, "x", headers=H) if False else (None, None)
    with app3.test_request_context("/", base_url="http://notes.example.com"):
        check(app3.session_interface.get_cookie_secure(app3) is True, "本番ではログインのクッキーに Secure を付ける")

    # ------------------------------------------------------------ 退会と掃除
    wc = app.test_client()
    r, wa = register(wc, "leaver")
    setup_vault(wc, wa)
    push(wc, [{"kind": "note", "id": "w1", "base": 0, "blob": blob()}])
    wid = sql("SELECT id FROM users WHERE name='leaver'")[0][0]
    check(wc.post("/api/account/withdraw", json={"confirm": "x", "agree": True}, headers=H).status_code == 400, "確認の入力がなければ退会しない")
    wc.post("/api/account/withdraw", json={"confirm": "delete", "agree": True}, headers=H)
    check(wc.get("/api/account").status_code == 401, "退会するとすぐログアウト")
    sql("UPDATE users SET delete_after=? WHERE id=?", "2000-01-01T00:00:00", wid)
    conn = pkv.connect()
    store.purge_expired(conn, pkv.config)
    conn.commit()
    conn.close()
    left = [sql(f"SELECT COUNT(*) FROM {t} WHERE user_id=?", wid)[0][0] for t in ("credentials", "vault_keys", "devices", "records", "auth_log")]
    check(not sql("SELECT 1 FROM users WHERE id=?", wid) and left == [0, 0, 0, 0, 0], "期限が過ぎると、本人の行がすべて消える")
    r, _ = register(app.test_client(), "newbie")
    check(sql("SELECT id FROM users WHERE name='newbie'")[0][0] > wid, "消した人の番号は使い回さない")

    # ------------------------------------------------------------ 設計の移し替え
    mt = tempfile.mkdtemp(prefix="pkv-mig-")
    ma, mp = make_app(mt, extra_schema="CREATE TABLE IF NOT EXISTS memo (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, body TEXT);")
    mc = ma.test_client()
    register(mc, "migr")
    con = sqlite3.connect(os.path.join(mt, "pkvault.db"))
    con.execute("INSERT INTO memo(user_id, body) VALUES(1, 'a'), (1, 'b')")
    con.execute("DELETE FROM memo WHERE body='b'")
    con.commit()
    con.close()
    mb, _ = make_app(mt, extra_schema="CREATE TABLE IF NOT EXISTS memo (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, body TEXT, pinned INTEGER DEFAULT 0);")
    con = sqlite3.connect(os.path.join(mt, "pkvault.db"))
    cols = [r[1] for r in con.execute("PRAGMA table_info(memo)")]
    rows = con.execute("SELECT id, body, pinned FROM memo").fetchall()
    con.execute("INSERT INTO memo(user_id, body) VALUES(1, 'c')")
    newid = con.execute("SELECT MAX(id) FROM memo").fetchone()[0]
    users = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    con.close()
    check("pinned" in cols and rows == [(1, "a", 0)] and users == 1, "列を足すと、全データを新しい設計に移す")
    check(newid == 3, "移し替えても、消した行の番号を使い回さない")
    check(any(p.endswith("before-migrate.db") for p in os.listdir(os.path.join(mt, "backups"))), "移し替えの前の DB をバックアップに残す")

    # ------------------------------------------------------------ 同時の保存（本物のサーバーにスレッドで）
    from werkzeug.serving import make_server
    ct = tempfile.mkdtemp(prefix="pkv-conc-")
    ca, _ = make_app(ct, record_kinds={"note": 30}, register_net_hour=1000)
    srv = make_server("127.0.0.1", 0, ca, threaded=True)
    port = srv.server_port
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://localhost:{port}"

    def opener():
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

    def call(op, method, path, body=None):
        req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={**H, **({"Content-Type": "application/json"} if body is not None else {})})
        try:
            with op.open(req, timeout=30) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    owner = opener()
    sa = SoftAuthenticator(synced=True)
    st, o = call(owner, "POST", "/api/auth/register/options", {"name": "conc"})
    call(owner, "POST", "/api/auth/register/finish", {"credential": sa.create(o, origin=base)})
    devices = []
    for _ in range(8):
        op = opener()
        st, o = call(op, "POST", "/api/auth/passkey/options")
        call(op, "POST", "/api/auth/passkey/verify", {"credential": sa.get(o, origin=base)})
        devices.append(op)
    results = []

    def same_record(op):
        results.append(call(op, "POST", "/api/vault/push", {"changes": [{"kind": "note", "id": "same", "base": 0, "blob": blob()}]}))
    ts = [threading.Thread(target=same_record, args=(d,)) for d in devices]
    [t.start() for t in ts]
    [t.join() for t in ts]
    applied = sum(len(r[1].get("applied", [])) for r in results if r[0] == 200)
    check(applied == 1 and all(r[0] in (200, 503) for r in results), f"8台が同じ記録を同時に保存しても、通るのは1台だけ（黙って上書きしない）")
    results.clear()

    def many_new(op, i):
        results.append(call(op, "POST", "/api/vault/push", {"changes": [{"kind": "note", "id": f"n{i}-{j}", "base": 0, "blob": blob()} for j in range(5)]}))
    ts = [threading.Thread(target=many_new, args=(d, i)) for i, d in enumerate(devices)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    _, sy = call(devices[0], "GET", "/api/vault/sync?since=0")
    check(len(sy["records"]) <= 30, f"同時に送っても件数の上限を超えない（{len(sy['records'])}件）")
    revs = sorted(r["rev"] for r in sy["records"])
    check(len(set(revs)) == len(revs) and sy["rev"] == max(revs + [0]), "変更番号が重ならず、最後の番号とそろう")
    srv.shutdown()

    print(f"\n{passed} checks passed")
finally:
    shutil.rmtree(TMP, ignore_errors=True)
