"""自分のアカウント：表示・名前・ログインを保つ期間・パスキー（追加・名前・削除）・復旧キーの作り直し・ログイン中の端末・退会"""
import re
from datetime import datetime, timedelta

from flask import Blueprint, current_app, g, jsonify, session
from webauthn import options_to_json

from .core import cfg, db, epoch, msg, now, rows
from .guard import (apply_session_days, body, current_user, drop_devices, in_recovery, jstr, log_event, login_required,
                    recent_auth_required, recovery_allowed, session_days_of, start_session)
from .ids import user_code
from .passkeys import (AUTH_RE, WRAP_RE, app_json, cred_dict, is_security_key, no_passkey, passkey_available,
                       provider_name, put_challenge, put_recovery, registration_options, store_credential,
                       take_challenge, user_public, verify_new_credential)

bp = Blueprint("pkv_account", __name__)

LOG_DEFAULT = 30


def _account_json():
    u = current_user()
    creds = rows(db().execute("SELECT id, name, created, last_used, backed_up, transports, aaguid, kind FROM credentials "
                              "WHERE user_id=? AND pending=0 ORDER BY created", (g.uid,)))
    for c in creds:
        c["provider"] = provider_name(c.pop("aaguid"))
        c["vault"] = bool(db().execute("SELECT 1 FROM vault_keys WHERE user_id=? AND kind='passkey' AND cred_id=?", (g.uid, c["id"])).fetchone())
    total = db().execute("SELECT COUNT(*) FROM auth_log WHERE user_id=?", (g.uid,)).fetchone()[0]
    log = rows(db().execute("SELECT event, ua, at, cred, ip, country, detail FROM auth_log WHERE user_id=? ORDER BY id DESC LIMIT ?",
                            (g.uid, LOG_DEFAULT)))
    return jsonify(user=user_public(u), user_id=user_code(u), passkeys=creds,
                   has_recovery=bool(u["recovery_hash"]), recovery_created=u["recovery_created"], created=u["created"],
                   scope=session.get("scope"), log=log, log_total=total, passkey=passkey_available(),
                   session_days=session_days_of(u), session_choices=list(cfg().session_days),
                   current_cred=session.get("cid") or "")


@bp.get("/account")
@login_required
def account():
    return _account_json()


@bp.get("/account/recovery-view")
@recovery_allowed
def account_recovery_view():
    return _account_json()


@bp.get("/account/log")
@login_required
def account_log():
    return jsonify(rows(db().execute("SELECT event, ua, at, cred, ip, country, detail FROM auth_log WHERE user_id=? "
                                     "ORDER BY id DESC LIMIT 2000", (g.uid,))))


@bp.put("/account/name")
@login_required
def rename_account():
    """表示名はいつでも変えてよい（復旧にはユーザーIDを使うので、名前が変わっても困らない）"""
    name = jstr(body(), "name").strip()
    if not re.match(cfg().name_pattern, name):
        return jsonify(error=cfg().name_error), 400
    db().execute("UPDATE users SET name=? WHERE id=?", (name, g.uid))
    log_event(g.uid, "rename")
    db().commit()
    return jsonify(ok=True, account=name)


@bp.put("/account/session")
@login_required
def set_session_days():
    """ログインを保つ期間。短くするのはすぐ、長くするのはパスキーでの本人確認のあと
    （クッキーを盗んだ人が、期間を延ばして長く居座れないように）。変えると、すべての端末のログインに効く"""
    choices = tuple(cfg().session_days)
    days = body().get("days")
    if type(days) is not int or days not in choices:
        return jsonify(error="bad request"), 400
    cur = session_days_of(current_user())
    longer = sorted(choices).index(days) > sorted(choices).index(cur)
    if longer and epoch() - session.get("auth_at", 0) > cfg().reauth_window:
        return jsonify(error="reauth", message=msg("reauth")), 403
    db().execute("UPDATE users SET session_days=? WHERE id=?", (days, g.uid))
    apply_session_days(days)
    log_event(g.uid, "session:days")
    db().commit()
    return jsonify(ok=True, session_days=days)


# ---------------------------------------------------------------- パスキー

@bp.post("/account/passkeys/options")
@recovery_allowed
def add_passkey_options():
    if not passkey_available():
        return no_passkey()
    u = current_user()
    exclude = rows(db().execute("SELECT id, transports FROM credentials WHERE user_id=?", (g.uid,)))
    opts = registration_options(u["name"], u["handle"], exclude, body().get("hint"))
    put_challenge("add", opts.challenge)
    return app_json(options_to_json(opts))


@bp.post("/account/passkeys")
@recovery_allowed
def add_passkey():
    ch = take_challenge("add")
    if not ch:
        return jsonify(error=msg("timeout")), 400
    d = body()
    cj = cred_dict(d)
    try:
        v = verify_new_credential(cj, ch["c"])
    except Exception as e:  # noqa: BLE001
        current_app.logger.warning("passkey registration failed: %s", type(e).__name__)
        return jsonify(error=msg("register_failed")), 400
    out = dict(ok=True)
    if is_security_key(cj):
        # 物理セキュリティキーは2本以上が必須：1本目は「保留」にして、2本目が登録できたら両方を有効にする
        active = db().execute("SELECT COUNT(*) FROM credentials WHERE user_id=? AND kind='security-key' AND pending=0", (g.uid,)).fetchone()[0]
        waiting = db().execute("SELECT id FROM credentials WHERE user_id=? AND kind='security-key' AND pending=1", (g.uid,)).fetchall()
        if active == 0 and not waiting:
            cname = store_credential(g.uid, v, cj, d.get("device"), kind="security-key", pending=True)
            log_event(g.uid, "passkey:add:pending", cname)
            db().commit()
            return jsonify(ok=True, pending=True, cred_id=jstr(cj, "id"), message=msg("first_key"))
        cname = store_credential(g.uid, v, cj, d.get("device"), kind="security-key")
        db().execute("UPDATE credentials SET pending=0 WHERE user_id=? AND kind='security-key' AND pending=1", (g.uid,))
        out["activated"] = [r["id"] for r in waiting]  # 2本目で使えるようになった1本目（端末はこれにも鍵を包んで預ける）
    else:
        cname = store_credential(g.uid, v, cj, d.get("device"))
    log_event(g.uid, "passkey:add", cname)
    out["cred_id"] = jstr(cj, "id")
    if in_recovery():
        # 復旧の完了：使った復旧キーはすぐに使えなくする（新しいキーは端末が作って /vault/recovery で預ける）。
        # ほかの端末はすべてログアウト（割符も消す）、退会手続きは取り消し
        db().execute("UPDATE users SET sess_ver=sess_ver+1, delete_after=NULL, recovery_hash=NULL, recovery_salt=NULL WHERE id=?", (g.uid,))
        db().execute("DELETE FROM vault_keys WHERE user_id=? AND kind='recovery'", (g.uid,))
        drop_devices(g.uid)
        u = dict(db().execute("SELECT * FROM users WHERE id=?", (g.uid,)).fetchone())
        out["user_id"] = user_code(u)
        log_event(g.uid, "recovery:done", cname)
        start_session(u, "recovery", cred=cname, cred_id=jstr(cj, "id"))
    db().commit()
    return jsonify(out)


@bp.put("/account/passkeys/<cid>")
@login_required
def rename_passkey(cid):
    name = jstr(body(), "name").strip()[:40]
    db().execute("UPDATE credentials SET name=? WHERE id=? AND user_id=?", (name or "パスキー", cid, g.uid))
    db().commit()
    return jsonify(ok=True)


@bp.delete("/account/passkeys/<cid>")
@recent_auth_required
def delete_passkey(cid):
    c = db().execute("SELECT kind FROM credentials WHERE id=? AND user_id=? AND pending=0", (cid, g.uid)).fetchone()
    if not c:
        return jsonify(error="not found"), 404
    left = db().execute("SELECT COUNT(*) FROM credentials WHERE user_id=? AND id<>? AND pending=0", (g.uid, cid)).fetchone()[0]
    if left == 0:
        return jsonify(error=msg("last_passkey")), 400
    if c["kind"] == "security-key":
        sk_left = db().execute("SELECT COUNT(*) FROM credentials WHERE user_id=? AND id<>? AND kind='security-key' AND pending=0",
                               (g.uid, cid)).fetchone()[0]
        if sk_left == 1:
            return jsonify(error=msg("sk_pair"), sk_pair=True), 400
    db().execute("DELETE FROM credentials WHERE id=? AND user_id=?", (cid, g.uid))
    db().execute("DELETE FROM vault_keys WHERE user_id=? AND kind='passkey' AND cred_id=?", (g.uid, cid))
    log_event(g.uid, "passkey:delete")
    db().commit()
    return jsonify(ok=True)


@bp.delete("/account/security-keys")
@recent_auth_required
def delete_security_keys():
    """セキュリティキーをまとめて削除（2本必須のため個別には消せないとき）"""
    others = db().execute("SELECT COUNT(*) FROM credentials WHERE user_id=? AND kind<>'security-key' AND pending=0", (g.uid,)).fetchone()[0]
    if others == 0:
        return jsonify(error=msg("sk_only")), 400
    db().execute("DELETE FROM vault_keys WHERE user_id=? AND kind='passkey' AND cred_id IN "
                 "(SELECT id FROM credentials WHERE user_id=? AND kind='security-key')", (g.uid, g.uid))
    db().execute("DELETE FROM credentials WHERE user_id=? AND kind='security-key'", (g.uid,))
    log_event(g.uid, "passkey:delete")
    db().commit()
    return jsonify(ok=True)


# ---------------------------------------------------------------- 復旧キー

@bp.post("/account/recovery")
@recent_auth_required
def regen_recovery():
    """復旧キーの作り直し：端末で作った新しいキーの「確認用の値」と、新しいキーで包んだデータ鍵を預かる。古いキーはここで使えなくなる"""
    d = body()
    auth, blob = jstr(d, "auth"), jstr(d, "blob")
    if not AUTH_RE.match(auth) or not WRAP_RE.match(blob):
        return jsonify(error="bad request"), 400
    put_recovery(g.uid, auth, blob)
    log_event(g.uid, "recovery:regen")
    db().commit()
    return jsonify(ok=True, user_id=user_code(current_user()))


# ---------------------------------------------------------------- ログイン中の端末

@bp.get("/account/devices")
@login_required
def account_devices():
    """ログイン中の端末の一覧（割符は出さない）"""
    out = rows(db().execute("SELECT id, ua, created, last_seen FROM devices WHERE user_id=? ORDER BY last_seen DESC", (g.uid,)))
    for x in out:
        x["current"] = x["id"] == session.get("dev")
    return jsonify(out)


@bp.delete("/account/devices/<dev>")
@login_required
def account_device_delete(dev):
    """1台だけログアウトさせる。その端末の割符を消すので、端末に置いたデータ鍵も開けなくなる"""
    if not db().execute("SELECT 1 FROM devices WHERE id=? AND user_id=?", (dev, g.uid)).fetchone():
        return jsonify(error="not found"), 404
    db().execute("DELETE FROM devices WHERE id=? AND user_id=?", (dev, g.uid))
    log_event(g.uid, "device:logout")
    db().commit()
    return jsonify(ok=True, current=dev == session.get("dev"))


@bp.post("/account/logout-all")
@login_required
def logout_all():
    """この端末以外を、すべてログアウトさせる"""
    db().execute("UPDATE users SET sess_ver=sess_ver+1 WHERE id=?", (g.uid,))
    session["ver"] = db().execute("SELECT sess_ver FROM users WHERE id=?", (g.uid,)).fetchone()[0]
    drop_devices(g.uid, keep=session.get("dev"))
    log_event(g.uid, "logout-all")
    db().commit()
    return jsonify(ok=True)


@bp.post("/account/withdraw")
@recent_auth_required
def withdraw():
    """退会：すぐにすべての端末でログアウトし、決まった日数のあとに完全削除。それまでにパスキーでログインすれば取り消せる"""
    d = body()
    if jstr(d, "confirm").strip() != "delete" or d.get("agree") is not True:
        return jsonify(error=msg("withdraw_confirm")), 400
    until = (datetime.now() + timedelta(days=cfg().withdraw_days)).isoformat(timespec="seconds")
    db().execute("UPDATE users SET delete_after=?, sess_ver=sess_ver+1 WHERE id=?", (until, g.uid))
    drop_devices(g.uid)
    log_event(g.uid, "withdraw")
    db().commit()
    session.clear()
    return jsonify(ok=True, delete_after=until)
