"""ログイン：状態の確認・規約への同意・パスキーでログイン・復旧（ユーザーID＋復旧キー）・ログアウト・新規登録"""
import hmac
import re
import secrets

from flask import Blueprint, current_app, jsonify, session
from webauthn import generate_authentication_options, options_to_json, verify_authentication_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import UserVerificationRequirement

from .core import cfg, db, epoch, msg, not_found, now
from .guard import (account_block, body, client_net, count_log, current_user, fail, in_recovery, jstr, log_event,
                    login_required, start_session)
from .ids import uid_lookup_hash
from .passkeys import (AUTH_RE, app_json, create_user, cred_dict, expected_origin, no_passkey, passkey_available,
                       pow_ok, pow_token, put_challenge, recovery_digest, registration_options, rp_id, store_credential,
                       take_challenge, user_public, verify_new_credential, welcome)

bp = Blueprint("pkv_auth", __name__)


@bp.get("/auth")
def auth_state():
    c = cfg()
    u = current_user()
    out = dict(ok=bool(u), user=user_public(u) if u else None, scope=session.get("scope") if u else None,
               passkey=passkey_available(), register=c.open_registration, terms=c.terms_version,
               kit=dict(prefix=c.crypto_prefix, session_days=list(c.session_days)))
    if c.terms_version:  # 規約を改定したあと、まだ確かめていない人にはお知らせを出す
        out["terms_update"] = bool(u) and not (u["terms_agreed"] or "").startswith(c.terms_version + " ")
    return jsonify(out)


@bp.post("/account/terms")
@login_required
def account_terms():
    """改定した利用規約を確かめた（同意した版と日時を記録）"""
    if not cfg().terms_version:
        return not_found()
    if body().get("agree") is not True:
        return jsonify(error=msg("agree_needed")), 400
    db().execute("UPDATE users SET terms_agreed=? WHERE id=?", (f"{cfg().terms_version} {now()}", current_user()["id"]))
    db().commit()
    return jsonify(ok=True)


# ---------------------------------------------------------------- パスキーでログイン（本人確認も同じ）

@bp.post("/auth/passkey/options")
def passkey_login_options():
    if not passkey_available():
        return no_passkey()
    opts = generate_authentication_options(rp_id=rp_id(), user_verification=UserVerificationRequirement.REQUIRED)
    put_challenge("auth", opts.challenge)
    return app_json(options_to_json(opts))


@bp.post("/auth/passkey/verify")
def passkey_login_verify():
    ch = take_challenge("auth")
    if not ch:
        return jsonify(error=msg("timeout")), 400
    if count_log("fail:passkey", 10, net=client_net()) >= cfg().passkey_fail_10min:
        return jsonify(error=msg("too_many")), 429
    cred = cred_dict(body())
    c = db().execute("SELECT * FROM credentials WHERE id=?", (jstr(cred, "id"),)).fetchone()
    if not c:
        return fail("fail:passkey", msg("unknown_passkey"))
    if c["pending"]:
        return fail("fail:passkey", msg("pending_key"))
    u = dict(db().execute("SELECT * FROM users WHERE id=?", (c["user_id"],)).fetchone())
    resp = cred.get("response")
    uh = resp.get("userHandle") if isinstance(resp, dict) else None
    try:
        handle_ok = not uh or base64url_to_bytes(uh) == u["handle"]
    except Exception:  # noqa: BLE001 — 壊れた値
        handle_ok = False
    if not handle_ok:
        return fail("fail:passkey", msg("handle_mismatch"))
    try:
        v = verify_authentication_response(
            credential=cred, expected_challenge=base64url_to_bytes(ch["c"]), expected_rp_id=rp_id(),
            expected_origin=expected_origin(), credential_public_key=c["public_key"],
            credential_current_sign_count=c["sign_count"], require_user_verification=True)
    except Exception as e:  # noqa: BLE001 — 検証の失敗はすべて同じ扱い
        current_app.logger.warning("passkey verification failed: %s", type(e).__name__)  # 利用者には出さず、サーバーの記録にだけ残す
        return fail("fail:passkey", msg("verify_failed"))
    db().execute("UPDATE credentials SET sign_count=?, last_used=? WHERE id=?", (v.new_sign_count, now(), c["id"]))
    block = account_block(u, withdrawing_ok=True)
    if block:
        log_event(u["id"], "login:blocked", c["name"])
        db().commit()
        return jsonify(error=block), 403
    me = current_user()
    if me and me["id"] == u["id"] and not in_recovery():
        session["auth_at"] = epoch()  # 本人確認（重要な操作の前）。ログインは作り直さない
        log_event(u["id"], "reauth", c["name"])
        db().commit()
        return jsonify(ok=True, user=user_public(u), reauth=True)
    cancelled = bool(u["delete_after"])  # 退会手続き中に本人がパスキーでログインしたら、退会を取り消す
    if cancelled:
        db().execute("UPDATE users SET delete_after=NULL WHERE id=?", (u["id"],))
        log_event(u["id"], "withdraw:cancel", c["name"])
    start_session(u, "passkey", cred=c["name"], cred_id=c["id"])
    db().commit()
    return jsonify(ok=True, user=user_public(u), withdraw_cancelled=cancelled)


# ---------------------------------------------------------------- 復旧（ユーザーID＋復旧キー）

@bp.get("/auth/pow")
def pow_challenge():
    token, bits = pow_token()
    return jsonify(token=token, bits=bits)


@bp.post("/auth/recover")
def recover():
    """ユーザーID＋復旧キーで「復旧モード」に入る。できるのは新しいパスキーの登録だけ（期限つき）。
    登録が済むと：復旧キーは使用済みになり、ほかの端末はすべてログアウト、退会手続き中なら取り消し"""
    c, d, net = cfg(), body(), client_net()
    # 1) 大規模な攻撃中は受付を止める  2) ネットワーク単位の制限  3) 作業証明  4) ID 単位の制限
    if count_log("fail:recover", 60) >= c.recover_global_hour:
        return jsonify(error=msg("recover_paused")), 503
    if count_log("fail:recover", 15, net=net) >= c.recover_net_15min or count_log("fail:recover", 1440, net=net) >= c.recover_net_day:
        return jsonify(error=msg("too_many")), 429
    if not pow_ok(d.get("pow_token"), d.get("pow_nonce")):
        return jsonify(error=msg("pow_failed"), pow=True), 400
    uid_h = uid_lookup_hash(jstr(d, "user_id")[:64])
    acct = uid_h[:16]
    if count_log("fail:recover", 60, cred=acct) >= c.recover_account_hour:
        db().commit()
        return jsonify(error=msg("recover_account_locked")), 429
    u = db().execute("SELECT * FROM users WHERE uid_hash=?", (uid_h,)).fetchone()
    salt = u["recovery_salt"] if u and u["recovery_salt"] else "x"
    auth = jstr(d, "auth")[:64]
    ok = bool(AUTH_RE.match(auth)) and hmac.compare_digest(
        recovery_digest(salt, auth), u["recovery_hash"] if u and u["recovery_hash"] else "0" * 64)
    if not (u and u["recovery_salt"] and ok):
        return fail("fail:recover", msg("recover_wrong"), cred=acct)
    u = dict(u)
    block = account_block(u, withdrawing_ok=True)
    if block:
        db().commit()
        return jsonify(error=block), 403
    start_session(u, "recovery", scope="recovery")
    log_event(u["id"], "recovery:start")
    db().commit()
    return jsonify(ok=True, user=user_public(u), scope="recovery", withdrawing=bool(u["delete_after"]))


@bp.post("/auth/logout")
def logout():
    u = current_user()
    if u:
        log_event(u["id"], "logout")
        db().execute("DELETE FROM devices WHERE id=? AND user_id=?", (session.get("dev") or "", u["id"]))
        db().commit()
    session.clear()
    return jsonify(ok=True)


# ---------------------------------------------------------------- 新規登録

@bp.post("/auth/register/options")
def register_options():
    c = cfg()
    if not c.open_registration:
        return not_found()
    if not passkey_available():
        return no_passkey()
    d = body()
    # 乱用対策：同じネットワークから・全体での1時間あたりの件数
    if count_log("register", 60, net=client_net()) >= c.register_net_hour or count_log("register", 60) >= c.register_global_hour:
        return jsonify(error=msg("register_busy")), 429
    name = jstr(d, "name").strip()
    if not re.match(c.name_pattern, name):
        return jsonify(error=c.name_error), 400
    if c.terms_version and d.get("agree") is not True:
        return jsonify(error=msg("agree_needed")), 400
    if c.register_check:
        err = c.register_check(d)
        if err:
            return jsonify(error=err), 400
    handle = secrets.token_bytes(32)
    opts = registration_options(name, handle, (), d.get("hint"))
    put_challenge("register", opts.challenge, name=name, handle=bytes_to_base64url(handle))
    return app_json(options_to_json(opts))


@bp.post("/auth/register/finish")
def register_finish():
    if not cfg().open_registration:
        return not_found()
    ch = take_challenge("register")
    if not ch:
        return jsonify(error=msg("timeout")), 400
    d = body()
    cj = cred_dict(d)
    try:
        v = verify_new_credential(cj, ch["c"])
    except Exception as e:  # noqa: BLE001
        current_app.logger.warning("passkey registration failed: %s", type(e).__name__)
        return jsonify(error=msg("register_failed")), 400
    user, code = create_user(ch["name"], base64url_to_bytes(ch["handle"]))
    cname = store_credential(user["id"], v, cj, d.get("device"))
    return welcome(user, code, cname, jstr(cj, "id"), "register")
