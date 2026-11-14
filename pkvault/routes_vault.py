"""データの鍵と暗号化した記録：鍵の包み（パスキー・復旧キー）と端末の割符・差分の受け渡し（同期）・保存（版の照合と上限）"""
import re
import time

from flask import Blueprint, g, jsonify, request, session

from .core import ago, cfg, db, msg, no_store, not_found, now, rows
from .guard import body, current_user, in_recovery, jstr, log_event, login_required, note_limit, recovery_allowed
from .ids import user_code
from .passkeys import AUTH_RE, WRAP_RE, put_recovery

bp = Blueprint("pkv_vault", __name__)


def has_vault(uid):
    return bool(db().execute("SELECT 1 FROM vault_keys WHERE user_id=? LIMIT 1", (uid,)).fetchone())


# ---------------------------------------------------------------- データ鍵の包み・端末の割符

@bp.get("/vault/state")
@login_required
def vault_state():
    """ログイン中の端末に要るもの：このログインに使ったパスキーの包みと、この端末の割符"""
    w = db().execute("SELECT blob FROM vault_keys WHERE user_id=? AND kind='passkey' AND cred_id=?",
                     (g.uid, session.get("cid") or "")).fetchone()
    dev = db().execute("SELECT id, share FROM devices WHERE id=? AND user_id=?", (session.get("dev") or "", g.uid)).fetchone()
    return no_store(jsonify(user=g.uid, has_vault=has_vault(g.uid), cred_id=session.get("cid") or "", wrap=w["blob"] if w else None,
                            device=dict(id=dev["id"], share=dev["share"]) if dev else None,
                            has_recovery=bool(current_user()["recovery_hash"])))


@bp.get("/vault/recovery-wrap")
@recovery_allowed
def vault_recovery_wrap():
    """復旧キーの包み：復旧モード（ユーザーID＋復旧キーの確認が済んだあいだ）だけ渡す"""
    if not in_recovery():
        return not_found()
    w = db().execute("SELECT blob FROM vault_keys WHERE user_id=? AND kind='recovery'", (g.uid,)).fetchone()
    return no_store(jsonify(user=g.uid, wrap=w["blob"] if w else None))


@bp.post("/vault/setup")
@login_required
def vault_setup():
    """初めての鍵の用意（アカウントを作った直後）：端末で作ったデータ鍵を、このログインのパスキーと新しい復旧キーで包んだものを預かる"""
    d = body()
    if has_vault(g.uid):
        return jsonify(error=msg("vault_exists")), 409
    cid, pw, rw, auth = jstr(d, "cred_id"), jstr(d, "passkey_wrap"), jstr(d, "recovery_wrap"), jstr(d, "recovery_auth")
    if not cid or cid != session.get("cid") or not WRAP_RE.match(pw) or not WRAP_RE.match(rw) or not AUTH_RE.match(auth):
        return jsonify(error="bad request"), 400
    db().execute("INSERT INTO vault_keys(user_id,kind,cred_id,blob,created) VALUES(?,'passkey',?,?,?)", (g.uid, cid, pw, now()))
    put_recovery(g.uid, auth, rw)
    log_event(g.uid, "vault:setup")
    db().commit()
    return jsonify(ok=True)


@bp.put("/vault/passkey")
@recovery_allowed
def vault_passkey():
    """パスキーを足したとき：そのパスキーで包んだデータ鍵を預かる（本人のパスキーで、登録が済んだものだけ）"""
    d = body()
    cid, blob = jstr(d, "cred_id"), jstr(d, "blob")
    if not WRAP_RE.match(blob) or not db().execute("SELECT 1 FROM credentials WHERE id=? AND user_id=? AND pending=0", (cid, g.uid)).fetchone():
        return jsonify(error="bad request"), 400
    db().execute("INSERT INTO vault_keys(user_id,kind,cred_id,blob,created) VALUES(?,'passkey',?,?,?) "
                 "ON CONFLICT(user_id,kind,cred_id) DO UPDATE SET blob=excluded.blob, created=excluded.created", (g.uid, cid, blob, now()))
    db().commit()
    return jsonify(ok=True)


@bp.put("/vault/recovery")
@login_required
def vault_recovery():
    """復旧を終えた直後の、新しい復旧キーの預け入れ（復旧キーがない状態のときだけ。ふだんの作り直しは /account/recovery）"""
    d = body()
    auth, blob = jstr(d, "auth"), jstr(d, "blob")
    if current_user()["recovery_hash"] or not AUTH_RE.match(auth) or not WRAP_RE.match(blob):
        return jsonify(error="bad request"), 400
    put_recovery(g.uid, auth, blob)
    log_event(g.uid, "recovery:regen")
    db().commit()
    return jsonify(ok=True, user_id=user_code(current_user()))


# ---------------------------------------------------------------- 暗号化した記録の受け渡し（同期）

RECORD_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
BLOB_RE = re.compile(r"^[A-Za-z0-9_-]+$")
ACT_RE = re.compile(r"^[a-z0-9_]+(:[a-z0-9_]+){0,3}$")
_push_hits = {}


def push_limited():
    t = time.time()
    hits = [x for x in _push_hits.get(g.uid, []) if t - x < 600]
    if len(_push_hits) > 10000:
        _push_hits.clear()
    _push_hits[g.uid] = hits + [t]
    return len(hits) >= cfg().push_per_10min


@bp.get("/vault/sync")
@login_required
def vault_sync():
    """差分：since より後に変わった記録（暗号文のまま）と、今の変更番号。古すぎる端末（消した印を片付けたあと）には全件を渡す"""
    since = request.args.get("since", 0, type=int) or 0
    since = min(max(since, 0), 2 ** 62)  # 変な値（負・とても大きい数）でも落ちない
    u = db().execute("SELECT rev, min_rev FROM users WHERE id=?", (g.uid,)).fetchone()
    full = since <= 0 or since < u["min_rev"]
    q = "SELECT kind, id, ver, rev, deleted, blob FROM records WHERE user_id=?" + ("" if full else " AND rev>?")
    recs = rows(db().execute(q + " ORDER BY rev", (g.uid,) if full else (g.uid, since)))
    if full:
        recs = [r for r in recs if not r["deleted"]]  # 全件を渡すときは、消した印は要らない
    return no_store(jsonify(rev=u["rev"], full=full, records=recs))


@bp.post("/vault/push")
@login_required
def vault_push():
    """端末で暗号化した記録を受け取る。版（base）が今の版と同じときだけ書き、違えば衝突として今の版を返す"""
    c, conf, d = db(), cfg(), body()
    changes, acts = d.get("changes"), d.get("acts", [])
    if not isinstance(changes, list) or not isinstance(acts, list) or len(changes) > conf.push_max or len(acts) > 50:
        return jsonify(error="bad request"), 400
    if push_limited():
        note_limit("push")
        return jsonify(error=msg("push_busy")), 429
    incoming = sum(len(x["blob"]) for x in changes if isinstance(x, dict) and isinstance(x.get("blob"), str))
    if incoming and c.execute("SELECT COALESCE(SUM(size),0) FROM records WHERE user_id=?", (g.uid,)).fetchone()[0] + incoming > conf.user_bytes_max:
        return jsonify(error=msg("bytes_full")), 400
    applied, conflicts, counts = [], [], {}
    rev = c.execute("SELECT rev FROM users WHERE id=?", (g.uid,)).fetchone()[0]
    for x in changes:
        if not isinstance(x, dict):
            return jsonify(error="bad request"), 400
        kind, rid, base, deleted, blob = x.get("kind"), x.get("id"), x.get("base"), x.get("deleted") is True, x.get("blob")
        if not isinstance(kind, str) or kind not in conf.record_kinds or not isinstance(rid, str) or not RECORD_ID_RE.match(rid) \
                or type(base) is not int or base < 0 or base > 2 ** 53 \
                or (not deleted and (not isinstance(blob, str) or not BLOB_RE.match(blob)
                                     or len(blob) > conf.blob_max.get(kind, conf.blob_max_default))):
            return jsonify(error="bad request"), 400
        cur = c.execute("SELECT ver, deleted, blob FROM records WHERE user_id=? AND kind=? AND id=?", (g.uid, kind, rid)).fetchone()
        have = cur["ver"] if cur else 0
        if base != have:
            conflicts.append(dict(kind=kind, id=rid, ver=have, deleted=bool(cur and cur["deleted"]), blob=cur["blob"] if cur else None))
            continue
        if not deleted and (not cur or cur["deleted"]):  # 新しく増える記録だけ、種類ごとの上限を確かめる
            if kind not in counts:
                counts[kind] = c.execute("SELECT COUNT(*) FROM records WHERE user_id=? AND kind=? AND deleted=0", (g.uid, kind)).fetchone()[0]
            if counts[kind] + 1 > conf.record_kinds[kind]:
                return jsonify(error=msg("count_full")), 400
            counts[kind] += 1
        if deleted and not cur:
            continue  # まだない記録の削除は、何もしない
        rev += 1
        c.execute("INSERT INTO records(user_id,kind,id,ver,rev,deleted,blob,size,updated) VALUES(?,?,?,?,?,?,?,?,?) "
                  "ON CONFLICT(user_id,kind,id) DO UPDATE SET ver=excluded.ver, rev=excluded.rev, deleted=excluded.deleted, "
                  "blob=excluded.blob, size=excluded.size, updated=excluded.updated",
                  (g.uid, kind, rid, have + 1, rev, 1 if deleted else 0, None if deleted else blob, 0 if deleted else len(blob), now()))
        applied.append(dict(kind=kind, id=rid, ver=have + 1, rev=rev))
    c.execute("UPDATE users SET rev=? WHERE id=?", (rev, g.uid))
    if conf.acts:
        room = conf.acts_per_min - c.execute("SELECT COUNT(*) FROM auth_log WHERE user_id=? AND event LIKE 'act:%' AND at>=?",
                                             (g.uid, ago(seconds=60))).fetchone()[0]
        for a in acts[:max(0, room)]:  # 操作の記録：種類は読める形、対象（題名など）は端末で暗号化した説明
            if isinstance(a, dict) and isinstance(a.get("event"), str) and a["event"] in conf.acts and ACT_RE.match(a["event"]):
                det = a.get("detail")
                det = det if isinstance(det, str) and BLOB_RE.match(det or "-") and len(det) <= 1200 else ""
                log_event(g.uid, "act:" + a["event"], "", det)
    c.commit()
    return jsonify(rev=rev, applied=applied, conflicts=conflicts)
