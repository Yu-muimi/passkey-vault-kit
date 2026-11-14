"""土台：部品の設定の取り出し・DB への接続・時刻・サーバー秘密鍵（とそこから作る用途ごとの鍵）・ログインのクッキー"""
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from flask import current_app, g, has_request_context, jsonify, request
from flask.sessions import SecureCookieSessionInterface

from .messages import message

EXT = "pkvault"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def kit():
    """組み込んだ部品（PasskeyVault）。設定は kit().config"""
    return current_app.extensions[EXT]


def cfg():
    return kit().config


def msg(key, **kw):
    return message(cfg(), key, **kw)


def now():
    return datetime.now().isoformat(timespec="seconds")


def ago(**kw):
    return (datetime.now() - timedelta(**kw)).isoformat(timespec="seconds")


def epoch():
    return int(datetime.now(timezone.utc).timestamp())


def rows(cur):
    return [dict(r) for r in cur]


def connect(path, timeout=10):
    conn = sqlite3.connect(path, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA secure_delete=ON")  # 消した行の中身を0で上書きする（ファイルの空き領域に中身を残さない）
    return conn


def db():
    """この要求の DB の接続（要求が終わると閉じる）。アプリの表も、同じ接続で読み書きしてよい"""
    if "_pkv_db" not in g:
        g._pkv_db = connect(kit().db_path)
        if has_request_context() and request.method not in SAFE_METHODS:
            # 書く要求は、最初に書き込みの鍵を取ってから読む（同時に届いた要求が同じ版・同じ件数を読んで、
            # 片方の保存を黙って上書きしたり、上限をすり抜けたりしないように）。読む要求は待たせない
            g._pkv_db.execute("BEGIN IMMEDIATE")
    return g._pkv_db


def close_db(_exc=None):
    conn = g.pop("_pkv_db", None)
    if conn:
        conn.close()


def subkey(label):
    """サーバー秘密鍵から、用途ごとの鍵を作る（ユーザーIDの照合・暗号化、復旧キーの照合、作業証明の署名）"""
    k = current_app.secret_key
    return hmac.new(k.encode() if isinstance(k, str) else k, label.encode(), hashlib.sha256).digest()


def load_secret(data_dir):
    """サーバー秘密鍵（data/secret.key）。なければ作る。複数のワーカーが同時に起動しても、作れるのは1つだけ（O_EXCL）"""
    path = data_dir / "secret.key"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    except FileExistsError:
        pass
    for _ in range(50):  # 別のワーカーが書き終えるのを待つ
        key = path.read_text().strip()
        if len(key) == 64:
            return key
        time.sleep(0.05)
    raise RuntimeError("secret.key を読めませんでした")


class KitSession(SecureCookieSessionInterface):
    # 本番（rp_id を決めたとき）は必ず、それ以外も https で開かれたときは Secure を付ける
    def get_cookie_secure(self, app):
        return bool(app.config.get("SESSION_COOKIE_SECURE")) or request.is_secure

    # クッキーが消える日時：本人が選んだ「ログインを保つ期間」（ttl）。使うたびに延びる。
    # 「毎回」（ttl=0）は permanent にしないので、ブラウザーを閉じると消えるクッキーになる
    def get_expiration_time(self, app, session):
        days = session.get("ttl")
        if session.permanent and isinstance(days, int) and days >= 1:
            return datetime.now(timezone.utc) + timedelta(days=days)
        return super().get_expiration_time(app, session)


def db_busy(e):
    """保存が集中して、書き込みの鍵を待ちきれなかったとき：エラー（500）ではなく「混み合っている」と答える。
    何も書かずに終わっている（途中まで書いたものも取り消し済み）ので、端末は少し待って送り直せばよい"""
    if "locked" not in str(e) and "busy" not in str(e):
        raise e
    resp = jsonify(error=msg("busy"))
    resp.headers["Retry-After"] = "1"
    return resp, 503


def not_found():
    """存在しない場所への応答（どこでも同じ形にして、ある・ないを見分けられないようにする）"""
    return jsonify(error="not found"), 404


def no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp
