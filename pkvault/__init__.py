"""pkvault — パスキーだけでログインし、中身は端末で暗号化して預かる仕組み（Flask に組み込む開発用の部品）

    from flask import Flask
    from pkvault import PasskeyVault, Config

    app = Flask(__name__)
    pkv = PasskeyVault(app, Config(app_name="メモ帳", record_kinds={"note": 5000}, crypto_prefix="memo/v1"))

    @app.get("/api/hello")
    @pkv.login_required
    def hello():
        return {"user": pkv.user_id()}

組み込むと：
  - {api_prefix}/auth…・/account…・/vault… の API が増える（routes_*.py）
  - {api_prefix}/ の下の変更系の要求は、ヘッダー {csrf_header}: 1 が必須になる（アプリの API も守られる）
  - ログインのクッキーは部品が管理する（app.session を使う）
"""
import sqlite3
from datetime import timedelta
from pathlib import Path

from flask import g, jsonify, request

from . import guard, store
from .config import Config
from .core import EXT, KitSession, close_db, connect, db_busy, load_secret, not_found
from .routes_account import bp as account_bp
from .routes_auth import bp as auth_bp
from .routes_vault import bp as vault_bp

__all__ = ["PasskeyVault", "Config"]
__version__ = "1.0.0"


class PasskeyVault:
    def __init__(self, app=None, config=None, **kw):
        self.config = config or Config(**kw)
        self.db_path = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        c = self.config
        if not c.api_prefix.startswith("/") or c.api_prefix.endswith("/"):
            raise ValueError("api_prefix は / で始まり、/ で終わらない形にしてください（例 /api）")
        if c.session_days_default not in c.session_days:
            raise ValueError("session_days_default は session_days の中から選んでください")
        data = Path(c.data_dir)
        data.mkdir(parents=True, exist_ok=True)
        self.db_path = data / c.db_name
        if not app.secret_key:
            app.secret_key = load_secret(data)
        app.session_interface = KitSession()
        app.config.update(
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE="Lax",
            SESSION_COOKIE_SECURE=bool(c.rp_id),  # 本番（ドメインを決めたとき）は、HTTPS の通信でだけクッキーを送らせる
            SESSION_COOKIE_NAME=c.cookie_name,
            PERMANENT_SESSION_LIFETIME=timedelta(days=max(tuple(c.session_days) + (1,))),
        )
        app.config.setdefault("MAX_CONTENT_LENGTH", 20 * 1024 * 1024)
        app.extensions[EXT] = self
        app.teardown_appcontext(close_db)
        # 順番に意味がある：掃除 → CSRF の確認 → ホスト名の確認
        app.before_request(lambda: store.periodic_purge(self.db_path, c))
        app.before_request(guard.csrf_check)
        app.before_request(guard.host_check)
        app.register_error_handler(sqlite3.OperationalError, db_busy)

        def api_404(e):
            # 部品の API の場所では、405（場所はあるが使い方が違う）も 404 と同じ形にする（ある・ないを見分けられないように）
            if request.path.startswith(c.api_prefix + "/"):
                return not_found()
            return e
        app.register_error_handler(404, api_404)
        app.register_error_handler(405, api_404)
        for bp in (auth_bp, account_bp, vault_bp):
            app.register_blueprint(bp, url_prefix=c.api_prefix)
        store.init_db(self.db_path, c)

    # ---- アプリから使う道具
    login_required = staticmethod(guard.login_required)
    recent_auth_required = staticmethod(guard.recent_auth_required)

    @staticmethod
    def current_user():
        """ログイン中の人（users の行の辞書）。復旧モードのときも返るので、アプリの API には login_required を使うこと"""
        return guard.current_user()

    @staticmethod
    def user_id():
        """login_required の中で：本人の番号"""
        return g.uid

    @staticmethod
    def db():
        """この要求の DB の接続（アプリの表を extra_schema で同じ DB に置いたとき）"""
        from .core import db
        return db()

    @staticmethod
    def json_error(text, code=400):
        return jsonify(error=text), code

    def connect(self):
        """要求の外（管理の道具・定期の処理など）で DB を開く"""
        return connect(self.db_path)

    def set_block(self, uid, banned=None, suspended_until=None):
        """利用停止・一時的な制限（管理の道具から）。どちらもすべての端末のログインを切る"""
        conn = self.connect()
        try:
            if banned is not None:
                conn.execute("UPDATE users SET banned=? WHERE id=?", (1 if banned else 0, uid))
            if suspended_until is not None:
                conn.execute("UPDATE users SET suspended_until=? WHERE id=?", (suspended_until or None, uid))
            conn.execute("UPDATE users SET sess_ver=sess_ver+1 WHERE id=?", (uid,))
            conn.execute("DELETE FROM devices WHERE user_id=?", (uid,))
            conn.commit()
        finally:
            conn.close()
