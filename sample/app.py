"""見本：暗号化されたメモ帳（部品の組み込み方の見本）。メモの中身は端末で暗号化され、サーバーには暗号文だけが届く

  .venv/Scripts/python sample/app.py          … http://localhost:5180 （パスキーは localhost なら http でも使える）
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, send_from_directory  # noqa: E402

from pkvault import Config, PasskeyVault  # noqa: E402

HERE = Path(__file__).resolve().parent
KIT_STATIC = HERE.parent / "static" / "pkvault"

app = Flask(__name__, static_folder=str(HERE / "static"), static_url_path="/static")
pkv = PasskeyVault(app, Config(
    app_name="暗号メモ",
    data_dir=os.environ.get("SAMPLE_DATA", HERE / "data"),
    crypto_prefix="sample-notes/v1",            # このアプリだけのラベル（決めたら変えない）
    record_kinds={"note": 5000},                # 預かる記録の種類と、1人あたりの上限
    blob_max={"note": 200 * 1024},
    acts=frozenset({"note:add", "note:delete"}),  # 操作の記録（本人の画面にだけ出る）
    # 本番では：rp_id="memo.example.com", client_ip_header="CF-Connecting-IP", country_header="CF-IPCountry", require_ip_header=True
))


@app.after_request
def security_headers(resp):
    # 画面のスクリプトは自分のサイトのものだけ（ほかのサイトのスクリプトを読み込ませない）
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                               "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "publickey-credentials-get=(self), publickey-credentials-create=(self)"
    return resp


@app.get("/")
def index():
    return send_from_directory(HERE / "static", "index.html", max_age=0)


@app.get("/pkvault/<path:name>")
def kit_files(name):
    return send_from_directory(KIT_STATIC, name, max_age=0)


if os.environ.get("SAMPLE_TEST") == "1":
    # 画面の確かめだけ：試験用のパスキー（本物のパスキーのない環境で、ログインの流れを試す）。本番では配らない
    @app.get("/__test/soft-authenticator.mjs")
    def soft_authenticator():
        return send_from_directory(HERE.parent / "tests", "soft-authenticator.mjs", mimetype="text/javascript", max_age=0)


# アプリ自身の API の見本：ログインしている本人だけ（中身は暗号文なので、サーバーで分かるのは件数と大きさだけ）
@app.get("/api/usage")
@pkv.login_required
def usage():
    r = pkv.db().execute("SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS bytes FROM records WHERE user_id=? AND deleted=0",
                         (pkv.user_id(),)).fetchone()
    return {"notes": r["n"], "bytes": r["bytes"]}


if __name__ == "__main__":
    app.run("127.0.0.1", int(os.environ.get("PORT", 5180)), debug=False)
