"""試験用のサーバー：部品だけを組み込んだ Flask を、空のデータで起動する（終わったらデータごと消す）

  .venv/Scripts/python tests/serve.py 8765        … http://localhost:8765 で待つ（試験の Node から使う）
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, send_from_directory  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

from pkvault import Config, PasskeyVault  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


def make_app(data_dir, **kw):
    app = Flask(__name__, static_folder=None)
    conf = dict(app_name="試験", data_dir=data_dir, record_kinds={"note": 200, "tag": 50}, crypto_prefix="test/v1",
                client_ip_header="X-Test-IP", acts=frozenset({"note:add", "note:edit"}), pow_bits=8, backup=False)
    conf.update(kw)
    pkv = PasskeyVault(app, Config(**conf))

    @app.get("/static/pkvault/<path:name>")
    def kit_static(name):
        return send_from_directory(os.path.join(ROOT, "static", "pkvault"), name)

    return app, pkv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    tmp = tempfile.mkdtemp(prefix="pkv-test-")
    app, _ = make_app(tmp, register_net_hour=1000, register_global_hour=1000, recover_net_15min=1000, recover_net_day=1000)
    srv = make_server("127.0.0.1", port, app, threaded=True)
    print(f"READY {port} {tmp}", flush=True)
    try:
        srv.serve_forever()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
