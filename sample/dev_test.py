"""画面の確かめ用の起動：試験用のパスキーを配り、データは一時フォルダー（終わったら消える）"""
import os
import runpy
import shutil
import tempfile
from pathlib import Path

tmp = tempfile.mkdtemp(prefix="pkv-sample-")
os.environ.update(SAMPLE_TEST="1", SAMPLE_DATA=tmp)
try:
    runpy.run_path(str(Path(__file__).with_name("app.py")), run_name="__main__")
finally:
    shutil.rmtree(tmp, ignore_errors=True)
