"""DB：表の設計・本人の行の削除・期限切れの掃除・毎日のバックアップ・設計の移し替え・起動時の用意"""
import os
import re
import sqlite3
import time
from datetime import datetime
from pathlib import Path

from .core import ago, connect, now

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, -- 番号は二度と使わない（削除した人の番号を、あとから登録した人に付けない）
  name TEXT NOT NULL,                   -- 表示名。重複してよい（アカウントはユーザーIDで区別する）
  handle BLOB NOT NULL UNIQUE,          -- WebAuthn の user.id（推測できないランダム値）
  recovery_hash TEXT,                   -- 復旧キーの照合用：HMAC(サーバー秘密鍵から作った鍵, ソルト＋端末で作った確認用の値)
  recovery_salt TEXT,
  recovery_created TEXT,
  uid_hash TEXT,                        -- ユーザーID（復旧に使う）の照合用 HMAC。平文は保存しない
  uid_enc TEXT,                         -- ユーザーIDを本人に表示するための暗号文（AES-GCM、鍵は secret.key から）
  sess_ver INTEGER DEFAULT 1,           -- 増やすと全端末のログインが無効になる
  suspended_until TEXT,                 -- 一時的な利用制限（この日時まで）
  banned INTEGER DEFAULT 0,             -- 利用停止
  delete_after TEXT,                    -- 退会手続き中：この日時を過ぎたら完全に削除
  login_count INTEGER DEFAULT 0, last_seen TEXT,
  terms_agreed TEXT,                    -- 利用規約に同意した版と日時
  rev INTEGER DEFAULT 0,                -- 預かった記録の変更番号（何か変わるたびに +1。端末は「ここまで持っている」で差分を受け取る）
  min_rev INTEGER DEFAULT 0,            -- これより前の削除の印は片付けた（これより古い端末は全件を受け取り直す）
  session_days INTEGER DEFAULT 30,      -- ログインを保つ期間（使わないままこの日数がたつとログアウト）。0＝毎回
  created TEXT NOT NULL, last_login TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS users_uid ON users(uid_hash);
CREATE TABLE IF NOT EXISTS credentials (  -- パスキー（公開鍵だけ。秘密鍵は利用者の端末から出ない）
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key BLOB NOT NULL,
  sign_count INTEGER DEFAULT 0,
  transports TEXT DEFAULT '',
  name TEXT DEFAULT '',
  backed_up INTEGER DEFAULT 0,          -- 同期するパスキーか（iCloud・Google など）
  aaguid TEXT DEFAULT '',               -- 保存先の種類（表示名に使う）
  kind TEXT DEFAULT '',                 -- 'security-key'＝物理キー（2本そろえて使う）
  pending INTEGER DEFAULT 0,            -- 物理キーの1本目（2本目が登録されるまで使えない）
  created TEXT NOT NULL, last_used TEXT
);
CREATE INDEX IF NOT EXISTS credentials_user ON credentials(user_id);
CREATE TABLE IF NOT EXISTS auth_log (     -- ログイン・設定の変更などの記録（本人の画面に出す。回数制限にも使う）
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  event TEXT NOT NULL,
  ip TEXT DEFAULT '', ua TEXT DEFAULT '', at TEXT NOT NULL,
  cred TEXT DEFAULT '', net TEXT DEFAULT '',
  detail TEXT DEFAULT '',               -- 操作の説明（端末で暗号化したもの。本人の画面でだけ開ける）
  country TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS auth_log_user ON auth_log(user_id, id);
CREATE INDEX IF NOT EXISTS auth_log_ev ON auth_log(event, at);
CREATE INDEX IF NOT EXISTS auth_log_net ON auth_log(net, at);
CREATE TABLE IF NOT EXISTS pow_used (token TEXT PRIMARY KEY, at INTEGER NOT NULL);  -- 使用済みの作業証明・チャレンジ
CREATE TABLE IF NOT EXISTS vault_keys (   -- データ鍵の包み（パスキーごと・復旧キー）。サーバーには開けない
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,                   -- 'passkey' / 'recovery'
  cred_id TEXT NOT NULL DEFAULT '',
  blob TEXT NOT NULL,
  created TEXT NOT NULL,
  PRIMARY KEY (user_id, kind, cred_id)
);
CREATE TABLE IF NOT EXISTS devices (      -- ログイン中の端末と、その端末に渡す割符（端末に置いたデータ鍵を開くのに要る）
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  share TEXT NOT NULL,
  ua TEXT DEFAULT '',
  created TEXT NOT NULL, last_seen TEXT
);
CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id);
CREATE TABLE IF NOT EXISTS records (      -- 端末で暗号化した記録（暗号文だけ）
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  id TEXT NOT NULL,
  ver INTEGER NOT NULL,                 -- 記録の版（保存のたびに +1。端末は「どの版を元に直したか」を送る）
  rev INTEGER NOT NULL,                 -- 変わったときの、その人の変更番号
  deleted INTEGER DEFAULT 0,            -- 消した印（ほかの端末に消したことを伝えるため、しばらく残す）
  blob TEXT,
  size INTEGER DEFAULT 0,
  updated TEXT NOT NULL,
  PRIMARY KEY (user_id, kind, id)
);
CREATE INDEX IF NOT EXISTS records_rev ON records(user_id, rev);
CREATE INDEX IF NOT EXISTS records_size ON records(user_id, size);
"""


def full_schema(cfg):
    return SCHEMA + "\n" + (cfg.extra_schema or "")


# ---------------------------------------------------------------- 本人の行の削除・掃除

def delete_user_rows(conn, uid, cfg):
    """アカウントを完全に消す（パスキー・鍵の包み・端末・記録は users からの連鎖で消える）。記録は持ち主とのつながりを外す"""
    if cfg.on_delete_user:
        cfg.on_delete_user(conn, uid)
    conn.execute("UPDATE auth_log SET user_id=NULL, detail='' WHERE user_id=?", (uid,))
    conn.execute("DELETE FROM users WHERE id=?", (uid,))


def purge_expired(conn, cfg):
    """退会から決まった日数を過ぎたアカウントの完全削除・期限切れの一時データの掃除"""
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA secure_delete=ON")
    for r in conn.execute("SELECT id FROM users WHERE delete_after IS NOT NULL AND delete_after<?", (now(),)).fetchall():
        delete_user_rows(conn, r[0], cfg)
    conn.execute("DELETE FROM credentials WHERE pending=1 AND created<?", (ago(minutes=30),))  # 2本目が来なかった物理キー
    conn.execute("DELETE FROM pow_used WHERE at<?", (int(time.time()) - 86400,))
    # 消した印は決まった日数で片付ける（それより長く開いていなかった端末は、全件を受け取り直す）
    old = ago(days=cfg.tombstone_days)
    for uid, mx in conn.execute("SELECT user_id, MAX(rev) FROM records WHERE deleted=1 AND updated<? GROUP BY user_id", (old,)).fetchall():
        conn.execute("DELETE FROM records WHERE user_id=? AND deleted=1 AND updated<?", (uid, old))
        conn.execute("UPDATE users SET min_rev=MAX(min_rev, ?) WHERE id=?", (mx, uid))
    # 使われなくなった端末（選べるいちばん長いログインの期間を過ぎたもの）の割符を消す
    conn.execute("DELETE FROM devices WHERE last_seen<?", (ago(days=max(cfg.session_days + (1,))),))
    conn.execute("DELETE FROM auth_log WHERE at<?", (ago(days=cfg.log_days),))


# ---------------------------------------------------------------- バックアップ
# 毎日の分（pkvault-YYYYMMDD.db）と、移し替えの前の分（それ以外）を別々に数えて古い順に消す

DAILY_RE = re.compile(r"^pkvault-\d{8}\.db$")


def backup_dir(db_path):
    return Path(db_path).parent / "backups"


def backup_to(db_path, dest):
    dest.parent.mkdir(mode=0o700, exist_ok=True)
    tmp = Path(f"{dest}.{os.getpid()}.tmp")
    src, out = sqlite3.connect(db_path, timeout=30), sqlite3.connect(tmp)
    try:
        src.backup(out)
    finally:
        out.close()
        src.close()
    tmp.chmod(0o600)
    os.replace(tmp, dest)


def daily_backup(db_path, cfg):
    dest = backup_dir(db_path) / f"pkvault-{datetime.now():%Y%m%d}.db"
    if cfg.backup and not dest.exists():
        backup_to(db_path, dest)
        rotate_backups(db_path, cfg)


def rotate_backups(db_path, cfg):
    files = sorted(backup_dir(db_path).glob("pkvault-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    daily = [p for p in files if DAILY_RE.match(p.name)]
    event = [p for p in files if not DAILY_RE.match(p.name)]
    for p in daily[cfg.backup_keep_daily:] + event[cfg.backup_keep_event:]:
        p.unlink(missing_ok=True)


# ---------------------------------------------------------------- 設計の移し替え
# 表の定義（SCHEMA ＋ アプリの extra_schema）を変えたら、起動時に今の DB と形を比べる。違っていれば、設計どおりの
# 新しい DB を作って全データを移し、件数と中身が同じことを確かめてから入れ替える。古い DB はバックアップに残す。
# 設計にない表・列は移さない。移せない（制約を満たさない）データがあれば、何も変えずに止まる（サーバーは起動しない）

def _shape(conn):
    """DB の形：表ごとの列（名前・型・NOT NULL・初期値・主キー）と並び・外部キー・索引。全文検索などの内部の表は除く"""
    vt = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND upper(sql) LIKE 'CREATE VIRTUAL%'")]
    shape = {}
    for name, typ, sql in conn.execute("SELECT name, type, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall():
        if any(name.startswith(v + "_") for v in vt):
            continue
        if typ == "table" and name not in vt:
            cols = tuple(tuple(r)[1:] for r in conn.execute(f'PRAGMA table_info("{name}")'))
            fks = tuple(tuple(r)[2:] for r in conn.execute(f'PRAGMA foreign_key_list("{name}")'))
            shape[("table", name)] = (cols, fks, bool(re.search(r"(?i)\bAUTOINCREMENT\b", sql or "")))
        elif sql:  # 仮想の表・索引（主キーなどで自動で作られる索引は sql がないので除く）
            shape[("vtable" if typ == "table" else typ, name)] = re.sub(r"\s+", " ", re.sub(r"(?i)\s+IF NOT EXISTS", "", sql)).strip()
    return shape


def _rows_of(conn, schema, table, cols):
    q = ",".join(f'"{c}"' for c in cols)
    return conn.execute(f'SELECT {q} FROM {schema}."{table}" ORDER BY {q}').fetchall()


def migrate_to_schema(db_path, cfg):
    """今の DB が設計と違えば、設計どおりの新しい DB に全データを移して入れ替える。移したら True"""
    schema = full_schema(cfg)
    ref = sqlite3.connect(":memory:")
    ref.executescript(schema)
    want = _shape(ref)
    ref.close()
    cur = sqlite3.connect(db_path, timeout=30)
    have = _shape(cur)
    if have == want:
        cur.close()
        return False
    cur.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # 書き込み途中のぶん（WAL）も本体へ
    cur.close()
    db_path = Path(db_path)
    new = db_path.with_name(db_path.name + ".new")
    for p in (new, Path(f"{new}-journal")):
        p.unlink(missing_ok=True)
    out = sqlite3.connect(new)
    try:
        out.executescript(schema)
        out.execute("ATTACH DATABASE ? AS old", (str(db_path),))
        old_cols = {name: {r[1] for r in out.execute(f'PRAGMA old.table_info("{name}")')} for (kind, name) in have if kind == "table"}
        moved = {}
        out.execute("BEGIN")
        for (kind, name), (cols, _fks, _ai) in [(k, v) for k, v in want.items() if k[0] == "table"]:
            if name not in old_cols:
                continue
            common = [c[0] for c in cols if c[0] in old_cols[name]]
            q = ",".join(f'"{c}"' for c in common)
            out.execute(f'INSERT INTO main."{name}" ({q}) SELECT {q} FROM old."{name}"')
            moved[name] = common
        # 使用済みの番号（AUTOINCREMENT）を引き継ぐ：削除した行の番号を、あとから使い回さないように
        if out.execute("SELECT 1 FROM old.sqlite_master WHERE name='sqlite_sequence'").fetchone():
            for name, seq in out.execute("SELECT name, seq FROM old.sqlite_sequence").fetchall():
                if name not in moved:
                    continue
                if out.execute("SELECT 1 FROM main.sqlite_sequence WHERE name=?", (name,)).fetchone():
                    out.execute("UPDATE main.sqlite_sequence SET seq=MAX(seq, ?) WHERE name=?", (seq, name))
                else:
                    out.execute("INSERT INTO main.sqlite_sequence(name, seq) VALUES(?, ?)", (name, seq))
        if cfg.on_migrated:
            cfg.on_migrated(out)
        out.execute("COMMIT")
        # 確かめる：移した表は、件数と中身（移した列のすべての行）が古い DB と同じ。外部キーと DB の整合性も
        for name, common in moved.items():
            if _rows_of(out, "main", name, common) != _rows_of(out, "old", name, common):
                raise RuntimeError(f"DB の移し替えで {name} の中身が一致しません")
        if out.execute("PRAGMA main.foreign_key_check").fetchall():
            raise RuntimeError("DB の移し替えで、持ち主のいない行が見つかりました")
        if out.execute("PRAGMA main.integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("DB の移し替えで、新しい DB の整合性の確認に失敗しました")
        out.execute("DETACH DATABASE old")
        out.close()
    except Exception:
        out.close()
        new.unlink(missing_ok=True)
        raise
    backup_to(db_path, backup_dir(db_path) / f"pkvault-{datetime.now():%Y%m%d-%H%M%S}-before-migrate.db")
    os.replace(new, db_path)
    for ext in ("-wal", "-shm"):
        Path(f"{db_path}{ext}").unlink(missing_ok=True)
    rotate_backups(db_path, cfg)
    return True


# ---------------------------------------------------------------- 起動時の用意

class _InitLock:
    """起動時の処理（DB の移し替えなど）を、同時に起動した複数のワーカーのうち1つずつ順に行うためのロック"""

    def __init__(self, folder):
        self.path = Path(folder) / ".pkvault-init.lock"

    def __enter__(self):
        self.f = os.fdopen(os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600), "r+")
        try:
            import fcntl
            fcntl.flock(self.f, fcntl.LOCK_EX)
        except ImportError:  # Windows
            import msvcrt
            while True:
                try:
                    msvcrt.locking(self.f.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    time.sleep(0.1)
        return self

    def __exit__(self, *_):
        self.f.close()


def init_db(db_path, cfg):
    db_path = Path(db_path)
    with _InitLock(db_path.parent):
        if db_path.exists():
            migrate_to_schema(db_path, cfg)
        conn = connect(db_path, timeout=30)
        conn.isolation_level = None
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(full_schema(cfg))
        conn.execute("BEGIN IMMEDIATE")
        purge_expired(conn, cfg)
        conn.execute("COMMIT")
        conn.close()
    for f in (db_path, db_path.parent / "secret.key"):  # DB とサーバー秘密鍵は、動かしている本人だけが読める
        try:
            f.chmod(0o600)
        except OSError:
            pass


_last_purge = {}


def periodic_purge(db_path, cfg):
    """1時間に1回：期限切れの掃除と、毎日のバックアップ"""
    key = str(db_path)
    if time.time() - _last_purge.get(key, 0) < 3600:
        return
    _last_purge[key] = time.time()
    try:
        conn = connect(db_path, timeout=10)
        purge_expired(conn, cfg)
        conn.commit()
        conn.close()
        daily_backup(db_path, cfg)
    except (sqlite3.Error, OSError):
        pass
