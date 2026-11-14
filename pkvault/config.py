"""設定：部品を組み込むアプリごとに変える値。ここにない値は、部品の中で決めている（変えないほうが安全なもの）"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


# よく使われるパスキーの保存先（AAGUID → 表示名）。attestation なしでも多くの環境で送られてくる
PROVIDERS = {
    "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google パスワードマネージャー",
    "adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome（Mac）",
    "fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud キーチェーン",
    "dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud キーチェーン",
    "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
    "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
    "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
    "53414d53-554e-4700-0000-000000000000": "Samsung Pass",
    "bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
    "d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
}


@dataclass
class Config:
    # ---- アプリの名前と場所
    app_name: str = "My App"              # パスキーの画面に出る名前（RP の名前）
    rp_id: Optional[str] = None           # 本番のドメイン（例 notes.example.com）。None なら開いたホスト名（開発用。localhost なら http でも動く）
    origin: Optional[str] = None          # 本番のオリジン。None なら https://{rp_id}（rp_id もなければ開いたアドレス）
    data_dir: str | Path = "data"         # DB・サーバー秘密鍵・バックアップを置くフォルダ
    db_name: str = "pkvault.db"
    api_prefix: str = "/api"              # 部品の API の場所（/api/auth、/api/vault/sync など）

    # ---- 端末とのやりとり
    csrf_header: str = "X-PKV"            # 変更系の API に必須のヘッダー（値は "1"）。端末の部品と合わせる
    cookie_name: str = "pkv_session"
    crypto_prefix: str = "pkvault/v1"     # 暗号のラベルの頭（アプリごとに変える。あとから変えると、預けた暗号文が開けなくなる）

    # ---- 預かる記録（暗号文）の種類と上限
    record_kinds: dict = field(default_factory=lambda: {"item": 10000})  # 種類 → 1人あたりの件数の上限
    blob_max: dict = field(default_factory=dict)  # 種類 → 1件の暗号文の上限（base64url の文字数）
    blob_max_default: int = 400 * 1024
    user_bytes_max: int = 100 * 1024 * 1024       # 1人が預けられる暗号文の合計
    push_max: int = 500                           # 1回に送れる件数
    push_per_10min: int = 1200                    # 送信の回数の上限（10分あたり・1人）
    acts: frozenset = frozenset()                 # 操作の記録として受け付ける種類（例 {"item:add"}）。空なら記録しない
    acts_per_min: int = 120

    # ---- ログイン
    session_days: tuple = (0, 1, 7, 30)  # 本人が選べる「ログインを保つ期間」（日）。0＝毎回（ブラウザーを閉じるまで）
    session_days_default: int = 30
    session_max_days: int = 90           # 使い続けていても、ログインからこの日数で再ログイン
    every_time_idle_days: int = 1        # 「毎回」でも、使わないままこの日数で必ず切る
    reauth_window: int = 15 * 60         # 重要な操作は、直近この秒数以内に本人確認していること
    recovery_ttl: int = 15 * 60          # 復旧モードの長さ（秒）
    challenge_ttl: int = 300
    withdraw_days: int = 30              # 退会してから完全に消すまでの日数（そのあいだはパスキーでログインすると取り消せる）
    name_pattern: str = r"^[A-Za-z0-9]{2,20}$"
    name_error: str = "名前は英数字（半角）2〜20文字にしてください"
    terms_version: Optional[str] = None  # 利用規約の版。決めると、登録に同意が必須になり、改定したら知らせる
    open_registration: bool = True       # だれでも登録できるか
    register_check: Optional[Callable] = None  # 登録の前の追加の確認（招待コードなど）。fn(body) → エラーの文 か None

    # ---- 接続元（回数制限の単位）
    client_ip_header: Optional[str] = None  # 前に置いた中継（Cloudflare など）が付ける接続元のヘッダー（例 "CF-Connecting-IP"）。
                                            # 中継がないのに決めると、だれでも偽れるので決めないこと
    country_header: Optional[str] = None    # 例 "CF-IPCountry"
    require_ip_header: bool = False         # True なら、上のヘッダーのない要求を断る（中継を通らない直接の接続を断る）

    # ---- 総当たり・乱用の対策
    pow_bits: int = 16                   # 復旧の作業証明の基本の難しさ（ブラウザで1〜2秒）
    pow_ttl: int = 600
    recover_net_15min: int = 5           # 同じネットワーク（IPv6 は /64）から15分にこの回数失敗 → 待ち
    recover_net_day: int = 20            # 同じネットワークから1日にこの回数失敗 → 24時間止める
    recover_account_hour: int = 5        # 同じユーザーIDへの失敗が1時間にこの回数 → そのIDの復旧を1時間止める
    recover_global_hour: int = 500       # 全体で1時間にこの回数失敗 → 復旧の受付を一時停止
    register_net_hour: int = 3
    register_global_hour: int = 30
    passkey_fail_10min: int = 10

    # ---- DB の掃除とバックアップ
    tombstone_days: int = 90             # 消した印を残す日数（これより長く開いていなかった端末は全件を受け取り直す）
    log_days: int = 400
    backup: bool = True                  # 毎日のバックアップ（data/backups）
    backup_keep_daily: int = 14
    backup_keep_event: int = 10

    # ---- アプリの表（同じ DB に置く場合）とつなぎ口
    extra_schema: str = ""               # アプリの表の CREATE 文（部品の表と同じく、起動時に設計どおりへ移し替える）
    on_delete_user: Optional[Callable] = None  # fn(conn, uid)：完全に消すとき、アプリの表から本人の行を消す
    on_migrated: Optional[Callable] = None     # fn(conn)：設計を移し替えたあと（全文検索の作り直しなど）
    providers: dict = field(default_factory=lambda: dict(PROVIDERS))
    messages: dict = field(default_factory=dict)  # 画面に返す文の差し替え（キーは pkvault/messages.py）
