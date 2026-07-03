import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import tempfile
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import httpx
import uvicorn
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from telethon import TelegramClient, events
from telethon.errors import SessionPasswordNeededError
from telethon.sessions import StringSession
from telethon.tl.functions.messages import GetForumTopicsRequest

try:
    import discord
except Exception:
    discord = None


APP_NAME = "dc-tg-line-forwarder"
SESSION_COOKIE = "dc_tg_line_admin"
SESSION_TTL_SECONDS = 60 * 60 * 12
LOCAL_TZ = timezone(timedelta(hours=8))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc8_now() -> str:
    return datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S UTC+8")


def today_start_utc() -> str:
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()


def env_str(name: str, default: str = "") -> str:
    value = os.getenv(name)
    return default if value is None else value.strip()


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def env_int(name: str, default: int = 0) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def safe_json_loads(raw: str, default: Any = None) -> Any:
    try:
        return json.loads(raw) if raw else default
    except Exception:
        return default


def model_to_dict(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[\s,;]+", value or "") if item.strip()]


def parse_multiline(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[\r\n,;]+", value or "") if item.strip()]


def parse_discord_channel_ids(value: str) -> list[str]:
    seen: set[str] = set()
    ids: list[str] = []
    for item in re.split(r"[\s,;]+", value or ""):
        cleaned = item.strip().replace("discord:", "")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            ids.append(cleaned)
    return ids


def mask_secret(value: str, visible: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= visible * 2:
        return value[:1] + "***"
    return value[:visible] + "***" + value[-visible:]


def redact_secrets(text: str) -> str:
    if not text:
        return ""
    patterns = [
        r"(LINE_CHANNEL_ACCESS_TOKEN['\"]?\s*[:=]\s*['\"]?)[^,'\"\s}]+",
        r"(LINE_CHANNEL_SECRET['\"]?\s*[:=]\s*['\"]?)[^,'\"\s}]+",
        r"(DISCORD_USER_TOKEN['\"]?\s*[:=]\s*['\"]?)[^,'\"\s}]+",
        r"(USER_TOKEN['\"]?\s*[:=]\s*['\"]?)[^,'\"\s}]+",
        r"Bearer\s+[A-Za-z0-9._\-+/=]{12,}",
    ]
    redacted = text
    for pattern in patterns:
        if pattern.startswith("("):
            redacted = re.sub(pattern, r"\1***", redacted, flags=re.IGNORECASE)
        else:
            redacted = re.sub(pattern, "Bearer ***", redacted, flags=re.IGNORECASE)
    return redacted


DISCORD_MENTION_PATTERN = re.compile(r"<@!?\d+>|<@&\d+>|<#\d+>")
DISCORD_CUSTOM_EMOJI_PATTERN = re.compile(r"<a?:[A-Za-z0-9_]+:\d+>")


def clean_discord_text(text: str) -> str:
    if not text:
        return ""
    cleaned = DISCORD_MENTION_PATTERN.sub(" ", text)
    cleaned = DISCORD_CUSTOM_EMOJI_PATTERN.sub(" ", cleaned)
    cleaned = re.sub(r"@(everyone|here)\b", " ", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"[ \t\r\f\v]+", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


class RuntimeSettings(BaseModel):
    allow_image_signal: bool = Field(default_factory=lambda: env_bool("ALLOW_IMAGE_SIGNAL", True))
    monitored_chat_ids: list[str] = Field(default_factory=lambda: parse_csv(env_str("TG_SOURCE_CHATS")))
    discord_channel_ids: list[str] = Field(default_factory=lambda: parse_discord_channel_ids(env_str("DISCORD_CHANNEL_IDS") or env_str("TARGET_CHANNEL_ID")))
    line_to: str = Field(default_factory=lambda: env_str("LINE_TO"))
    line_message_prefix: str = Field(default_factory=lambda: env_str("LINE_MESSAGE_PREFIX", ""))


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = asyncio.Lock()

    def connect(self) -> sqlite3.Connection:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    async def init(self) -> None:
        async with self._lock:
            def _run() -> None:
                with self.connect() as conn:
                    conn.executescript(
                        """
                        PRAGMA journal_mode=WAL;
                        CREATE TABLE IF NOT EXISTS settings (
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS raw_messages (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            platform TEXT NOT NULL,
                            chat_id TEXT NOT NULL,
                            chat_name TEXT,
                            message_id TEXT NOT NULL,
                            reply_to_message_id TEXT,
                            sender_id TEXT,
                            text TEXT,
                            has_image INTEGER DEFAULT 0,
                            image_path TEXT,
                            image_urls TEXT,
                            line_status TEXT DEFAULT 'pending',
                            line_error TEXT,
                            line_sent_at TEXT,
                            created_at TEXT NOT NULL,
                            processed INTEGER DEFAULT 0,
                            UNIQUE(chat_id, message_id)
                        );
                        CREATE TABLE IF NOT EXISTS processed_messages (
                            chat_id TEXT NOT NULL,
                            message_id TEXT NOT NULL,
                            processed_at TEXT NOT NULL,
                            PRIMARY KEY(chat_id, message_id)
                        );
                        CREATE TABLE IF NOT EXISTS line_webhook_events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            source_type TEXT,
                            line_to TEXT,
                            event_type TEXT,
                            reply_token TEXT,
                            message_text TEXT,
                            raw_json TEXT,
                            created_at TEXT NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS logs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            level TEXT NOT NULL,
                            source TEXT NOT NULL,
                            message TEXT NOT NULL,
                            details TEXT,
                            created_at TEXT NOT NULL
                        );
                        """
                    )
                    conn.commit()
            await asyncio.to_thread(_run)

    async def execute(self, sql: str, params: tuple = ()) -> None:
        async with self._lock:
            def _run() -> None:
                with self.connect() as conn:
                    conn.execute(sql, params)
                    conn.commit()
            await asyncio.to_thread(_run)

    async def fetchall(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        async with self._lock:
            def _run() -> list[sqlite3.Row]:
                with self.connect() as conn:
                    return conn.execute(sql, params).fetchall()
            return await asyncio.to_thread(_run)

    async def fetchone(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        rows = await self.fetchall(sql, params)
        return rows[0] if rows else None

    async def log(self, level: str, source: str, message: str, details: Any = None) -> None:
        if isinstance(details, (dict, list)):
            details = json.dumps(details, ensure_ascii=False)
        await self.execute(
            "INSERT INTO logs(level, source, message, details, created_at) VALUES (?, ?, ?, ?, ?)",
            (level.upper(), source, message, redact_secrets(str(details)) if details is not None else None, utc_now()),
        )

    async def seed_settings(self, settings: RuntimeSettings) -> None:
        for key, value in model_to_dict(settings).items():
            exists = await self.fetchone("SELECT key FROM settings WHERE key=?", (key,))
            if not exists:
                await self.execute(
                    "INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?)",
                    (key, json.dumps(value, ensure_ascii=False), utc_now()),
                )

    async def get_settings(self) -> RuntimeSettings:
        base = model_to_dict(RuntimeSettings())
        rows = await self.fetchall("SELECT key, value FROM settings")
        for row in rows:
            if row["key"] in base:
                base[row["key"]] = safe_json_loads(row["value"], row["value"])
        if os.getenv("ALLOW_IMAGE_SIGNAL") not in (None, ""):
            base["allow_image_signal"] = env_bool("ALLOW_IMAGE_SIGNAL", bool(base.get("allow_image_signal")))
        if os.getenv("TG_SOURCE_CHATS") not in (None, ""):
            base["monitored_chat_ids"] = parse_csv(env_str("TG_SOURCE_CHATS"))
        if os.getenv("DISCORD_CHANNEL_IDS") not in (None, "") or os.getenv("TARGET_CHANNEL_ID") not in (None, ""):
            base["discord_channel_ids"] = parse_discord_channel_ids(env_str("DISCORD_CHANNEL_IDS") or env_str("TARGET_CHANNEL_ID"))
        if os.getenv("LINE_TO") not in (None, ""):
            base["line_to"] = env_str("LINE_TO")
        if os.getenv("LINE_MESSAGE_PREFIX") not in (None, ""):
            base["line_message_prefix"] = env_str("LINE_MESSAGE_PREFIX")
        return RuntimeSettings(**base)

    async def set_setting(self, key: str, value: Any) -> None:
        await self.execute(
            """
            INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """,
            (key, json.dumps(value, ensure_ascii=False), utc_now()),
        )


DB_PATH = env_str("DB_PATH", "/tmp/app.db")
db = Database(DB_PATH)
app = FastAPI(title=APP_NAME)


class AuthManager:
    def __init__(self) -> None:
        self.admin_password = env_str("ADMIN_PASSWORD")
        self.signing_secret = hashlib.sha256((self.admin_password or secrets.token_hex(16)).encode()).digest()

    def enabled(self) -> bool:
        return bool(self.admin_password)

    def make_token(self) -> str:
        exp = str(int(time.time()) + SESSION_TTL_SECONDS)
        nonce = secrets.token_urlsafe(16)
        payload = f"{exp}:{nonce}"
        sig = hmac.new(self.signing_secret, payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}:{sig}"

    def verify_token(self, token: str) -> bool:
        try:
            exp, nonce, sig = token.split(":", 2)
            if int(exp) < int(time.time()) or not nonce:
                return False
            expected = hmac.new(self.signing_secret, f"{exp}:{nonce}".encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, sig)
        except Exception:
            return False

    def verify_password(self, password: str) -> bool:
        return bool(self.admin_password) and hmac.compare_digest(password, self.admin_password)


auth = AuthManager()


async def require_auth(request: Request) -> None:
    if not auth.enabled():
        raise HTTPException(status_code=503, detail="ADMIN_PASSWORD is required")
    token = request.cookies.get(SESSION_COOKIE, "")
    if not auth.verify_token(token):
        raise HTTPException(status_code=303, headers={"Location": "/login"})


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def checked(value: Any) -> str:
    return "checked" if value else ""


def zh_bool(value: Any) -> str:
    return "是" if bool(value) else "否"


def status_class(value: str) -> str:
    lowered = str(value or "").lower()
    if lowered in {"sent", "connected", "ok", "configured"}:
        return "ok"
    if lowered in {"pending", "starting"}:
        return "muted"
    return "warn"


def status_text(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    return f"<span class='{status_class(text)}'>{html.escape(text)}</span>"


def row_value(row: sqlite3.Row, key: str, default: str = "") -> Any:
    return row[key] if key in row.keys() else default


def rows_table(rows: list[sqlite3.Row] | list[dict[str, Any]], columns: list[str]) -> str:
    header = "".join(f"<th>{html.escape(col)}</th>" for col in columns)
    body = ""
    for row in rows:
        cells = []
        for col in columns:
            value = row.get(col, "") if isinstance(row, dict) else row_value(row, col)
            if col in {"processed", "has_image"}:
                value = zh_bool(value)
            if col in {"line_status"}:
                cells.append(f"<td>{status_text(value)}</td>")
            else:
                cells.append(f"<td>{html.escape(str(value or ''))}</td>")
        body += "<tr>" + "".join(cells) + "</tr>"
    return f"<table><tr>{header}</tr>{body}</table>"


def layout(title: str, body: str) -> str:
    nav = """
    <nav>
      <a href="/">控制台</a>
      <a href="/sources">Telegram 來源</a>
      <a href="/settings">設定</a>
      <a href="/signals">訊息紀錄</a>
      <a href="/discord-import">Discord 匯入</a>
      <a href="/line/events">LINE 事件</a>
      <a href="/logs">日誌</a>
      <a href="/telegram-session">Telegram 登入</a>
      <a href="/logout">登出</a>
    </nav>
    """
    return f"""
    <!doctype html>
    <html lang="zh-Hant">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>{html.escape(title)} - {APP_NAME}</title>
      <style>
        :root {{
          --bg: #f6f7f8;
          --panel: #ffffff;
          --text: #192026;
          --muted: #65717d;
          --line: #d8dee5;
          --accent: #0f766e;
          --warn: #b42318;
          --ok: #087443;
        }}
        * {{ box-sizing: border-box; }}
        body {{ margin: 0; font-family: Arial, "Noto Sans TC", sans-serif; background: var(--bg); color: var(--text); }}
        header {{ padding: 18px 22px 8px; background: var(--panel); border-bottom: 1px solid var(--line); }}
        h1 {{ font-size: 24px; margin: 0 0 12px; letter-spacing: 0; }}
        h2 {{ font-size: 18px; margin: 0 0 12px; letter-spacing: 0; }}
        nav {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        nav a, .btn {{ display: inline-flex; min-height: 36px; align-items: center; justify-content: center; border: 1px solid var(--line); border-radius: 6px; padding: 8px 12px; background: #fff; color: var(--text); text-decoration: none; cursor: pointer; font-size: 14px; }}
        .btn.primary {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
        .btn.danger {{ color: var(--warn); border-color: #f2b8b5; }}
        main {{ padding: 18px 22px 40px; max-width: 1240px; margin: 0 auto; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; align-items: start; }}
        .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin-bottom: 14px; }}
        label {{ display: block; margin: 12px 0 6px; color: #2a333b; font-weight: 600; }}
        input[type="text"], input[type="password"], input:not([type]), textarea {{ width: 100%; border: 1px solid var(--line); border-radius: 6px; min-height: 38px; padding: 8px 10px; font: inherit; background: #fff; }}
        textarea {{ resize: vertical; }}
        table {{ width: 100%; border-collapse: collapse; background: #fff; }}
        th, td {{ border-bottom: 1px solid var(--line); padding: 9px 8px; text-align: left; vertical-align: top; font-size: 14px; }}
        th {{ background: #eef2f6; font-weight: 700; }}
        .table-wrap {{ overflow-x: auto; border: 1px solid var(--line); border-radius: 8px; background: #fff; }}
        .text-cell {{ white-space: pre-wrap; overflow-wrap: anywhere; max-width: 520px; }}
        .muted {{ color: var(--muted); }}
        .ok {{ color: var(--ok); font-weight: 700; }}
        .warn {{ color: var(--warn); font-weight: 700; }}
        .toolbar {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
        .action-stack {{ display: flex; gap: 6px; flex-wrap: wrap; }}
        pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #f0f3f6; border-radius: 6px; padding: 10px; }}
      </style>
    </head>
    <body>
      <header><h1>{html.escape(title)}</h1>{nav}</header>
      <main>{body}</main>
    </body>
    </html>
    """


def page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(layout(title, body))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> HTMLResponse:
    fields = []
    for error in exc.errors():
        loc = list(error.get("loc") or [])
        if loc:
            fields.append(str(loc[-1]))
    detail = ", ".join(sorted(set(fields))) if fields else "必要欄位"
    return page("表單錯誤", f"<div class='card warn'>表單送出失敗，請補齊：{html.escape(detail)}</div>")


def split_line_text(text: str, limit: int = 4900) -> list[str]:
    if not text:
        return [""]
    chunks: list[str] = []
    remaining = text
    while len(remaining) > limit:
        cut = remaining.rfind("\n", 0, limit)
        if cut < limit // 2:
            cut = limit
        chunks.append(remaining[:cut].strip())
        remaining = remaining[cut:].strip()
    if remaining:
        chunks.append(remaining)
    if len(chunks) > 5:
        chunks = chunks[:4] + [chunks[4][:4700].rstrip() + "\n\n...（訊息過長，已截斷）"]
    return chunks


def line_token() -> str:
    return env_str("LINE_CHANNEL_ACCESS_TOKEN")


def line_secret() -> str:
    return env_str("LINE_CHANNEL_SECRET")


async def line_api_post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    token = line_token()
    if not token:
        raise RuntimeError("LINE_CHANNEL_ACCESS_TOKEN is not configured")
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            f"https://api.line.me/v2/bot/{path.lstrip('/')}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
        )
    if response.status_code >= 300:
        raise RuntimeError(f"LINE API {response.status_code}: {response.text}")
    try:
        return response.json() if response.text else {"ok": True}
    except Exception:
        return {"ok": True, "text": response.text}


async def line_push_text(to: str, text: str) -> None:
    messages = [{"type": "text", "text": chunk} for chunk in split_line_text(text)]
    await line_api_post("message/push", {"to": to, "messages": messages})


async def line_reply_text(reply_token: str, text: str) -> None:
    if not reply_token:
        return
    messages = [{"type": "text", "text": chunk} for chunk in split_line_text(text)[:5]]
    await line_api_post("message/reply", {"replyToken": reply_token, "messages": messages})


def line_to_values(settings: RuntimeSettings) -> list[str]:
    return parse_multiline(settings.line_to)


def source_platform_from_chat_id(chat_id: str) -> str:
    return "Discord" if str(chat_id).startswith("discord:") else "Telegram"


def format_line_message(
    settings: RuntimeSettings,
    chat_id: str,
    chat_name: str,
    message_id: str,
    sender_id: str,
    text: str,
    has_image: bool,
    image_urls: list[str],
    reply_to_message_id: Optional[str],
    edited: bool = False,
) -> str:
    platform = source_platform_from_chat_id(chat_id)
    header = f"[{platform}{' 編輯更新' if edited else ''}] {chat_name or chat_id}"
    parts = []
    if settings.line_message_prefix.strip():
        parts.append(settings.line_message_prefix.strip())
    parts.extend(
        [
            header,
            f"來源 ID: {chat_id}",
            f"訊息 ID: {message_id}",
            f"發送者: {sender_id or '-'}",
            f"時間: {utc8_now()}",
        ]
    )
    if reply_to_message_id:
        parts.append(f"回覆訊息 ID: {reply_to_message_id}")
    if has_image:
        parts.append("附件: 包含圖片或圖片連結")
    if image_urls:
        parts.append("圖片 URL:\n" + "\n".join(image_urls))
    body = (text or "").strip() or ("[image]" if has_image else "")
    return "\n".join(parts) + "\n\n" + body


async def save_raw_message(
    platform: str,
    chat_id: str,
    chat_name: str,
    message_id: str | int,
    sender_id: str,
    text: str,
    has_image: bool,
    image_path: Optional[str],
    image_urls: Optional[list[str]] = None,
    reply_to_message_id: Optional[str | int] = None,
) -> bool:
    message_key = str(message_id)
    exists = await db.fetchone("SELECT 1 FROM processed_messages WHERE chat_id=? AND message_id=?", (chat_id, message_key))
    if exists:
        return False
    await db.execute(
        """
        INSERT OR IGNORE INTO raw_messages(
            platform, chat_id, chat_name, message_id, reply_to_message_id, sender_id,
            text, has_image, image_path, image_urls, created_at, processed
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (
            platform,
            chat_id,
            chat_name,
            message_key,
            str(reply_to_message_id) if reply_to_message_id not in (None, "") else None,
            sender_id,
            text,
            int(has_image),
            image_path,
            json.dumps(image_urls or [], ensure_ascii=False),
            utc_now(),
        ),
    )
    return True


async def upsert_raw_message(
    platform: str,
    chat_id: str,
    chat_name: str,
    message_id: str | int,
    sender_id: str,
    text: str,
    has_image: bool,
    image_path: Optional[str],
    image_urls: Optional[list[str]] = None,
    force_update: bool = False,
    reply_to_message_id: Optional[str | int] = None,
) -> bool:
    message_key = str(message_id)
    exists = await db.fetchone("SELECT 1 FROM raw_messages WHERE chat_id=? AND message_id=?", (chat_id, message_key))
    if exists and not force_update:
        processed = await db.fetchone("SELECT 1 FROM processed_messages WHERE chat_id=? AND message_id=?", (chat_id, message_key))
        return not bool(processed)
    if exists:
        await db.execute(
            """
            UPDATE raw_messages
            SET platform=?, chat_name=?, sender_id=?, text=?, has_image=?, image_path=?, image_urls=?,
                reply_to_message_id=?, line_status='pending', line_error=NULL, line_sent_at=NULL,
                created_at=?, processed=0
            WHERE chat_id=? AND message_id=?
            """,
            (
                platform,
                chat_name,
                sender_id,
                text,
                int(has_image),
                image_path,
                json.dumps(image_urls or [], ensure_ascii=False),
                str(reply_to_message_id) if reply_to_message_id not in (None, "") else None,
                utc_now(),
                chat_id,
                message_key,
            ),
        )
    else:
        await save_raw_message(platform, chat_id, chat_name, message_key, sender_id, text, has_image, image_path, image_urls, reply_to_message_id)
    return True


async def mark_processed(chat_id: str, message_id: str | int) -> None:
    message_key = str(message_id)
    await db.execute(
        "INSERT OR IGNORE INTO processed_messages(chat_id, message_id, processed_at) VALUES (?, ?, ?)",
        (chat_id, message_key, utc_now()),
    )
    await db.execute("UPDATE raw_messages SET processed=1 WHERE chat_id=? AND message_id=?", (chat_id, message_key))


async def process_message(
    chat_id: str,
    chat_name: str,
    message_id: str | int,
    sender_id: str,
    text: str,
    has_image: bool,
    image_path: Optional[str],
    image_urls: Optional[list[str]] = None,
    reply_to_message_id: Optional[str | int] = None,
    edited: bool = False,
) -> None:
    settings = await db.get_settings()
    recipients = line_to_values(settings)
    message_key = str(message_id)
    image_url_list = image_urls or []
    try:
        if not recipients:
            raise RuntimeError("LINE_TO is empty; open /line/events or set LINE_TO")
        line_text = format_line_message(
            settings,
            chat_id,
            chat_name,
            message_key,
            sender_id,
            text,
            has_image,
            image_url_list,
            str(reply_to_message_id) if reply_to_message_id not in (None, "") else None,
            edited=edited,
        )
        for recipient in recipients:
            await line_push_text(recipient, line_text)
        await db.execute(
            "UPDATE raw_messages SET line_status='sent', line_error=NULL, line_sent_at=? WHERE chat_id=? AND message_id=?",
            (utc_now(), chat_id, message_key),
        )
        await db.log("INFO", "line", "Message forwarded to LINE", {"chat_id": chat_id, "message_id": message_key, "recipient_count": len(recipients)})
    except Exception as exc:
        error = redact_secrets(str(exc))
        await db.execute(
            "UPDATE raw_messages SET line_status='failed', line_error=? WHERE chat_id=? AND message_id=?",
            (error, chat_id, message_key),
        )
        await db.log("ERROR", "line", "LINE forwarding failed", {"chat_id": chat_id, "message_id": message_key, "error": error})
    finally:
        await mark_processed(chat_id, message_key)
        if image_path and os.path.exists(image_path):
            try:
                os.remove(image_path)
            except OSError:
                pass


async def get_setting_value(key: str, default: str = "") -> str:
    row = await db.fetchone("SELECT value FROM settings WHERE key=?", (key,))
    if not row:
        return default
    value = safe_json_loads(row["value"], row["value"])
    return str(value).strip() if value is not None else default


async def get_telegram_session_string() -> str:
    stored = await get_setting_value("tg_session_string") or await get_setting_value("telegram_session_string")
    return stored or env_str("TG_SESSION_STRING")


async def get_telegram_credentials() -> tuple[int, str, str]:
    return env_int("TG_API_ID", 0), env_str("TG_API_HASH"), await get_telegram_session_string()


def telethon_entity_id_variants(value: Any) -> set[str]:
    variants: set[str] = set()
    if value is None or value == "":
        return variants
    raw = str(value).strip()
    variants.add(raw)
    try:
        number = int(raw)
    except (TypeError, ValueError):
        return variants
    variants.add(str(number))
    abs_number = abs(number)
    variants.add(str(abs_number))
    variants.add(f"-{abs_number}")
    variants.add(f"-100{abs_number}")
    return variants


def chat_identifier_set(chat: Any, chat_id: str) -> set[str]:
    username = getattr(chat, "username", None)
    identifiers: set[str] = set()
    identifiers.update(telethon_entity_id_variants(chat_id))
    identifiers.update(telethon_entity_id_variants(getattr(chat, "id", None)))
    if username:
        identifiers.add(username)
        identifiers.add("@" + username.lstrip("@"))
    return identifiers


def parse_telegram_topic_source(value: Any) -> Optional[tuple[str, str]]:
    raw = str(value or "").strip()
    match = re.match(r"^(?:tg-topic|topic):(.+):(\d+)$", raw)
    if not match:
        return None
    return match.group(1).strip(), match.group(2).strip()


def telegram_topic_source_code(chat_id: Any, topic_id: Any) -> str:
    return f"tg-topic:{str(chat_id).strip()}:{str(topic_id).strip()}"


def telegram_topic_identifier_set(chat_id: Any, topic_id: Any) -> set[str]:
    topic = str(topic_id or "").strip()
    if not topic:
        return set()
    identifiers: set[str] = set()
    for chat_variant in telethon_entity_id_variants(chat_id):
        identifiers.add(telegram_topic_source_code(chat_variant, topic))
        identifiers.add(f"topic:{chat_variant}:{topic}")
    return identifiers


def telegram_message_topic_id(message: Any) -> Optional[str]:
    reply_to = getattr(message, "reply_to", None)
    if not reply_to:
        return None
    top_id = getattr(reply_to, "reply_to_top_id", None)
    if top_id:
        return str(top_id)
    reply_msg_id = getattr(reply_to, "reply_to_msg_id", None)
    if getattr(reply_to, "forum_topic", False) and reply_msg_id:
        return str(reply_msg_id)
    return None


def telegram_reply_to_message_id(message: Any) -> Optional[int]:
    reply_to = getattr(message, "reply_to", None)
    if not reply_to:
        return None
    reply_msg_id = getattr(reply_to, "reply_to_msg_id", None)
    if reply_msg_id in (None, ""):
        return None
    try:
        return int(reply_msg_id)
    except (TypeError, ValueError):
        return None


def is_chat_allowed(chat: Any, chat_id: str, settings: RuntimeSettings, topic_id: Optional[str] = None) -> bool:
    selected_chats: set[str] = set()
    selected_topics: set[str] = set()
    for item in settings.monitored_chat_ids:
        raw = str(item).strip()
        if not raw:
            continue
        parsed_topic = parse_telegram_topic_source(raw)
        if parsed_topic:
            selected_topics.update(telegram_topic_identifier_set(parsed_topic[0], parsed_topic[1]))
            continue
        selected_chats.add(raw)
        selected_chats.update(telethon_entity_id_variants(raw))
    if not selected_chats and not selected_topics:
        return False
    if chat_identifier_set(chat, chat_id) & selected_chats:
        return True
    if topic_id and telegram_topic_identifier_set(chat_id, topic_id) & selected_topics:
        return True
    return False


async def get_dialog_cache() -> list[dict[str, Any]]:
    row = await db.fetchone("SELECT value FROM settings WHERE key='telegram_dialogs_cache'")
    if not row:
        return []
    cached = safe_json_loads(row["value"], [])
    return cached if isinstance(cached, list) else []


async def fetch_telegram_forum_topics(client: TelegramClient, entity: Any, chat_id: str) -> list[dict[str, Any]]:
    topics: list[dict[str, Any]] = []
    input_peer = await client.get_input_entity(entity)
    offset_date = None
    offset_id = 0
    offset_topic = 0
    seen: set[str] = set()
    for _ in range(5):
        result = await client(
            GetForumTopicsRequest(
                peer=input_peer,
                q="",
                offset_date=offset_date,
                offset_id=offset_id,
                offset_topic=offset_topic,
                limit=100,
            )
        )
        batch = list(getattr(result, "topics", []) or [])
        if not batch:
            break
        for topic in batch:
            topic_id = str(getattr(topic, "id", "") or "")
            title = str(getattr(topic, "title", "") or "").strip()
            if not topic_id or not title or getattr(topic, "hidden", False):
                continue
            if topic_id in seen:
                continue
            seen.add(topic_id)
            topics.append(
                {
                    "topic_id": topic_id,
                    "source_code": telegram_topic_source_code(chat_id, topic_id),
                    "title": title,
                    "closed": bool(getattr(topic, "closed", False)),
                    "pinned": bool(getattr(topic, "pinned", False)),
                    "top_message": str(getattr(topic, "top_message", "") or ""),
                }
            )
        if len(batch) < 100:
            break
        last = batch[-1]
        offset_topic = int(getattr(last, "id", 0) or 0)
        offset_id = int(getattr(last, "top_message", 0) or 0)
        offset_date = getattr(last, "date", None)
    return topics


telegram_client: Optional[TelegramClient] = None
telegram_status: dict[str, Any] = {"running": False, "connected": False, "last_error": None, "started_at": None}
pending_login_sessions: dict[str, dict[str, Any]] = {}


async def fetch_telegram_dialogs() -> list[dict[str, Any]]:
    api_id, api_hash, session_string = await get_telegram_credentials()
    if not (api_id and api_hash and session_string):
        raise RuntimeError("Please configure TG_API_ID, TG_API_HASH, and TG_SESSION_STRING first")
    client = telegram_client
    owns_client = False
    if client is None or not client.is_connected():
        client = TelegramClient(StringSession(session_string), api_id, api_hash)
        await client.connect()
        owns_client = True
    try:
        if not await client.is_user_authorized():
            raise RuntimeError("Telegram StringSession is not authorized")
        dialogs: list[dict[str, Any]] = []
        async for dialog in client.iter_dialogs(limit=500):
            entity = dialog.entity
            chat_id = str(dialog.id)
            username = getattr(entity, "username", None)
            if dialog.is_user:
                kind = "private"
            elif dialog.is_group or getattr(entity, "megagroup", False):
                kind = "group"
            elif dialog.is_channel or getattr(entity, "broadcast", False):
                kind = "channel"
            else:
                kind = "other"
            topics: list[dict[str, Any]] = []
            if getattr(entity, "forum", False):
                try:
                    topics = await fetch_telegram_forum_topics(client, entity, chat_id)
                except Exception as exc:
                    await db.log("WARN", "telegram", "Telegram forum topic refresh failed", {"chat_id": chat_id, "name": dialog.name or chat_id, "error": str(exc)})
            dialogs.append(
                {
                    "chat_id": chat_id,
                    "entity_id": str(getattr(entity, "id", "")),
                    "identifiers": sorted(chat_identifier_set(entity, chat_id)),
                    "name": dialog.name or chat_id,
                    "type": "supergroup_forum" if topics else kind,
                    "username": ("@" + username.lstrip("@")) if username else "",
                    "topics": topics,
                }
            )
        dialogs.sort(key=lambda item: (item["type"], str(item["name"]).lower()))
        await db.set_setting("telegram_dialogs_cache", dialogs)
        await db.log("INFO", "telegram", "Telegram monitored source cache updated", {"count": len(dialogs)})
        return dialogs
    finally:
        if owns_client:
            await client.disconnect()


async def cached_telegram_topic_title(chat_id: str, topic_id: str) -> str:
    wanted = telegram_topic_identifier_set(chat_id, topic_id)
    for dialog in await get_dialog_cache():
        for topic in dialog.get("topics", []) or []:
            source_code = str(topic.get("source_code", "") or "")
            if source_code in wanted or telegram_topic_source_code(dialog.get("chat_id", ""), topic.get("topic_id", "")) in wanted:
                return str(topic.get("title", "") or "").strip()
    return ""


async def handle_incoming_message(event: events.NewMessage.Event) -> None:
    tmp_image = None
    try:
        settings = await db.get_settings()
        chat = await event.get_chat()
        sender = await event.get_sender()
        chat_id = str(event.chat_id or getattr(chat, "id", ""))
        chat_name = getattr(chat, "title", None) or getattr(chat, "username", None) or getattr(chat, "first_name", None) or chat_id
        sender_id = str(getattr(sender, "id", "") or "")
        message_id = int(event.message.id)
        topic_id = telegram_message_topic_id(event.message)
        reply_to_message_id = telegram_reply_to_message_id(event.message)
        if not is_chat_allowed(chat, chat_id, settings, topic_id):
            return
        source_chat_id = chat_id
        source_chat_name = chat_name
        if topic_id:
            source_chat_id = telegram_topic_source_code(chat_id, topic_id)
            topic_title = await cached_telegram_topic_title(chat_id, topic_id)
            source_chat_name = f"{chat_name} / {topic_title or 'Topic ' + topic_id}"
        text = event.message.message or ""
        if reply_to_message_id:
            try:
                replied = await event.message.get_reply_message()
                replied_text = str(getattr(replied, "message", "") or "").strip() if replied else ""
                if replied_text:
                    text = (text + f"\n[reply_to message_id={reply_to_message_id}]\n" + replied_text).strip()
                    await db.execute(
                        """
                        INSERT OR IGNORE INTO raw_messages(
                            platform, chat_id, chat_name, message_id, reply_to_message_id,
                            sender_id, text, has_image, image_path, image_urls, created_at, processed
                        ) VALUES ('Telegram', ?, ?, ?, NULL, ?, ?, ?, NULL, '[]', ?, 1)
                        """,
                        (
                            source_chat_id,
                            source_chat_name,
                            str(reply_to_message_id),
                            str(getattr(getattr(replied, "sender", None), "id", "") or ""),
                            replied_text,
                            int(bool(getattr(replied, "photo", None))),
                            utc_now(),
                        ),
                    )
            except Exception as exc:
                await db.log("WARN", "telegram", "Telegram reply message fetch failed; continuing with reply id only", {"chat_id": source_chat_id, "message_id": message_id, "reply_to_message_id": reply_to_message_id, "error": redact_secrets(str(exc))})
        has_image = bool(event.message.photo)
        if has_image and settings.allow_image_signal:
            fd, tmp_image = tempfile.mkstemp(prefix="tg_signal_", suffix=".jpg")
            os.close(fd)
            await event.message.download_media(file=tmp_image)
        saved = await save_raw_message("Telegram", source_chat_id, source_chat_name, message_id, sender_id, text, has_image, "deleted_after_forward" if tmp_image else None, [], reply_to_message_id)
        if not saved:
            await db.log("INFO", "telegram", "Duplicate message ignored", {"chat_id": source_chat_id, "message_id": message_id})
            return
        await db.log("INFO", "telegram", "Telegram message accepted", {"chat_id": source_chat_id, "message_id": message_id, "has_image": has_image})
        await process_message(source_chat_id, source_chat_name, message_id, sender_id, text, has_image, tmp_image, [], reply_to_message_id)
        tmp_image = None
    except Exception as exc:
        await db.log("ERROR", "telegram", "Incoming message handling failed", redact_secrets(str(exc)))
    finally:
        if tmp_image and os.path.exists(tmp_image):
            try:
                os.remove(tmp_image)
            except OSError:
                pass


async def start_telegram_listener() -> None:
    global telegram_client
    if telegram_status["running"]:
        return
    telegram_status.update({"running": True, "started_at": utc_now(), "last_error": None})
    while True:
        try:
            api_id, api_hash, session_string = await get_telegram_credentials()
            if not (api_id and api_hash and session_string):
                telegram_status.update({"running": False, "connected": False, "last_error": "TG_API_ID / TG_API_HASH / TG_SESSION_STRING not fully configured"})
                await db.log("WARN", "telegram", "Telegram listener not started: missing credentials")
                return
            telegram_client = TelegramClient(StringSession(session_string), api_id, api_hash)
            await telegram_client.connect()
            if not await telegram_client.is_user_authorized():
                raise RuntimeError("Telegram StringSession is not authorized")
            telegram_client.add_event_handler(handle_incoming_message, events.NewMessage(incoming=True))
            telegram_status.update({"connected": True, "last_error": None})
            await db.log("INFO", "telegram", "Telegram listener connected; monitored sources are managed from UI/settings")
            await telegram_client.run_until_disconnected()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            telegram_status.update({"connected": False, "last_error": redact_secrets(str(exc))})
            await db.log("ERROR", "telegram", "Listener disconnected; retrying", redact_secrets(str(exc)))
            await asyncio.sleep(10)
        finally:
            telegram_status["connected"] = False


def discord_chat_id(channel_id: Any) -> str:
    cleaned = str(channel_id or "").strip()
    return cleaned if cleaned.startswith("discord:") else f"discord:{cleaned}"


async def get_discord_channel_ids() -> list[str]:
    settings = await db.get_settings()
    return parse_discord_channel_ids(",".join(settings.discord_channel_ids))


def is_allowed_discord_channel(channel: Any, target_channels: set[str]) -> bool:
    channel_id = str(getattr(channel, "id", "") or "")
    return bool(channel and target_channels and channel_id in target_channels)


def discord_message_author_id(message: Any) -> str:
    author = getattr(message, "author", None)
    return str(getattr(author, "id", "") or "")


def discord_embed_text(embed: Any) -> str:
    parts: list[str] = []
    for attr in ("title", "description", "url"):
        value = getattr(embed, attr, None)
        if value:
            parts.append(str(value))
    provider = getattr(embed, "provider", None)
    provider_name = getattr(provider, "name", None) if provider else None
    if provider_name:
        parts.append(str(provider_name))
    author = getattr(embed, "author", None)
    author_name = getattr(author, "name", None) if author else None
    if author_name:
        parts.append(str(author_name))
    footer = getattr(embed, "footer", None)
    footer_text = getattr(footer, "text", None) if footer else None
    if footer_text:
        parts.append(str(footer_text))
    for field in getattr(embed, "fields", []) or []:
        name = getattr(field, "name", None)
        value = getattr(field, "value", None)
        if name or value:
            parts.append(f"{name or ''}\n{value or ''}".strip())
    return "\n".join(part for part in parts if part).strip()


def discord_component_text(component: Any) -> str:
    parts: list[str] = []
    for attr in ("label", "custom_id", "url", "placeholder"):
        value = getattr(component, attr, None)
        if value:
            parts.append(str(value))
    for child in getattr(component, "children", []) or []:
        child_text = discord_component_text(child)
        if child_text:
            parts.append(child_text)
    return "\n".join(parts).strip()


def discord_image_urls_from_embed(embed: Any) -> list[str]:
    urls: list[str] = []
    for attr in ("image", "thumbnail"):
        obj = getattr(embed, attr, None)
        url = getattr(obj, "url", None) or getattr(obj, "proxy_url", None)
        if url:
            urls.append(str(url))
    return urls


def discord_attachment_list(message: Any) -> list[Any]:
    attachments = getattr(message, "attachments", []) or []
    if hasattr(attachments, "values"):
        return list(attachments.values())
    return list(attachments)


def discord_attachment_url(attachment: Any) -> str:
    return str(getattr(attachment, "url", None) or getattr(attachment, "proxy_url", None) or "")


def discord_attachment_is_image(attachment: Any) -> bool:
    content_type = str(getattr(attachment, "content_type", "") or "")
    filename = str(getattr(attachment, "filename", "") or "")
    url = discord_attachment_url(attachment)
    suffix = os.path.splitext(filename or url.split("?")[0])[1].lower()
    return content_type.startswith("image/") or suffix in {".png", ".jpg", ".jpeg", ".webp", ".gif"}


def suffix_from_discord_media(name_or_url: str, default: str = ".png") -> str:
    suffix = os.path.splitext((name_or_url or "").split("?")[0])[1].lower()
    return suffix if suffix in {".png", ".jpg", ".jpeg", ".webp", ".gif"} else default


async def download_discord_url_image(url: str) -> Optional[str]:
    if not url:
        return None
    suffix = suffix_from_discord_media(url)
    tmp = tempfile.NamedTemporaryFile(delete=False, prefix="discord_signal_", suffix=suffix)
    path = tmp.name
    tmp.close()
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            content_type = response.headers.get("content-type", "")
            if content_type and not content_type.lower().startswith("image/"):
                raise RuntimeError(f"URL is not an image: {content_type}")
            with open(path, "wb") as f:
                f.write(response.content)
        return path
    except Exception:
        try:
            os.remove(path)
        except OSError:
            pass
        raise


async def download_discord_attachment_image(attachment: Any) -> Optional[str]:
    if not discord_attachment_is_image(attachment):
        return None
    suffix = suffix_from_discord_media(str(getattr(attachment, "filename", "") or discord_attachment_url(attachment)))
    tmp = tempfile.NamedTemporaryFile(delete=False, prefix="discord_signal_", suffix=suffix)
    path = tmp.name
    tmp.close()
    try:
        if hasattr(attachment, "save"):
            await attachment.save(path)
        else:
            url = discord_attachment_url(attachment)
            downloaded = await download_discord_url_image(url)
            if not downloaded:
                return None
            os.replace(downloaded, path)
        return path
    except Exception:
        try:
            os.remove(path)
        except OSError:
            pass
        raise


async def fetch_discord_reference(message: Any) -> Optional[Any]:
    reference = getattr(message, "reference", None)
    if not reference:
        return None
    resolved = getattr(reference, "resolved", None) or getattr(reference, "cached_message", None)
    if resolved and not isinstance(resolved, Exception):
        return resolved
    message_id = getattr(reference, "message_id", None) or getattr(reference, "messageId", None)
    channel = getattr(message, "channel", None)
    if not message_id or not channel:
        return None
    try:
        if hasattr(channel, "fetch_message"):
            return await channel.fetch_message(int(message_id))
        messages = getattr(channel, "messages", None)
        if messages and hasattr(messages, "fetch"):
            return await messages.fetch(int(message_id))
    except Exception as exc:
        await db.log("WARN", "discord", "Discord referenced message fetch failed", {"message_id": str(message_id), "error": str(exc)})
    return None


def discord_reference_message_id(message: Any) -> Optional[int]:
    reference = getattr(message, "reference", None)
    if not reference:
        return None
    message_id = getattr(reference, "message_id", None) or getattr(reference, "messageId", None)
    if message_id in (None, ""):
        return None
    try:
        return int(message_id)
    except (TypeError, ValueError):
        return None


async def extract_discord_message(message: Any, include_reference: bool = True, allow_image_signal: bool = True) -> tuple[str, list[str], Optional[str], Optional[int]]:
    parts: list[str] = []
    image_urls: list[str] = []
    image_path: Optional[str] = None
    reply_to_message_id = discord_reference_message_id(message)
    for attr in ("content", "clean_content", "system_content"):
        value = getattr(message, attr, None)
        if value and str(value) not in parts:
            parts.append(str(value))
    for embed in getattr(message, "embeds", []) or []:
        embed_text = discord_embed_text(embed)
        if embed_text:
            parts.append(embed_text)
        image_urls.extend(discord_image_urls_from_embed(embed))
    for attachment in discord_attachment_list(message):
        url = discord_attachment_url(attachment)
        filename = str(getattr(attachment, "filename", "") or "")
        if url:
            parts.append(f"[attachment] {filename} {url}".strip())
        if allow_image_signal and image_path is None and discord_attachment_is_image(attachment):
            try:
                image_path = await download_discord_attachment_image(attachment)
            except Exception as exc:
                await db.log("ERROR", "discord", "Discord image attachment download failed", str(exc))
    for component in getattr(message, "components", []) or []:
        component_text = discord_component_text(component)
        if component_text:
            parts.append(component_text)
    if include_reference:
        replied = await fetch_discord_reference(message)
        if replied:
            replied_text, replied_image_urls, replied_image_path, _ = await extract_discord_message(replied, include_reference=False, allow_image_signal=False)
            if replied_text:
                parts.append(f"[reply_to message_id={reply_to_message_id}]\n" + replied_text)
            for url in replied_image_urls:
                parts.append(f"[reply_embed-image] {url}")
            if replied_image_path and os.path.exists(replied_image_path):
                try:
                    os.remove(replied_image_path)
                except OSError:
                    pass
    for url in image_urls:
        parts.append(f"[embed-image] {url}")
        if allow_image_signal and image_path is None:
            try:
                image_path = await download_discord_url_image(url)
            except Exception as exc:
                await db.log("ERROR", "discord", "Discord embed image download failed", {"url": url, "error": str(exc)})
    text = clean_discord_text("\n".join(part for part in parts if part))
    return text, image_urls, image_path, reply_to_message_id


discord_status: dict[str, Any] = {"running": False, "connected": False, "last_error": None, "started_at": None}
discord_recent_update_hashes: dict[str, tuple[str, float]] = {}
discord_client: Any = None


async def handle_discord_message(message: Any, force_update: bool = False) -> None:
    user = getattr(discord_client, "user", None)
    author = getattr(message, "author", None)
    channel = getattr(message, "channel", None)
    target_channels = set(await get_discord_channel_ids())
    if not is_allowed_discord_channel(channel, target_channels):
        return
    if user is not None and author is not None and getattr(author, "id", None) == getattr(user, "id", None):
        return

    chat_id = discord_chat_id(getattr(channel, "id", ""))
    chat_name = f"Discord / {getattr(channel, 'name', getattr(channel, 'id', chat_id))}"
    message_id = str(getattr(message, "id", int(time.time() * 1000)))
    sender_id = discord_message_author_id(message)
    image_path = None
    try:
        settings = await db.get_settings()
        text, image_urls, image_path, reply_to_message_id = await extract_discord_message(message, allow_image_signal=settings.allow_image_signal)
        has_image = image_path is not None or bool(image_urls)
        if not text and has_image:
            text = "[discord image]"
        if not text and not has_image:
            await db.log("INFO", "discord", "Discord message ignored: no usable content after extraction", {"chat_id": chat_id, "message_id": message_id})
            return
        if force_update:
            cache_key = f"{chat_id}:{message_id}"
            text_hash = hashlib.sha256(f"{text}|{has_image}|{','.join(image_urls)}".encode()).hexdigest()
            previous = discord_recent_update_hashes.get(cache_key)
            now_ts = time.time()
            if previous and previous[0] == text_hash and now_ts - previous[1] < 10:
                return
            discord_recent_update_hashes[cache_key] = (text_hash, now_ts)
            for key, (_, seen_at) in list(discord_recent_update_hashes.items()):
                if now_ts - seen_at > 60:
                    discord_recent_update_hashes.pop(key, None)
        saved = await upsert_raw_message("Discord", chat_id, chat_name, message_id, sender_id, text, has_image, "deleted_after_forward" if image_path else None, image_urls, force_update=force_update, reply_to_message_id=reply_to_message_id)
        if not saved:
            return
        await db.log("INFO", "discord", "Discord message extracted", {"chat_id": chat_id, "message_id": message_id, "reply_to_message_id": reply_to_message_id, "force_update": force_update, "text_length": len(text), "has_image": has_image, "image_url_count": len(image_urls), "embed_count": len(getattr(message, "embeds", []) or []), "attachment_count": len(discord_attachment_list(message))})
        asyncio.create_task(process_discord_message(chat_id, chat_name, message_id, sender_id, text, has_image, image_path, image_urls, reply_to_message_id, edited=force_update))
        image_path = None
    finally:
        if image_path and os.path.exists(image_path):
            try:
                os.remove(image_path)
            except OSError:
                pass


class MyDiscordSelfBot(discord.Client if discord is not None else object):
    async def on_ready(self) -> None:
        discord_status["connected"] = True
        discord_status["last_error"] = None
        target_channels = await get_discord_channel_ids()
        await db.log("INFO", "discord", "Discord listener connected", {"user": str(getattr(self, "user", "")), "channel_count": len(target_channels), "channels": target_channels})

    async def on_message(self, message: Any) -> None:
        await handle_discord_message(message)

    async def on_message_edit(self, before: Any, after: Any) -> None:
        await handle_discord_message(after, force_update=True)

    async def on_raw_message_edit(self, payload: Any) -> None:
        channel_id = str(getattr(payload, "channel_id", "") or "")
        target_channels = set(await get_discord_channel_ids())
        if channel_id not in target_channels:
            return
        try:
            channel = self.get_channel(int(channel_id)) if hasattr(self, "get_channel") else None
            if channel is None and hasattr(self, "fetch_channel"):
                channel = await self.fetch_channel(int(channel_id))
            if channel is None or not hasattr(channel, "fetch_message"):
                return
            message = await channel.fetch_message(int(getattr(payload, "message_id")))
            await handle_discord_message(message, force_update=True)
        except Exception as exc:
            await db.log("WARN", "discord", "Discord raw message edit fetch failed", {"channel_id": channel_id, "message_id": str(getattr(payload, "message_id", "")), "error": str(exc)})


async def process_discord_message(
    chat_id: str,
    chat_name: str,
    message_id: str,
    sender_id: str,
    text: str,
    has_image: bool,
    image_path: Optional[str],
    image_urls: Optional[list[str]],
    reply_to_message_id: Optional[int] = None,
    edited: bool = False,
) -> None:
    try:
        await process_message(chat_id, chat_name, message_id, sender_id, text, has_image, image_path, image_urls, reply_to_message_id, edited=edited)
    finally:
        if image_path and os.path.exists(image_path):
            try:
                os.remove(image_path)
            except OSError:
                pass


async def start_discord_listener() -> None:
    global discord_client
    if discord_status["running"]:
        return
    token = env_str("USER_TOKEN") or env_str("DISCORD_USER_TOKEN")
    target_channels = await get_discord_channel_ids()
    if not token:
        discord_status.update({"running": False, "connected": False, "last_error": "USER_TOKEN / DISCORD_USER_TOKEN not configured"})
        await db.log("WARN", "discord", "Discord listener not started: missing USER_TOKEN / DISCORD_USER_TOKEN")
        return
    if discord is None:
        discord_status.update({"running": False, "connected": False, "last_error": "discord package is not installed"})
        await db.log("ERROR", "discord", "Discord listener not started: discord package is not installed")
        return

    discord_status.update({"running": True, "connected": False, "started_at": utc_now(), "last_error": None})
    while True:
        try:
            client_kwargs: dict[str, Any] = {}
            if hasattr(discord, "Intents"):
                try:
                    intents = discord.Intents.default()
                    for attr in ("guilds", "messages", "guild_messages", "message_content"):
                        if hasattr(intents, attr):
                            setattr(intents, attr, True)
                    client_kwargs["intents"] = intents
                except Exception as exc:
                    await db.log("WARN", "discord", "Discord intents setup failed; starting without explicit intents", str(exc))
            try:
                discord_client = MyDiscordSelfBot(**client_kwargs)
            except TypeError:
                discord_client = MyDiscordSelfBot()
            await db.log("INFO", "discord", "Discord listener starting", {"channel_count": len(target_channels), "channels": target_channels})
            try:
                await discord_client.start(token, bot=False)
            except TypeError:
                await discord_client.start(token)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            discord_status.update({"connected": False, "last_error": redact_secrets(str(exc))})
            await db.log("ERROR", "discord", "Discord listener disconnected; retrying", redact_secrets(str(exc)))
            await asyncio.sleep(10)
        finally:
            discord_status["connected"] = False


background_tasks: list[asyncio.Task] = []


async def startup() -> None:
    await db.init()
    await db.seed_settings(RuntimeSettings())
    background_tasks.append(asyncio.create_task(start_telegram_listener()))
    background_tasks.append(asyncio.create_task(start_discord_listener()))


async def shutdown() -> None:
    for task in background_tasks:
        task.cancel()
    if telegram_client and telegram_client.is_connected():
        await telegram_client.disconnect()
    if discord_client and hasattr(discord_client, "close"):
        await discord_client.close()


app.router.on_startup.append(startup)
app.router.on_shutdown.append(shutdown)


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {"ok": True, "app": APP_NAME, "time": utc_now()}


@app.get("/login", response_class=HTMLResponse)
async def login_page() -> HTMLResponse:
    return page(
        "登入",
        """
        <div class="card">
          <form method="post" action="/login">
            <label>後台密碼</label>
            <input type="password" name="password" autofocus>
            <button class="btn primary" type="submit">登入</button>
          </form>
        </div>
        """,
    )


@app.post("/login")
async def login(password: str = Form(...)) -> RedirectResponse:
    if auth.verify_password(password):
        response = redirect("/")
        response.set_cookie(SESSION_COOKIE, auth.make_token(), httponly=True, secure=False, samesite="lax", max_age=SESSION_TTL_SECONDS)
        return response
    await db.log("WARN", "ui", "Admin login failed")
    return redirect("/login")


@app.get("/logout")
async def logout() -> RedirectResponse:
    response = redirect("/login")
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def dashboard() -> HTMLResponse:
    settings = await db.get_settings()
    today = today_start_utc()
    message_count = await db.fetchone("SELECT COUNT(*) AS c FROM raw_messages WHERE created_at>=?", (today,))
    sent_count = await db.fetchone("SELECT COUNT(*) AS c FROM raw_messages WHERE line_status='sent' AND created_at>=?", (today,))
    failed_count = await db.fetchone("SELECT COUNT(*) AS c FROM raw_messages WHERE line_status='failed' AND created_at>=?", (today,))
    recent_rows = await db.fetchall("SELECT created_at, platform, chat_name, message_id, has_image, line_status, line_error FROM raw_messages ORDER BY id DESC LIMIT 12")
    info = [
        {"項目": "LINE token", "值": "configured" if bool(line_token()) else "missing"},
        {"項目": "LINE_TO", "值": settings.line_to or "未設定"},
        {"項目": "Telegram", "值": "connected" if telegram_status.get("connected") else (telegram_status.get("last_error") or "not connected")},
        {"項目": "Discord", "值": "connected" if discord_status.get("connected") else (discord_status.get("last_error") or "not connected")},
        {"項目": "Telegram 已選來源", "值": str(len(settings.monitored_chat_ids))},
        {"項目": "Discord 頻道", "值": str(len(settings.discord_channel_ids))},
        {"項目": "允許圖片標記", "值": zh_bool(settings.allow_image_signal)},
        {"項目": "今日訊息", "值": str(message_count["c"] if message_count else 0)},
        {"項目": "今日成功轉發", "值": str(sent_count["c"] if sent_count else 0)},
        {"項目": "今日轉發失敗", "值": str(failed_count["c"] if failed_count else 0)},
    ]
    body = "<div class='grid'><section class='card'><h2>狀態</h2>" + rows_table(info, ["項目", "值"]) + "</section>"
    body += """
    <section class="card">
      <h2>快速測試</h2>
      <div class="toolbar">
        <form method="post" action="/line/test"><button class="btn primary" type="submit">送 LINE 測試</button></form>
        <form method="post" action="/sources/refresh"><button class="btn" type="submit">刷新 Telegram 來源</button></form>
      </div>
    </section></div>
    """
    body += "<section class='card'><h2>最近訊息</h2><div class='table-wrap'>" + rows_table(recent_rows, ["created_at", "platform", "chat_name", "message_id", "has_image", "line_status", "line_error"]) + "</div></section>"
    return page("控制台", body)


@app.post("/line/test", dependencies=[Depends(require_auth)])
async def line_test() -> RedirectResponse:
    settings = await db.get_settings()
    try:
        recipients = line_to_values(settings)
        if not recipients:
            raise RuntimeError("LINE_TO is empty")
        for recipient in recipients:
            await line_push_text(recipient, f"{settings.line_message_prefix.strip() + chr(10) if settings.line_message_prefix.strip() else ''}LINE 測試通知\n時間: {utc8_now()}\n服務: {APP_NAME}")
        await db.log("INFO", "line", "LINE test message sent", {"recipient_count": len(recipients)})
    except Exception as exc:
        await db.log("ERROR", "line", "LINE test message failed", redact_secrets(str(exc)))
    return redirect("/")


@app.get("/settings", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def settings_page() -> HTMLResponse:
    settings = await db.get_settings()
    body = f"""
    <section class="card">
      <form method="post" action="/settings">
        <label><input type="checkbox" name="allow_image_signal" value="true" {checked(settings.allow_image_signal)}> 允許圖片標記與 Discord 圖片 URL 擷取</label>
        <label>LINE_TO（一行一個，可填 userId、groupId 或 roomId）</label>
        <textarea name="line_to" rows="4" placeholder="U... 或 C...">{html.escape(settings.line_to)}</textarea>
        <label>LINE 訊息前綴</label>
        <input name="line_message_prefix" value="{html.escape(settings.line_message_prefix)}" placeholder="例如：交易群通知">
        <label>Discord 頻道 ID（一行一個）</label>
        <textarea name="discord_channel_ids" rows="6" placeholder="123456789012345678">{html.escape(chr(10).join(settings.discord_channel_ids))}</textarea>
        <button class="btn primary" type="submit">儲存設定</button>
      </form>
    </section>
    <section class="card">
      <h2>環境狀態</h2>
      <table>
        <tr><th>項目</th><th>值</th></tr>
        <tr><td>LINE_CHANNEL_ACCESS_TOKEN</td><td>{html.escape(mask_secret(line_token())) or "未設定"}</td></tr>
        <tr><td>LINE_CHANNEL_SECRET</td><td>{html.escape(mask_secret(line_secret())) or "未設定"}</td></tr>
        <tr><td>TG_API_ID / TG_API_HASH</td><td>{zh_bool(bool(env_int("TG_API_ID", 0) and env_str("TG_API_HASH")))}</td></tr>
        <tr><td>TG_SESSION_STRING</td><td>{zh_bool(bool(await get_telegram_session_string()))}</td></tr>
        <tr><td>DISCORD_USER_TOKEN / USER_TOKEN</td><td>{zh_bool(bool(env_str("DISCORD_USER_TOKEN") or env_str("USER_TOKEN")))}</td></tr>
        <tr><td>DB_PATH</td><td>{html.escape(DB_PATH)}</td></tr>
      </table>
    </section>
    """
    return page("設定", body)


@app.post("/settings", dependencies=[Depends(require_auth)])
async def save_settings(
    allow_image_signal: Optional[str] = Form(None),
    line_to: str = Form(""),
    line_message_prefix: str = Form(""),
    discord_channel_ids: str = Form(""),
) -> RedirectResponse:
    updates = {
        "allow_image_signal": allow_image_signal == "true",
        "line_to": "\n".join(parse_multiline(line_to)),
        "line_message_prefix": line_message_prefix.strip(),
        "discord_channel_ids": parse_discord_channel_ids(discord_channel_ids),
    }
    for key, value in updates.items():
        await db.set_setting(key, value)
    await db.log("INFO", "ui", "Settings updated", updates)
    return redirect("/settings")


@app.get("/sources", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def sources_page(refresh: int = 0) -> HTMLResponse:
    settings = await db.get_settings()
    dialogs: list[dict[str, Any]] = []
    error = ""
    if refresh:
        try:
            dialogs = await fetch_telegram_dialogs()
        except Exception as exc:
            error = str(exc)
            await db.log("ERROR", "telegram", "Telegram source refresh failed", error)
    if not dialogs:
        dialogs = await get_dialog_cache()
    if not dialogs and not refresh:
        try:
            dialogs = await fetch_telegram_dialogs()
        except Exception as exc:
            error = str(exc)
            await db.log("WARN", "telegram", "Telegram source auto-refresh failed", error)
    selected = {str(item) for item in settings.monitored_chat_ids}
    listed_ids = {str(item.get("chat_id", "")) for item in dialogs}
    for item in dialogs:
        for topic in item.get("topics", []) or []:
            source_code = str(topic.get("source_code", "") or "")
            if source_code:
                listed_ids.add(source_code)
            listed_ids.update(telegram_topic_identifier_set(item.get("chat_id", ""), topic.get("topic_id", "")))
    manual_selected = sorted(item for item in selected if item and item not in listed_ids)
    api_id, api_hash, session_string = await get_telegram_credentials()
    body = f"""
    <section class="card">
      <form method="post" action="/sources/refresh">
        <button class="btn" type="submit">刷新 Telegram 頻道清單</button>
      </form>
      <p class="muted">TG_API_ID: {zh_bool(bool(api_id))} / TG_API_HASH: {zh_bool(bool(api_hash))} / TG_SESSION_STRING: {zh_bool(bool(session_string))}</p>
    </section>
    """
    if error:
        body += f"<section class='card warn'>Telegram 頻道清單抓取失敗：{html.escape(redact_secrets(error))}</section>"
    if not dialogs:
        body += "<section class='card warn'>目前沒有 Telegram 頻道快取。請先完成 Telegram 登入，再按「刷新 Telegram 頻道清單」。也可以在下方手動輸入來源 ID。</section>"
    body += "<form method='post' action='/sources'>"
    if dialogs:
        body += "<div class='table-wrap'><table><tr><th>選取</th><th>名稱</th><th>類型</th><th>ID</th><th>username</th></tr>"
        for item in dialogs:
            chat_id = str(item.get("chat_id", ""))
            username = str(item.get("username", ""))
            identifiers = {str(x) for x in item.get("identifiers", [])}
            item_checked = "checked" if chat_id in selected or username in selected or bool(identifiers & selected) else ""
            body += f"<tr><td><label><input type='checkbox' name='selected_chat_ids' value='{html.escape(chat_id)}' {item_checked}> 監聽</label></td><td>{html.escape(str(item.get('name','')))}</td><td>{html.escape(str(item.get('type','')))}</td><td>{html.escape(chat_id)}</td><td>{html.escape(username)}</td></tr>"
            for topic in item.get("topics", []) or []:
                topic_id = str(topic.get("topic_id", "") or "")
                source_code = str(topic.get("source_code", "") or telegram_topic_source_code(chat_id, topic_id))
                topic_identifiers = telegram_topic_identifier_set(chat_id, topic_id)
                topic_checked = "checked" if source_code in selected or bool(topic_identifiers & selected) else ""
                topic_title = str(topic.get("title", "") or topic_id)
                topic_status = "topic / closed" if topic.get("closed") else "topic"
                body += (
                    f"<tr><td><label><input type='checkbox' name='selected_chat_ids' value='{html.escape(source_code)}' {topic_checked}> 監聽</label></td>"
                    f"<td>&nbsp;&nbsp;↳ {html.escape(topic_title)}</td><td>{html.escape(topic_status)}</td><td>{html.escape(source_code)}</td><td>{html.escape(username)}</td></tr>"
                )
        body += "</table></div>"
    body += f"""
      <section class="card">
        <label>手動來源 ID（一行一個，可填 Telegram chat_id、@username，或 tg-topic:群組ID:topicID）</label>
        <textarea name="manual_source_ids" rows="6">{html.escape(chr(10).join(manual_selected))}</textarea>
        <button class="btn primary" type="submit">儲存來源</button>
      </section>
    </form>
    """
    return page("Telegram 來源", body)


@app.post("/sources", dependencies=[Depends(require_auth)])
async def save_sources(request: Request) -> RedirectResponse:
    form = await request.form()
    selected = [str(item) for item in form.getlist("selected_chat_ids") if str(item).strip()]
    manual_source_ids = parse_csv(str(form.get("manual_source_ids") or ""))
    for item in manual_source_ids:
        if item not in selected:
            selected.append(item)
    await db.set_setting("monitored_chat_ids", selected)
    await db.log("INFO", "ui", "Monitored sources updated", {"count": len(selected), "selected": selected})
    return redirect("/sources")


@app.post("/sources/update", dependencies=[Depends(require_auth)])
async def update_sources(request: Request) -> RedirectResponse:
    return await save_sources(request)


@app.post("/sources/refresh", dependencies=[Depends(require_auth)])
async def refresh_sources() -> RedirectResponse:
    try:
        await fetch_telegram_dialogs()
    except Exception as exc:
        await db.log("ERROR", "telegram", "Telegram source refresh failed", redact_secrets(str(exc)))
    return redirect("/sources")


@app.get("/discord-import", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def discord_import_page() -> HTMLResponse:
    body = """
    <section class="card">
      <form method="post" action="/discord-import">
        <label>Discord 頻道 ID</label><input name="channel_id">
        <label>來源名稱</label><input name="channel_name" value="Discord Manual">
        <label>訊息 ID</label><input name="message_id">
        <label>發送者</label><input name="sender_id" value="manual">
        <label>訊息內容</label><textarea name="text" rows="10"></textarea>
        <button class="btn primary" type="submit">匯入並轉發 LINE</button>
      </form>
    </section>
    """
    return page("Discord 匯入", body)


@app.post("/discord-import", dependencies=[Depends(require_auth)])
async def discord_import(channel_id: str = Form(...), channel_name: str = Form("Discord Manual"), message_id: str = Form(""), sender_id: str = Form("manual"), text: str = Form(...)) -> RedirectResponse:
    mid = message_id.strip() or str(int(time.time() * 1000))
    chat_id = discord_chat_id(channel_id)
    await upsert_raw_message("Discord", chat_id, channel_name, mid, sender_id, text, False, None, [], force_update=True)
    await process_discord_message(chat_id, channel_name, mid, sender_id, text, False, None, [], None)
    return redirect("/signals")


@app.get("/signals", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def signals_page() -> HTMLResponse:
    rows = await db.fetchall("SELECT * FROM raw_messages ORDER BY id DESC LIMIT 150")
    body = "<div class='table-wrap'><table><tr><th>來源</th><th>原文</th><th>圖片</th><th>LINE</th><th>時間</th><th>操作</th></tr>"
    for row in rows:
        actions = f"<form method='post' action='/messages/{row['id']}/resend'><button class='btn' type='submit'>重送</button></form>"
        line_note = status_text(row["line_status"]) + (f"<br><span class='warn'>{html.escape(str(row['line_error'] or ''))}</span>" if row["line_error"] else "")
        body += (
            "<tr>"
            f"<td class='text-cell'>{html.escape(str(row['chat_name'] or ''))}<br><span class='muted'>{html.escape(str(row['chat_id']))} / {html.escape(str(row['message_id']))}</span></td>"
            f"<td class='text-cell'>{html.escape(str(row['text'] or ''))}</td>"
            f"<td>{zh_bool(row['has_image'])}</td>"
            f"<td>{line_note}</td>"
            f"<td>{html.escape(str(row['created_at']))}</td>"
            f"<td>{actions}</td>"
            "</tr>"
        )
    body += "</table></div>"
    return page("訊息紀錄", body)


@app.post("/messages/{raw_id}/resend", dependencies=[Depends(require_auth)])
async def resend_message(raw_id: int) -> RedirectResponse:
    row = await db.fetchone("SELECT * FROM raw_messages WHERE id=?", (raw_id,))
    if not row:
        await db.log("WARN", "ui", "Raw message not found for resend", raw_id)
        return redirect("/signals")
    image_urls = safe_json_loads(row["image_urls"], [])
    await db.execute("DELETE FROM processed_messages WHERE chat_id=? AND message_id=?", (row["chat_id"], row["message_id"]))
    await db.execute("UPDATE raw_messages SET processed=0, line_status='pending', line_error=NULL WHERE id=?", (raw_id,))
    await process_message(
        row["chat_id"],
        row["chat_name"] or row["chat_id"],
        row["message_id"],
        row["sender_id"] or "",
        row["text"] or "",
        bool(row["has_image"]),
        None,
        image_urls if isinstance(image_urls, list) else [],
        row["reply_to_message_id"],
    )
    return redirect("/signals")


def line_source_to_value(source: dict[str, Any]) -> str:
    return str(source.get("groupId") or source.get("roomId") or source.get("userId") or "")


def should_reply_line_id(event: dict[str, Any]) -> bool:
    event_type = str(event.get("type") or "")
    if event_type in {"follow", "join"}:
        return True
    message = event.get("message") if isinstance(event.get("message"), dict) else {}
    text = str(message.get("text") or "").strip().lower()
    return text in {"/id", "id", "line id", "group id", "群組id", "群組 id"}


@app.post("/line/webhook")
async def line_webhook(request: Request) -> dict[str, Any]:
    secret = line_secret()
    if not secret:
        raise HTTPException(status_code=503, detail="LINE_CHANNEL_SECRET is not configured")
    body = await request.body()
    signature = request.headers.get("x-line-signature", "")
    expected = base64.b64encode(hmac.new(secret.encode(), body, hashlib.sha256).digest()).decode()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="Invalid LINE signature")
    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    events_payload = payload.get("events", []) if isinstance(payload, dict) else []
    for event in events_payload:
        source = event.get("source") if isinstance(event.get("source"), dict) else {}
        line_to = line_source_to_value(source)
        message = event.get("message") if isinstance(event.get("message"), dict) else {}
        message_text = str(message.get("text") or "")
        reply_token = str(event.get("replyToken") or "")
        await db.execute(
            """
            INSERT INTO line_webhook_events(source_type, line_to, event_type, reply_token, message_text, raw_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(source.get("type") or ""),
                line_to,
                str(event.get("type") or ""),
                reply_token,
                message_text,
                json.dumps(event, ensure_ascii=False),
                utc_now(),
            ),
        )
        if line_to and should_reply_line_id(event):
            try:
                await line_reply_text(reply_token, f"收到。這個聊天室請填：\nLINE_TO={line_to}")
            except Exception as exc:
                await db.log("ERROR", "line", "LINE webhook reply failed", redact_secrets(str(exc)))
    return {"ok": True}


@app.get("/line/events", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def line_events_page() -> HTMLResponse:
    rows = await db.fetchall("SELECT * FROM line_webhook_events ORDER BY id DESC LIMIT 80")
    body = """
    <section class="card">
      <h2>Webhook URL</h2>
      <p class="muted">在 LINE Developers 的 Messaging API channel 填入：<code>https://你的-zeabur-domain/line/webhook</code>。加入好友或邀請進群組後，傳 <code>/id</code>，這裡會出現可填入 LINE_TO 的值。</p>
    </section>
    """
    body += "<div class='table-wrap'>" + rows_table(rows, ["created_at", "source_type", "line_to", "event_type", "message_text"]) + "</div>"
    return page("LINE 事件", body)


@app.get("/logs", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def logs_page() -> HTMLResponse:
    rows = await db.fetchall("SELECT * FROM logs ORDER BY id DESC LIMIT 200")
    return page("日誌", "<div class='table-wrap'>" + rows_table(rows, ["created_at", "level", "source", "message", "details"]) + "</div>")


@app.get("/telegram-session", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def telegram_session_page(request: Request) -> HTMLResponse:
    session_id = request.cookies.get("tg_setup_id") or secrets.token_urlsafe(16)
    api_ready = bool(env_int("TG_API_ID", 0) and env_str("TG_API_HASH"))
    session_string = await get_telegram_session_string()
    body = f"""
    <section class="card">
      <p>TG_SESSION_STRING: {status_text('configured') if session_string else '未設定'}</p>
      <p>TG_API_ID / TG_API_HASH: {status_text('configured') if api_ready else '未設定'}</p>
      <form method="post" action="/telegram-session/send-code">
        <label>電話號碼（含國碼，例如 +8869...）</label>
        <input name="phone">
        <input type="hidden" name="session_id" value="{html.escape(session_id)}">
        <button class="btn" type="submit">送出驗證碼</button>
      </form>
      <form method="post" action="/telegram-session/sign-in">
        <label>驗證碼</label><input name="code">
        <label>兩步驟密碼</label><input type="password" name="password">
        <input type="hidden" name="session_id" value="{html.escape(session_id)}">
        <button class="btn primary" type="submit">建立 StringSession</button>
      </form>
    </section>
    """
    response = HTMLResponse(layout("Telegram 登入", body))
    response.set_cookie("tg_setup_id", session_id, httponly=True, samesite="lax", max_age=SESSION_TTL_SECONDS)
    return response


@app.post("/telegram-session/send-code", dependencies=[Depends(require_auth)])
async def telegram_send_code(phone: str = Form(...), session_id: str = Form(...)) -> RedirectResponse:
    api_id, api_hash, _ = await get_telegram_credentials()
    if not (api_id and api_hash):
        await db.log("ERROR", "telegram", "Missing TG_API_ID/TG_API_HASH")
        return redirect("/telegram-session")
    client = TelegramClient(StringSession(), api_id, api_hash)
    await client.connect()
    sent = await client.send_code_request(phone)
    pending_login_sessions[session_id] = {"client": client, "phone": phone, "phone_code_hash": sent.phone_code_hash}
    await db.log("INFO", "telegram", "Telegram login code sent", {"phone": phone})
    return redirect("/telegram-session")


@app.post("/telegram-session/login", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
@app.post("/telegram-session/sign-in", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def telegram_sign_in(code: str = Form(...), password: str = Form(""), session_id: str = Form(...)) -> HTMLResponse:
    pending = pending_login_sessions.get(session_id)
    if not pending:
        return page("Telegram 登入", "<section class='card warn'>請先送出驗證碼。</section>")
    client: TelegramClient = pending["client"]
    try:
        try:
            await client.sign_in(phone=pending["phone"], code=code, phone_code_hash=pending["phone_code_hash"])
        except SessionPasswordNeededError:
            if not password:
                return page("Telegram 登入", "<section class='card warn'>需要 Telegram 兩步驟密碼。</section>")
            await client.sign_in(password=password)
        session_string = client.session.save()
        await db.set_setting("tg_session_string", session_string)
        pending_login_sessions.pop(session_id, None)
        telegram_status["running"] = False
        asyncio.create_task(start_telegram_listener())
        return page("Telegram 登入", f"<section class='card'><p class='ok'>Session 已儲存，監聽器會自動啟動。</p><p class='muted'>建議把下方值複製到 Zeabur 的 TG_SESSION_STRING，避免重部署後 SQLite 遺失。</p><pre>{html.escape(session_string)}</pre></section>")
    except Exception as exc:
        return page("Telegram 登入", f"<section class='card warn'>登入失敗：{html.escape(redact_secrets(str(exc)))}</section>")
    finally:
        if client.is_connected():
            await client.disconnect()


if __name__ == "__main__":
    port = env_int("PORT", 8080)
    uvicorn.run(app, host="0.0.0.0", port=port)
