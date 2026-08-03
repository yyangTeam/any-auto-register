"""Local mailbox pool provider.

The importer accepts:

* Xinlan/BH Mailer "common" account rows. Microsoft accounts with Client Id +
  refresh token are read through Microsoft Graph; rows without OAuth material
  fall back to IMAP only when inbound server fields are present and usable.
* iCloud relay rows in the form: email@icloud.com---https://.../email@icloud.com
  (three or more hyphens are accepted as the separator).
* Tokenized iCloud inbox rows in the form:
  email@icloud.com----https://email.example/icloud/ACCESS_TOKEN.
* FlySMS pickup rows in the form:
  email@icloud.com------https://flysms.xyz/icloud/pickup#email=...&key=...
"""

from __future__ import annotations

import base64
import csv
import email as email_lib
import hashlib
import imaplib
import json
import re
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from email.header import decode_header
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

from core.base_mailbox import BaseMailbox, MailboxAccount, _extract_verification_link


GRAPH_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
GRAPH_MESSAGES_URL = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
DEFAULT_GRAPH_SCOPE = "https://graph.microsoft.com/Mail.Read offline_access"
OUTLOOK_TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
OUTLOOK_IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
OUTLOOK_IMAP_HOST = "outlook.office365.com"
DEFAULT_STATE_FILE = Path(__file__).resolve().parent.parent / "data" / ".local_mailbox_pool_state.json"
LEGACY_STATE_FILE = Path(__file__).resolve().parent.parent / "data" / ".local_ms_mailbox_pool_state.json"
LOCAL_MAIL_POOL_PROVIDER_NAME = "local_mail_pool"
LEGACY_LOCAL_MS_POOL_PROVIDER_NAME = "local_ms_pool"
ICLOUD_RELAY_DOMAINS = {"icloud.com", "me.com", "mac.com"}
FLYSMS_PICKUP_HOST = "flysms.xyz"
FLYSMS_PICKUP_PATH = "/icloud/pickup"
FLYSMS_LATEST_MESSAGE_URL = "https://flysms.xyz/icloud/api/pickup/messages/latest"
FLYSMS_TOKEN_RE = re.compile(r"^tok_[A-Za-z0-9_-]{1,508}$")
_IGNORABLE_TRAILING_STATUSES = {
    "trial", "plus", "paid", "success", "failed", "registered", "active",
    "free", "expired", "invalid", "subscribed", "done", "ok",
    "已注册", "成功", "失败", "已失败", "plus订单", "注册失败",
}


class _MailboxCardHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.messages: list[dict[str, str]] = []
        self._current: dict[str, list[str]] | None = None
        self._capture_field = ""
        self._capture_tag = ""

    @staticmethod
    def _classes(attrs: list[tuple[str, str | None]]) -> set[str]:
        value = next((value or "" for key, value in attrs if key == "class"), "")
        return {item for item in value.split() if item}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = self._classes(attrs)
        if tag == "article" and "mail-card" in classes:
            self._current = {"subject": [], "date": [], "body": []}
            self._capture_field = ""
            self._capture_tag = ""
            return
        if self._current is None:
            return
        if tag == "span" and "subject" in classes:
            self._capture_field, self._capture_tag = "subject", tag
        elif tag == "span" and "date" in classes:
            self._capture_field, self._capture_tag = "date", tag
        elif tag == "pre" and "body" in classes:
            self._capture_field, self._capture_tag = "body", tag

    def handle_endtag(self, tag: str) -> None:
        if self._capture_tag == tag:
            self._capture_field = ""
            self._capture_tag = ""
        if tag == "article" and self._current is not None:
            message = {
                key: re.sub(r"\s+", " ", "".join(value)).strip()
                for key, value in self._current.items()
            }
            if any(message.values()):
                self.messages.append(message)
            self._current = None

    def handle_data(self, data: str) -> None:
        if self._current is not None and self._capture_field:
            self._current[self._capture_field].append(data)


@dataclass(frozen=True)
class LocalMicrosoftMailboxEntry:
    email: str
    password: str = ""
    login_account: str = ""
    imap_host: str = ""
    imap_port: str = ""
    imap_account_type: str = ""
    imap_security: str = ""
    smtp_host: str = ""
    smtp_port: str = ""
    smtp_security: str = ""
    note: str = ""
    proxy_mode: str = ""
    proxy: str = ""
    label: str = ""
    recovery_email: str = ""
    recovery_password: str = ""
    client_id: str = ""
    refresh_token: str = ""
    totp_secret: str = ""
    totp_url: str = ""
    login_mode: str = ""
    receive_provider: str = "microsoft"
    icloud_api_url: str = ""
    raw: str = ""

    @property
    def key(self) -> str:
        return self.email.strip().lower()

    @property
    def graph_ready(self) -> bool:
        return bool(self.client_id and self.refresh_token)

    @property
    def imap_ready(self) -> bool:
        return bool(self.imap_host and (self.login_account or self.email) and self.password)

    @property
    def icloud_api_ready(self) -> bool:
        return self.receive_provider == "icloud_api" and bool(self.icloud_api_url)

    @property
    def receive_ready(self) -> bool:
        return self.icloud_api_ready or self.graph_ready or self.imap_ready

    @property
    def existing_login_ready(self) -> bool:
        return bool(self.password and (self.totp_secret or self.totp_url))

    @property
    def usable_ready(self) -> bool:
        return self.receive_ready or self.existing_login_ready

    @property
    def source(self) -> str:
        if self.icloud_api_ready:
            return "icloud_api"
        return "xinlan_common"

    def credentials(self) -> dict:
        return {
            "email": self.email,
            "password": self.password,
            "login_account": self.login_account,
            "imap_host": self.imap_host,
            "imap_port": self.imap_port,
            "imap_account_type": self.imap_account_type,
            "imap_security": self.imap_security,
            "client_id": self.client_id,
            "refresh_token": self.refresh_token,
            "recovery_email": self.recovery_email,
            "recovery_password": self.recovery_password,
            "totp_secret": self.totp_secret,
            "totp_url": self.totp_url,
            "login_mode": self.login_mode,
            "receive_provider": self.receive_provider,
            "icloud_api_url": self.icloud_api_url,
        }


def _truthy(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "y"}


def _safe_text(value: object) -> str:
    return str(value or "").strip().strip("\ufeff")


def _csv_split(line: str, delimiter: str) -> list[str]:
    try:
        return next(csv.reader([line], delimiter=delimiter, quotechar='"', skipinitialspace=True))
    except Exception:
        return line.split(delimiter)


def _is_ignorable_trailing_status(value: str) -> bool:
    """Return whether an export's final field is a status, not credentials."""
    text = _safe_text(value)
    normalized = re.sub(r"\s+", "", text).lower()
    if not normalized or normalized not in _IGNORABLE_TRAILING_STATUSES:
        return False
    # Do not discard credential-shaped values even if a future status name
    # overlaps with one of them.
    if re.match(r"https?://", text, flags=re.I) or "@" in text:
        return False
    if re.fullmatch(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", text):
        return False
    if text.lower().startswith("rt.1"):
        return False
    return not bool(re.fullmatch(r"[A-Z2-7\s-]{16,}", text, flags=re.I))


def _strip_trailing_statuses(parts: list[str]) -> list[str]:
    """Remove only consecutive trailing export statuses from parsed fields."""
    while len(parts) > 1 and _is_ignorable_trailing_status(parts[-1]):
        parts.pop()
    return parts


def split_xinlan_common_line(line: str) -> list[str]:
    text = str(line or "").strip().strip("\ufeff")
    if not text:
        return []
    labeled_email = re.search(r"chatgpt谷歌邮箱\s*[：:]\s*([^\s,，|]+@[^\s,，|]+)", text, re.I)
    if labeled_email:
        labeled_password = re.search(r"chatgpt密码\s*[：:]\s*(\S+)", text, re.I)
        labeled_totp = re.search(r"一次性安全码密钥\s*[：:]\s*([A-Z2-7\s-]{16,})", text, re.I)
        return _strip_trailing_statuses([
            labeled_email.group(1),
            labeled_password.group(1) if labeled_password else "",
            labeled_totp.group(1) if labeled_totp else "",
        ])
    # Match direct relay rows before fixed-width account formats. Only inspect
    # the first separator after the @ so `email----password----url` remains a
    # password-login row, while six-hyphen relay rows keep an intact URL.
    at_index = text.find("@")
    delimiter = re.search(r"-{3,}", text[at_index + 1:]) if at_index >= 0 else None
    if delimiter:
        delimiter_start = at_index + 1 + delimiter.start()
        delimiter_end = at_index + 1 + delimiter.end()
        relay_email = text[:delimiter_start].strip()
        relay_url = text[delimiter_end:].strip()
        if _looks_like_http_url(relay_url):
            return [relay_email, relay_url]
    # Four-hyphen rows may contain a password before the inbox URL. Keep long
    # relay separators (for example 16 hyphens) on the legacy relay branch.
    if "----" in text:
        hyphen_parts = text.split("----")
        if all(part.strip() for part in hyphen_parts):
            return _strip_trailing_statuses([item.strip() for item in hyphen_parts])
    # Some account exports use exactly three hyphens for four fields:
    # email---password---MFA secret---old access-token JWT. Preserve all four
    # fields before the legacy variable-separator matcher collapses the middle.
    triple_parts = text.split("---")
    if len(triple_parts) >= 3 and "@" in triple_parts[0] and all(part.strip() for part in triple_parts):
        return _strip_trailing_statuses([item.strip() for item in triple_parts])
    if len(triple_parts) == 4 and "@" in triple_parts[0]:
        maybe_totp = re.sub(r"[\s-]+", "", triple_parts[2]).upper()
        maybe_access_token = triple_parts[3].strip()
        if (
            re.fullmatch(r"[A-Z2-7]{16,}", maybe_totp)
            and re.fullmatch(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", maybe_access_token)
        ):
            return [item.strip() for item in triple_parts]
    variable_separator_match = re.fullmatch(
        r"(?P<email>\S+?@\S+?)-{3,}(?P<middle>.+?)-{3,}(?P<last>\S+)",
        text,
        flags=re.I,
    )
    if variable_separator_match:
        return [
            variable_separator_match.group("email").strip(),
            variable_separator_match.group("middle").strip(),
            variable_separator_match.group("last").strip(),
        ]
    # Three-hyphen rows may be either `email---url` or `email---token---url`.
    # Keep the middle token when it exists so downstream mailbox parsers can
    # decide whether it is a password, an inbox token, or a provider-specific
    # secret.
    if text.count("---") >= 2 and "@" in text.split("---", 1)[0]:
        if len(triple_parts) >= 3 and all(part.strip() for part in triple_parts):
            return [triple_parts[0].strip(), "---".join(triple_parts[1:-1]).strip(), triple_parts[-1].strip()]
    if text.count("|") >= 2:
        pipe_parts = _strip_trailing_statuses(text.split("|"))
        return [pipe_parts[0].strip(), "|".join(pipe_parts[1:-1]), pipe_parts[-1].strip()]
    if "\t" in text:
        return _strip_trailing_statuses([item.strip() for item in text.split("\t")])
    if "，" in text:
        return _strip_trailing_statuses([item.strip() for item in _csv_split(text, "，")])
    if "," in text:
        return _strip_trailing_statuses([item.strip() for item in _csv_split(text, ",")])
    return _strip_trailing_statuses([item.strip() for item in re.split(r"\s+", text) if item.strip()])


def _email_domain(value: str) -> str:
    return str(value or "").strip().lower().rsplit("@", 1)[-1]


def _looks_like_http_url(value: str) -> bool:
    try:
        parsed = urlparse(str(value or "").strip())
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False


def _parse_flysms_pickup_url(value: str, expected_email: str) -> tuple[str, str] | None:
    """Return FlySMS pickup credentials, or None for a non-FlySMS URL."""
    try:
        parsed = urlparse(str(value or "").strip())
    except Exception:
        return None

    is_flysms = (
        parsed.scheme == "https"
        and (parsed.hostname or "").lower() == FLYSMS_PICKUP_HOST
        and parsed.port in (None, 443)
        and parsed.path.rstrip("/") == FLYSMS_PICKUP_PATH
    )
    if not is_flysms:
        return None
    if parsed.query or parsed.username or parsed.password:
        raise RuntimeError("FlySMS 取件链接无效: 不支持查询参数或 URL 内嵌账号")

    params = parse_qs(parsed.fragment, keep_blank_values=True)
    if set(params) != {"email", "key"} or len(params["email"]) != 1 or len(params["key"]) != 1:
        raise RuntimeError("FlySMS 取件链接无效: #email 和 key 必须各出现一次")

    email = _safe_text(params["email"][0]).lower()
    token = _safe_text(params["key"][0])
    if email != _safe_text(expected_email).lower():
        raise RuntimeError("FlySMS 取件链接中的邮箱与账号池邮箱不一致")
    if not FLYSMS_TOKEN_RE.fullmatch(token):
        raise RuntimeError("FlySMS 取件链接中的 key 格式无效")
    return email, token


def parse_xinlan_common_rows(text: str) -> list[LocalMicrosoftMailboxEntry]:
    entries: list[LocalMicrosoftMailboxEntry] = []
    seen: set[str] = set()
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith("'"):
            continue
        parts = split_xinlan_common_line(line)
        if not parts:
            continue
        padded = parts + [""] * max(0, 19 - len(parts))
        email = _safe_text(padded[0])
        if "@" not in email:
            continue

        # iCloud 接码地址格式：
        #   cracked-xxx@icloud.com---https://icloud-api.top/show/.../cracked-xxx@icloud.com
        # 三个及以上连字符均支持。
        # 第二列是 URL 时，后续供应商元数据不参与收码，避免被误当密码/IMAP 字段。
        icloud_api_row = (
            len(parts) >= 2
            and _looks_like_http_url(_safe_text(parts[1]))
        )
        if icloud_api_row:
            entry = LocalMicrosoftMailboxEntry(
                email=email,
                login_account=email,
                receive_provider="icloud_api",
                icloud_api_url=_safe_text(parts[1]),
                raw=line,
            )
            if entry.key in seen:
                continue
            seen.add(entry.key)
            entries.append(entry)
            continue

        # 常见导出格式有三类：
        # 1) 心蓝/BH 19 列通用格式：邮箱、密码、登录账号、IMAP...、client_id、refresh_token...
        # 2) 简化 OAuth 格式：邮箱----密码----client_id----refresh_token[----totp]
        # 3) 已注册账号格式：邮箱----OpenAI 密码----MFA，或 邮箱|OpenAI 密码|MFA
        # 4) 密码登录 + 接码地址：邮箱----OpenAI 密码----接码 URL
        # 5) 密码登录 + 接码地址 + MFA 地址：邮箱----密码----接码 URL----2FA URL
        # 6) 已登录导出格式：邮箱---密码---MFA---旧 access_token
        # 旧逻辑会把 4 列格式的 refresh_token 误当作 imap_host，随后 socket
        # DNS 解析抛出 "label too long"。这里优先识别简化 OAuth 格式。
        simplified_oauth = False
        if len(parts) in (4, 5):
            maybe_client_id = _safe_text(parts[2])
            maybe_refresh_token = _safe_text(parts[3])
            simplified_oauth = bool(
                maybe_client_id
                and maybe_refresh_token
                and len(maybe_refresh_token) > 80
                and "." not in maybe_client_id.strip("{}")
            )

        password_with_inbox = (
            len(parts) == 3
            and _looks_like_http_url(_safe_text(parts[2]))
        )
        password_with_inbox_and_totp_url = (
            len(parts) == 4
            and _looks_like_http_url(_safe_text(parts[2]))
            and _looks_like_http_url(_safe_text(parts[3]))
        )
        login_with_mfa = False
        login_with_mfa_and_access_token = False
        if len(parts) in (3, 4):
            maybe_totp = re.sub(r"[\s-]+", "", _safe_text(parts[2])).upper()
            login_with_mfa = bool(re.fullmatch(r"[A-Z2-7]{16,}", maybe_totp))
            if len(parts) == 4:
                maybe_access_token = _safe_text(parts[3])
                login_with_mfa_and_access_token = bool(
                    login_with_mfa
                    and re.fullmatch(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", maybe_access_token)
                )

        if password_with_inbox_and_totp_url:
            entry = LocalMicrosoftMailboxEntry(
                email=email,
                password=_safe_text(parts[1]),
                login_account=email,
                totp_url=_safe_text(parts[3]),
                login_mode="password_mfa_url",
                receive_provider="icloud_api",
                icloud_api_url=_safe_text(parts[2]),
                raw=line,
            )
        elif password_with_inbox:
            entry = LocalMicrosoftMailboxEntry(
                email=email,
                password=_safe_text(parts[1]),
                login_account=email,
                login_mode="password_or_email_otp",
                receive_provider="icloud_api",
                icloud_api_url=_safe_text(parts[2]),
                raw=line,
            )
        elif login_with_mfa and (len(parts) == 3 or login_with_mfa_and_access_token):
            # `|` 货商格式可能包含有意义的密码空格；只清理邮箱和 MFA，
            # 密码保留第一个与最后一个 `|` 之间的原始内容。
            preserve_password_spaces = "----" not in line and line.count("|") >= 2
            entry = LocalMicrosoftMailboxEntry(
                email=email,
                password=str(parts[1]) if preserve_password_spaces else _safe_text(parts[1]),
                login_account=email,
                totp_secret=re.sub(r"[\s-]+", "", _safe_text(parts[2])).upper(),
                login_mode="password_mfa",
                raw=line,
            )
        elif simplified_oauth:
            entry = LocalMicrosoftMailboxEntry(
                email=email,
                password=_safe_text(parts[1]),
                login_account=email,
                client_id=_safe_text(parts[2]),
                refresh_token=_safe_text(parts[3]),
                totp_secret=_safe_text(parts[4]) if len(parts) > 4 else "",
                raw=line,
            )
        else:
            entry = LocalMicrosoftMailboxEntry(
                email=email,
                password=_safe_text(padded[1]),
                login_account=_safe_text(padded[2]) or email,
                imap_host=_safe_text(padded[3]),
                imap_port=_safe_text(padded[4]),
                imap_account_type=_safe_text(padded[5]),
                imap_security=_safe_text(padded[6]),
                smtp_host=_safe_text(padded[7]),
                smtp_port=_safe_text(padded[8]),
                smtp_security=_safe_text(padded[9]),
                note=_safe_text(padded[10]),
                proxy_mode=_safe_text(padded[11]),
                proxy=_safe_text(padded[12]),
                label=_safe_text(padded[13]),
                recovery_email=_safe_text(padded[14]),
                recovery_password=_safe_text(padded[15]),
                client_id=_safe_text(padded[16]),
                refresh_token=_safe_text(padded[17]),
                totp_secret=_safe_text(padded[18]),
                raw=line,
            )
        if entry.key in seen:
            continue
        seen.add(entry.key)
        entries.append(entry)
    return entries


class LocalMicrosoftMailboxPool(BaseMailbox):
    """Use existing mailbox accounts from a local text pool."""

    _lock = threading.Lock()

    def __init__(
        self,
        *,
        pool_text: str = "",
        pool_file: str = "",
        state_file: str = "",
        graph_scope: str = "",
        allow_reuse: bool = False,
        avoid_repeat: bool = False,
        failure_cooldown_seconds: int = 0,
        proxy: str = None,
    ):
        self.pool_text = str(pool_text or "")
        self.pool_file = str(pool_file or "").strip()
        self.state_file = Path(state_file or DEFAULT_STATE_FILE)
        self.graph_scope = str(graph_scope or DEFAULT_GRAPH_SCOPE).strip()
        self.allow_reuse = bool(allow_reuse)
        self.avoid_repeat = bool(avoid_repeat)
        self._attempted_keys: set[str] = set()
        self.failure_cooldown_seconds = max(int(failure_cooldown_seconds or 0), 0)
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self._oauth_mail_strategy: dict[str, str] = {}

    @classmethod
    def from_config(cls, config: dict) -> "LocalMicrosoftMailboxPool":
        return cls(
            pool_text=config.get("local_mail_pool_text") or config.get("local_ms_pool_text", ""),
            pool_file=config.get("local_mail_pool_file") or config.get("local_ms_pool_file", ""),
            state_file=config.get("local_mail_pool_state_file") or config.get("local_ms_pool_state_file", ""),
            graph_scope=config.get("local_ms_graph_scope", ""),
            allow_reuse=_truthy(config.get("local_mail_pool_allow_reuse") if "local_mail_pool_allow_reuse" in config else config.get("local_ms_pool_allow_reuse")),
            avoid_repeat=_truthy(config.get("local_mail_pool_avoid_repeat")),
            failure_cooldown_seconds=config.get("local_mail_pool_failure_cooldown_seconds", 0),
            proxy=config.get("proxy") or None,
        )

    def _load_pool_text(self) -> str:
        chunks: list[str] = []
        state = self._state()
        retry_rows = dict(state.get("retry_rows") or {})
        pending_rows = dict(state.get("pending_rows") or {})
        managed_rows = [
            str(item.get("raw") or "").strip()
            for rows in (retry_rows, pending_rows)
            for item in rows.values()
            if isinstance(item, dict) and str(item.get("raw") or "").strip()
        ]
        if managed_rows:
            chunks.append("\n".join(managed_rows))
        if self.pool_text.strip():
            chunks.append(self.pool_text)
        if self.pool_file:
            path = Path(self.pool_file).expanduser()
            if not path.exists():
                raise RuntimeError(f"本地邮箱池文件不存在: {path}")
            chunks.append(path.read_text(encoding="utf-8-sig"))
        combined = "\n".join(chunks)
        if not combined.strip():
            raise RuntimeError("本地邮箱池为空，请粘贴心蓝格式、邮箱接码地址、密码 + MFA 账号或配置文件路径")
        return combined

    def _entries(self) -> list[LocalMicrosoftMailboxEntry]:
        entries = parse_xinlan_common_rows(self._load_pool_text())
        if not entries:
            raise RuntimeError("本地邮箱池未解析到有效邮箱")
        return entries

    def _usable_entries(self) -> list[LocalMicrosoftMailboxEntry]:
        entries = [entry for entry in self._entries() if entry.usable_ready]
        if not entries:
            raise RuntimeError("本地邮箱池没有可用账号，请提供密码 + MFA，或接码 URL、Microsoft OAuth、IMAP 收件配置")
        return entries

    def _state(self) -> dict:
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception:
            if self.state_file == DEFAULT_STATE_FILE and LEGACY_STATE_FILE.exists():
                try:
                    return json.loads(LEGACY_STATE_FILE.read_text(encoding="utf-8"))
                except Exception:
                    pass
            return {"used": {}}

    def _save_state(self, state: dict) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

    def _source_id(self) -> str:
        material = f"{self.pool_file}\n{self.pool_text}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()[:16]

    def _reserve(self, entry: LocalMicrosoftMailboxEntry) -> None:
        if self.allow_reuse:
            return
        state = self._state()
        used = dict(state.get("used") or {})
        cooldowns = dict(state.get("cooldowns") or {})
        cooldowns.pop(entry.key, None)
        used[entry.key] = {
            "email": entry.email,
            "reserved_at": datetime.now(timezone.utc).isoformat(),
            "source_id": self._source_id(),
        }
        state["used"] = used
        state["cooldowns"] = cooldowns
        self._save_state(state)

    def release_email(self, account_or_email, *, cooldown: bool = False, error: str = "") -> bool:
        """Release a reservation made by get_email() for failed tasks.

        Successful tasks intentionally keep the reservation so the same imported
        account is not processed again. Failed tasks can call this to make the
        mailbox available for retry.
        """
        if self.allow_reuse:
            return False
        email_value = getattr(account_or_email, "email", account_or_email)
        key = str(email_value or "").strip().lower()
        if not key:
            return False
        with self._lock:
            entries = {entry.key: entry for entry in self._entries()}
            state = self._state()
            used = dict(state.get("used") or {})
            if key not in used:
                retry_rows = dict(state.get("retry_rows") or {})
                retry_item = dict(retry_rows.get(key) or {})
                if retry_item and str(error or "").strip():
                    retry_item["last_error"] = str(error).strip()
                    retry_item["updated_at"] = datetime.now(timezone.utc).isoformat()
                    retry_rows[key] = retry_item
                    state["retry_rows"] = retry_rows
                    self._save_state(state)
                return False
            used.pop(key, None)
            state["used"] = used
            cooldowns = dict(state.get("cooldowns") or {})
            cooldowns.pop(key, None)
            state["cooldowns"] = cooldowns
            entry = entries.get(key)
            if entry and entry.raw:
                retry_rows = dict(state.get("retry_rows") or {})
                previous = dict(retry_rows.get(key) or {})
                retry_rows[key] = {
                    "email": entry.email,
                    "raw": entry.raw,
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "attempts": int(previous.get("attempts") or 0) + 1,
                    "last_error": str(error or previous.get("last_error") or "").strip(),
                }
                state["retry_rows"] = retry_rows
                pending_rows = dict(state.get("pending_rows") or {})
                pending_rows.pop(key, None)
                state["pending_rows"] = pending_rows
            self._save_state(state)
            return True

    def release_unsaved_reservations(self, saved_emails: set[str]) -> list[str]:
        """Release current-pool reservations that have no saved platform account."""
        saved_keys = {str(email or "").strip().lower() for email in saved_emails if str(email or "").strip()}
        entries = {entry.key: entry for entry in self._usable_entries()}
        with self._lock:
            state = self._state()
            used = dict(state.get("used") or {})
            pending_rows = dict(state.get("pending_rows") or {})
            retry_rows = dict(state.get("retry_rows") or {})
            completed_rows_removed = False
            for key in saved_keys:
                if key in pending_rows:
                    pending_rows.pop(key, None)
                    completed_rows_removed = True
                if key in retry_rows:
                    retry_rows.pop(key, None)
                    completed_rows_removed = True
            orphaned_keys = [key for key in entries if key in used and key not in saved_keys]
            if not orphaned_keys:
                if completed_rows_removed:
                    state["pending_rows"] = pending_rows
                    state["retry_rows"] = retry_rows
                    self._save_state(state)
                return []
            cooldowns = dict(state.get("cooldowns") or {})
            for key in orphaned_keys:
                used.pop(key, None)
                cooldowns.pop(key, None)
                entry = entries.get(key)
                if entry and entry.raw:
                    previous = dict(retry_rows.get(key) or {})
                    retry_rows[key] = {
                        "email": entry.email,
                        "raw": entry.raw,
                        "failed_at": datetime.now(timezone.utc).isoformat(),
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                        "attempts": int(previous.get("attempts") or 0) + 1,
                        "last_error": str(previous.get("last_error") or "").strip(),
                    }
            for key in orphaned_keys:
                pending_rows.pop(key, None)
            state["used"] = used
            state["cooldowns"] = cooldowns
            state["retry_rows"] = retry_rows
            state["pending_rows"] = pending_rows
            self._save_state(state)
            return [entries[key].email for key in orphaned_keys]

    def import_registration_rows(self, text: str) -> dict[str, int]:
        """Add new rows to the managed registration queue without changing provider config."""
        source_lines = [
            line.strip()
            for line in str(text or "").splitlines()
            if line.strip() and not line.strip().startswith(("#", "//", "'"))
        ]
        parsed = parse_xinlan_common_rows("\n".join(source_lines))
        usable = [entry for entry in parsed if entry.usable_ready]
        with self._lock:
            state = self._state()
            pending_rows = dict(state.get("pending_rows") or {})
            retry_rows = dict(state.get("retry_rows") or {})
            used = dict(state.get("used") or {})
            configured_chunks = [self.pool_text] if self.pool_text.strip() else []
            if self.pool_file:
                path = Path(self.pool_file).expanduser()
                if path.exists():
                    configured_chunks.append(path.read_text(encoding="utf-8-sig"))
            configured_entries = parse_xinlan_common_rows("\n".join(configured_chunks))
            existing_keys = {entry.key for entry in configured_entries}
            imported = 0
            duplicates = 0
            skipped_used = 0
            now = datetime.now(timezone.utc).isoformat()
            for entry in usable:
                if entry.key in used:
                    skipped_used += 1
                    continue
                if entry.key in pending_rows or entry.key in retry_rows or entry.key in existing_keys:
                    duplicates += 1
                    continue
                pending_rows[entry.key] = {
                    "email": entry.email,
                    "raw": entry.raw,
                    "imported_at": now,
                    "updated_at": now,
                    "attempts": 0,
                }
                existing_keys.add(entry.key)
                imported += 1
            state["pending_rows"] = pending_rows
            self._save_state(state)
        return {
            "imported": imported,
            "duplicates": duplicates,
            "skipped_used": skipped_used,
            "invalid": max(len(source_lines) - len(usable), 0),
        }

    def registration_pool_snapshot(self) -> dict:
        with self._lock:
            state = self._state()
            used = set((state.get("used") or {}).keys())
            pending_rows = dict(state.get("pending_rows") or {})
            retry_rows = dict(state.get("retry_rows") or {})
            items: list[dict] = []
            for status, rows in (("new", pending_rows), ("failed", retry_rows)):
                for key, value in rows.items():
                    item = dict(value or {})
                    in_use = key in used
                    items.append({
                        "email": str(item.get("email") or key),
                        "source_row": str(item.get("raw") or ""),
                        "status": status,
                        "in_use": in_use,
                        "attempts": int(item.get("attempts") or 0),
                        "error": str(item.get("last_error") or ""),
                        "updated_at": str(item.get("updated_at") or item.get("failed_at") or item.get("imported_at") or ""),
                    })
            items.sort(key=lambda item: (item["status"] != "failed", item["updated_at"], item["email"]))
            return {
                "new_count": len(pending_rows),
                "failed_count": len(retry_rows),
                "available_count": sum(1 for item in items if not item["in_use"]),
                "running_count": sum(1 for item in items if item["in_use"]),
                "items": items,
            }

    def delete_registration_row(self, email: str) -> bool:
        key = str(email or "").strip().lower()
        if not key:
            return False
        with self._lock:
            state = self._state()
            if key in dict(state.get("used") or {}):
                raise RuntimeError("邮箱正在注册中，任务结束后再删除")
            removed = False
            for field in ("pending_rows", "retry_rows"):
                rows = dict(state.get(field) or {})
                if key in rows:
                    rows.pop(key, None)
                    state[field] = rows
                    removed = True
            if removed:
                self._save_state(state)
            return removed

    def mark_email_succeeded(self, account_or_email) -> bool:
        email_value = getattr(account_or_email, "email", account_or_email)
        key = str(email_value or "").strip().lower()
        if not key:
            return False
        with self._lock:
            state = self._state()
            removed = False
            for field in ("pending_rows", "retry_rows"):
                rows = dict(state.get(field) or {})
                if key in rows:
                    rows.pop(key, None)
                    state[field] = rows
                    removed = True
            if removed:
                self._save_state(state)
            return removed

    def clear_failure_cooldowns(self, emails: list[str] | None = None) -> int:
        targets = {str(email or "").strip().lower() for email in (emails or []) if str(email or "").strip()}
        with self._lock:
            state = self._state()
            cooldowns = dict(state.get("cooldowns") or {})
            if targets:
                removed = sum(1 for key in targets if key in cooldowns)
                for key in targets:
                    cooldowns.pop(key, None)
            else:
                removed = len(cooldowns)
                cooldowns.clear()
            if removed:
                state["cooldowns"] = cooldowns
                self._save_state(state)
            return removed

    def _available_entry(self) -> LocalMicrosoftMailboxEntry:
        entries = self._usable_entries()
        state = self._state()
        used = set((state.get("used") or {}).keys())
        for entry in entries:
            if self.avoid_repeat and entry.key in self._attempted_keys:
                continue
            if self.allow_reuse or entry.key not in used:
                return entry
        raise RuntimeError(f"本地邮箱池已用尽: total={len(entries)}")

    def available_count(self) -> int:
        entries = self._usable_entries()
        if self.allow_reuse:
            return len(entries)
        used = set((self._state().get("used") or {}).keys())
        return sum(1 for entry in entries if entry.key not in used)

    def peek_email(self) -> str:
        return self._available_entry().email

    def source_row_for_email(self, email: str) -> str:
        key = str(email or "").strip().lower()
        if not key:
            return ""
        for entry in self._entries():
            if entry.key == key:
                return entry.raw
        return ""

    def _account_from_entry(self, entry: LocalMicrosoftMailboxEntry) -> MailboxAccount:
        credentials = entry.credentials()
        credentials = {key: value for key, value in credentials.items() if value}
        return MailboxAccount(
            email=entry.email,
            account_id=entry.key,
            extra={
                "provider_account": {
                    "provider_type": "mailbox",
                    "provider_name": LOCAL_MAIL_POOL_PROVIDER_NAME,
                    "login_identifier": entry.login_account or entry.email,
                    "display_name": entry.email,
                    "credentials": credentials,
                    "metadata": {
                        "source": entry.source,
                        "legacy_provider_name": LEGACY_LOCAL_MS_POOL_PROVIDER_NAME,
                        "has_graph_refresh_token": bool(entry.graph_ready),
                        "has_imap_config": bool(entry.imap_ready),
                        "has_icloud_api_url": bool(entry.icloud_api_ready),
                    },
                },
                "provider_resource": {
                    "provider_type": "mailbox",
                    "provider_name": LOCAL_MAIL_POOL_PROVIDER_NAME,
                    "resource_type": "mailbox",
                    "resource_identifier": entry.key,
                    "handle": entry.email,
                    "display_name": entry.email,
                    "metadata": {
                        "email": entry.email,
                        "source": entry.source,
                        "legacy_provider_name": LEGACY_LOCAL_MS_POOL_PROVIDER_NAME,
                        "reserved": not self.allow_reuse,
                    },
                },
            },
        )

    def _reserve_entry(self, entry: LocalMicrosoftMailboxEntry) -> MailboxAccount:
        if self.avoid_repeat:
            self._attempted_keys.add(entry.key)
        self._reserve(entry)
        return self._account_from_entry(entry)

    def get_email(self) -> MailboxAccount:
        with self._lock:
            return self._reserve_entry(self._available_entry())

    def get_email_by_address(self, email: str) -> MailboxAccount:
        """Reserve the exact local-pool row requested by a single-email task."""
        key = str(email or "").strip().lower()
        if not key:
            raise ValueError("指定邮箱不能为空")
        with self._lock:
            entry = next((item for item in self._usable_entries() if item.key == key), None)
            if entry is None:
                raise RuntimeError(f"指定邮箱不在本地邮箱池中或格式不可用: {email}")
            state = self._state()
            used = set((state.get("used") or {}).keys())
            if not self.allow_reuse and entry.key in used:
                raise RuntimeError(f"指定邮箱已被占用或已注册: {entry.email}")
            if self.avoid_repeat and entry.key in self._attempted_keys:
                raise RuntimeError(f"指定邮箱本次任务已经尝试过: {entry.email}")
            return self._reserve_entry(entry)

    def _entry_for_account(self, account: MailboxAccount) -> LocalMicrosoftMailboxEntry:
        account_email = str(getattr(account, "email", "") or "").strip().lower()
        extra = dict(getattr(account, "extra", {}) or {})
        provider_account = dict(extra.get("provider_account") or {})
        credentials = dict(provider_account.get("credentials") or {})
        if credentials:
            return LocalMicrosoftMailboxEntry(
                email=str(credentials.get("email") or account.email or ""),
                password=str(credentials.get("password") or ""),
                login_account=str(credentials.get("login_account") or account.email or ""),
                imap_host=str(credentials.get("imap_host") or ""),
                imap_port=str(credentials.get("imap_port") or ""),
                imap_account_type=str(credentials.get("imap_account_type") or ""),
                imap_security=str(credentials.get("imap_security") or ""),
                client_id=str(credentials.get("client_id") or ""),
                refresh_token=str(credentials.get("refresh_token") or ""),
                recovery_email=str(credentials.get("recovery_email") or ""),
                recovery_password=str(credentials.get("recovery_password") or ""),
                totp_secret=str(credentials.get("totp_secret") or ""),
                totp_url=str(credentials.get("totp_url") or ""),
                login_mode=str(credentials.get("login_mode") or ""),
                receive_provider=str(credentials.get("receive_provider") or "microsoft"),
                icloud_api_url=str(credentials.get("icloud_api_url") or ""),
            )

        for entry in self._entries():
            if entry.key == account_email:
                return entry
        raise RuntimeError(f"本地邮箱池未找到账号: {getattr(account, 'email', '')}")

    @staticmethod
    def _decode_mime(value: str) -> str:
        parts = []
        for raw, charset in decode_header(value or ""):
            if isinstance(raw, bytes):
                parts.append(raw.decode(charset or "utf-8", errors="replace"))
            else:
                parts.append(str(raw or ""))
        return "".join(parts)

    @staticmethod
    def _message_id(mail: dict) -> str:
        return str(mail.get("id") or mail.get("internetMessageId") or mail.get("receivedDateTime") or "")

    @staticmethod
    def _message_text(mail: dict) -> str:
        body = mail.get("body") or {}
        return " ".join(
            str(value or "")
            for value in (
                mail.get("subject"),
                mail.get("bodyPreview"),
                body.get("content") if isinstance(body, dict) else "",
            )
        )

    def _graph_access_token(self, entry: LocalMicrosoftMailboxEntry) -> str:
        if not entry.graph_ready:
            raise RuntimeError(f"微软邮箱缺少 Client Id 或刷新令牌: {entry.email}")
        response = requests.post(
            GRAPH_TOKEN_URL,
            data={
                "client_id": entry.client_id,
                "grant_type": "refresh_token",
                "refresh_token": entry.refresh_token,
                "scope": self.graph_scope,
            },
            proxies=self.proxy,
            timeout=25,
        )
        if response.status_code != 200:
            raise RuntimeError(f"Microsoft refresh_token 换 access_token 失败: HTTP {response.status_code} {response.text[:200]}")
        token = str((response.json() or {}).get("access_token") or "").strip()
        if not token:
            raise RuntimeError("Microsoft refresh_token 响应缺少 access_token")
        return token

    def _graph_messages(self, entry: LocalMicrosoftMailboxEntry) -> list[dict]:
        token = self._graph_access_token(entry)
        response = requests.get(
            GRAPH_MESSAGES_URL,
            headers={"authorization": f"Bearer {token}", "accept": "application/json"},
            params={
                "$top": "25",
                "$orderby": "receivedDateTime desc",
                "$select": "id,subject,bodyPreview,receivedDateTime,from,toRecipients,body",
            },
            proxies=self.proxy,
            timeout=25,
        )
        if response.status_code != 200:
            raise RuntimeError(f"Microsoft Graph 读取邮件失败: HTTP {response.status_code} {response.text[:200]}")
        payload = response.json() or {}
        return list(payload.get("value") or [])

    def _outlook_imap_access_token(self, entry: LocalMicrosoftMailboxEntry) -> str:
        if not entry.graph_ready:
            raise RuntimeError(f"微软邮箱缺少 Client Id 或刷新令牌: {entry.email}")
        response = requests.post(
            OUTLOOK_TOKEN_URL,
            data={
                "client_id": entry.client_id,
                "grant_type": "refresh_token",
                "refresh_token": entry.refresh_token,
                "scope": OUTLOOK_IMAP_SCOPE,
            },
            proxies=self.proxy,
            timeout=25,
        )
        if response.status_code != 200:
            raise RuntimeError(f"Microsoft IMAP refresh_token 换 access_token 失败: HTTP {response.status_code} {response.text[:200]}")
        token = str((response.json() or {}).get("access_token") or "").strip()
        if not token:
            raise RuntimeError("Microsoft IMAP refresh_token 响应缺少 access_token")
        return token

    def _imap_connect(self, entry: LocalMicrosoftMailboxEntry):
        host = entry.imap_host.strip()
        port = int(entry.imap_port or 993)
        security = entry.imap_security.lower()
        if port == 993 or "ssl" in security:
            return imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
        conn = imaplib.IMAP4(host, port)
        if "tls" in security:
            conn.starttls(ssl_context=ssl.create_default_context())
        return conn

    def _read_imap_inbox(self, conn) -> list[dict]:
        messages: list[dict] = []
        conn.select("INBOX", readonly=True)
        _, msg_nums = conn.search(None, "ALL")
        ids = msg_nums[0].split() if msg_nums and msg_nums[0] else []
        for mid in reversed(ids[-30:]):
            _, data = conn.fetch(mid, "(RFC822)")
            if not data or not data[0]:
                continue
            msg = email_lib.message_from_bytes(data[0][1])
            subject = self._decode_mime(str(msg.get("Subject", "") or ""))
            parts: list[str] = []
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() not in ("text/plain", "text/html"):
                        continue
                    payload = part.get_payload(decode=True)
                    if payload:
                        parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    parts.append(payload.decode(msg.get_content_charset() or "utf-8", errors="replace"))
            received_at = ""
            try:
                msg_date = parsedate_to_datetime(str(msg.get("Date", "") or ""))
                if msg_date:
                    if msg_date.tzinfo is None:
                        msg_date = msg_date.replace(tzinfo=timezone.utc)
                    received_at = msg_date.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            except Exception:
                received_at = ""
            messages.append({
                "id": str(msg.get("Message-ID") or mid.decode("ascii", errors="ignore")),
                "subject": subject,
                "bodyPreview": " ".join(parts),
                "receivedDateTime": received_at,
            })
        return messages

    def _imap_messages(self, entry: LocalMicrosoftMailboxEntry) -> list[dict]:
        if not entry.imap_ready:
            raise RuntimeError(f"微软邮箱没有可用的 Graph token，也没有 IMAP 收件配置: {entry.email}")
        conn = self._imap_connect(entry)
        try:
            conn.login(entry.login_account or entry.email, entry.password)
            return self._read_imap_inbox(conn)
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    def _outlook_oauth_imap_messages(self, entry: LocalMicrosoftMailboxEntry) -> list[dict]:
        token = self._outlook_imap_access_token(entry)
        conn = imaplib.IMAP4_SSL(OUTLOOK_IMAP_HOST, 993, ssl_context=ssl.create_default_context())
        try:
            login_account = entry.login_account or entry.email
            auth = f"user={login_account}\x01auth=Bearer {token}\x01\x01"
            conn.authenticate("XOAUTH2", lambda _: auth.encode("utf-8"))
            return self._read_imap_inbox(conn)
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    @staticmethod
    def _json_message_candidates(payload: Any) -> list[Any]:
        if isinstance(payload, list):
            return payload
        if not isinstance(payload, dict):
            return []
        for key in ("messages", "mails", "emails", "mail", "list", "rows", "items", "data", "result"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = LocalMicrosoftMailboxPool._json_message_candidates(value)
                if nested:
                    return nested
        return [payload]

    @staticmethod
    def _first_json_text(item: dict, keys: tuple[str, ...]) -> str:
        for key in keys:
            value = item.get(key)
            if value not in (None, "", [], {}):
                return str(value)
        return ""

    @staticmethod
    def _decode_data_uri(value: str) -> str:
        text = str(value or "")
        if not text.lower().startswith("data:"):
            return text
        header, separator, payload = text.partition(",")
        if not separator or len(payload) > 8_000_000:
            return text
        try:
            if ";base64" in header.lower():
                raw = base64.b64decode(payload, validate=False)
                charset_match = re.search(r"charset=([^;,]+)", header, flags=re.I)
                charset = charset_match.group(1).strip() if charset_match else "utf-8"
                return raw.decode(charset, errors="replace")
            return unquote(payload)
        except Exception:
            return text

    @staticmethod
    def _stable_message_id(*parts: object) -> str:
        material = "\n".join(str(part or "") for part in parts)
        return hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()[:24]

    def _flysms_messages(self, entry: LocalMicrosoftMailboxEntry, email: str, token: str) -> list[dict]:
        response = requests.get(
            FLYSMS_LATEST_MESSAGE_URL,
            headers={
                "accept": "application/json",
                "authorization": f"Bearer {token}",
                "x-mailbox-email": email,
                "user-agent": "Mozilla/5.0",
            },
            proxies=self.proxy,
            timeout=25,
        )
        if response.status_code == 404:
            return []
        if response.status_code != 200:
            errors = {
                401: "邮箱或 key 无效",
                403: "邮箱已到期、停用或无权取件",
                429: "请求过于频繁",
                503: "邮箱正在同步或服务暂时不可用",
            }
            detail = errors.get(response.status_code, "收件请求失败")
            retry_after = str(response.headers.get("retry-after") or "").strip()
            if response.status_code == 429 and retry_after:
                detail += f"，请在 {retry_after} 秒后重试"
            raise RuntimeError(f"FlySMS {detail}: HTTP {response.status_code}")

        try:
            payload = response.json()
        except Exception as exc:
            raise RuntimeError("FlySMS 返回了无法解析的邮件数据") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("FlySMS 返回了无法识别的邮件数据")

        response_email = _safe_text(payload.get("email")).lower()
        if response_email and response_email != entry.key:
            raise RuntimeError("FlySMS 返回的邮箱与账号池邮箱不一致")

        message = payload.get("message")
        if not isinstance(message, dict):
            return []
        subject = _safe_text(message.get("subject"))
        body = " ".join(
            value
            for value in (
                subject,
                _safe_text(message.get("text")),
                _safe_text(message.get("html")),
                _safe_text(message.get("from")),
            )
            if value
        )
        received = self._first_json_text(
            message,
            ("mailboxReceivedAt", "date", "ingestedAt", "sentAt"),
        )
        return [{
            "id": self._stable_message_id(
                "flysms",
                entry.key,
                message.get("mailbox"),
                message.get("uid"),
            ),
            "subject": subject,
            "bodyPreview": body,
            "receivedDateTime": received,
        }]

    @staticmethod
    def _tokenized_latest_endpoint(url: str) -> str | None:
        parsed = urlparse(str(url or "").strip())
        if parsed.path.rstrip("/").lower() != "/latest" or not parsed.scheme or not parsed.netloc:
            return None
        query = parse_qs(parsed.query)
        email = str((query.get("email") or query.get("mail") or [""])[0]).strip()
        auth_code = str((query.get("auth_code") or query.get("code") or query.get("key") or [""])[0]).strip()
        if not email or not auth_code:
            return None
        return (
            f"{parsed.scheme}://{parsed.netloc}/mail-api/"
            f"{quote(auth_code, safe='')}/{quote(email, safe='')}"
        )

    @staticmethod
    def _yangyang_messages_endpoint(url: str) -> tuple[str, str, str, str] | None:
        parsed = urlparse(str(url or "").strip())
        if not parsed.scheme or not parsed.netloc:
            return None
        parts = [unquote(item) for item in parsed.path.split("/") if item]
        if len(parts) != 3 or parts[0].lower() != "messages" or not parts[1] or not parts[2]:
            return None
        token, email = parts[1], parts[2]
        base = f"{parsed.scheme}://{parsed.netloc}"
        encoded_token = quote(token, safe="")
        encoded_email = quote(email, safe="")
        return (
            f"{base}/api/messages/{encoded_token}/{encoded_email}",
            f"{base}/message",
            token,
            email,
        )

    def _yangyang_api_messages(
        self,
        entry: LocalMicrosoftMailboxEntry,
        endpoint: tuple[str, str, str, str],
    ) -> list[dict]:
        list_url, detail_base, token, email = endpoint
        headers = {
            "accept": "application/json",
            "user-agent": "Mozilla/5.0",
            "cache-control": "no-cache, no-store",
            "pragma": "no-cache",
        }
        response = requests.get(
            list_url,
            headers=headers,
            params={"_": time.time_ns()},
            proxies=self.proxy,
            timeout=25,
        )
        if response.status_code != 200:
            raise RuntimeError(f"iCloud 邮件列表读取失败: HTTP {response.status_code} {response.text[:200]}")
        payload = response.json() or {}
        items = payload.get("items") or payload.get("messages") or []
        if not isinstance(items, list):
            return []

        messages: list[dict] = []
        for item in items[:50]:
            if not isinstance(item, dict):
                continue
            message_id = str(item.get("id") or item.get("message_id") or "").strip()
            merged = dict(item)
            if message_id:
                try:
                    detail_url = (
                        f"{detail_base}/{quote(message_id, safe='')}/"
                        f"{quote(token, safe='')}/{quote(email, safe='')}"
                    )
                    detail_response = requests.get(
                        detail_url,
                        headers=headers,
                        params={"_": time.time_ns()},
                        proxies=self.proxy,
                        timeout=25,
                    )
                    if detail_response.status_code == 200:
                        detail = detail_response.json() or {}
                        if isinstance(detail, dict):
                            merged.update(detail)
                except Exception:
                    pass
            subject = self._first_json_text(merged, ("subject", "title"))
            body = self._decode_data_uri(
                self._first_json_text(
                    merged,
                    ("body", "body_preview", "bodyPreview", "html", "text", "message", "verification_code", "code", "otp"),
                )
            )
            received = self._first_json_text(
                merged,
                ("receivedAt", "received_at", "received_time", "date", "time", "timestamp"),
            )
            messages.append({
                "id": message_id or self._stable_message_id(entry.email, subject, body, received),
                "subject": subject,
                "bodyPreview": " ".join(value for value in (subject, body) if value),
                "receivedDateTime": received,
            })
        return messages

    def _server_rendered_html_messages(
        self,
        entry: LocalMicrosoftMailboxEntry,
        text: str,
    ) -> list[dict]:
        parser = _MailboxCardHTMLParser()
        try:
            parser.feed(str(text or ""))
            parser.close()
        except Exception:
            return []
        messages = []
        for item in parser.messages:
            subject = str(item.get("subject") or "")
            body = str(item.get("body") or "")
            received = str(item.get("date") or "")
            messages.append({
                "id": self._stable_message_id(entry.email, subject, body, received),
                "subject": subject,
                "bodyPreview": " ".join(value for value in (subject, body) if value),
                "receivedDateTime": received,
            })
        return messages

    @staticmethod
    def _mailroom_public_endpoint(url: str) -> tuple[str, str] | None:
        parsed = urlparse(str(url or "").strip())
        if not parsed.fragment or not parsed.path.rstrip("/").endswith("/check.html"):
            return None
        fragment = unquote(parsed.fragment).strip()
        if fragment.startswith("token="):
            fragment = str((parse_qs(fragment).get("token") or [""])[0]).strip()
        if not fragment or len(fragment) > 2048 or re.search(r"[\s/\\]", fragment):
            return None
        return f"{parsed.scheme}://{parsed.netloc}/public-api/v1/check", fragment

    @staticmethod
    def _json_code_values(payload: Any) -> list[str]:
        if not isinstance(payload, dict):
            return []
        containers = [payload]
        for key in ("data", "result"):
            value = payload.get(key)
            if isinstance(value, dict):
                containers.append(value)
        codes: list[str] = []
        for container in containers:
            for key in (
                "codes",
                "verificationCodes",
                "verification_codes",
                "verificationCode",
                "verification_code",
                "code",
                "otp",
                "oneTimeCode",
                "one_time_code",
            ):
                value = container.get(key)
                values = value if isinstance(value, list) else [value]
                for item in values:
                    if isinstance(item, dict):
                        item = item.get("code") or item.get("value") or item.get("text")
                    text = str(item or "").strip()
                    if text and text not in codes:
                        codes.append(text)
        return codes

    def _icloud_api_messages(self, entry: LocalMicrosoftMailboxEntry) -> list[dict]:
        if not entry.icloud_api_ready:
            raise RuntimeError(f"iCloud 邮箱缺少接码地址: {entry.email}")
        flysms_credentials = _parse_flysms_pickup_url(entry.icloud_api_url, entry.email)
        if flysms_credentials:
            return self._flysms_messages(entry, *flysms_credentials)
        yangyang_endpoint = self._yangyang_messages_endpoint(entry.icloud_api_url)
        if yangyang_endpoint:
            try:
                return self._yangyang_api_messages(entry, yangyang_endpoint)
            except RuntimeError as exc:
                if "HTTP 404" not in str(exc):
                    raise
        mailroom_endpoint = self._mailroom_public_endpoint(entry.icloud_api_url)
        headers = {
            "accept": "application/json,text/html,text/plain,*/*",
            "user-agent": "Mozilla/5.0",
            "cache-control": "no-cache, no-store",
            "pragma": "no-cache",
        }
        tokenized_latest_endpoint = self._tokenized_latest_endpoint(entry.icloud_api_url)
        if mailroom_endpoint:
            api_url, share_token = mailroom_endpoint
            response = requests.post(
                api_url,
                headers={
                    "accept": "application/json",
                    "authorization": f"Bearer {share_token}",
                    "user-agent": headers["user-agent"],
                    "cache-control": headers["cache-control"],
                    "pragma": headers["pragma"],
                },
                proxies=self.proxy,
                timeout=25,
            )
        elif tokenized_latest_endpoint:
            response = requests.get(
                tokenized_latest_endpoint,
                headers=headers,
                params={
                    "folder": "inbox",
                    "refresh": "1",
                    "async": "1",
                    "_": time.time_ns(),
                },
                proxies=self.proxy,
                timeout=25,
            )
        else:
            response = requests.get(
                entry.icloud_api_url,
                headers=headers,
                params={"_": time.time_ns()},
                proxies=self.proxy,
                timeout=25,
            )
        if response.status_code != 200:
            raise RuntimeError(f"iCloud 接码地址读取失败: HTTP {response.status_code} {response.text[:200]}")

        text = response.text or ""
        messages: list[dict] = []
        payload: Any = None
        content_type = str(response.headers.get("content-type") or "").lower()
        if "json" in content_type:
            try:
                payload = response.json()
            except Exception:
                payload = None
        else:
            stripped = text.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    payload = response.json()
                except Exception:
                    payload = None

        if payload is None:
            rendered_messages = self._server_rendered_html_messages(entry, text)
            if rendered_messages:
                return rendered_messages

        if payload is not None:
            explicit_code_text = " ".join(self._json_code_values(payload))
            for item in self._json_message_candidates(payload):
                if not isinstance(item, dict):
                    body = " ".join(value for value in (str(item or ""), explicit_code_text) if value)
                    if body:
                        messages.append({
                            "id": self._stable_message_id(entry.email, body),
                            "subject": "",
                            "bodyPreview": body,
                            "receivedDateTime": "",
                        })
                    continue
                subject = self._first_json_text(item, ("subject", "title", "mail_subject", "sub"))
                message_body = self._decode_data_uri(
                    self._first_json_text(
                        item,
                        (
                            "body",
                            "body_preview",
                            "bodyPreview",
                            "content",
                            "html",
                            "text",
                            "message",
                            "mail_text",
                            "mail_content",
                            "verification_code",
                            "verificationCode",
                            "code",
                            "otp",
                        ),
                    )
                )
                body = " ".join(
                    value
                    for value in (
                        subject,
                        message_body,
                        self._first_json_text(item, ("from", "sender", "from_email")),
                        explicit_code_text,
                    )
                    if value
                )
                received = self._first_json_text(
                    item,
                    (
                        "receivedDateTime",
                        "received_time",
                        "created_at",
                        "createdAt",
                        "date",
                        "time",
                        "timestamp",
                    ),
                )
                mid = self._first_json_text(item, ("id", "mail_id", "message_id", "uid"))
                if mailroom_endpoint:
                    mid = self._stable_message_id(entry.email, mid, subject, body, received)
                messages.append({
                    "id": mid or self._stable_message_id(entry.email, subject, body, received),
                    "subject": subject,
                    "bodyPreview": body or json.dumps(item, ensure_ascii=False),
                    "receivedDateTime": received,
                })
            if messages:
                return messages

        # Relay pages can contain per-request nonces or dynamic scripts. Hashing
        # the raw page would make the same old OTP look like a new message on
        # every poll. Use the visible mail text so the ID changes only when the
        # displayed message (including its OTP) actually changes.
        stable_text = re.sub(r"\s+", " ", self._clean_search_text(text)).strip()
        return [{
            "id": self._stable_message_id(entry.email, stable_text or text),
            "subject": "",
            "bodyPreview": text,
            "receivedDateTime": "",
        }]

    def _messages(self, account: MailboxAccount) -> list[dict]:
        entry = self._entry_for_account(account)
        if entry.icloud_api_ready:
            return self._icloud_api_messages(entry)
        if entry.graph_ready:
            preferred = self._oauth_mail_strategy.get(entry.key, "graph")
            modes = [preferred, "imap" if preferred == "graph" else "graph"]
            errors: list[str] = []
            for mode in modes:
                try:
                    if mode == "graph":
                        messages = self._graph_messages(entry)
                    else:
                        messages = self._outlook_oauth_imap_messages(entry)
                    self._oauth_mail_strategy[entry.key] = mode
                    return messages
                except Exception as exc:
                    errors.append(f"{mode}: {exc}")
            raise RuntimeError("Microsoft OAuth 收件失败；" + "；".join(errors))
        return self._imap_messages(entry)

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            return {self._message_id(mail) for mail in self._messages(account) if self._message_id(mail)}
        except Exception:
            return set()

    @staticmethod
    def _clean_search_text(text: str) -> str:
        cleaned = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.I | re.S)
        cleaned = re.sub(r"<script[^>]*>.*?</script>", " ", cleaned, flags=re.I | re.S)
        cleaned = re.sub(r"https?://[^\s<>'\"]+", " ", cleaned, flags=re.I)
        cleaned = re.sub(r"<[^>]+>", " ", cleaned)
        cleaned = re.sub(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", " ", cleaned)
        return cleaned

    @staticmethod
    def _extract_code_from_text(text: str, pattern: re.Pattern) -> str:
        # Prefer numbers near verification wording to avoid matching timestamps,
        # counters, URL tokens, or unrelated 6-digit values on HTML inbox pages.
        hinted = re.search(
            r"(?:验证码|驗證碼|校验码|認証コード|認證碼|確認コード|ログインコード|"
            r"code|verification|verify|otp|one[- ]?time|openai|chatgpt|codex)"
            r"[\s\S]{0,120}?(?<!#)(?<!\d)(\d{6})(?!\d)",
            text,
            flags=re.I,
        )
        if hinted:
            return hinted.group(1)
        match = pattern.search(text)
        if match:
            return match.group(1) if match.groups() else match.group(0)
        return ""

    @staticmethod
    def _message_received_ts(mail: dict) -> float:
        value = str(mail.get("receivedDateTime") or mail.get("createdDateTime") or "").strip()
        if not value:
            return 0.0
        try:
            normalized = value.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(normalized)
        except Exception:
            try:
                parsed = parsedate_to_datetime(value)
            except Exception:
                return 0.0
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone(timedelta(hours=8)))
        return parsed.timestamp()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        otp_sent_at: float | None = None,
    ) -> str:
        seen = set(before_ids or [])
        pattern = re.compile(code_pattern or r"(?<!#)(?<!\d)(\d{6})(?!\d)")
        start = time.time()
        try:
            entry = self._entry_for_account(account)
            poll_interval = 10 if self._mailroom_public_endpoint(entry.icloud_api_url) else 5
        except Exception:
            poll_interval = 5
        # Microsoft Graph 的 receivedDateTime 与本机触发时间之间可能有 1-2 秒偏差，
        # 给少量宽限；但仍然拒绝明显早于本次 OTP 发送的旧验证码。
        min_received_ts = (float(otp_sent_at) - 15.0) if otp_sent_at else 0.0
        while time.time() - start < timeout:
            try:
                mails = self._messages(account)
            except Exception:
                time.sleep(poll_interval)
                continue
            for mail in mails:
                mid = self._message_id(mail)
                if mid and mid in seen:
                    continue
                received_ts = self._message_received_ts(mail)
                if min_received_ts and received_ts and received_ts < min_received_ts:
                    if mid:
                        seen.add(mid)
                    continue
                text = self._clean_search_text(self._message_text(mail))
                if keyword and keyword.lower() not in text.lower():
                    if mid:
                        seen.add(mid)
                    continue
                code = self._extract_code_from_text(text, pattern)
                if code:
                    if mid:
                        seen.add(mid)
                    return code
                if mid:
                    seen.add(mid)
            time.sleep(poll_interval)
        raise TimeoutError(f"等待验证码超时 ({timeout}s)")

    def wait_for_link(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
    ) -> str:
        seen = set(before_ids or [])
        start = time.time()
        while time.time() - start < timeout:
            for mail in self._messages(account):
                mid = self._message_id(mail)
                if mid and mid in seen:
                    continue
                if mid:
                    seen.add(mid)
                link = _extract_verification_link(self._message_text(mail), keyword)
                if link:
                    return link
            time.sleep(5)
        raise TimeoutError(f"等待验证链接超时 ({timeout}s)")


# New generic name; keep LocalMicrosoftMailboxPool for import/backward compatibility.
LocalMailboxPool = LocalMicrosoftMailboxPool
