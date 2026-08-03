"""Small RFC 6238 TOTP helper used by account login flows."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import time
from urllib.parse import urlparse, urlunparse

import requests


def normalize_totp_secret(secret: str) -> str:
    return "".join(str(secret or "").strip().upper().replace("-", "").split())


def generate_totp(
    secret: str,
    *,
    timestamp: float | None = None,
    period: int = 30,
    digits: int = 6,
) -> str:
    normalized = normalize_totp_secret(secret)
    if not normalized:
        raise ValueError("MFA 密钥为空")
    if period <= 0 or digits <= 0:
        raise ValueError("TOTP 参数无效")

    padding = "=" * ((8 - len(normalized) % 8) % 8)
    try:
        key = base64.b32decode(normalized + padding, casefold=True)
    except Exception as exc:
        raise ValueError("MFA 密钥不是有效的 Base32") from exc
    if not key:
        raise ValueError("MFA 密钥为空")

    counter = int((time.time() if timestamp is None else timestamp) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def _totp_api_url(url: str) -> str:
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("MFA 取码地址无效")
    if parsed.path.rstrip("/") == "/view":
        parsed = parsed._replace(path="/api/v1/2fa", fragment="")
    return urlunparse(parsed)


def fetch_totp_code(url: str, *, proxy_url: str | None = None, timeout: int = 20) -> str:
    """Read a six-digit MFA code from a tokenized 2FA viewer/API URL."""
    api_url = _totp_api_url(url)
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    headers = {
        "accept": "application/json,text/plain,*/*",
        "user-agent": "Mozilla/5.0",
        "cache-control": "no-cache, no-store",
        "pragma": "no-cache",
    }

    for attempt in range(2):
        response = requests.get(api_url, headers=headers, proxies=proxies, timeout=timeout)
        if response.status_code != 200:
            error_code = ""
            try:
                payload = response.json()
                if isinstance(payload, dict):
                    error_code = str(payload.get("error") or "").strip()
            except Exception:
                pass
            suffix = f" ({error_code})" if error_code else ""
            raise RuntimeError(f"MFA 取码失败: HTTP {response.status_code}{suffix}")

        try:
            payload = response.json()
        except Exception:
            try:
                payload = json.loads(str(response.text or ""))
            except Exception:
                payload = {}
        code = str(payload.get("code") or payload.get("otp") or payload.get("totp") or "").strip() if isinstance(payload, dict) else ""
        if not re.fullmatch(r"\d{6}", code):
            match = re.search(r"(?<!\d)(\d{6})(?!\d)", str(response.text or ""))
            code = match.group(1) if match else ""
        if not code:
            raise RuntimeError("MFA 取码失败: 响应中没有有效六码")

        remaining = payload.get("remaining") if isinstance(payload, dict) else None
        if attempt == 0 and isinstance(remaining, int) and 0 <= remaining <= 3:
            time.sleep(remaining + 1)
            continue
        return code

    raise RuntimeError("MFA 取码失败")
