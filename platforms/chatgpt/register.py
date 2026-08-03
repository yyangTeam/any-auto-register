"""
注册流程引擎
从 main.py 中提取并重构的注册流程
"""

import re
import json
import time
import uuid
import base64
import random
import logging
import secrets
import string
import os
from typing import Optional, Dict, Any, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from curl_cffi import requests as cffi_requests
from core.http_client import _is_curl_tls_connect_error

from .oauth import OAuthManager, OAuthStart, generate_oauth_url, submit_callback_url
from .http_client import OpenAIHTTPClient, HTTPClientError
# from ..services import EmailServiceFactory, BaseEmailService, EmailServiceType  # removed: external dep
# from ..database import crud  # removed: external dep
# from ..database.session import get_db  # removed: external dep
from .constants import (
    OPENAI_API_ENDPOINTS,
    OPENAI_PAGE_TYPES,
    generate_random_user_info,
    OTP_CODE_PATTERN,
    DEFAULT_PASSWORD_LENGTH,
    PASSWORD_CHARSET,
    AccountStatus,
    TaskStatus,
    SENTINEL_SDK_URL,
    OAUTH_REDIRECT_URI,
    OAUTH_CLIENT_ID,
)
# from ..config.settings import get_settings  # removed: external dep


logger = logging.getLogger(__name__)


def _copy_session_cookies(src, dst) -> None:
    try:
        dst.cookies.update(src.cookies)
    except Exception:
        try:
            for cookie in src.cookies.jar:
                dst.cookies.set(cookie.name, cookie.value, domain=cookie.domain, path=cookie.path)
        except Exception:
            pass


class _TLSFallbackSession:
    """curl_cffi session wrapper for Codex login TLS fallback.

    The Codex login flow needs cookie continuity.  This wrapper retries curl
    TLS connect failures with a fresh session/profile while preserving cookies.
    """

    def __init__(self, session, *, proxy_url: str | None = None, log_fn: Callable[[str, str], None] | None = None):
        self._session = session
        self.proxy_url = proxy_url
        self.log_fn = log_fn

    @property
    def cookies(self):
        return self._session.cookies

    def __getattr__(self, name: str):
        return getattr(self._session, name)

    def _new_session(self, impersonate: str, proxy_url: str | None):
        session = cffi_requests.Session(impersonate=impersonate)
        if proxy_url:
            try:
                session.proxies = {"http": proxy_url, "https": proxy_url}
            except Exception:
                pass
        _copy_session_cookies(self._session, session)
        return session

    def request(self, method: str, url: str, **kwargs):
        try:
            return self._session.request(method, url, **kwargs)
        except cffi_requests.RequestsError as exc:
            if not _is_curl_tls_connect_error(exc):
                raise
            last_error: BaseException = exc
            first_hop = "proxy" if self.proxy_url else "direct"
            attempts: list[tuple[str, str | None, str]] = [
                ("chrome120", self.proxy_url, f"{first_hop}/chrome120"),
                ("chrome110", self.proxy_url, f"{first_hop}/chrome110"),
            ]
            if self.proxy_url:
                attempts.append(("chrome120", None, "direct/chrome120"))
            for impersonate, proxy_url, label in attempts:
                try:
                    if self.log_fn:
                        self.log_fn(f"Codex TLS 连接失败，切换 {label} 重试...", "warning")
                    session = self._new_session(impersonate, proxy_url)
                    response = session.request(method, url, **kwargs)
                    self._session = session
                    return response
                except cffi_requests.RequestsError as retry_exc:
                    last_error = retry_exc
                    if _is_curl_tls_connect_error(retry_exc):
                        continue
                    raise
            raise last_error

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)


@dataclass
class RegistrationResult:
    """注册结果"""
    success: bool
    email: str = ""
    password: str = ""  # 注册密码
    account_id: str = ""
    workspace_id: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    session_token: str = ""  # 会话令牌
    error_message: str = ""
    logs: list = None
    metadata: dict = None
    source: str = "register"  # 'register' 或 'login'，区分账号来源

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "success": self.success,
            "email": self.email,
            "password": self.password,
            "account_id": self.account_id,
            "workspace_id": self.workspace_id,
            "access_token": self.access_token[:20] + "..." if self.access_token else "",
            "refresh_token": self.refresh_token[:20] + "..." if self.refresh_token else "",
            "id_token": self.id_token[:20] + "..." if self.id_token else "",
            "session_token": self.session_token[:20] + "..." if self.session_token else "",
            "error_message": self.error_message,
            "logs": self.logs or [],
            "metadata": self.metadata or {},
            "source": self.source,
        }


@dataclass
class SignupFormResult:
    """提交注册表单的结果"""
    success: bool
    page_type: str = ""  # 响应中的 page.type 字段
    is_existing_account: bool = False  # 是否为已注册账号
    response_data: Dict[str, Any] = None  # 完整的响应数据
    error_message: str = ""


@dataclass
class SentinelPayload:
    """Sentinel 请求结果。"""
    p: str
    c: str
    flow: str
    t: str = ""


# ─── Sentinel helpers (ported from browser_register.py) ──────────

def _generate_datadog_trace_headers() -> dict:
    trace_hex = secrets.token_hex(8).rjust(16, "0")
    parent_hex = secrets.token_hex(8).rjust(16, "0")
    trace_id = str(int(trace_hex, 16))
    parent_id = str(int(parent_hex, 16))
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


class _SentinelTokenGenerator:
    """Dynamic sentinel token generator – mirrors browser_register._SentinelTokenGenerator."""

    def __init__(self, device_id: str, user_agent: str):
        self.device_id = device_id or str(uuid.uuid4())
        self.user_agent = user_agent
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= (h >> 16)
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= (h >> 13)
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= (h >> 16)
        return f"{h & 0xFFFFFFFF:08x}"

    @staticmethod
    def _b64(data) -> str:
        return base64.b64encode(json.dumps(data, separators=(",", ":")).encode("utf-8")).decode("ascii")

    def _config(self) -> list:
        perf_now = 1000 + random.random() * 49000
        return [
            "1920x1080",
            time.strftime("%a, %d %b %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)", time.gmtime()),
            4294705152,
            random.random(),
            self.user_agent,
            SENTINEL_SDK_URL,
            None,
            None,
            "en-US",
            "en-US,en",
            random.random(),
            "webkitTemporaryStorage\u2212undefined",
            "location",
            "Object",
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            int(time.time() * 1000 - perf_now),
        ]

    def generate_requirements_token(self) -> str:
        cfg = self._config()
        cfg[3] = 1
        cfg[9] = round(5 + random.random() * 45)
        return "gAAAAAC" + self._b64(cfg)

    def generate_token(self, seed: str, difficulty: str) -> str:
        max_attempts = 500000
        cfg = self._config()
        start_ms = int(time.time() * 1000)
        diff = str(difficulty or "0")
        for nonce in range(max_attempts):
            cfg[3] = nonce
            cfg[9] = round(int(time.time() * 1000) - start_ms)
            encoded = self._b64(cfg)
            digest = self._fnv1a32((seed or "") + encoded)
            if digest[: len(diff)] <= diff:
                return "gAAAAAB" + encoded + "~S"
        return "gAAAAAB" + self._b64(None)


class RegistrationEngine:
    """
    注册引擎
    负责协调邮箱服务、OAuth 流程和 OpenAI API 调用
    """

    def __init__(
        self,
        email_service: Any,
        proxy_url: Optional[str] = None,
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None,
        phone_callback: Optional[Callable[[], str]] = None,
    ):
        """
        初始化注册引擎

        Args:
            email_service: 邮箱服务实例
            proxy_url: 代理 URL
            callback_logger: 日志回调函数
            task_uuid: 任务 UUID（用于数据库记录）
        """
        self.email_service = email_service
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid
        self.phone_callback = phone_callback

        # 创建 HTTP 客户端
        self.http_client = OpenAIHTTPClient(proxy_url=proxy_url)
        # 没显式传代理时自动继承系统代理，避免 macOS fake-ip 直连导致 curl (35)。
        self.proxy_url = self.http_client.proxy_url

        # 创建 OAuth 管理器
        from .constants import OAUTH_CLIENT_ID, OAUTH_AUTH_URL, OAUTH_TOKEN_URL, OAUTH_REDIRECT_URI, OAUTH_SCOPE
        self.oauth_manager = OAuthManager(
            client_id=OAUTH_CLIENT_ID,
            auth_url=OAUTH_AUTH_URL,
            token_url=OAUTH_TOKEN_URL,
            redirect_uri=OAUTH_REDIRECT_URI,
            scope=OAUTH_SCOPE,
            proxy_url=self.proxy_url  # 传递代理配置
        )

        # 状态变量
        self.email: Optional[str] = None
        self.password: Optional[str] = None  # 注册密码
        self.totp_secret: Optional[str] = None  # 已注册账号的 MFA Base32 密钥
        self.totp_url: Optional[str] = None  # 已注册账号的 MFA 在线取码地址
        self.email_info: Optional[Dict[str, Any]] = None
        self.oauth_start: Optional[OAuthStart] = None
        self.session: Optional[cffi_requests.Session] = None
        self.session_token: Optional[str] = None  # 会话令牌
        self.logs: list = []
        self._otp_sent_at: Optional[float] = None  # OTP 发送时间戳
        self._is_existing_account: bool = False  # 是否为已注册账号（用于自动登录）
        self._device_id: Optional[str] = None
        self._sentinel_token: Optional[str] = None
        self._signup_sentinel: Optional[SentinelPayload] = None
        self._password_sentinel: Optional[SentinelPayload] = None
        self._create_account_continue_url: Optional[str] = None
        self._otp_continue_url: Optional[str] = None
        self._otp_page_type: Optional[str] = None
        self._last_codex_error: str = ""
        self._codex_direct_token_info: Optional[Dict[str, Any]] = None
        self._has_supplied_login_password = False
        # chatgpt.com NextAuth is occasionally challenged at the network edge
        # while auth.openai.com remains usable.  Keep this explicit so the
        # later session lookup can follow the same transport branch.
        self._uses_direct_openai_oauth = False

    @staticmethod
    def _debug_auth_enabled() -> bool:
        return str(
            os.environ.get("CHATGPT_DEBUG_CODEX_AUTH")
            or os.environ.get("CHATGPT_DEBUG_AUTH")
            or ""
        ).strip().lower() in {"1", "true", "yes", "on"}

    def _log(self, message: str, level: str = "info"):
        """记录日志"""
        timestamp = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"

        # 添加到日志列表
        self.logs.append(log_message)

        # 调用回调函数
        if self.callback_logger:
            self.callback_logger(message)

        # 记录到数据库（如果有关联任务）
        if self.task_uuid:
            try:
                with get_db() as db:
                    crud.append_task_log(db, self.task_uuid, message)
            except Exception as e:
                logger.warning(f"记录任务日志失败: {e}")

        # 根据级别记录到日志系统
        if level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.info(message)

    def _debug_log(self, message: str, level: str = "info"):
        if self._debug_auth_enabled():
            self._log(message, level)

    def _requires_create_account_callback(self) -> bool:
        """Only a newly created account must finish the web create callback."""
        return not self._is_existing_account

    @staticmethod
    def _parse_json_response(response, operation: str) -> Dict[str, Any]:
        """Parse an API response without hiding an HTML/WAF response as JSON."""
        try:
            payload = response.json()
        except Exception as exc:
            content_type = str((getattr(response, "headers", {}) or {}).get("content-type") or "")
            location = str((getattr(response, "headers", {}) or {}).get("location") or "")
            body = re.sub(r"\s+", " ", str(getattr(response, "text", "") or "")).strip()[:180]
            raise RuntimeError(
                f"{operation} 返回非 JSON: status={getattr(response, 'status_code', '?')} "
                f"content_type={content_type or '-'} url={getattr(response, 'url', '') or '-'} "
                f"location={location or '-'} body={body!r}"
            ) from exc
        if not isinstance(payload, dict):
            raise RuntimeError(
                f"{operation} 返回 JSON 类型异常: {type(payload).__name__} "
                f"status={getattr(response, 'status_code', '?')}"
            )
        return payload

    def _start_direct_openai_oauth(self, reason: str) -> bool:
        """Fallback for a chatgpt.com NextAuth edge challenge.

        The registration APIs already run on auth.openai.com.  Starting the
        normal PKCE authorization there preserves the existing registration
        path and its callback, without requiring a JSON NextAuth response.
        """
        try:
            self._log(f"ChatGPT NextAuth 不可用，切换 auth.openai.com 直连授权: {reason}", "warning")
            oauth_start = generate_oauth_url()
            response = self.session.get(
                oauth_start.auth_url,
                headers={"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
                timeout=20,
            )
            did = self.session.cookies.get("oai-did", "")
            # A challenged chatgpt.com request can taint the current cookie jar
            # for the subsequent auth.openai.com navigation.  Some exits also
            # challenge only specific TLS fingerprints, so retry with clean
            # sessions in the same order used by the existing TLS fallback.
            if not (200 <= response.status_code < 400) or not did:
                self._log("直连 OAuth 首次初始化未通过，切换浏览器指纹重试...", "warning")
                for profile in ("chrome136", "chrome120", "chrome110", "safari184"):
                    clean_session = cffi_requests.Session(impersonate=profile)
                    if self.proxy_url:
                        clean_session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
                    response = clean_session.get(
                        oauth_start.auth_url,
                        headers={"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
                        timeout=20,
                    )
                    did = clean_session.cookies.get("oai-did", "")
                    self._debug_log(
                        f"直连 OAuth 指纹 {profile}: status={response.status_code} did={'yes' if did else 'no'}"
                    )
                    if 200 <= response.status_code < 400 and did:
                        self.session = clean_session
                        try:
                            self.http_client.session = clean_session
                        except Exception:
                            pass
                        self._log(f"直连 OAuth 使用浏览器指纹: {profile}")
                        break
            if not (200 <= response.status_code < 400) or not did:
                self._log(
                    "auth.openai.com 直连授权初始化失败: "
                    f"status={response.status_code} did={'yes' if did else 'no'} "
                    f"content_type={response.headers.get('content-type', '')}",
                    "error",
                )
                return False
            self.oauth_start = oauth_start
            self._uses_direct_openai_oauth = True
            self._log(f"直连 OAuth 初始化成功: {getattr(response, 'url', oauth_start.auth_url)[:100]}...")
            return True
        except Exception as exc:
            self._log(f"auth.openai.com 直连授权初始化失败: {exc}", "error")
            return False

    def _start_codex_oauth_session(self, auth_url: str) -> tuple[_TLSFallbackSession, str, str]:
        """Start Codex OAuth only after a real auth session and device id exist."""
        last_detail = "no attempts"
        for profile in ("chrome136", "chrome110", "safari184", "chrome131", "chrome120"):
            try:
                raw_session = cffi_requests.Session(impersonate=profile)
                if self.proxy_url:
                    raw_session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
                response = raw_session.get(auth_url, timeout=20)
                did = raw_session.cookies.get("oai-did", "")
                last_detail = f"profile={profile} status={response.status_code} did={'yes' if did else 'no'}"
                self._debug_log(f"Codex OAuth 初始化: {last_detail}")
                if 200 <= response.status_code < 400 and did:
                    session = _TLSFallbackSession(
                        raw_session,
                        proxy_url=self.proxy_url,
                        log_fn=self._log,
                    )
                    self._log(f"Codex OAuth 初始化成功: profile={profile} status={response.status_code}")
                    return session, did, profile
            except Exception as exc:
                last_detail = f"profile={profile} error={type(exc).__name__}: {exc}"
                self._debug_log(f"Codex OAuth 初始化失败: {last_detail}", "warning")
        raise RuntimeError(f"Codex OAuth 初始化失败，未建立有效登录会话: {last_detail}")

    def _generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        """生成随机密码"""
        # OpenAI 注册页对纯字母数字密码存在更高概率拒绝，补一个符号位更稳。
        specials = ",._!@#"
        if length < 10:
            length = 10
        core = ''.join(secrets.choice(PASSWORD_CHARSET) for _ in range(length - 2))
        return (
            secrets.choice("abcdefghijklmnopqrstuvwxyz")
            + secrets.choice("0123456789")
            + secrets.choice(specials)
            + core
        )[:length]

    def _load_create_account_password_page(self) -> bool:
        """预加载 create-account/password 页面，拿到页面阶段 cookie。"""
        try:
            response = self.session.get(
                "https://auth.openai.com/create-account/password",
                headers={
                    "referer": "https://chatgpt.com/",
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                timeout=20,
            )
            self._log(f"加载密码页状态: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            self._log(f"加载密码页失败: {e}", "warning")
            return False

    def _check_ip_location(self) -> Tuple[bool, Optional[str]]:
        """检查 IP 地理位置"""
        try:
            return self.http_client.check_ip_location()
        except Exception as e:
            self._log(f"检查 IP 地理位置失败: {e}", "error")
            return False, None

    def _preflight_codex_auth_network(self) -> Tuple[bool, str]:
        """Codex Auth 前置连通性自测。

        这一步必须在占用本地邮箱池账号之前执行；否则线路不通时会白白把
        邮箱标记为 used。这里只做轻量 GET，不提交邮箱、不发 OTP。
        """
        try:
            from .constants import OPENAI_AUTH

            client = OpenAIHTTPClient(proxy_url=self.proxy_url)
            session = _TLSFallbackSession(
                client.session,
                proxy_url=client.proxy_url,
                log_fn=self._debug_log,
            )
            resp = session.get(f"{OPENAI_AUTH}/", timeout=12, allow_redirects=False)
            if resp.status_code in (200, 301, 302, 303, 307, 308, 401, 403, 404):
                self.proxy_url = client.proxy_url
                return True, f"status={resp.status_code} proxy={self.proxy_url or 'direct'}"
            return False, f"status={resp.status_code} proxy={client.proxy_url or 'direct'}"
        except Exception as exc:
            self._last_codex_error = str(exc)
            return False, f"{type(exc).__name__}: {exc} proxy={self.proxy_url or 'direct'}"

    def _create_email(self) -> bool:
        """创建邮箱"""
        try:
            service_name = self.email_service.service_type.value
            if service_name in {"local_ms_pool", "local_mail_pool"}:
                service_name = "本地邮箱池"
            self._log(f"正在创建 {service_name} 邮箱...")
            self.email_info = self.email_service.create_email()

            if not self.email_info or "email" not in self.email_info:
                self._log("创建邮箱失败: 返回信息不完整", "error")
                return False

            self.email = self.email_info["email"]
            self._log(f"成功创建邮箱: {self.email}")
            return True

        except Exception as e:
            self._log(f"创建邮箱失败: {e}", "error")
            return False

    def _start_oauth(self) -> bool:
        """通过 chatgpt.com NextAuth 发起 OAuth 流程"""
        try:
            from .constants import CHATGPT_APP
            self._log("通过 chatgpt.com NextAuth 发起 OAuth...")

            # 1. 访问 chatgpt.com 获取基础 cookie
            self.session.get(f"{CHATGPT_APP}/", timeout=15)
            oai_did = self.session.cookies.get("oai-did", "")
            self._log(f"chatgpt.com oai-did: {oai_did[:20]}...")

            # 2. 获取 CSRF token
            csrf_resp = self.session.get(f"{CHATGPT_APP}/api/auth/csrf", timeout=15)
            if csrf_resp.status_code != 200:
                return self._start_direct_openai_oauth(f"csrf HTTP {csrf_resp.status_code}")
            try:
                csrf_data = self._parse_json_response(csrf_resp, "NextAuth CSRF")
            except RuntimeError as exc:
                return self._start_direct_openai_oauth(str(exc))
            csrf_token = csrf_data.get("csrfToken", "")
            if not csrf_token:
                # 从 cookie 中提取
                csrf_cookie = self.session.cookies.get("__Host-next-auth.csrf-token", "")
                csrf_token = csrf_cookie.split("%7C")[0] if "%7C" in csrf_cookie else csrf_cookie.split("|")[0]
            if not csrf_token:
                return self._start_direct_openai_oauth("CSRF token 为空")
            self._log(f"CSRF token: {csrf_token[:20]}...")

            # 3. 调用 signin/openai 获取 authorize URL
            signin_url = f"{CHATGPT_APP}/api/auth/signin/openai"
            if oai_did:
                signin_url += f"?prompt=login&ext-oai-did={oai_did}"

            from urllib.parse import urlencode
            signin_resp = self.session.post(
                signin_url,
                headers={
                    "content-type": "application/x-www-form-urlencoded",
                    "origin": CHATGPT_APP,
                    "referer": f"{CHATGPT_APP}/",
                },
                data=urlencode({"callbackUrl": f"{CHATGPT_APP}/", "csrfToken": csrf_token, "json": "true"}),
                timeout=15,
            )
            self._log(f"signin/openai 状态: {signin_resp.status_code}")

            if signin_resp.status_code != 200:
                return self._start_direct_openai_oauth(f"signin/openai HTTP {signin_resp.status_code}")

            try:
                signin_data = self._parse_json_response(signin_resp, "NextAuth signin/openai")
            except RuntimeError as exc:
                return self._start_direct_openai_oauth(str(exc))
            auth_url = signin_data.get("url", "")
            if not auth_url:
                return self._start_direct_openai_oauth("signin/openai 未返回 authorize URL")
            from urllib.parse import urlparse
            parsed_auth_url = urlparse(str(auth_url))
            auth_host = (parsed_auth_url.hostname or "").lower()
            if not (auth_host.endswith("openai.com") and "authorize" in parsed_auth_url.path.lower()):
                return self._start_direct_openai_oauth(
                    f"signin/openai 返回非 authorize URL: {parsed_auth_url.scheme}://{auth_host}{parsed_auth_url.path}"
                )

            self._log(f"OAuth URL: {auth_url[:80]}...")

            # 存储为 OAuthStart (不需要 code_verifier，由 chatgpt.com 后端处理)
            self.oauth_start = OAuthStart(
                auth_url=auth_url,
                state="",  # state 由 NextAuth 管理
                code_verifier="",  # 不需要
                redirect_uri="",  # 不需要
            )
            return True

        except Exception as e:
            self._log(f"NextAuth OAuth 流程失败: {e}", "error")
            return False

    def _init_session(self) -> bool:
        """初始化会话"""
        try:
            self.session = self.http_client.session
            return True
        except Exception as e:
            self._log(f"初始化会话失败: {e}", "error")
            return False

    def _get_device_id(self) -> Optional[str]:
        """获取 Device ID"""
        try:
            if not self.oauth_start:
                return None

            response = self.session.get(
                self.oauth_start.auth_url,
                timeout=15
            )
            did = self.session.cookies.get("oai-did")
            self._log(f"Device ID: {did}")
            return did

        except Exception as e:
            self._log(f"获取 Device ID 失败: {e}", "error")
            return None

    def _check_sentinel(self, did: str, *, flow: str = "authorize_continue") -> Optional[SentinelPayload]:
        """检查 Sentinel 拦截（动态生成 token + 处理 PoW）"""
        try:
            ua = self.http_client.default_headers.get("User-Agent", "")
            generator = _SentinelTokenGenerator(did, ua)
            sent_p = generator.generate_requirements_token()
            sen_req_body = json.dumps({"p": sent_p, "id": did, "flow": flow}, separators=(",", ":"))

            from .constants import SENTINEL_FRAME_URL
            response = self.http_client.post(
                OPENAI_API_ENDPOINTS["sentinel"],
                headers={
                    "origin": "https://sentinel.openai.com",
                    "referer": SENTINEL_FRAME_URL,
                    "content-type": "text/plain;charset=UTF-8",
                },
                data=sen_req_body,
            )

            if response.status_code == 200:
                data = response.json()
                sen_token = str(data.get("token") or "")
                turnstile = data.get("turnstile") or {}

                # Handle proofofwork challenge if required
                initial_p = sent_p  # keep for dx decryption
                pow_meta = data.get("proofofwork") or {}
                if pow_meta.get("required") and pow_meta.get("seed"):
                    sent_p = generator.generate_token(
                        str(pow_meta.get("seed") or ""),
                        str(pow_meta.get("difficulty") or "0"),
                    )
                    self._log(f"Sentinel PoW solved: flow={flow}")

                # Solve turnstile dx with VM
                t_value = ""
                dx_b64 = str(turnstile.get("dx") or "")
                if dx_b64:
                    try:
                        from .sentinel_vm import solve_turnstile_dx
                        from .constants import SENTINEL_SDK_URL
                        t_value = solve_turnstile_dx(dx_b64, initial_p, user_agent=ua, sdk_url=SENTINEL_SDK_URL)
                        self._log(f"Sentinel VM solved: t_len={len(t_value)} flow={flow}")
                    except Exception as vm_err:
                        self._log(f"Sentinel VM failed: {vm_err}", "warning")

                payload = SentinelPayload(
                    p=sent_p,
                    c=sen_token,
                    flow=flow,
                    t=t_value,
                )
                self._log(f"Sentinel token 获取成功: flow={flow}")
                return payload
            else:
                self._log(f"Sentinel 检查失败: flow={flow} status={response.status_code}", "warning")
                return None

        except Exception as e:
            self._log(f"Sentinel 检查异常: flow={flow} {e}", "warning")
            return None

    def _submit_signup_form(self, did: str, sen_payload: Optional[SentinelPayload]) -> SignupFormResult:
        """
        提交注册表单（通过 authorize/continue 建立 session）

        Returns:
            SignupFormResult: 提交结果，包含账号状态判断
        """
        try:
            self._device_id = did
            self._signup_sentinel = sen_payload
            self._sentinel_token = sen_payload.c if sen_payload else None
            signup_body = f'{{"username":{{"value":"{self.email}","kind":"email"}},"screen_hint":"signup"}}'

            headers = {
                "referer": "https://auth.openai.com/create-account",
                "accept": "application/json",
                "content-type": "application/json",
            }

            if sen_payload:
                sentinel = json.dumps({
                    "p": sen_payload.p,
                    "t": sen_payload.t,
                    "c": sen_payload.c,
                    "id": did,
                    "flow": sen_payload.flow,
                }, separators=(",", ":"))
                headers["openai-sentinel-token"] = sentinel

            response = self.session.post(
                OPENAI_API_ENDPOINTS["signup"],
                headers=headers,
                data=signup_body,
            )

            self._log(f"提交注册表单状态: {response.status_code}")

            if response.status_code != 200:
                return SignupFormResult(
                    success=False,
                    error_message=f"HTTP {response.status_code}: {response.text[:200]}"
                )

            try:
                response_data = response.json()
                page_type = response_data.get("page", {}).get("type", "")
                self._log(f"响应页面类型: {page_type}")

                is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]
                if is_existing:
                    self._log(f"检测到已注册账号，将自动切换到登录流程")
                    self._is_existing_account = True

                return SignupFormResult(
                    success=True,
                    page_type=page_type,
                    is_existing_account=is_existing,
                    response_data=response_data
                )

            except Exception as parse_error:
                self._log(f"解析响应失败: {parse_error}", "warning")
                return SignupFormResult(success=True)

        except Exception as e:
            self._log(f"提交注册表单失败: {e}", "error")
            return SignupFormResult(success=False, error_message=str(e))

    @staticmethod
    def _is_invalid_state_signup(result: SignupFormResult) -> bool:
        message = str(getattr(result, "error_message", "") or "").lower()
        return "invalid_state" in message or "sign-in session is no longer valid" in message

    def _retry_signup_with_fresh_session(self) -> SignupFormResult:
        """Retry a single-use/expired signup state with a clean OAuth session."""
        self._log("注册会话已失效，正在使用全新 OAuth 会话重试一次...", "warning")
        self.http_client = OpenAIHTTPClient(proxy_url=self.proxy_url)
        self.session = None
        self.oauth_start = None
        self._uses_direct_openai_oauth = False
        self._is_existing_account = False

        if not self._init_session():
            return SignupFormResult(success=False, error_message="重新初始化会话失败")
        if not self._start_oauth():
            return SignupFormResult(success=False, error_message="重新开始 OAuth 流程失败")
        did = self._get_device_id()
        if not did:
            return SignupFormResult(success=False, error_message="重新获取 Device ID 失败")
        sen_payload = self._check_sentinel(did)
        return self._submit_signup_form(did, sen_payload)

    def _register_password(self) -> Tuple[bool, Optional[str]]:
        """注册密码"""
        try:
            ua = self.http_client.default_headers.get("User-Agent", "")
            chrome_match = re.search(r"Chrome/(\d+)", ua)
            chrome_major = str(chrome_match.group(1) if chrome_match else "136")
            sec_ch_ua = f'"Chromium";v="{chrome_major}", "Google Chrome";v="{chrome_major}", "Not.A/Brand";v="99"'

            candidates = []
            while len(candidates) < 3:
                pwd = self._generate_password()
                if pwd not in candidates:
                    candidates.append(pwd)

            for index, password in enumerate(candidates, start=1):
                self.password = password

                # Reload page + refresh sentinel for each attempt (tokens are single-use)
                self._load_create_account_password_page()
                if self._device_id:
                    self._password_sentinel = self._check_sentinel(self._device_id, flow="username_password_create")
                    if self._password_sentinel:
                        self._log(
                            f"密码阶段 Sentinel 已刷新: flow={self._password_sentinel.flow} "
                            f"turnstile={'yes' if self._password_sentinel.t else 'no'}"
                        )

                self._log(f"生成密码[{index}/{len(candidates)}]: {password}")

                register_body = json.dumps({
                    "password": password,
                    "username": self.email
                })

                register_headers = {
                    "origin": "https://auth.openai.com",
                    "referer": "https://auth.openai.com/create-account/password",
                    "accept": "application/json",
                    "content-type": "application/json",
                    "accept-language": "en-US,en;q=0.9",
                    "sec-ch-ua": sec_ch_ua,
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"Windows"',
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-origin",
                    **_generate_datadog_trace_headers(),
                }
                if self._device_id:
                    register_headers["oai-device-id"] = self._device_id
                if self._password_sentinel and self._device_id:
                    register_headers["openai-sentinel-token"] = json.dumps({
                        "p": self._password_sentinel.p,
                        "t": self._password_sentinel.t,
                        "c": self._password_sentinel.c,
                        "id": self._device_id,
                        "flow": self._password_sentinel.flow,
                    }, separators=(",", ":"))

                response = self.session.post(
                    OPENAI_API_ENDPOINTS["register"],
                    headers=register_headers,
                    data=register_body,
                )

                self._log(f"提交密码状态[{index}/{len(candidates)}]: {response.status_code}")

                if response.status_code == 200:
                    # 解析响应，检测已注册账号
                    try:
                        resp_data = response.json()
                        page_type = resp_data.get("page", {}).get("type", "")
                        self._log(f"注册响应页面类型: {page_type}")
                        if page_type == OPENAI_PAGE_TYPES.get("EMAIL_OTP_VERIFICATION", "email_otp_verification"):
                            self._log("检测到已注册账号，自动切换到登录流程")
                            self._is_existing_account = True
                    except Exception:
                        pass
                    return True, password

                error_text = response.text[:500]
                self._log(f"密码注册失败[{index}/{len(candidates)}]: {error_text}", "warning")

                try:
                    error_json = response.json()
                    error_msg = error_json.get("error", {}).get("message", "")
                    error_code = error_json.get("error", {}).get("code", "")

                    if "already" in error_msg.lower() or "exists" in error_msg.lower() or error_code == "user_exists":
                        self._log(f"邮箱 {self.email} 可能已在 OpenAI 注册过", "error")
                        self._mark_email_as_registered()
                        return False, None
                except Exception:
                    pass

            return False, None

        except Exception as e:
            self._log(f"密码注册失败: {e}", "error")
            return False, None

    def _mark_email_as_registered(self):
        """标记邮箱为已注册状态（用于防止重复尝试）"""
        try:
            with get_db() as db:
                # 检查是否已存在该邮箱的记录
                existing = crud.get_account_by_email(db, self.email)
                if not existing:
                    # 创建一个失败记录，标记该邮箱已注册过
                    crud.create_account(
                        db,
                        email=self.email,
                        password="",  # 空密码表示未成功注册
                        email_service=self.email_service.service_type.value,
                        email_service_id=self.email_info.get("service_id") if self.email_info else None,
                        status="failed",
                        extra_data={"register_failed_reason": "email_already_registered_on_openai"}
                    )
                    self._log(f"已在数据库中标记邮箱 {self.email} 为已注册状态")
        except Exception as e:
            logger.warning(f"标记邮箱状态失败: {e}")

    def _send_verification_code(self) -> bool:
        """发送验证码"""
        try:
            # 记录发送时间戳
            self._otp_sent_at = time.time()

            response = self.session.get(
                OPENAI_API_ENDPOINTS["send_otp"],
                headers={
                    "referer": "https://auth.openai.com/create-account/password",
                    "accept": "application/json",
                },
            )

            self._log(f"验证码发送状态: {response.status_code}")
            return response.status_code == 200

        except Exception as e:
            self._log(f"发送验证码失败: {e}", "error")
            return False

    def _get_verification_code(self) -> Optional[str]:
        """获取验证码"""
        try:
            self._log(f"正在等待邮箱 {self.email} 的验证码...")

            email_id = self.email_info.get("service_id") if self.email_info else None
            code = self.email_service.get_verification_code(
                email=self.email,
                email_id=email_id,
                timeout=120,
                pattern=OTP_CODE_PATTERN,
                otp_sent_at=self._otp_sent_at,
            )

            if code:
                self._log(f"成功获取验证码: {code}")
                return code
            else:
                self._log("等待验证码超时", "error")
                return None

        except Exception as e:
            self._log(f"获取验证码失败: {e}", "error")
            return None

    def _validate_verification_code(self, code: str) -> bool:
        """验证验证码"""
        try:
            code_body = f'{{"code":"{code}"}}'

            response = self.session.post(
                OPENAI_API_ENDPOINTS["validate_otp"],
                headers={
                    "referer": "https://auth.openai.com/email-verification",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=code_body,
            )

            self._log(f"验证码校验状态: {response.status_code}")
            if response.status_code != 200:
                self._log(f"验证码校验响应: {response.text[:300]}", "warning")
                return False

            # 解析响应，存储 continue_url 和 page_type
            try:
                resp_data = response.json()
                self._otp_continue_url = resp_data.get("continue_url", "")
                self._otp_page_type = resp_data.get("page", {}).get("type", "")
                self._log(f"验证码校验 -> page_type={self._otp_page_type}")
            except Exception:
                self._otp_continue_url = ""
                self._otp_page_type = ""
            return True

        except Exception as e:
            self._log(f"验证验证码失败: {e}", "error")
            return False

    def _create_user_account(self) -> bool:
        """创建用户账户"""
        try:
            user_info = generate_random_user_info()
            self._log(f"生成用户信息: {user_info['name']}, 生日: {user_info['birthdate']}")
            create_account_body = json.dumps(user_info)

            # 调 client_auth_session_dump 推进服务器 auth 状态机
            try:
                dump_resp = self.session.get(
                    "https://auth.openai.com/api/accounts/client_auth_session_dump",
                    headers={
                        "referer": "https://auth.openai.com/email-verification",
                        "accept": "application/json",
                    },
                    timeout=20,
                )
                self._log(f"client_auth_session_dump 状态: {dump_resp.status_code}")
            except Exception as e:
                self._log(f"client_auth_session_dump 异常: {e}", "warning")

            create_headers = {
                "referer": "https://auth.openai.com/about-you",
                "accept": "application/json",
                "content-type": "application/json",
                "origin": "https://auth.openai.com",
                "sec-fetch-site": "same-origin",
                **_generate_datadog_trace_headers(),
            }
            if self._device_id:
                create_headers["oai-device-id"] = self._device_id

            # create_account 也需要 sentinel token (flow=oauth_create_account)
            if self._device_id:
                ca_sentinel = self._check_sentinel(self._device_id, flow="oauth_create_account")
                if ca_sentinel:
                    create_headers["openai-sentinel-token"] = json.dumps({
                        "p": ca_sentinel.p,
                        "t": ca_sentinel.t,
                        "c": ca_sentinel.c,
                        "id": self._device_id,
                        "flow": ca_sentinel.flow,
                    }, separators=(",", ":"))
                    self._log(f"create_account Sentinel 已获取: flow={ca_sentinel.flow}")

            response = self.session.post(
                OPENAI_API_ENDPOINTS["create_account"],
                headers=create_headers,
                data=create_account_body,
            )

            self._log(f"账户创建状态: {response.status_code}")

            if response.status_code != 200:
                self._log(f"账户创建失败: {response.text[:200]}", "warning")
                return False

            # 提取 continue_url（ChatGPT Web 流程直接返回 OAuth callback URL）
            try:
                resp_data = response.json()
                self._create_account_continue_url = resp_data.get("continue_url", "")
                if self._create_account_continue_url:
                    self._log(f"create_account continue_url: {self._create_account_continue_url[:100]}...")
            except Exception:
                pass

            return True

        except Exception as e:
            self._log(f"创建账户失败: {e}", "error")
            return False

    def _session_cookies_for_browser(self, session) -> list[dict]:
        """Convert curl_cffi session cookies to browser-context cookies."""
        cookies: list[dict] = []
        try:
            jar = getattr(getattr(session, "cookies", None), "jar", None) or getattr(session, "cookies", None)
            for c in list(jar or []):
                name = str(getattr(c, "name", "") or "")
                value = str(getattr(c, "value", "") or "")
                if not name:
                    continue
                domain = str(getattr(c, "domain", "") or "auth.openai.com")
                if "openai.com" not in domain and "chatgpt.com" not in domain:
                    continue
                item = {
                    "name": name,
                    "value": value,
                    "domain": domain,
                    "path": str(getattr(c, "path", "") or "/"),
                    "secure": bool(getattr(c, "secure", True)),
                    "httpOnly": bool(getattr(c, "has_nonstandard_attr", lambda _n: False)("HttpOnly")),
                }
                expires = getattr(c, "expires", None)
                if expires:
                    try:
                        item["expires"] = int(expires)
                    except Exception:
                        pass
                cookies.append(item)
        except Exception as exc:
            self._log(f"导出登录 cookies 失败: {exc}", "warning")
        return cookies

    def _sync_browser_cookies_to_session(self, page, session) -> None:
        """把临时浏览器里的 auth/chatgpt cookies 回灌到 curl_cffi session。

        add_phone 只能走浏览器页面时，手机号验证后的登录态经常只存在于
        browser context。回灌后可继续用原 OAuth state 走 workspace/consent，
        避免再完整跑一遍 Codex Auth 邮箱 OTP。
        """
        try:
            cookies = page.context.cookies()
        except Exception as exc:
            self._debug_log(f"回灌浏览器 cookies 失败: {exc}", "warning")
            return

        for cookie in cookies or []:
            try:
                name = str(cookie.get("name") or "")
                value = str(cookie.get("value") or "")
                domain = str(cookie.get("domain") or "").strip() or "auth.openai.com"
                path = str(cookie.get("path") or "/")
                if not name or not value:
                    continue
                if "openai.com" not in domain and "chatgpt.com" not in domain:
                    continue
                try:
                    session.cookies.set(name, value, domain=domain, path=path)
                except TypeError:
                    session.cookies.set(name, value)
                if domain.startswith("."):
                    try:
                        session.cookies.set(name, value, domain=domain.lstrip("."), path=path)
                    except Exception:
                        pass
            except Exception:
                continue

    def _codex_api_auth_url(self, codex_oauth) -> str:
        from .constants import OPENAI_AUTH

        try:
            query = codex_oauth.auth_url.split("?", 1)[1]
        except Exception:
            return codex_oauth.auth_url
        return f"{OPENAI_AUTH}/api/oauth/oauth2/auth?{query}"

    def _extract_codex_callback_from_state(self, state: dict | None) -> str:
        try:
            from platforms.chatgpt.browser_register import _extract_code_from_url
        except Exception:
            return ""
        raw = state if isinstance(state, dict) else {}
        for key in ("current_url", "continue_url"):
            url = str(raw.get(key) or "")
            if _extract_code_from_url(url) and "state=" in url:
                return url
        return ""

    def _try_codex_callback_with_session(self, login_session, codex_oauth, login_client=None, *, quiet: bool = False) -> Optional[str]:
        """Try to continue the current Codex OAuth session without redoing email OTP."""
        try:
            from platforms.chatgpt.browser_register import _follow_redirects_for_code

            log = self._debug_log if quiet else self._log
            callback = self._complete_codex_consent_with_session(
                login_session,
                codex_oauth,
                login_client,
                quiet=quiet,
            )
            if callback:
                return callback

            for next_url in (self._codex_api_auth_url(codex_oauth), codex_oauth.auth_url):
                callback = _follow_redirects_for_code(
                    login_session,
                    next_url,
                    log,
                    max_redirects=12,
                )
                if callback:
                    return callback
            return None
        except Exception as exc:
            self._debug_log(f"Codex OAuth session 续接失败: {exc}", "warning")
            return None

    def _click_codex_continue_in_browser(self, page) -> bool:
        """Best-effort click/submit for Codex consent/workspace pages."""
        try:
            clicked = bool(page.evaluate(
                """
                () => {
                  const visible = (el) => {
                    const style = window.getComputedStyle(el);
                    const rect = el.getBoundingClientRect();
                    return !!(style && style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0);
                  };
                  const forms = Array.from(document.querySelectorAll('form'));
                  for (const form of forms) {
                    const buttons = Array.from(form.querySelectorAll('button[type="submit"], input[type="submit"], button, [role="button"]'));
                    const target = buttons.find((el) => visible(el) && /continue|allow|authorize|select|继续|授权/i.test(String(el.innerText || el.textContent || el.value || ''))) ||
                                   buttons.find((el) => visible(el));
                    if (target) {
                      if (form.requestSubmit && target.tagName.toLowerCase() === 'button') form.requestSubmit(target);
                      else target.click();
                      return true;
                    }
                  }
                  const nodes = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], a'));
                  const target = nodes.find((el) => visible(el) && /continue|allow|authorize|select|next|继续|授权|下一步/i.test(String(el.innerText || el.textContent || el.getAttribute('aria-label') || ''))) ||
                                 nodes.find((el) => visible(el) && String(el.getAttribute('type') || '').toLowerCase() === 'submit');
                  if (target) {
                    target.click();
                    return true;
                  }
                  return false;
                }
                """
            ))
            return clicked
        except Exception as exc:
            self._debug_log(f"Codex browser continue 点击失败: {exc}", "warning")
            return False

    def _wait_browser_codex_callback(self, page, timeout: float = 10.0) -> str:
        try:
            from platforms.chatgpt.browser_register import _extract_code_from_url
        except Exception:
            return ""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                current_url = str(page.url or "")
            except Exception:
                current_url = ""
            if _extract_code_from_url(current_url) and "state=" in current_url:
                return current_url
            time.sleep(0.5)
        return ""

    def _continue_codex_oauth_in_browser_after_phone(self, page, login_session, codex_oauth, login_client=None) -> Optional[str]:
        """手机号验证完成后，只做几秒钟快速 callback 探测。

        add_phone 完成后旧 OAuth session 经常不会继续吐 callback。这里不再长时间
        导航/轮询；几秒内拿不到就交给外层重新跑一遍 Codex Auth。
        """
        try:
            from platforms.chatgpt.browser_register import (
                _derive_registration_state_from_page,
                _extract_callback_url_from_exception,
                _extract_code_from_url,
            )
        except Exception as exc:
            self._debug_log(f"加载 Codex OAuth browser 续接工具失败: {exc}", "warning")
            return None

        def _check_current() -> str:
            try:
                current = str(page.url or "")
            except Exception:
                current = ""
            if _extract_code_from_url(current) and "state=" in current:
                return current
            try:
                state = _derive_registration_state_from_page(page)
            except Exception:
                state = {}
            return self._extract_codex_callback_from_state(state)

        # 先回灌 cookies，只检查当前 URL/state。不要在旧会话里长时间 goto/redirect。
        self._sync_browser_cookies_to_session(page, login_session)
        deadline = time.time() + 3.0
        round_idx = 0
        while time.time() < deadline:
            round_idx += 1
            callback = _check_current()
            if callback:
                return callback
            try:
                state = _derive_registration_state_from_page(page)
            except Exception:
                state = {}
            page_type = str(state.get("page_type") or "")
            current_url = str(state.get("current_url") or getattr(page, "url", "") or "")
            self._debug_log(f"Codex add_phone 后快速探测[{round_idx}]: page={page_type or '-'} url={current_url[:120]}")

            if page_type in {"consent", "sign_in_with_chatgpt_codex_consent", "workspace_selection", "organization_selection", "external_url"}:
                if self._click_codex_continue_in_browser(page):
                    callback = self._wait_browser_codex_callback(page, timeout=1.5)
                    if callback:
                        return callback

            time.sleep(0.4)
        return None

    def _complete_add_phone_in_browser(self, login_session, codex_oauth, did: str, login_client=None) -> Optional[str]:
        """Use the existing browser add-phone implementation to finish SMS verification."""
        if not self.phone_callback:
            self._log("Codex CLI 登录进入 add_phone，但未配置可用 SMS phone_callback", "error")
            return None
        try:
            from camoufox.sync_api import Camoufox
            from platforms.chatgpt.browser_register import (
                _build_proxy_config,
                _camoufox_launch_options,
                _handle_add_phone_challenge,
                _extract_code_from_url,
                _derive_registration_state_from_page,
                _extract_callback_url_from_exception,
            )
            from .constants import OPENAI_AUTH

            ua = ""
            try:
                ua = str((login_client.default_headers or {}).get("User-Agent") or "") if login_client else ""
            except Exception:
                ua = ""
            proxy = _build_proxy_config(self.proxy_url)
            launch_opts = _camoufox_launch_options(headless=True, proxy=proxy)

            self._log("Codex Auth 需要手机验证，开始短信验证...")
            with Camoufox(**launch_opts) as browser:
                page = browser.new_page()
                cookies = self._session_cookies_for_browser(login_session)
                if cookies:
                    page.context.add_cookies(cookies)
                try:
                    page.context.add_cookies([
                        {"name": "oai-did", "value": did, "domain": "auth.openai.com", "path": "/"},
                        {"name": "oai-did", "value": did, "domain": ".auth.openai.com", "path": "/"},
                    ])
                except Exception:
                    pass

                try:
                    page.goto(f"{OPENAI_AUTH}/add-phone", wait_until="domcontentloaded", timeout=30000)
                except Exception as exc:
                    callback_url = _extract_callback_url_from_exception(exc)
                    if callback_url:
                        self._log("Codex add_phone 前已获取到 callback URL")
                        return callback_url
                    raise
                state = _handle_add_phone_challenge(
                    page,
                    self.phone_callback,
                    device_id=did,
                    user_agent=ua,
                    log=self._log,
                    resume_url="",
                )
                self._debug_log(f"Codex add_phone 完成: page={state.get('page_type') or '-'}")

                callback_url = self._extract_codex_callback_from_state(state)
                if callback_url:
                    self._log("手机验证后获取到 Codex callback URL")
                    return callback_url

                self._sync_browser_cookies_to_session(page, login_session)
                callback_url = self._continue_codex_oauth_in_browser_after_phone(
                    page,
                    login_session,
                    codex_oauth,
                    login_client,
                )
                if callback_url:
                    self._log("手机验证完成，已续接 Codex OAuth")
                    return callback_url
                self._log("手机验证已完成，旧 OAuth 会话 3 秒内未返回 callback，准备重跑 Codex Auth...")
            return None
        except Exception as exc:
            self._log(f"Codex add_phone 浏览器处理失败: {exc}", "error")
            return None

    def _complete_codex_add_phone_with_retry(self, login_session, codex_oauth, did: str, login_client=None):
        """Finish SMS verification and refresh only the OAuth state when necessary."""
        callback = self._complete_add_phone_in_browser(
            login_session,
            codex_oauth,
            did,
            login_client,
        )
        if callback:
            return callback, codex_oauth

        if not getattr(self.phone_callback, "completed", False):
            return None, codex_oauth
        if getattr(self, "_codex_retry_after_phone", False):
            return None, codex_oauth

        self._codex_retry_after_phone = True
        self._log("手机验证已完成，旧 OAuth 会话未返回 callback，立即重跑 Codex Auth...")
        callback = self._acquire_codex_callback()
        if self._codex_direct_token_info:
            return None, getattr(self, "_codex_oauth", codex_oauth)
        return callback, getattr(self, "_codex_oauth", codex_oauth)

    def _cookies_dict_from_session(self, session) -> dict:
        cookies: dict[str, str] = {}
        try:
            for c in session.cookies.jar:
                name = str(getattr(c, "name", "") or "")
                value = str(getattr(c, "value", "") or "")
                if name and value:
                    cookies[name] = value
        except Exception:
            try:
                cookies.update(dict(session.cookies))
            except Exception:
                pass
        return cookies

    def _complete_codex_consent_with_session(self, login_session, codex_oauth, login_client=None, *, quiet: bool = False) -> Optional[str]:
        """Complete Codex consent/workspace selection in the protocol session and return OAuth callback URL."""
        try:
            from platforms.chatgpt.browser_register import (
                _decode_oauth_session_cookie,
                _extract_workspace_from_consent_html,
                _extract_flow_state,
                _follow_redirects_for_code,
                _normalize_url,
            )
            from .constants import OPENAI_AUTH
            import urllib.parse

            consent_url = f"{OPENAI_AUTH}/sign-in-with-chatgpt/codex/consent"
            log = self._debug_log if quiet else self._log
            cookies_dict = self._cookies_dict_from_session(login_session)
            session_meta = _decode_oauth_session_cookie(cookies_dict)
            workspaces = list(session_meta.get("workspaces") or [])
            if not workspaces:
                session_meta = _extract_workspace_from_consent_html(login_session, consent_url)
                workspaces = list(session_meta.get("workspaces") or [])
            if not workspaces:
                log("Codex consent 缺少 workspace 信息", "warning")
                return None

            workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
            if not workspace_id:
                log("Codex consent workspace_id 为空", "warning")
                return None
            log(f"Codex consent 选择 workspace: {workspace_id}")

            ua = ""
            try:
                ua = str((login_client.default_headers or {}).get("User-Agent") or "") if login_client else ""
            except Exception:
                ua = ""
            headers = {
                "accept": "application/json",
                "referer": consent_url,
                "origin": OPENAI_AUTH,
                "content-type": "application/json",
            }
            if ua:
                headers["user-agent"] = ua
            ws_resp = login_session.post(
                f"{OPENAI_AUTH}/api/accounts/workspace/select",
                headers=headers,
                data=json.dumps({"workspace_id": workspace_id}),
                allow_redirects=False,
                timeout=30,
            )
            log(f"Codex workspace/select: {ws_resp.status_code}")

            next_url = str(ws_resp.headers.get("Location") or "").strip()
            next_data = {}
            if not next_url:
                try:
                    next_data = ws_resp.json() or {}
                except Exception:
                    next_data = {}
                next_url = str(next_data.get("continue_url") or "").strip()
            next_url = _normalize_url(next_url, consent_url)
            if next_url and "code=" in next_url and "state=" in next_url:
                log("Codex consent 直接得到 callback URL")
                return next_url

            orgs = list((((next_data.get("data") or {}).get("orgs")) or []))
            if orgs and orgs[0].get("id"):
                org_id = str(orgs[0].get("id") or "").strip()
                org_body = {"org_id": org_id}
                projects = list(orgs[0].get("projects") or [])
                if projects and projects[0].get("id"):
                    org_body["project_id"] = str(projects[0].get("id") or "").strip()
                log(f"Codex consent 选择 organization: {org_id}")
                org_resp = login_session.post(
                    f"{OPENAI_AUTH}/api/accounts/organization/select",
                    headers=headers,
                    data=json.dumps(org_body),
                    allow_redirects=False,
                    timeout=30,
                )
                log(f"Codex organization/select: {org_resp.status_code}")
                next_url = str(org_resp.headers.get("Location") or "").strip() or next_url
                if not next_url:
                    try:
                        org_data = org_resp.json() or {}
                        next_url = str(org_data.get("continue_url") or "").strip()
                        if not next_url:
                            org_state = _extract_flow_state(org_data, str(org_resp.url))
                            next_url = org_state.get("continue_url") or org_state.get("current_url") or ""
                    except Exception:
                        next_url = ""
                next_url = _normalize_url(next_url, consent_url)

            if not next_url and next_data:
                state = _extract_flow_state(next_data, str(ws_resp.url))
                next_url = state.get("continue_url") or state.get("current_url") or ""
                next_url = _normalize_url(next_url, consent_url)
            if not next_url:
                next_url = f"{OPENAI_AUTH}/api/oauth/oauth2/auth?" + codex_oauth.auth_url.split("?", 1)[1]
            log(f"Codex consent continue: {next_url[:100]}...")
            callback_url = _follow_redirects_for_code(login_session, next_url, log, max_redirects=12)
            if callback_url:
                log("Codex consent 获取到 callback URL")
                return callback_url
            log("Codex consent 未能跟到 callback URL", "warning")
            return None
        except Exception as exc:
            (self._debug_log if quiet else self._log)(f"Codex consent 处理失败: {exc}", "error")
            return None

    def _complete_codex_email_otp(
        self,
        login_session,
        *,
        send_code: bool,
        referer: str,
    ) -> Optional[str]:
        """Send (when needed), fetch and validate a Codex login email OTP."""
        from .constants import OPENAI_AUTH, OPENAI_API_ENDPOINTS

        if send_code:
            self._otp_sent_at = time.time()
            send_resp = login_session.get(
                OPENAI_API_ENDPOINTS["send_otp"],
                headers={"referer": referer},
                timeout=15,
                allow_redirects=False,
            )
            content_type = str((getattr(send_resp, "headers", {}) or {}).get("content-type") or "").lower()
            location = str((getattr(send_resp, "headers", {}) or {}).get("location") or "").strip()
            self._debug_log(
                f"Codex login OTP 发送: {send_resp.status_code} "
                f"content_type={content_type or '-'} location={location[:120] or '-'}"
            )
            if send_resp.status_code not in (200, 201, 204):
                self._log(f"Codex login OTP 发送失败: {send_resp.text[:200]}", "error")
                return None
            if location or (content_type and "json" not in content_type):
                self._log(
                    "Codex login OTP 发送未确认：接口发生跳转或返回的不是 JSON，停止等待验证码",
                    "error",
                )
                return None
            self._log("Codex login 一次性验证码已发送")
        else:
            self._otp_sent_at = time.time()

        self._log("Codex login 等待邮箱一次性验证码...")
        code = self._get_verification_code()
        if not code:
            self._log("Codex login 获取验证码失败", "error")
            return None

        otp_resp = login_session.post(
            OPENAI_API_ENDPOINTS["validate_otp"],
            headers={
                "referer": f"{OPENAI_AUTH}/email-verification",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=json.dumps({"code": code}),
        )
        self._debug_log(f"Codex login OTP 校验: {otp_resp.status_code}")
        if otp_resp.status_code != 200:
            self._log(f"Codex login OTP 失败: {otp_resp.text[:200]}", "error")
            return None

        otp_page = str((otp_resp.json().get("page") or {}).get("type") or "")
        self._debug_log(f"Codex login OTP -> page_type={otp_page}")
        return otp_page

    def _complete_codex_login_password_in_browser(self) -> Optional[Dict[str, Any]]:
        """Finish a password challenge via MFA or the passwordless email fallback."""
        try:
            from core.totp import fetch_totp_code, generate_totp
            from platforms.chatgpt.browser_register import ChatGPTBrowserRegister

            def wait_for_browser_otp() -> Optional[str]:
                # The browser state machine only invokes this after the button click
                # has transitioned to the email verification page.
                self._otp_sent_at = time.time()
                self._log("Codex login 已确认进入验证码页面，开始读取新邮件")
                return self._get_verification_code()

            def current_mfa_code() -> Optional[str]:
                secret = str(getattr(self, "totp_secret", "") or "").strip()
                totp_url = str(getattr(self, "totp_url", "") or "").strip()
                if totp_url:
                    code = fetch_totp_code(totp_url, proxy_url=self.proxy_url)
                    self._log("Codex login 已从 MFA 地址获取当前验证码")
                    return code
                if not secret:
                    return None
                code = generate_totp(secret)
                self._log("Codex login 已生成当前 MFA 验证码")
                return code

            has_mfa = bool(
                str(getattr(self, "totp_secret", "") or "").strip()
                or str(getattr(self, "totp_url", "") or "").strip()
            )
            browser_flow = ChatGPTBrowserRegister(
                headless=True,
                proxy=self.proxy_url,
                otp_callback=None if has_mfa else wait_for_browser_otp,
                mfa_callback=current_mfa_code if has_mfa else None,
                phone_callback=self.phone_callback,
                log_fn=self._log,
            )
            browser_password = self.password
            if getattr(self, "_is_existing_account", False) and not getattr(self, "_has_supplied_login_password", False):
                # URL-only mailbox entries receive a generated registration
                # password from the worker. It is not a valid existing-account
                # credential, so choose the browser's email-OTP login action.
                browser_password = ""
            token_info = browser_flow._retry_oauth_fresh_browser(self.email, browser_password)
            if not isinstance(token_info, dict):
                browser_error = str(getattr(browser_flow, "last_oauth_error", "") or "").strip()
                self._last_codex_error = browser_error or "浏览器 OAuth 未完成"
                return None
            access_token = str(token_info.get("access_token") or "").strip()
            refresh_token = str(token_info.get("refresh_token") or token_info.get("rt") or "").strip()
            if not access_token or not refresh_token:
                self._last_codex_error = "浏览器 OAuth token 缺少 access_token 或 refresh_token(rt)"
                return None
            self._log("Codex login 浏览器 OAuth 已完成")
            return token_info
        except Exception as exc:
            self._last_codex_error = f"浏览器 OAuth 失败: {exc}"
            self._log(self._last_codex_error, "error")
            return None

    def _acquire_codex_callback(self) -> Optional[str]:
        """
        注册完成后，通过 Codex CLI OAuth 完整登录流程获取 callback URL。
        使用新 session，走 authorize → authorize/continue → OTP → callback 流程。
        """
        try:
            self._last_codex_error = ""
            self._codex_direct_token_info = None
            from .constants import (
                CODEX_CLIENT_ID, CODEX_REDIRECT_URI, CODEX_SCOPE,
                OPENAI_AUTH, OPENAI_API_ENDPOINTS,
            )
            import urllib.parse

            self._log("开始 Codex CLI 登录流程...")

            # 1. 生成 Codex CLI OAuth URL (Hydra)
            codex_oauth = generate_oauth_url(
                redirect_uri=CODEX_REDIRECT_URI,
                scope=CODEX_SCOPE,
                client_id=CODEX_CLIENT_ID,
            )
            self._codex_oauth = codex_oauth

            # 2. 访问 authorize URL 获取 device_id + session cookies.
            # A 403 must not be retried with the same fingerprint/session.
            login_session, did, _ = self._start_codex_oauth_session(codex_oauth.auth_url)
            login_client = OpenAIHTTPClient(proxy_url=self.proxy_url)
            self._debug_log(f"Codex login device_id: {did}")

            # 3. 获取 Sentinel token
            sen_payload = None
            try:
                ua = login_client.default_headers.get("User-Agent", "")
                generator = _SentinelTokenGenerator(did, ua)
                sent_p = generator.generate_requirements_token()
                sen_req_body = json.dumps({"p": sent_p, "id": did, "flow": "authorize_continue"}, separators=(",", ":"))

                from .constants import SENTINEL_FRAME_URL
                sen_resp = login_session.post(
                    OPENAI_API_ENDPOINTS["sentinel"],
                    headers={
                        "origin": "https://sentinel.openai.com",
                        "referer": SENTINEL_FRAME_URL,
                        "content-type": "text/plain;charset=UTF-8",
                    },
                    data=sen_req_body,
                )
                if sen_resp.status_code == 200:
                    data = sen_resp.json()
                    turnstile = data.get("turnstile") or {}
                    pow_meta = data.get("proofofwork") or {}
                    if pow_meta.get("required") and pow_meta.get("seed"):
                        sent_p = generator.generate_token(
                            str(pow_meta.get("seed") or ""),
                            str(pow_meta.get("difficulty") or "0"),
                        )
                    t_raw = turnstile.get("dx", "")
                    t_val = ""
                    if t_raw:
                        try:
                            t_val = generator.decrypt_turnstile(t_raw, sent_p)
                        except Exception:
                            pass
                    sen_payload = SentinelPayload(p=sent_p, t=t_val, c=str(data.get("token") or ""), flow="authorize_continue")
                    self._debug_log("Codex login Sentinel 已获取")
            except Exception as e:
                self._log(f"Codex login Sentinel 失败: {e}", "warning")

            # 5. authorize/continue 提交邮箱（登录已有账号）
            signup_body = f'{{"username":{{"value":"{self.email}","kind":"email"}},"screen_hint":"login"}}'
            headers = {
                "referer": "https://auth.openai.com/log-in",
                "accept": "application/json",
                "content-type": "application/json",
            }
            if sen_payload:
                headers["openai-sentinel-token"] = json.dumps({
                    "p": sen_payload.p, "t": sen_payload.t, "c": sen_payload.c,
                    "id": did, "flow": sen_payload.flow,
                }, separators=(",", ":"))

            resp = login_session.post(OPENAI_API_ENDPOINTS["signup"], headers=headers, data=signup_body)
            self._debug_log(f"Codex login authorize/continue: {resp.status_code}")
            if resp.status_code != 200:
                self._log(f"Codex login authorize/continue 失败: {resp.text[:200]}", "error")
                return None

            resp_data = resp.json()
            page_type = resp_data.get("page", {}).get("type", "")
            self._debug_log(f"Codex login page_type: {page_type}")

            # 6. 如果需要 OTP/手机号验证，继续完成挑战
            if page_type == "add_phone":
                self._log("Codex login 直接进入 add_phone，开始短信验证...")
                callback = self._complete_add_phone_in_browser(login_session, codex_oauth, did, login_client)
                if callback:
                    return callback
                if getattr(self.phone_callback, "completed", False) and not getattr(self, "_codex_retry_after_phone", False):
                    self._codex_retry_after_phone = True
                    self._log("手机验证已完成，旧 OAuth 会话未返回 callback，立即重跑 Codex Auth...")
                    return self._acquire_codex_callback()
                return None

            if page_type in ("email_otp_send", "email_otp_verification"):
                otp_page = self._complete_codex_email_otp(
                    login_session,
                    send_code=page_type == "email_otp_send",
                    referer=f"{OPENAI_AUTH}/email-verification",
                )
                if otp_page is None:
                    return None

                if otp_page == "add_phone":
                    self._log("Codex CLI 登录进入 add_phone，开始短信验证...")
                    callback = self._complete_add_phone_in_browser(login_session, codex_oauth, did, login_client)
                    if callback:
                        return callback
                    if getattr(self.phone_callback, "completed", False) and not getattr(self, "_codex_retry_after_phone", False):
                        self._codex_retry_after_phone = True
                        self._log("手机验证已完成，旧 OAuth 会话未返回 callback，立即重跑 Codex Auth...")
                        return self._acquire_codex_callback()
                    return None

            # 7. 已有账号遇到密码验证时，强制改走邮箱一次性验证码。
            elif page_type == "login_password":
                self._log("Codex login 遇到密码验证，切换浏览器点击一次性验证码入口...")
                token_info = self._complete_codex_login_password_in_browser()
                if not token_info:
                    return None
                self._codex_direct_token_info = token_info
                return "browser-token-ready"

            # 新账号创建密码仍走密码提交，不属于登录密码验证。
            elif page_type == "create_account_password":
                self._log(f"Codex login 提交密码...")
                if not self.password:
                    self._log("无密码可用", "error")
                    return None

                # 加载密码页获取 sentinel
                login_session.get(f"{OPENAI_AUTH}/log-in/password", timeout=15)
                pwd_sentinel = None
                try:
                    ua2 = login_client.default_headers.get("User-Agent", "")
                    gen2 = _SentinelTokenGenerator(did, ua2)
                    sp2 = gen2.generate_requirements_token()
                    sr2 = json.dumps({"p": sp2, "id": did, "flow": "login_password"}, separators=(",", ":"))
                    from .constants import SENTINEL_FRAME_URL as SF2
                    sr2_resp = login_client.post(
                        OPENAI_API_ENDPOINTS["sentinel"],
                        headers={"origin": "https://sentinel.openai.com", "referer": SF2, "content-type": "text/plain;charset=UTF-8"},
                        data=sr2,
                    )
                    if sr2_resp.status_code == 200:
                        d2 = sr2_resp.json()
                        pm2 = d2.get("proofofwork") or {}
                        if pm2.get("required") and pm2.get("seed"):
                            sp2 = gen2.generate_token(str(pm2.get("seed") or ""), str(pm2.get("difficulty") or "0"))
                        tr2 = (d2.get("turnstile") or {}).get("dx", "")
                        tv2 = ""
                        if tr2:
                            try: tv2 = gen2.decrypt_turnstile(tr2, sp2)
                            except: pass
                        pwd_sentinel = SentinelPayload(p=sp2, t=tv2, c=str(d2.get("token") or ""), flow="login_password")
                        self._debug_log("Codex login 密码 Sentinel 已获取")
                except Exception as e:
                    self._log(f"Codex login 密码 Sentinel 失败: {e}", "warning")

                pwd_headers = {
                    "origin": OPENAI_AUTH,
                    "referer": f"{OPENAI_AUTH}/log-in/password",
                    "accept": "application/json",
                    "content-type": "application/json",
                }
                if did:
                    pwd_headers["oai-device-id"] = did
                if pwd_sentinel:
                    pwd_headers["openai-sentinel-token"] = json.dumps({
                        "p": pwd_sentinel.p, "t": pwd_sentinel.t, "c": pwd_sentinel.c,
                        "id": did, "flow": pwd_sentinel.flow,
                    }, separators=(",", ":"))

                pwd_body = json.dumps({"password": self.password, "username": self.email})
                pwd_resp = login_session.post(OPENAI_API_ENDPOINTS["register"], headers=pwd_headers, data=pwd_body)
                self._debug_log(f"Codex login 密码提交: {pwd_resp.status_code}")
                if pwd_resp.status_code != 200:
                    self._log(f"Codex login 密码失败: {pwd_resp.text[:200]}", "error")
                    return None

                pwd_data = pwd_resp.json()
                pwd_page = pwd_data.get("page", {}).get("type", "")
                self._debug_log(f"Codex login 密码 -> page_type={pwd_page}")

                # 密码后可能需要 OTP
                if pwd_page == "email_otp_verification" or pwd_page == "email_otp_send":
                    if pwd_page == "email_otp_send":
                        login_session.get(OPENAI_API_ENDPOINTS["send_otp"], headers={
                            "referer": f"{OPENAI_AUTH}/email-verification",
                        }, timeout=15)
                    self._log("Codex login: 等待验证码...")
                    self._otp_sent_at = time.time()
                    code = self._get_verification_code()
                    if not code:
                        self._log("Codex login 获取验证码失败", "error")
                        return None
                    code_body = f'{{"code":"{code}"}}'
                    otp_resp = login_session.post(
                        OPENAI_API_ENDPOINTS["validate_otp"],
                        headers={"referer": f"{OPENAI_AUTH}/email-verification", "accept": "application/json", "content-type": "application/json"},
                        data=code_body,
                    )
                    self._debug_log(f"Codex login OTP: {otp_resp.status_code}")
                    if otp_resp.status_code != 200:
                        self._log(f"Codex login OTP 失败: {otp_resp.text[:200]}", "error")
                        return None
                    otp_data = otp_resp.json()
                    otp_page = otp_data.get("page", {}).get("type", "")
                    self._debug_log(f"Codex login OTP -> page_type={otp_page}")
                    if otp_page == "add_phone":
                        self._log("Codex CLI 登录进入 add_phone，开始短信验证...")
                        callback = self._complete_add_phone_in_browser(login_session, codex_oauth, did, login_client)
                        if callback:
                            return callback
                        if getattr(self.phone_callback, "completed", False) and not getattr(self, "_codex_retry_after_phone", False):
                            self._codex_retry_after_phone = True
                            self._log("手机验证已完成，旧 OAuth 会话未返回 callback，立即重跑 Codex Auth...")
                            return self._acquire_codex_callback()
                        return None

            # 8. 如果 OTP 后进入 Codex consent/workspace 页面，先完成 workspace/organization 选择。
            current_page_type = locals().get("otp_page") or locals().get("pwd_page") or locals().get("page_type") or ""
            if current_page_type == "sign_in_with_chatgpt_codex_consent":
                self._log("Codex login 进入 consent，开始选择 workspace...")
                callback = self._complete_codex_consent_with_session(login_session, codex_oauth, login_client)
                if callback:
                    return callback

            # 9. 重新访问 authorize URL 获取回调
            self._debug_log("Codex login: 重新访问 OAuth URL 获取回调...")
            response = login_session.get(codex_oauth.auth_url, allow_redirects=False, timeout=15)
            max_redirects = 10
            current_url = codex_oauth.auth_url
            for i in range(max_redirects):
                if response.status_code not in (301, 302, 303, 307, 308):
                    break
                location = response.headers.get("Location", "")
                if not location:
                    break
                next_url = urllib.parse.urljoin(current_url, location)
                self._debug_log(f"Codex login 重定向 {i+1}: {next_url[:80]}...")
                if "code=" in next_url and "state=" in next_url:
                    self._log("找到 Codex CLI 回调 URL")
                    return next_url
                current_url = next_url
                response = login_session.get(current_url, allow_redirects=False, timeout=15)

            self._log(f"Codex login 最终: status={response.status_code}, url={current_url[:100]}", "warning")
            return None

        except Exception as e:
            self._last_codex_error = str(e)
            self._log(f"Codex CLI 登录流程失败: {e}", "error")
            return None

    def _get_workspace_id(self) -> Optional[str]:
        """获取 Workspace ID"""
        try:
            auth_cookie = self.session.cookies.get("oai-client-auth-session")
            if not auth_cookie:
                self._log("未能获取到授权 Cookie", "error")
                return None

            # 解码 JWT
            import base64
            import json as json_module

            try:
                segments = auth_cookie.split(".")
                if len(segments) < 1:
                    self._log("授权 Cookie 格式错误", "error")
                    return None

                # 解码第一个 segment
                payload = segments[0]
                pad = "=" * ((4 - (len(payload) % 4)) % 4)
                decoded = base64.urlsafe_b64decode((payload + pad).encode("ascii"))
                auth_json = json_module.loads(decoded.decode("utf-8"))

                workspaces = auth_json.get("workspaces") or []
                if not workspaces:
                    self._log("授权 Cookie 里没有 workspace 信息", "error")
                    return None

                workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
                if not workspace_id:
                    self._log("无法解析 workspace_id", "error")
                    return None

                self._log(f"Workspace ID: {workspace_id}")
                return workspace_id

            except Exception as e:
                self._log(f"解析授权 Cookie 失败: {e}", "error")
                return None

        except Exception as e:
            self._log(f"获取 Workspace ID 失败: {e}", "error")
            return None

    def _select_workspace(self, workspace_id: str) -> Optional[str]:
        """选择 Workspace"""
        try:
            select_body = f'{{"workspace_id":"{workspace_id}"}}'

            response = self.session.post(
                OPENAI_API_ENDPOINTS["select_workspace"],
                headers={
                    "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                    "content-type": "application/json",
                },
                data=select_body,
            )

            if response.status_code != 200:
                self._log(f"选择 workspace 失败: {response.status_code}", "error")
                self._log(f"响应: {response.text[:200]}", "warning")
                return None

            continue_url = str((response.json() or {}).get("continue_url") or "").strip()
            if not continue_url:
                self._log("workspace/select 响应里缺少 continue_url", "error")
                return None

            self._log(f"Continue URL: {continue_url[:100]}...")
            return continue_url

        except Exception as e:
            self._log(f"选择 Workspace 失败: {e}", "error")
            return None

    def _follow_redirects(self, start_url: str) -> Optional[str]:
        """跟随重定向链，寻找回调 URL"""
        try:
            current_url = start_url
            max_redirects = 6

            for i in range(max_redirects):
                self._log(f"重定向 {i+1}/{max_redirects}: {current_url[:100]}...")

                response = self.session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=15
                )

                location = response.headers.get("Location") or ""

                # 如果不是重定向状态码，停止
                if response.status_code not in [301, 302, 303, 307, 308]:
                    self._log(f"非重定向状态码: {response.status_code}")
                    break

                if not location:
                    self._log("重定向响应缺少 Location 头")
                    break

                # 构建下一个 URL
                import urllib.parse
                next_url = urllib.parse.urljoin(current_url, location)

                # 检查是否包含回调参数
                if "code=" in next_url and "state=" in next_url:
                    self._log(f"找到回调 URL: {next_url[:100]}...")
                    return next_url

                current_url = next_url

            self._log("未能在重定向链中找到回调 URL", "error")
            return None

        except Exception as e:
            self._log(f"跟随重定向失败: {e}", "error")
            return None

    def _handle_oauth_callback(self, callback_url: str) -> Optional[Dict[str, Any]]:
        """处理 OAuth 回调"""
        try:
            if not self.oauth_start:
                self._log("OAuth 流程未初始化", "error")
                return None

            self._log("处理 OAuth 回调...")
            token_info = self.oauth_manager.handle_callback(
                callback_url=callback_url,
                expected_state=self.oauth_start.state,
                code_verifier=self.oauth_start.code_verifier
            )

            self._log("OAuth 授权成功")
            return token_info

        except Exception as e:
            self._log(f"处理 OAuth 回调失败: {e}", "error")
            return None

    def login_existing_via_codex_auth(
        self,
        *,
        email: str = "",
        password: str = "",
        totp_secret: str = "",
        totp_url: str = "",
    ) -> RegistrationResult:
        """已注册账号入口：只走 Codex OAuth 登录，不走 create-account 注册链路。"""
        result = RegistrationResult(success=False, logs=self.logs)
        try:
            self._log("=" * 60)
            self._log("开始已注册账号 Codex Auth 登录流程")
            self._log("=" * 60)

            ok, preflight = self._preflight_codex_auth_network()
            if not ok:
                result.error_message = f"Codex Auth 网络自测失败，未占用邮箱: {preflight}"
                self._log(result.error_message, "error")
                return result
            self._debug_log(f"Codex Auth 网络自测通过: {preflight}")

            # 1. 获取/绑定邮箱账号。邮箱池在 create_email() 里完成占用和元数据绑定。
            if email:
                self.email = email
            # Only supplier-provided credentials are valid for a password
            # challenge. URL-only mailbox registrations use a generated
            # password and must keep the email-OTP fallback instead.
            self._has_supplied_login_password = bool(str(password or "").strip())
            self.password = password or self.password or ""
            self.totp_secret = totp_secret or getattr(self, "totp_secret", "") or ""
            self.totp_url = totp_url or getattr(self, "totp_url", "") or ""
            if not self.email_info:
                self._log("1. 获取邮箱池账号...")
                if not self._create_email():
                    result.error_message = "获取邮箱账号失败"
                    return result
            elif not self.email and self.email_info.get("email"):
                self.email = self.email_info.get("email")

            result.email = self.email or email
            self._is_existing_account = True

            # MFA 导入账号由凭据格式决定登录方式，不能让协议页状态将其降级为邮箱 OTP。
            if self.totp_secret or self.totp_url:
                self._log("2. 已识别密码 + MFA 账号，固定走密码和 MFA 登录...")
                token_info = self._complete_codex_login_password_in_browser()
                if token_info:
                    self._codex_direct_token_info = token_info
                    callback_url = "browser-token-ready"
                else:
                    callback_url = None
            else:
                self._log("2. 走 Codex Auth 获取 OAuth callback...")
                callback_url = self._acquire_codex_callback()
            if not callback_url:
                if self._last_codex_error:
                    result.error_message = f"Codex Auth 未获取到 callback URL: {self._last_codex_error}"
                else:
                    result.error_message = "Codex Auth 未获取到 callback URL"
                return result

            token_info = self._codex_direct_token_info
            if token_info:
                self._log("3. 使用浏览器完成的 Codex OAuth token...")
            else:
                self._log("3. 交换 Codex OAuth token...")
                from .constants import CODEX_CLIENT_ID, CODEX_REDIRECT_URI
                token_json = submit_callback_url(
                    callback_url=callback_url,
                    expected_state=self._codex_oauth.state,
                    code_verifier=self._codex_oauth.code_verifier,
                    redirect_uri=CODEX_REDIRECT_URI,
                    client_id=CODEX_CLIENT_ID,
                    proxy_url=self.proxy_url,
                )
                token_info = json.loads(token_json)

            access_token = str(token_info.get("access_token") or "")
            refresh_token = str(token_info.get("refresh_token") or token_info.get("rt") or "")
            if not access_token:
                result.error_message = "Codex Auth token 响应缺少 access_token"
                return result
            if not refresh_token:
                result.error_message = "Codex Auth token 响应缺少 refresh_token(rt)，不计入成功"
                self._log(result.error_message, "error")
                return result

            result.success = True
            result.email = str(token_info.get("email") or result.email or self.email or email)
            result.password = self.password or password or ""
            result.account_id = str(token_info.get("account_id") or "")
            result.access_token = access_token
            result.refresh_token = refresh_token
            result.id_token = str(token_info.get("id_token") or "")
            result.source = "login"
            result.metadata = {
                "email_service": self.email_service.service_type.value,
                "proxy_used": self.proxy_url,
                "registered_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "is_existing_account": True,
                "auth_flow": "codex_auth",
            }

            self._log("=" * 60)
            self._log("Codex Auth 登录成功! (已注册账号)")
            self._log(f"邮箱: {result.email}")
            self._log(f"Account ID: {result.account_id}")
            self._log("=" * 60)
            return result

        except Exception as e:
            self._log(f"Codex Auth 登录过程中发生错误: {e}", "error")
            result.error_message = str(e)
            return result

    def run(self) -> RegistrationResult:
        """
        执行完整的注册流程

        支持已注册账号自动登录：
        - 如果检测到邮箱已注册，自动切换到登录流程
        - 已注册账号跳过：设置密码、发送验证码、创建用户账户
        - 共用步骤：获取验证码、验证验证码、Workspace 和 OAuth 回调

        Returns:
            RegistrationResult: 注册结果
        """
        result = RegistrationResult(success=False, logs=self.logs)

        try:
            self._log("=" * 60)
            self._log("开始注册流程")
            self._log("=" * 60)

            # 1. 检查 IP 地理位置
            self._log("1. 检查 IP 地理位置...")
            ip_ok, location = self._check_ip_location()
            if not ip_ok:
                result.error_message = f"IP 地理位置不支持: {location}"
                self._log(f"IP 检查失败: {location}", "error")
                return result

            self._log(f"IP 位置: {location}")

            ok, preflight = self._preflight_codex_auth_network()
            if not ok:
                result.error_message = f"OpenAI Auth 网络自测失败，未占用邮箱: {preflight}"
                self._log(result.error_message, "error")
                return result
            self._debug_log(f"OpenAI Auth 网络自测通过: {preflight}")

            # 2. 创建邮箱
            self._log("2. 创建邮箱...")
            if not self._create_email():
                result.error_message = "创建邮箱失败"
                return result

            result.email = self.email

            # 3. 初始化会话
            self._log("3. 初始化会话...")
            if not self._init_session():
                result.error_message = "初始化会话失败"
                return result

            # 4. 开始 OAuth 流程
            self._log("4. 开始 OAuth 授权流程...")
            if not self._start_oauth():
                result.error_message = "开始 OAuth 流程失败"
                return result

            # 5. 获取 Device ID
            self._log("5. 获取 Device ID...")
            did = self._get_device_id()
            if not did:
                result.error_message = "获取 Device ID 失败"
                return result

            # 6. 检查 Sentinel 拦截
            self._log("6. 检查 Sentinel 拦截...")
            sen_payload = self._check_sentinel(did)
            if sen_payload:
                self._log("Sentinel 检查通过")
            else:
                self._log("Sentinel 检查失败或未启用", "warning")

            # 7. 提交注册表单 + 解析响应判断账号状态
            self._log("7. 提交注册表单...")
            signup_result = self._submit_signup_form(did, sen_payload)
            if not signup_result.success and self._is_invalid_state_signup(signup_result):
                signup_result = self._retry_signup_with_fresh_session()
            if not signup_result.success:
                result.error_message = f"提交注册表单失败: {signup_result.error_message}"
                return result

            # 8. [已注册账号跳过] 注册密码
            if self._is_existing_account:
                self._log("8. [已注册账号] 跳过密码设置，OTP 已自动发送")
            else:
                self._log("8. 注册密码...")
                password_ok, password = self._register_password()
                if not password_ok:
                    result.error_message = "注册密码失败"
                    return result

            # 9. [已注册账号跳过] 发送验证码
            if self._is_existing_account:
                self._log("9. [已注册账号] 跳过发送验证码，使用自动发送的 OTP")
                # 已注册账号的 OTP 在提交表单时已自动发送，记录时间戳
                self._otp_sent_at = time.time()
            else:
                self._log("9. 发送验证码...")
                if not self._send_verification_code():
                    result.error_message = "发送验证码失败"
                    return result

            # 10. 获取验证码
            self._log("10. 等待验证码...")
            code = self._get_verification_code()
            if not code:
                result.error_message = "获取验证码失败"
                return result

            # 11. 验证验证码
            self._log("11. 验证验证码...")
            if not self._validate_verification_code(code):
                result.error_message = "验证验证码失败"
                return result

            # 12. 根据 OTP 响应决定下一步
            if self._otp_page_type == "about_you" and not self._is_existing_account:
                # 正常注册流程: about_you → create_account
                self._log("12. 创建用户账户...")
                if not self._create_user_account():
                    result.error_message = "创建用户账户失败"
                    return result
            elif self._is_existing_account:
                self._log("12. [已注册账号] 跳过创建用户账户")
            else:
                self._log(f"12. OTP page_type={self._otp_page_type}，尝试创建账户...")
                if not self._create_user_account():
                    result.error_message = "创建用户账户失败"
                    return result

            # 13. 跟随 callback URL 到 chatgpt.com 获取 session
            callback_url = self._create_account_continue_url
            has_chatgpt_callback = bool(callback_url and "code=" in str(callback_url))
            session_token = None
            account_cookie = ""
            if not has_chatgpt_callback and self._requires_create_account_callback():
                result.error_message = "create_account 未返回有效的 callback URL"
                return result
            if has_chatgpt_callback:
                self._log("13. 跟随 callback URL 到 chatgpt.com...")
                cb_resp = self.session.get(callback_url, timeout=20)
                self._log(f"callback 状态: {cb_resp.status_code}")

                # 提取 session cookie
                session_token = self.session.cookies.get("__Secure-next-auth.session-token")
                account_cookie = self.session.cookies.get("_account", "")
                if session_token:
                    self._log(f"获取到 session-token: {session_token[:30]}...")
                if account_cookie:
                    self._log(f"获取到 _account: {account_cookie}")
            else:
                self._log("13. [已注册账号] 无 create_account callback，直接进入 Codex OAuth")

            # 14. 从 chatgpt.com/api/auth/session 获取 access_token
            from .constants import CHATGPT_APP
            self._log("14. 获取 session 信息...")
            access_token = ""
            if self._uses_direct_openai_oauth or not has_chatgpt_callback:
                # The direct branch never depends on a chatgpt.com session:
                # the Codex PKCE flow below supplies the required tokens.
                self._log("跳过 chatgpt.com session 查询，继续获取 Codex token")
            else:
                session_resp = self.session.get(
                    f"{CHATGPT_APP}/api/auth/session",
                    headers={"accept": "application/json"},
                    timeout=15,
                )
                self._log(f"session API 状态: {session_resp.status_code}")
                try:
                    session_data = self._parse_json_response(session_resp, "NextAuth session")
                except RuntimeError as exc:
                    result.error_message = str(exc)
                    self._log(result.error_message, "error")
                    return result
                access_token = str(session_data.get("accessToken") or "")
                self._log(f"session keys: {list(session_data.keys())}")
                self._log(f"accessToken 长度: {len(access_token)}")

                if not access_token:
                    result.error_message = "chatgpt.com session 未返回 accessToken"
                    return result

                self._log("NextAuth session 获取成功")

            # 15. Codex CLI OTP 登录获取 refresh_token + id_token
            codex_token_info = None
            try:
                self._log("15. Codex CLI OTP 登录...")
                from .constants import (
                    CODEX_CLIENT_ID, CODEX_REDIRECT_URI, CODEX_SCOPE,
                    OPENAI_AUTH, SENTINEL_FRAME_URL,
                )
                import urllib.parse

                codex_oauth = generate_oauth_url(
                    redirect_uri=CODEX_REDIRECT_URI,
                    scope=CODEX_SCOPE,
                    client_id=CODEX_CLIENT_ID,
                )

                # 用全新且已验证的 session（Hydra 需要干净 session）。
                # HTTP 403 也必须切换指纹，不能带着空 state 继续提交邮箱。
                login_session, did2, codex_profile = self._start_codex_oauth_session(codex_oauth.auth_url)
                self._log(f"Codex login did: {did2[:20]}...")

                # 获取 sentinel（与 authorize/continue 复用同一登录会话）
                sen2 = None
                try:
                    profile_major = "".join(ch for ch in codex_profile if ch.isdigit()) or "136"
                    ua2 = (
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15"
                        if codex_profile.startswith("safari")
                        else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        f"(KHTML, like Gecko) Chrome/{profile_major}.0.0.0 Safari/537.36"
                    )
                    gen2 = _SentinelTokenGenerator(did2, ua2)
                    sp2 = gen2.generate_requirements_token()
                    sr2 = json.dumps({"p": sp2, "id": did2, "flow": "authorize_continue"}, separators=(",", ":"))
                    sr2_resp = login_session.post(
                        OPENAI_API_ENDPOINTS["sentinel"],
                        headers={"origin": "https://sentinel.openai.com", "referer": SENTINEL_FRAME_URL, "content-type": "text/plain;charset=UTF-8"},
                        data=sr2,
                    )
                    if sr2_resp.status_code == 200:
                        d2 = sr2_resp.json()
                        pm2 = d2.get("proofofwork") or {}
                        if pm2.get("required") and pm2.get("seed"):
                            sp2 = gen2.generate_token(str(pm2.get("seed") or ""), str(pm2.get("difficulty") or "0"))
                        tr2 = (d2.get("turnstile") or {}).get("dx", "")
                        tv2 = ""
                        if tr2:
                            try: tv2 = gen2.decrypt_turnstile(tr2, sp2)
                            except: pass
                        sen2 = SentinelPayload(p=sp2, t=tv2, c=str(d2.get("token") or ""), flow="authorize_continue")
                        self._log("Codex sentinel 获取成功")
                except Exception as e:
                    self._log(f"Codex sentinel 失败: {e}", "warning")

                # authorize/continue 提交邮箱（不带 screen_hint，让 codex_cli_simplified_flow 决定）
                signup_headers = {
                    "referer": f"{OPENAI_AUTH}/log-in",
                    "accept": "application/json",
                    "content-type": "application/json",
                }
                if sen2 and did2:
                    signup_headers["openai-sentinel-token"] = json.dumps({
                        "p": sen2.p, "t": sen2.t, "c": sen2.c,
                        "id": did2, "flow": sen2.flow,
                    }, separators=(",", ":"))

                signup_body = json.dumps({"username": {"value": self.email, "kind": "email"}, "screen_hint": "signup"})
                signup_resp = login_session.post(
                    OPENAI_API_ENDPOINTS["signup"], headers=signup_headers, data=signup_body
                )
                self._log(f"Codex authorize/continue: {signup_resp.status_code}")
                if signup_resp.status_code != 200:
                    raise RuntimeError(f"authorize/continue 失败: {signup_resp.text[:200]}")

                page_type = signup_resp.json().get("page", {}).get("type", "")
                self._log(f"Codex page_type: {page_type}")

                # 已有账号可能直接要求密码。URL-only 邮箱没有已知密码，
                # 交给浏览器点击一次性验证码入口完成 OAuth。
                if page_type == "login_password":
                    self._log("Codex 遇到密码验证，切换浏览器一次性验证码登录...")
                    codex_token_info = self._complete_codex_login_password_in_browser()
                    if not codex_token_info:
                        raise RuntimeError(self._last_codex_error or "浏览器一次性验证码 OAuth 未完成")

                # 如果返回 email_otp_send 或 email_otp_verification，走 OTP 流程
                elif page_type in ("email_otp_send", "email_otp_verification"):
                    # 发送 OTP
                    if page_type == "email_otp_send":
                        login_session.get(OPENAI_API_ENDPOINTS["send_otp"], headers={
                            "referer": f"{OPENAI_AUTH}/email-verification",
                        }, timeout=15)
                        self._log("Codex OTP 已发送")

                    # 等待 OTP
                    self._otp_sent_at = time.time()
                    code = self._get_verification_code()
                    if not code:
                        raise RuntimeError("Codex OTP 获取失败")
                    self._log(f"Codex OTP: {code}")

                    # 验证 OTP
                    otp_resp = login_session.post(
                        OPENAI_API_ENDPOINTS["validate_otp"],
                        headers={
                            "referer": f"{OPENAI_AUTH}/email-verification",
                            "accept": "application/json",
                            "content-type": "application/json",
                        },
                        data=json.dumps({"code": code}),
                    )
                    self._log(f"Codex OTP validate: {otp_resp.status_code}")
                    if otp_resp.status_code != 200:
                        raise RuntimeError(f"Codex OTP 验证失败: {otp_resp.text[:200]}")

                    otp_data = otp_resp.json()
                    otp_page = otp_data.get("page", {}).get("type", "")
                    self._log(f"Codex OTP -> page_type={otp_page}")

                    codex_callback = None
                    callback_oauth = codex_oauth
                    if otp_page == "add_phone":
                        self._log("Codex CLI 仍需 add_phone，开始短信验证...")
                        codex_callback, callback_oauth = self._complete_codex_add_phone_with_retry(
                            login_session,
                            codex_oauth,
                            did2,
                        )
                        if self._codex_direct_token_info:
                            codex_token_info = self._codex_direct_token_info
                        elif not codex_callback:
                            raise RuntimeError(self._last_codex_error or "add_phone required")
                    elif otp_page == "login_password":
                        self._log("Codex OTP 后仍需密码验证，切换浏览器一次性验证码登录...")
                        codex_token_info = self._complete_codex_login_password_in_browser()
                        if not codex_token_info:
                            raise RuntimeError(self._last_codex_error or "浏览器一次性验证码 OAuth 未完成")
                    else:
                        # OTP 后可能进入 consent/workspace。优先续接当前会话，
                        # 不能重新启动一个新的登录 state。
                        self._log(f"Codex OTP 后续接 OAuth: page_type={otp_page or '-'}")
                        codex_callback = self._try_codex_callback_with_session(
                            login_session,
                            codex_oauth,
                        )

                    if codex_callback:
                        self._log("Codex CLI callback 获取成功")
                        token_json = submit_callback_url(
                            callback_url=codex_callback,
                            expected_state=callback_oauth.state,
                            code_verifier=callback_oauth.code_verifier,
                            redirect_uri=CODEX_REDIRECT_URI,
                            client_id=CODEX_CLIENT_ID,
                            proxy_url=self.proxy_url,
                        )
                        codex_token_info = json.loads(token_json)
                        self._log(f"Codex token 成功: keys={list(codex_token_info.keys())}")
                    elif not codex_token_info:
                        self._log("Codex callback 未获取，当前会话未完成 consent/workspace", "warning")
                else:
                    self._log(f"Codex 非 OTP 流程 ({page_type})，跳过", "warning")
            except Exception as e:
                self._log(f"Codex CLI 登录失败: {e}", "warning")

            # 提取账户信息：必须使用 Codex CLI token，且必须带 refresh_token(rt)。
            if codex_token_info and codex_token_info.get("access_token"):
                self._log("使用 Codex CLI token（完整 refresh_token + id_token）")
                result.account_id = codex_token_info.get("account_id", "") or account_cookie or ""
                result.access_token = codex_token_info.get("access_token", "")
                result.refresh_token = codex_token_info.get("refresh_token", "") or codex_token_info.get("rt", "")
                result.id_token = codex_token_info.get("id_token", "")
            else:
                result.error_message = "未获取到 Codex CLI token/refresh_token(rt)，不计入成功"
                self._log(result.error_message, "error")
                return result

            if not result.refresh_token:
                result.error_message = "Codex CLI token 缺少 refresh_token(rt)，不计入成功"
                self._log(result.error_message, "error")
                return result

            result.password = self.password or ""
            result.source = "login" if self._is_existing_account else "register"

            if session_token:
                self.session_token = session_token
                result.session_token = session_token
                self._log(f"获取到 Session Token")

            # 17. 完成
            self._log("=" * 60)
            if self._is_existing_account:
                self._log("登录成功! (已注册账号)")
            else:
                self._log("注册成功!")
            self._log(f"邮箱: {result.email}")
            self._log(f"Account ID: {result.account_id}")
            self._log(f"Workspace ID: {result.workspace_id}")
            self._log("=" * 60)

            result.success = True
            result.metadata = {
                "email_service": self.email_service.service_type.value,
                "proxy_used": self.proxy_url,
                "registered_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "is_existing_account": self._is_existing_account,
            }

            return result

        except Exception as e:
            self._log(f"注册过程中发生未预期错误: {e}", "error")
            result.error_message = str(e)
            return result

    def save_to_database(self, result: RegistrationResult) -> bool:
        """
        保存注册结果到数据库

        Args:
            result: 注册结果

        Returns:
            是否保存成功
        """
        if not result.success:
            return False

        return True  # 由 account_manager 统一处理存库
