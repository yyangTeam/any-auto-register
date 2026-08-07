"""ChatGPT 协议邮箱注册 worker。"""
from __future__ import annotations

from typing import Callable

from platforms.chatgpt.register import RegistrationEngine


class _MailboxEmailService:
    def __init__(self, *, mailbox, mailbox_account, provider: str, before_ids: set | None = None):
        self.service_type = type("ST", (), {"value": provider})()
        self._mailbox = mailbox
        self._mailbox_account = mailbox_account
        self._before_ids = set(before_ids or [])
        self._acct = None

    def create_email(self, config=None):
        self._acct = self._mailbox_account
        return {
            "email": self._mailbox_account.email,
            "service_id": getattr(self._mailbox_account, "account_id", ""),
            "token": getattr(self._mailbox_account, "account_id", ""),
        }

    def get_verification_code(self, email=None, email_id=None, timeout=120, pattern=None, otp_sent_at=None):
        acct = self._acct or self._mailbox_account
        try:
            code = self._mailbox.wait_for_code(
                acct,
                keyword="",
                timeout=timeout,
                code_pattern=pattern,
                before_ids=self._before_ids,
                otp_sent_at=otp_sent_at,
            )
        except TypeError:
            code = self._mailbox.wait_for_code(
                acct,
                keyword="",
                timeout=timeout,
                code_pattern=pattern,
                before_ids=self._before_ids,
            )
        try:
            self._before_ids = self._mailbox.get_current_ids(acct)
        except Exception:
            pass
        return code

    def update_status(self, success, error=None):
        return None

    @property
    def status(self):
        return None


class ChatGPTProtocolMailboxWorker:
    def __init__(
        self,
        *,
        mailbox,
        mailbox_account,
        provider: str,
        proxy_url: str | None = None,
        log_fn: Callable[[str], None] = print,
        before_ids: set | None = None,
        phone_callback: Callable[[], str] | None = None,
        phone_cleanup: Callable[[], None] | None = None,
    ):
        if not mailbox or not mailbox_account:
            raise ValueError("ChatGPT 注册流程依赖 mailbox provider，当前未获取到邮箱账号")
        email_service = _MailboxEmailService(
            mailbox=mailbox,
            mailbox_account=mailbox_account,
            provider=provider,
            before_ids=before_ids,
        )
        self.phone_cleanup = phone_cleanup
        self.engine = RegistrationEngine(
            email_service=email_service,
            proxy_url=proxy_url,
            callback_logger=log_fn,
            phone_callback=phone_callback,
        )

    def _mailbox_credentials(self) -> dict:
        extra = dict(getattr(self.engine.email_service._mailbox_account, "extra", {}) or {})
        provider_account = dict(extra.get("provider_account") or {})
        return dict(provider_account.get("credentials") or {})

    @staticmethod
    def _uses_existing_account_login(credentials: dict) -> bool:
        password = str(credentials.get("password") or "").strip()
        totp_secret = str(credentials.get("totp_secret") or "").strip()
        totp_url = str(credentials.get("totp_url") or "").strip()
        login_mode = str(credentials.get("login_mode") or "").strip()
        inbox_url = str(credentials.get("icloud_api_url") or "").strip()
        return bool(
            login_mode == "email_otp_only"
            or (inbox_url and not password)
            or (password and (totp_secret or totp_url))
            or (password and login_mode == "password_or_email_otp")
        )

    def run(self, *, email: str, password: str):
        self.engine.email = email
        credentials = self._mailbox_credentials()
        credential_password = str(credentials.get("password") or "")
        credential_totp_secret = str(credentials.get("totp_secret") or "")
        credential_totp_url = str(credentials.get("totp_url") or "")
        self.engine.password = credential_password or password
        self.engine.totp_secret = credential_totp_secret
        self.engine.totp_url = credential_totp_url

        # 收码 URL、密码/MFA 和密码+收码 URL 都从第一步进入 Codex OAuth。
        # Codex 对真新邮箱会返回 create_account_password，仍可在同一流程注册；
        # 已注册邮箱则只完成 Codex 自己的一次邮箱验证。
        success = False
        try:
            if self._uses_existing_account_login(credentials):
                result = self.engine.login_existing_via_codex_auth(
                    email=email,
                    password=credential_password or "",
                    totp_secret=credential_totp_secret,
                    totp_url=credential_totp_url,
                )
            else:
                result = self.engine.run()

            if not result or not result.success:
                raise RuntimeError(result.error_message if result else "注册失败")
            success = True
            return result
        finally:
            if not success:
                try:
                    release = getattr(self.engine.email_service._mailbox, "release_email", None)
                    if callable(release):
                        try:
                            released = release(
                                self.engine.email_service._mailbox_account,
                                cooldown=False,
                            )
                        except TypeError:
                            released = release(self.engine.email_service._mailbox_account)
                        if released:
                            self.engine._log(f"失败任务已释放邮箱占用，可立即重试: {self.engine.email_service._mailbox_account.email}")
                except Exception as exc:
                    try:
                        self.engine._log(f"释放邮箱占用失败: {exc}")
                    except Exception:
                        pass
            if callable(self.phone_cleanup):
                self.phone_cleanup()
