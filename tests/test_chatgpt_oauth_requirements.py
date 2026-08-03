from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from core.base_platform import RegisterConfig
from core.totp import fetch_totp_code, generate_totp
from platforms.chatgpt import browser_register as browser_register_module
from platforms.chatgpt.protocol_mailbox import ChatGPTProtocolMailboxWorker
from platforms.chatgpt.plugin import (
    ChatGPTPlatform,
    _assert_complete_oauth_callback,
    _generate_chatgpt_registration_password,
)
from platforms.chatgpt.register import RegistrationEngine, SignupFormResult


def test_nextauth_non_json_response_has_bounded_diagnostics():
    response = SimpleNamespace(
        status_code=403,
        url="https://chatgpt.com/api/auth/csrf",
        text="<html>" + ("x" * 500) + "</html>",
        headers={"content-type": "text/html", "location": ""},
        json=lambda: (_ for _ in ()).throw(ValueError("Expecting value")),
    )

    with pytest.raises(RuntimeError, match=r"NextAuth CSRF 返回非 JSON: status=403 content_type=text/html") as exc_info:
        RegistrationEngine._parse_json_response(response, "NextAuth CSRF")

    assert len(str(exc_info.value)) < 350


def test_invalid_state_signup_retries_with_fresh_oauth_session(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine.proxy_url = "http://127.0.0.1:18080"
    engine.session = object()
    engine.oauth_start = object()
    engine._uses_direct_openai_oauth = True
    engine._is_existing_account = True
    engine._log = lambda message, level="info": None
    fresh_client = SimpleNamespace(session=object())
    monkeypatch.setattr("platforms.chatgpt.register.OpenAIHTTPClient", lambda proxy_url=None: fresh_client)

    calls = []
    engine._init_session = lambda: calls.append("session") or True
    engine._start_oauth = lambda: calls.append("oauth") or True
    engine._get_device_id = lambda: calls.append("did") or "new-device"
    sentinel = SimpleNamespace(p="p", c="c", flow="authorize_continue", t="")
    engine._check_sentinel = lambda did: calls.append(("sentinel", did)) or sentinel
    engine._submit_signup_form = lambda did, sen: calls.append(("submit", did, sen)) or SignupFormResult(success=True)

    result = engine._retry_signup_with_fresh_session()

    assert result.success is True
    assert calls == ["session", "oauth", "did", ("sentinel", "new-device"), ("submit", "new-device", sentinel)]
    assert engine._uses_direct_openai_oauth is False
    assert engine._is_existing_account is False


def test_invalid_state_signup_detection_is_specific():
    assert RegistrationEngine._is_invalid_state_signup(
        SignupFormResult(success=False, error_message='HTTP 409: {"code":"invalid_state"}')
    )
    assert not RegistrationEngine._is_invalid_state_signup(
        SignupFormResult(success=False, error_message="HTTP 409: account_deactivated")
    )


def test_nextauth_edge_challenge_falls_back_to_direct_openai_oauth(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine._uses_direct_openai_oauth = False
    logs = []
    engine._log = lambda message, level="info": logs.append((level, message))
    oauth_start = SimpleNamespace(auth_url="https://auth.openai.com/api/accounts/authorize?state=test")
    monkeypatch.setattr("platforms.chatgpt.register.generate_oauth_url", lambda: oauth_start)

    class Cookies:
        def __init__(self):
            self.values = {}

        def get(self, key, default=""):
            return self.values.get(key, default)

    class Response:
        def __init__(self, status_code, *, text="", headers=None, url=""):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}
            self.url = url

    class Session:
        def __init__(self):
            self.cookies = Cookies()
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append(url)
            if url.endswith("/api/auth/csrf"):
                return Response(403, text="<html>challenge</html>", headers={"content-type": "text/html"}, url=url)
            if url == oauth_start.auth_url:
                self.cookies.values["oai-did"] = "did_123"
                return Response(200, headers={"content-type": "text/html"}, url="https://auth.openai.com/log-in-or-create-account")
            return Response(403, text="<html>challenge</html>", headers={"content-type": "text/html"}, url=url)

    engine.session = Session()

    assert engine._start_oauth() is True
    assert engine.oauth_start is oauth_start
    assert engine._uses_direct_openai_oauth is True
    assert oauth_start.auth_url in engine.session.calls
    assert any("直连授权" in message for _, message in logs)


def test_create_account_callback_is_only_required_for_new_accounts():
    engine = object.__new__(RegistrationEngine)

    engine._is_existing_account = False
    assert engine._requires_create_account_callback() is True

    engine._is_existing_account = True
    assert engine._requires_create_account_callback() is False


def test_codex_oauth_bootstrap_retries_http_challenge_until_device_id(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine.proxy_url = None
    engine._log = lambda message, level="info": None
    engine._debug_log = lambda message, level="info": None
    attempted_profiles = []

    class Cookies:
        def __init__(self, did=""):
            self.did = did

        def get(self, name, default=""):
            return self.did if name == "oai-did" else default

    class Session:
        def __init__(self, profile):
            attempted_profiles.append(profile)
            self.profile = profile
            self.cookies = Cookies("did_123" if profile == "chrome110" else "")

        def get(self, url, **kwargs):
            return SimpleNamespace(status_code=200 if self.profile == "chrome110" else 403)

    monkeypatch.setattr(
        "platforms.chatgpt.register.cffi_requests.Session",
        lambda impersonate: Session(impersonate),
    )

    session, did, profile = engine._start_codex_oauth_session("https://auth.openai.com/oauth/authorize")

    assert attempted_profiles == ["chrome136", "chrome110"]
    assert did == "did_123"
    assert profile == "chrome110"
    assert session.cookies.get("oai-did") == "did_123"


def test_assert_complete_oauth_callback_accepts_complete_payload():
    _assert_complete_oauth_callback({
        "account_id": "acct_123",
        "access_token": "at_123",
        "refresh_token": "rt_123",
        "id_token": "id_123",
    })


def test_assert_complete_oauth_callback_rejects_partial_payload():
    with pytest.raises(RuntimeError, match=r"OAuth .*refresh_token"):
        _assert_complete_oauth_callback({
            "account_id": "acct_123",
            "access_token": "at_123",
            "refresh_token": "",
            "id_token": "",
        })


def test_generate_chatgpt_registration_password_meets_openai_strength_requirements():
    for _ in range(8):
        password = _generate_chatgpt_registration_password()
        assert len(password) >= 12
        assert any(ch.islower() for ch in password)
        assert any(ch.isupper() for ch in password)
        assert any(ch.isdigit() for ch in password)
        assert any(ch in ",._!@#" for ch in password)


def test_chatgpt_platform_preserves_user_supplied_password():
    platform = object.__new__(ChatGPTPlatform)
    assert platform._prepare_registration_password("Secret123!") == "Secret123!"


def test_codex_oauth_login_password_uses_password_then_email_otp(monkeypatch):
    oauth_start = SimpleNamespace(
        auth_url="https://auth.openai.com/log-in/password",
        state="state_123",
        code_verifier="verifier_123",
        redirect_uri="http://localhost:1455/auth/callback",
        client_id="client_123",
    )

    class FakePage:
        url = "about:blank"

        def goto(self, url, **kwargs):
            self.url = url

        def evaluate(self, script):
            return "Test User Agent"

    page = FakePage()
    events = []

    monkeypatch.setattr("platforms.chatgpt.oauth.generate_oauth_url", lambda **kwargs: oauth_start)
    monkeypatch.setattr(browser_register_module, "_get_page_oauth_url", lambda page: "")

    def submit_password(page, password, log):
        events.append(("password", password))
        page.url = "https://auth.openai.com/email-verification"
        return {"ok": True, "status": 200, "text": ""}

    def submit_otp(page, code, log):
        events.append(("submit_otp", code))
        page.url = "http://localhost:1455/auth/callback?code=code_123&state=state_123"
        return {"ok": True, "status": 200, "text": ""}

    monkeypatch.setattr(browser_register_module, "_submit_oauth_password_direct", submit_password)
    monkeypatch.setattr(browser_register_module, "_submit_otp_via_page", submit_otp)
    monkeypatch.setattr(
        browser_register_module,
        "_switch_login_password_to_otp",
        lambda *args, **kwargs: pytest.fail("passwordless login must not be selected"),
    )
    monkeypatch.setattr(
        browser_register_module,
        "_submit_callback_result",
        lambda callback_url, oauth_start, proxy: {"callback_url": callback_url},
    )

    result = browser_register_module._do_codex_oauth(
        page,
        {},
        "user@example.com",
        "Secret123!",
        lambda: "123456",
        None,
        None,
        lambda message: None,
    )

    assert events == [("password", "Secret123!"), ("submit_otp", "123456")]
    assert result["callback_url"].startswith("http://localhost:1455/auth/callback?")


def test_generate_totp_matches_rfc_6238_sha1_vector():
    assert generate_totp(
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        timestamp=59,
        digits=8,
    ) == "94287082"


def test_fetch_totp_code_uses_viewer_api_and_preserves_query(monkeypatch):
    captured = {}

    class Response:
        status_code = 200
        text = '{"ok":true,"code":"123456","period":30,"remaining":20}'

        def json(self):
            return json.loads(self.text)

    def fake_get(url, **kwargs):
        captured.update(url=url, kwargs=kwargs)
        return Response()

    monkeypatch.setattr("core.totp.requests.get", fake_get)

    code = fetch_totp_code(
        "https://2fa.example/view?token=redacted&email=user%40example.com",
        proxy_url="http://127.0.0.1:18080",
    )

    assert code == "123456"
    assert captured["url"] == (
        "https://2fa.example/api/v1/2fa?token=redacted&email=user%40example.com"
    )
    assert captured["kwargs"]["proxies"]["https"] == "http://127.0.0.1:18080"


def test_codex_oauth_login_password_uses_configured_mfa(monkeypatch):
    oauth_start = SimpleNamespace(
        auth_url="https://auth.openai.com/log-in/password",
        state="state_123",
        code_verifier="verifier_123",
        redirect_uri="http://localhost:1455/auth/callback",
        client_id="client_123",
    )

    class FakePage:
        url = "about:blank"

        def goto(self, url, **kwargs):
            self.url = url

        def evaluate(self, script):
            return "Test User Agent"

    page = FakePage()
    events = []

    monkeypatch.setattr("platforms.chatgpt.oauth.generate_oauth_url", lambda **kwargs: oauth_start)
    monkeypatch.setattr(browser_register_module, "_get_page_oauth_url", lambda page: "")
    monkeypatch.setattr(
        browser_register_module,
        "_derive_oauth_state_from_page",
        lambda page: {
            "page_type": "mfa_challenge" if "/mfa" in page.url else "login_password",
            "continue_url": "",
        },
    )

    def submit_password(page, password, log):
        events.append(("password", password))
        page.url = "https://auth.openai.com/mfa"
        return {"ok": True, "status": 200, "text": ""}

    def submit_mfa(page, code, log):
        events.append(("mfa", code))
        page.url = "http://localhost:1455/auth/callback?code=code_123&state=state_123"
        return {"ok": True, "status": 200, "text": ""}

    monkeypatch.setattr(browser_register_module, "_submit_oauth_password_direct", submit_password)
    monkeypatch.setattr(browser_register_module, "_submit_otp_via_page", submit_mfa)
    monkeypatch.setattr(
        browser_register_module,
        "_submit_callback_result",
        lambda callback_url, oauth_start, proxy: {"callback_url": callback_url},
    )

    result = browser_register_module._do_codex_oauth(
        page,
        {},
        "user@example.com",
        "Secret123!",
        lambda: "email-code-must-not-be-used",
        None,
        None,
        lambda message: None,
        mfa_callback=lambda: "123456",
    )

    assert events == [("password", "Secret123!"), ("mfa", "123456")]
    assert result["callback_url"].startswith("http://localhost:1455/auth/callback?")


def test_protocol_codex_password_challenge_sends_and_validates_email_otp():
    engine = object.__new__(RegistrationEngine)
    engine._otp_sent_at = None
    engine._debug_log = lambda message: None
    engine._log = lambda message, level="info": None
    engine._get_verification_code = lambda: "654321"

    class Response:
        def __init__(self, status_code, data=None, text=""):
            self.status_code = status_code
            self._data = data or {}
            self.text = text
            self.headers = {"content-type": "application/json"}

        def json(self):
            return self._data

    class Session:
        def __init__(self):
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append(("GET", url, kwargs))
            return Response(200)

        def post(self, url, **kwargs):
            self.calls.append(("POST", url, kwargs))
            return Response(200, {"page": {"type": "add_phone"}})

    session = Session()
    page_type = engine._complete_codex_email_otp(
        session,
        send_code=True,
        referer="https://auth.openai.com/log-in/password",
    )

    assert page_type == "add_phone"
    assert engine._otp_sent_at is not None
    assert [call[0] for call in session.calls] == ["GET", "POST"]
    assert session.calls[0][1].endswith("/api/accounts/email-otp/send")
    assert json.loads(session.calls[1][2]["data"]) == {"code": "654321"}


def test_protocol_otp_send_rejects_redirect_false_positive():
    engine = object.__new__(RegistrationEngine)
    engine._otp_sent_at = None
    engine._debug_log = lambda message: None
    logs = []
    engine._log = lambda message, level="info": logs.append((level, message))
    engine._get_verification_code = lambda: pytest.fail("must not wait after redirect")

    response = SimpleNamespace(
        status_code=302,
        text="",
        headers={"location": "/log-in/password", "content-type": "text/html"},
    )
    session = SimpleNamespace(get=lambda *args, **kwargs: response)

    assert engine._complete_codex_email_otp(
        session,
        send_code=True,
        referer="https://auth.openai.com/log-in/password",
    ) is None
    assert any("发送失败" in message for _, message in logs)


def test_protocol_password_challenge_uses_browser_passwordless_action(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine.email = "user@example.com"
    engine.password = "Secret123!"
    engine.proxy_url = "http://127.0.0.1:18080"
    engine.phone_callback = None
    engine._otp_sent_at = None
    engine._last_codex_error = ""
    engine._log = lambda message, level="info": None
    engine._get_verification_code = lambda: "654321"
    captured = {}

    def retry(self, email, password):
        captured.update(email=email, password=password, proxy=self.proxy)
        assert self.otp_callback() == "654321"
        return {"access_token": "at", "refresh_token": "rt"}

    monkeypatch.setattr(browser_register_module.ChatGPTBrowserRegister, "_retry_oauth_fresh_browser", retry)

    token_info = engine._complete_codex_login_password_in_browser()

    assert token_info == {"access_token": "at", "refresh_token": "rt"}
    assert captured == {
        "email": "user@example.com",
        "password": "Secret123!",
        "proxy": "http://127.0.0.1:18080",
    }


def test_url_only_existing_account_uses_browser_email_otp_not_generated_password(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine.email = "user@icloud.com"
    engine.password = "GeneratedRegistrationPassword123!"
    engine._is_existing_account = True
    engine._has_supplied_login_password = False
    engine.totp_secret = ""
    engine.proxy_url = None
    engine.phone_callback = None
    engine._last_codex_error = ""
    engine._log = lambda message, level="info": None
    engine._get_verification_code = lambda: "654321"
    captured = {}

    def retry(self, email, password):
        captured.update(email=email, password=password)
        assert self.otp_callback() == "654321"
        return {"access_token": "at", "refresh_token": "rt"}

    monkeypatch.setattr(browser_register_module.ChatGPTBrowserRegister, "_retry_oauth_fresh_browser", retry)

    assert engine._complete_codex_login_password_in_browser() == {"access_token": "at", "refresh_token": "rt"}
    assert captured == {"email": "user@icloud.com", "password": ""}
    assert engine._otp_sent_at is not None


def test_mfa_browser_login_disables_email_otp_callback(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine.email = "user@example.com"
    engine.password = "Secret123!"
    engine.totp_secret = "JBSWY3DPEHPK3PXP"
    engine.proxy_url = None
    engine.phone_callback = None
    engine._last_codex_error = ""
    engine._log = lambda message, level="info": None
    engine._get_verification_code = lambda: pytest.fail("MFA login must not read mailbox OTP")

    def retry(self, email, password):
        assert self.otp_callback is None
        assert callable(self.mfa_callback)
        assert self.mfa_callback().isdigit()
        return {"access_token": "at", "refresh_token": "rt"}

    monkeypatch.setattr(browser_register_module.ChatGPTBrowserRegister, "_retry_oauth_fresh_browser", retry)

    token_info = engine._complete_codex_login_password_in_browser()

    assert token_info == {"access_token": "at", "refresh_token": "rt"}


def test_mfa_url_browser_login_fetches_remote_code(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine.email = "user@example.com"
    engine.password = "Secret123!"
    engine.totp_secret = ""
    engine.totp_url = "https://2fa.example/view?token=redacted"
    engine.proxy_url = None
    engine.phone_callback = None
    engine._last_codex_error = ""
    engine._log = lambda message, level="info": None
    engine._get_verification_code = lambda: pytest.fail("MFA URL login must not read mailbox OTP")

    monkeypatch.setattr("core.totp.fetch_totp_code", lambda url, proxy_url=None: "654321")

    def retry(self, email, password):
        assert self.otp_callback is None
        assert self.mfa_callback() == "654321"
        return {"access_token": "at", "refresh_token": "rt"}

    monkeypatch.setattr(browser_register_module.ChatGPTBrowserRegister, "_retry_oauth_fresh_browser", retry)

    assert engine._complete_codex_login_password_in_browser() == {
        "access_token": "at",
        "refresh_token": "rt",
    }


def test_existing_mfa_login_bypasses_protocol_email_otp_detection(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine.logs = []
    engine.email = "user@example.com"
    engine.password = "Secret123!"
    engine.totp_secret = ""
    engine.email_info = {"email": "user@example.com"}
    engine.email_service = SimpleNamespace(service_type=SimpleNamespace(value="local_ms_pool"))
    engine.proxy_url = None
    engine._last_codex_error = ""
    engine._is_existing_account = False
    engine._codex_direct_token_info = None
    engine._log = lambda message, level="info": None
    engine._preflight_codex_auth_network = lambda: (True, "ok")
    engine._debug_log = lambda message, level="info": None
    engine._acquire_codex_callback = lambda: pytest.fail("MFA login must bypass protocol page detection")
    engine._complete_codex_login_password_in_browser = lambda: {
        "email": "user@example.com",
        "account_id": "acct",
        "access_token": "at",
        "refresh_token": "rt",
        "id_token": "id",
    }
    monkeypatch.setattr(
        "platforms.chatgpt.register.submit_callback_url",
        lambda **kwargs: pytest.fail("browser token must not be exchanged again"),
    )

    result = engine.login_existing_via_codex_auth(
        password="Secret123!",
        totp_secret="JBSWY3DPEHPK3PXP",
    )

    assert result.success is True
    assert result.access_token == "at"
    assert result.refresh_token == "rt"
    assert engine._has_supplied_login_password is True


def test_existing_login_accepts_browser_oauth_token_without_callback_exchange(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine.logs = []
    engine.email = "user@example.com"
    engine.password = "Secret123!"
    engine.email_info = {"email": "user@example.com"}
    engine.email_service = SimpleNamespace(service_type=SimpleNamespace(value="local_ms_pool"))
    engine.proxy_url = None
    engine._last_codex_error = ""
    engine._is_existing_account = False
    engine._codex_direct_token_info = {
        "email": "user@example.com",
        "account_id": "acct",
        "access_token": "at",
        "refresh_token": "rt",
        "id_token": "id",
    }
    engine._log = lambda message, level="info": None
    engine._preflight_codex_auth_network = lambda: (True, "ok")
    engine._debug_log = lambda message, level="info": None
    engine._acquire_codex_callback = lambda: "browser-token-ready"
    monkeypatch.setattr(
        "platforms.chatgpt.register.submit_callback_url",
        lambda **kwargs: pytest.fail("browser token must not be exchanged again"),
    )

    result = engine.login_existing_via_codex_auth()

    assert result.success is True
    assert result.access_token == "at"
    assert result.refresh_token == "rt"


def test_protocol_mailbox_mapper_rejects_partial_oauth_result():
    platform = object.__new__(ChatGPTPlatform)
    platform.mailbox = None
    platform.config = RegisterConfig()
    adapter = ChatGPTPlatform.build_protocol_mailbox_adapter(platform)
    ctx = SimpleNamespace(password="Secret123!", proxy=None, log=lambda message: None)
    result = SimpleNamespace(
        email="user@example.com",
        password="Secret123!",
        account_id="acct_123",
        access_token="at_123",
        refresh_token="",
        id_token="",
        session_token="sess_123",
        workspace_id="",
    )

    with pytest.raises(RuntimeError, match=r"OAuth .*refresh_token"):
        adapter.result_mapper(ctx, result)


def test_protocol_mailbox_worker_passes_password_and_mfa_credentials():
    account = SimpleNamespace(
        email="user@example.com",
        account_id="user@example.com",
        extra={
            "provider_account": {
                "provider_name": "local_mail_pool",
                "credentials": {
                    "password": "Secret123!",
                    "totp_secret": "JBSWY3DPEHPK3PXP",
                },
            },
            "provider_resource": {"provider_name": "local_mail_pool"},
        },
    )
    mailbox = SimpleNamespace(release_email=lambda *args, **kwargs: False)
    worker = ChatGPTProtocolMailboxWorker(
        mailbox=mailbox,
        mailbox_account=account,
        provider="local_mail_pool",
    )
    captured = {}

    def login_existing(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(success=True)

    worker.engine.login_existing_via_codex_auth = login_existing

    result = worker.run(email=account.email, password="generated-password")

    assert result.success is True
    assert captured == {
        "email": "user@example.com",
        "password": "Secret123!",
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "totp_url": "",
    }


def test_protocol_mailbox_worker_uses_password_and_inbox_url_login_branch():
    account = SimpleNamespace(
        email="user@icloud.com",
        account_id="user@icloud.com",
        extra={
            "provider_account": {
                "credentials": {
                    "password": "LoginPassword123!",
                    "login_mode": "password_or_email_otp",
                    "icloud_api_url": "https://mail.example.com/inbox/token",
                },
            },
        },
    )
    worker = ChatGPTProtocolMailboxWorker(
        mailbox=SimpleNamespace(release_email=lambda *args, **kwargs: False),
        mailbox_account=account,
        provider="local_mail_pool",
    )
    captured = {}
    worker.engine.login_existing_via_codex_auth = lambda **kwargs: captured.update(kwargs) or SimpleNamespace(success=True)
    worker.engine.run = lambda: pytest.fail("password + inbox URL must use the login branch")

    assert worker.run(email=account.email, password="generated-password").success is True
    assert captured == {
        "email": "user@icloud.com",
        "password": "LoginPassword123!",
        "totp_secret": "",
        "totp_url": "",
    }


def test_protocol_mailbox_worker_passes_password_inbox_and_mfa_url():
    account = SimpleNamespace(
        email="user@icloud.com",
        account_id="user@icloud.com",
        extra={
            "provider_account": {
                "credentials": {
                    "password": "LoginPassword123!",
                    "login_mode": "password_mfa_url",
                    "icloud_api_url": "https://mail.example.com/inbox/token",
                    "totp_url": "https://2fa.example/view?token=redacted",
                },
            },
        },
    )
    worker = ChatGPTProtocolMailboxWorker(
        mailbox=SimpleNamespace(release_email=lambda *args, **kwargs: False),
        mailbox_account=account,
        provider="local_mail_pool",
    )
    captured = {}
    worker.engine.login_existing_via_codex_auth = lambda **kwargs: captured.update(kwargs) or SimpleNamespace(success=True)
    worker.engine.run = lambda: pytest.fail("password + MFA URL must use the login branch")

    assert worker.run(email=account.email, password="generated-password").success is True
    assert captured == {
        "email": "user@icloud.com",
        "password": "LoginPassword123!",
        "totp_secret": "",
        "totp_url": "https://2fa.example/view?token=redacted",
    }


def test_protocol_mailbox_worker_uses_new_registration_for_url_only_mailbox():
    account = SimpleNamespace(
        email="user@icloud.com",
        account_id="user@icloud.com",
        extra={"provider_account": {"credentials": {"icloud_api_url": "https://mail.example.com/inbox/token"}}},
    )
    worker = ChatGPTProtocolMailboxWorker(
        mailbox=SimpleNamespace(release_email=lambda *args, **kwargs: False),
        mailbox_account=account,
        provider="local_mail_pool",
    )
    worker.engine.login_existing_via_codex_auth = lambda **kwargs: pytest.fail("URL-only mailbox must not use the login branch")
    worker.engine.run = lambda: SimpleNamespace(success=True)

    assert worker.run(email=account.email, password="generated-password").success is True


def test_browser_register_run_rejects_session_fallback(monkeypatch):
    class FakePage:
        def __init__(self):
            self.url = "about:blank"
            self.context = SimpleNamespace(cookies=lambda: [])

        def goto(self, url, **kwargs):
            self.url = url

    class FakeBrowser:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def new_page(self):
            return FakePage()

    monkeypatch.setattr(browser_register_module, "Camoufox", lambda **kwargs: FakeBrowser())
    monkeypatch.setattr(browser_register_module, "_browser_registration_flow", lambda *args, **kwargs: {"page_type": "chatgpt_home"})
    monkeypatch.setattr(browser_register_module, "_click_first", lambda page, selectors, timeout=3: setattr(page, "url", "https://auth.openai.com/log-in") or selectors[0])
    monkeypatch.setattr(browser_register_module, "_get_cookies", lambda page: {})
    monkeypatch.setattr(browser_register_module, "_do_codex_oauth", lambda *args, **kwargs: None)
    monkeypatch.setattr(browser_register_module.ChatGPTBrowserRegister, "_retry_oauth_fresh_browser", lambda self, email, password: None)
    monkeypatch.setattr(browser_register_module.time, "sleep", lambda seconds: None)

    worker = browser_register_module.ChatGPTBrowserRegister(
        headless=True,
        proxy=None,
        otp_callback=None,
        log_fn=lambda message: None,
    )

    with pytest.raises(RuntimeError, match="已拒绝回退"):
        worker.run(email="user@example.com", password="Secret123!")


def test_fresh_browser_oauth_preserves_underlying_error(monkeypatch):
    class FakeBrowser:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def new_page(self):
            return object()

    monkeypatch.setattr(browser_register_module, "Camoufox", lambda **kwargs: FakeBrowser())
    monkeypatch.setattr(
        browser_register_module,
        "_do_codex_oauth",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("OAuth 登录密码提交失败: error_code: account_deactivated")
        ),
    )
    worker = browser_register_module.ChatGPTBrowserRegister(
        headless=True,
        log_fn=lambda message: None,
    )

    assert worker._retry_oauth_fresh_browser("user@example.com", "Secret123!") is None
    assert "account_deactivated" in worker.last_oauth_error


def test_password_login_reports_specific_browser_oauth_error(monkeypatch):
    class FakeBrowserRegister:
        last_oauth_error = "OAuth 登录密码提交失败: error_code: account_deactivated"

        def __init__(self, **kwargs):
            pass

        def _retry_oauth_fresh_browser(self, email, password):
            return None

    monkeypatch.setattr(browser_register_module, "ChatGPTBrowserRegister", FakeBrowserRegister)
    engine = object.__new__(RegistrationEngine)
    engine.email = "user@example.com"
    engine.password = "Secret123!"
    engine.totp_secret = "JBSWY3DPEHPK3PXP"
    engine.proxy_url = None
    engine.phone_callback = None
    engine._is_existing_account = True
    engine._has_supplied_login_password = True
    engine._log = lambda message, level="info": None

    assert engine._complete_codex_login_password_in_browser() is None
    assert "account_deactivated" in engine._last_codex_error


def test_add_phone_restarts_only_codex_oauth_after_sms_completion(monkeypatch):
    original_oauth = SimpleNamespace(state="old-state", code_verifier="old-verifier")
    refreshed_oauth = SimpleNamespace(state="new-state", code_verifier="new-verifier")
    engine = object.__new__(RegistrationEngine)
    engine.phone_callback = SimpleNamespace(completed=True)
    engine._codex_retry_after_phone = False
    engine._codex_direct_token_info = None
    engine._codex_oauth = refreshed_oauth
    engine._log = lambda message, level="info": None
    engine._complete_add_phone_in_browser = lambda *args, **kwargs: None
    engine._acquire_codex_callback = lambda: "http://localhost:1455/auth/callback?code=new&state=new-state"

    callback, oauth = engine._complete_codex_add_phone_with_retry(
        object(),
        original_oauth,
        "device-id",
    )

    assert callback.endswith("state=new-state")
    assert oauth is refreshed_oauth
    assert engine._codex_retry_after_phone is True
