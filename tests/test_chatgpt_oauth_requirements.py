from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from core.base_platform import RegisterConfig
from core.registration.helpers import build_otp_callback
from core.totp import fetch_totp_code, generate_totp
from platforms.chatgpt import browser_register as browser_register_module
from platforms.chatgpt.protocol_mailbox import ChatGPTProtocolMailboxWorker
from platforms.chatgpt.plugin import (
    ChatGPTPlatform,
    _assert_complete_oauth_callback,
    _generate_chatgpt_registration_password,
    _known_chatgpt_login_password,
)
from platforms.chatgpt.register import RegistrationEngine, SignupFormResult, _session_cookie_value


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


def test_existing_account_skips_web_otp_and_enters_codex_auth_once():
    engine = object.__new__(RegistrationEngine)
    engine.logs = []
    engine.email = "existing@icloud.com"
    engine.email_info = {"email": engine.email, "service_id": "mailbox-1"}
    engine._is_existing_account = False
    engine._otp_sent_at = 123.0
    engine._last_oauth_error = ""
    engine._log = lambda message, level="info": engine.logs.append(message)
    engine._debug_log = lambda message, level="info": None
    engine._check_ip_location = lambda: (True, "US")
    engine._preflight_codex_auth_network = lambda: (True, "ok")
    engine._create_email = lambda: True
    engine._init_session = lambda: True
    engine._start_oauth = lambda: True
    engine._get_device_id = lambda: "device-id"
    engine._check_sentinel = lambda did: None

    def submit_signup(did, sentinel):
        engine._is_existing_account = True
        return SignupFormResult(
            success=True,
            page_type="email_otp_verification",
            is_existing_account=True,
        )

    engine._submit_signup_form = submit_signup
    engine._register_password = lambda: pytest.fail("existing account must not register a password")
    engine._send_verification_code = lambda: pytest.fail("existing account must not send Web OTP")
    engine._get_verification_code = lambda: pytest.fail("existing account must not read Web OTP")
    engine._validate_verification_code = lambda code: pytest.fail("existing account must not validate Web OTP")
    codex_calls = []

    def login_existing(**kwargs):
        codex_calls.append(kwargs)
        assert engine._otp_sent_at is None
        return SimpleNamespace(success=True, email=engine.email, source="login")

    engine.login_existing_via_codex_auth = login_existing

    result = engine.run()

    assert result.success is True
    assert codex_calls == [{"email": "existing@icloud.com"}]
    assert any("直接进入 Codex OAuth" in message for message in engine.logs)


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


def test_codex_oauth_bootstrap_reuses_verified_session_cookies(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine.proxy_url = None
    engine._log = lambda message, level="info": None
    engine._debug_log = lambda message, level="info": None
    calls = []

    class Session:
        def __init__(self, impersonate=None):
            self.cookies = {}

        def get(self, url, **kwargs):
            calls.append((url, kwargs, dict(self.cookies)))
            return SimpleNamespace(status_code=302)

    monkeypatch.setattr("platforms.chatgpt.register.cffi_requests.Session", Session)
    verified_session = SimpleNamespace(cookies={
        "oai-did": "verified-device",
        "login_session": "verified-login",
    })

    session, did, profile = engine._start_codex_oauth_session(
        "https://auth.openai.com/oauth/authorize",
        seed_session=verified_session,
    )

    assert did == "verified-device"
    assert profile == "chrome136"
    assert session.cookies["login_session"] == "verified-login"
    assert calls[0][1]["allow_redirects"] is False
    assert calls[0][2]["login_session"] == "verified-login"


def test_cookie_lookup_prefers_auth_domain_when_names_are_duplicated():
    cookies = SimpleNamespace(jar=[
        SimpleNamespace(name="oai-did", value="chatgpt-device", domain=".chatgpt.com"),
        SimpleNamespace(name="oai-did", value="auth-device", domain="auth.openai.com"),
    ])
    session = SimpleNamespace(cookies=cookies)

    assert _session_cookie_value(session, "oai-did") == "auth-device"


def test_verified_codex_session_checks_callback_before_consent(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine._debug_log = lambda message, level="info": None
    engine._log = lambda message, level="info": None
    engine._codex_api_auth_url = lambda oauth: "https://auth.openai.com/api/oauth/oauth2/auth?state=test"
    engine._complete_codex_consent_with_session = lambda *args, **kwargs: pytest.fail(
        "consent should not run after the verified session returns a callback"
    )
    calls = []

    def follow(_session, url, _log, *, max_redirects):
        calls.append((url, max_redirects))
        return "http://localhost:1455/auth/callback?code=code_123&state=state_123"

    monkeypatch.setattr(browser_register_module, "_follow_redirects_for_code", follow)
    oauth = SimpleNamespace(auth_url="https://auth.openai.com/oauth/authorize?state=test")

    callback = engine._try_codex_callback_with_session(object(), oauth, quiet=True)

    assert callback.endswith("code=code_123&state=state_123")
    assert calls == [("https://auth.openai.com/api/oauth/oauth2/auth?state=test", 12)]


def test_codex_otp_continue_url_is_followed_before_starting_oauth_again(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine._codex_otp_continue_url = "/continue-after-otp"
    engine._debug_log = lambda message, level="info": None
    engine._log = lambda message, level="info": None
    engine._codex_api_auth_url = lambda oauth: "https://auth.openai.com/api/oauth/oauth2/auth?state=test"
    engine._complete_codex_consent_with_session = lambda *args, **kwargs: pytest.fail(
        "consent should not run after the OTP continue URL returns a callback"
    )
    calls = []

    def follow(_session, url, _log, *, max_redirects):
        calls.append(url)
        if url.endswith("/continue-after-otp"):
            return "http://localhost:1455/auth/callback?code=code_123&state=state_123"
        return ""

    monkeypatch.setattr(browser_register_module, "_follow_redirects_for_code", follow)
    oauth = SimpleNamespace(auth_url="https://auth.openai.com/oauth/authorize?state=test")

    callback = engine._try_codex_callback_with_session(object(), oauth)

    assert callback.endswith("code=code_123&state=state_123")
    assert calls == ["https://auth.openai.com/continue-after-otp"]


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


def test_otp_callback_does_not_reuse_message_consumed_by_previous_call():
    class FakeMailbox:
        def __init__(self):
            self.wait_before_ids = []
            self.current_ids = iter([
                {"existing", "first-otp"},
                {"existing", "first-otp", "second-otp"},
            ])

        def wait_for_code(self, account, **kwargs):
            self.wait_before_ids.append(set(kwargs["before_ids"]))
            return "111111" if len(self.wait_before_ids) == 1 else "222222"

        def get_current_ids(self, account):
            return next(self.current_ids)

    mailbox = FakeMailbox()
    ctx = SimpleNamespace(
        platform=SimpleNamespace(mailbox=mailbox),
        identity=SimpleNamespace(mailbox_account=object(), before_ids={"existing"}),
        log=lambda message: None,
    )
    otp_callback = build_otp_callback(ctx)

    assert otp_callback() == "111111"
    assert otp_callback() == "222222"
    assert mailbox.wait_before_ids == [
        {"existing"},
        {"existing", "first-otp"},
    ]


def test_browser_registration_existing_url_only_mailbox_switches_password_page_to_otp(monkeypatch):
    class FakePage:
        url = "https://auth.openai.com/log-in/password"

        def evaluate(self, script):
            return "Test User Agent"

    page = FakePage()
    events = []
    states = iter([
        {"page_type": "login_password", "current_url": page.url},
        {"page_type": "oauth_callback", "current_url": "http://localhost/callback"},
    ])

    monkeypatch.setattr(browser_register_module, "_seed_browser_device_id", lambda *args: None)
    monkeypatch.setattr(browser_register_module, "_start_browser_signup_via_page", lambda *args: next(states))
    monkeypatch.setattr(browser_register_module, "_get_cookies", lambda page: {})
    monkeypatch.setattr(browser_register_module, "_recover_signup_password_page", lambda *args: False)
    monkeypatch.setattr(
        browser_register_module,
        "_submit_oauth_password_direct",
        lambda *args: pytest.fail("generated registration password must not be submitted for an existing account"),
    )

    def switch_to_otp(page, log):
        events.append("switch_otp")
        page.url = "https://auth.openai.com/email-verification"
        return True

    monkeypatch.setattr(browser_register_module, "_switch_login_password_to_otp", switch_to_otp)
    monkeypatch.setattr(browser_register_module, "_derive_registration_state_from_page", lambda page: next(states))
    monkeypatch.setattr(browser_register_module, "_handle_post_signup_onboarding", lambda *args: None)
    monkeypatch.setattr(
        browser_register_module,
        "_extract_flow_state",
        lambda data, url: {"page_type": "oauth_callback", "current_url": url},
    )

    result = browser_register_module._browser_registration_flow(
        page,
        "user@icloud.com",
        "GeneratedRegistrationPassword123!",
        lambda: "654321",
        None,
        lambda message: None,
    )

    assert events == ["switch_otp"]
    assert result["account_password"] == ""


def test_switch_login_password_to_otp_uses_direct_send_when_control_is_hidden(monkeypatch):
    class FakePage:
        url = "https://auth.openai.com/log-in/password"

        def goto(self, url, **kwargs):
            self.url = url

    page = FakePage()
    captured = {}
    logs = []
    monkeypatch.setattr(browser_register_module, "_click_passwordless_login_if_available", lambda *args, **kwargs: False)

    def send_otp(page, *, referer=""):
        captured["referer"] = referer
        return {
            "ok": True,
            "status": 200,
            "headers": {"content-type": "application/json"},
            "data": {"page": {"type": "email_otp_verification"}},
        }

    monkeypatch.setattr(browser_register_module, "_send_browser_email_otp", send_otp)
    monkeypatch.setattr(
        browser_register_module,
        "_derive_registration_state_from_page",
        lambda page: {"page_type": "email_otp_verification", "current_url": page.url},
    )

    assert browser_register_module._switch_login_password_to_otp(
        page,
        logs.append,
        timeout=0,
    ) is True
    assert captured["referer"] == "https://auth.openai.com/log-in/password"
    assert page.url == "https://auth.openai.com/email-verification"
    assert any("通过接口切换" in message for message in logs)


def test_switch_login_password_to_otp_rejects_html_fallback_response(monkeypatch):
    class FakePage:
        url = "https://auth.openai.com/log-in/password"

    logs = []
    monkeypatch.setattr(browser_register_module, "_click_passwordless_login_if_available", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        browser_register_module,
        "_send_browser_email_otp",
        lambda *args, **kwargs: {
            "ok": True,
            "status": 200,
            "headers": {"content-type": "text/html"},
            "data": None,
        },
    )
    monkeypatch.setattr(browser_register_module, "_passwordless_control_summary", lambda page: "button:Continue")

    assert browser_register_module._switch_login_password_to_otp(
        FakePage(),
        logs.append,
        timeout=0,
    ) is False
    assert any("content_type=text/html" in message for message in logs)
    assert any("button:Continue" in message for message in logs)


def test_submit_otp_accepts_reset_new_password_transition(monkeypatch):
    class FakeLocator:
        def __init__(self):
            self.value = ""

        @property
        def first(self):
            return self

        def count(self):
            return 1

        def wait_for(self, **kwargs):
            return None

        def click(self, **kwargs):
            return None

        def fill(self, value):
            self.value = value

        def type(self, value, **kwargs):
            self.value += value

        def input_value(self):
            return self.value

    class FakePage:
        def __init__(self):
            self.url = "https://auth.openai.com/email-verification"
            self.input = FakeLocator()

        def wait_for_load_state(self, *args, **kwargs):
            return None

        def locator(self, selector):
            return self.input

        def get_by_label(self, *args, **kwargs):
            return self.input

        def get_by_role(self, *args, **kwargs):
            return self.input

    page = FakePage()
    monkeypatch.setattr(browser_register_module.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(browser_register_module, "_browser_pause", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        browser_register_module,
        "_click_first",
        lambda *args, **kwargs: setattr(page, "url", "https://auth.openai.com/reset-password/new-password") or 'button[type="submit"]',
    )

    result = browser_register_module._submit_otp_via_page(page, "654321", lambda message: None)

    assert result["ok"] is True
    assert result["url"] == "https://auth.openai.com/reset-password/new-password"


def test_reset_existing_account_password_completes_verified_flow(monkeypatch):
    page = SimpleNamespace(url="https://auth.openai.com/log-in/password")
    filled = []
    otp_calls = []

    def click_first(page, selectors, timeout=10):
        first = selectors[0]
        if first == 'a[href="/reset-password"]':
            page.url = "https://auth.openai.com/reset-password"
        elif "send_otp" in first:
            page.url = "https://auth.openai.com/email-verification"
        elif first == 'button[type="submit"]':
            page.url = "https://auth.openai.com/reset-password/success"
        elif first == 'a[href="/log-in/password"]':
            page.url = "https://auth.openai.com/log-in/password"
        else:
            pytest.fail(f"unexpected selectors: {selectors}")
        return first

    def submit_otp(page, code, log):
        otp_calls.append(code)
        page.url = "https://auth.openai.com/reset-password/new-password"
        return {"ok": True, "status": 200, "url": page.url, "data": None, "text": ""}

    monkeypatch.setattr(browser_register_module, "_click_first", click_first)
    monkeypatch.setattr(browser_register_module, "_submit_otp_via_page", submit_otp)
    monkeypatch.setattr(
        browser_register_module,
        "_fill_input_like_user",
        lambda page, selector, value: filled.append((selector, value)) or True,
    )

    result = browser_register_module._reset_existing_account_password(
        page,
        "GeneratedRegistrationPassword123!",
        lambda: "654321",
        lambda message: None,
    )

    assert result["ok"] is True
    assert otp_calls == ["654321"]
    assert filled == [
        ('input[name="new-password"]', "GeneratedRegistrationPassword123!"),
        ('input[name="confirm-password"]', "GeneratedRegistrationPassword123!"),
    ]
    assert page.url == "https://auth.openai.com/log-in/password"


def test_passwordless_login_click_is_skipped_on_email_otp_page(monkeypatch):
    page = SimpleNamespace(url="https://auth.openai.com/email-verification")
    monkeypatch.setattr(
        browser_register_module,
        "_click_first",
        lambda *args, **kwargs: pytest.fail("OTP page must not be treated as a passwordless-login choice"),
    )

    assert browser_register_module._click_passwordless_login_if_available(
        page,
        lambda message: None,
        context="test",
    ) is False


def test_browser_registration_uses_known_existing_login_password(monkeypatch):
    class FakePage:
        url = "https://auth.openai.com/log-in/password"

        def evaluate(self, script):
            return "Test User Agent"

    page = FakePage()
    submitted = []
    states = iter([
        {"page_type": "login_password", "current_url": page.url},
        {"page_type": "oauth_callback", "current_url": "http://localhost/callback"},
    ])
    monkeypatch.setattr(browser_register_module, "_seed_browser_device_id", lambda *args: None)
    monkeypatch.setattr(browser_register_module, "_start_browser_signup_via_page", lambda *args: next(states))
    monkeypatch.setattr(browser_register_module, "_get_cookies", lambda page: {})
    monkeypatch.setattr(browser_register_module, "_recover_signup_password_page", lambda *args: False)
    monkeypatch.setattr(
        browser_register_module,
        "_reset_existing_account_password",
        lambda *args, **kwargs: pytest.fail("known-password accounts must not reset their password"),
    )

    def submit_password(page, password, log):
        submitted.append(password)
        page.url = "http://localhost/callback"
        return {"ok": True, "status": 200, "url": page.url, "data": {"page": {"type": "oauth_callback"}}, "text": ""}

    monkeypatch.setattr(browser_register_module, "_submit_oauth_password_direct", submit_password)
    monkeypatch.setattr(browser_register_module, "_handle_post_signup_onboarding", lambda *args: None)
    monkeypatch.setattr(
        browser_register_module,
        "_extract_flow_state",
        lambda data, url: {"page_type": "oauth_callback", "current_url": url},
    )

    result = browser_register_module._browser_registration_flow(
        page,
        "user@icloud.com",
        "GeneratedRegistrationPassword123!",
        lambda: "654321",
        None,
        lambda message: None,
        login_password="KnownChatGPTPassword123!",
    )

    assert submitted == ["KnownChatGPTPassword123!"]
    assert result["account_password"] == "KnownChatGPTPassword123!"


def test_browser_registration_resets_password_when_email_otp_login_is_disabled(monkeypatch):
    class FakePage:
        url = "https://auth.openai.com/log-in/password"

        def evaluate(self, script):
            return "Test User Agent"

    page = FakePage()
    submitted = []
    resets = []
    monkeypatch.setattr(browser_register_module, "_seed_browser_device_id", lambda *args: None)
    monkeypatch.setattr(
        browser_register_module,
        "_start_browser_signup_via_page",
        lambda *args: {"page_type": "login_password", "current_url": page.url},
    )
    monkeypatch.setattr(browser_register_module, "_get_cookies", lambda page: {})
    monkeypatch.setattr(browser_register_module, "_recover_signup_password_page", lambda *args: False)
    monkeypatch.setattr(browser_register_module, "_switch_login_password_to_otp", lambda *args: False)

    def reset_password(page, password, otp_callback, log):
        resets.append(password)
        page.url = "https://auth.openai.com/log-in/password"
        return {"ok": True, "url": page.url, "text": ""}

    def submit_password(page, password, log):
        submitted.append(password)
        page.url = "http://localhost/callback?code=oauth-code"
        return {"ok": True, "status": 200, "url": page.url, "data": None, "text": ""}

    monkeypatch.setattr(browser_register_module, "_reset_existing_account_password", reset_password)
    monkeypatch.setattr(browser_register_module, "_submit_oauth_password_direct", submit_password)
    monkeypatch.setattr(
        browser_register_module,
        "_derive_registration_state_from_page",
        lambda page: {"page_type": "login_password", "current_url": page.url},
    )
    monkeypatch.setattr(browser_register_module, "_handle_post_signup_onboarding", lambda *args: None)

    result = browser_register_module._browser_registration_flow(
        page,
        "user@icloud.com",
        "GeneratedRegistrationPassword123!",
        lambda: "654321",
        None,
        lambda message: None,
    )

    assert resets == ["GeneratedRegistrationPassword123!"]
    assert submitted == ["GeneratedRegistrationPassword123!"]
    assert result["account_password"] == "GeneratedRegistrationPassword123!"


def test_browser_registration_preserves_created_password_when_phone_step_is_skipped(monkeypatch):
    class FakePage:
        url = "https://auth.openai.com/create-account/password"

        def evaluate(self, script):
            return "Test User Agent"

    page = FakePage()
    monkeypatch.setattr(browser_register_module, "_seed_browser_device_id", lambda *args: None)
    monkeypatch.setattr(
        browser_register_module,
        "_start_browser_signup_via_page",
        lambda *args: {"page_type": "create_account_password", "current_url": page.url},
    )
    monkeypatch.setattr(browser_register_module, "_get_cookies", lambda page: {})
    monkeypatch.setattr(
        browser_register_module,
        "_submit_password_via_page",
        lambda *args: {"ok": True, "status": 200, "url": "https://auth.openai.com/add-phone", "data": None, "text": ""},
    )
    monkeypatch.setattr(
        browser_register_module,
        "_extract_flow_state",
        lambda data, url: {"page_type": "add_phone", "current_url": url},
    )

    result = browser_register_module._browser_registration_flow(
        page,
        "new-user@example.com",
        "GeneratedRegistrationPassword123!",
        lambda: "654321",
        None,
        lambda message: None,
    )

    assert result["account_password"] == "GeneratedRegistrationPassword123!"


def test_known_chatgpt_login_password_ignores_url_only_mailbox_password():
    def make_context(credentials, *, supplied=False, password="GeneratedRegistrationPassword123!"):
        mailbox_account = SimpleNamespace(
            extra={"provider_account": {"credentials": credentials}},
        )
        return SimpleNamespace(
            identity=SimpleNamespace(mailbox_account=mailbox_account),
            password_supplied=supplied,
            password=password,
        )

    assert _known_chatgpt_login_password(make_context({"icloud_api_url": "https://mail.example/inbox"})) == ""
    assert _known_chatgpt_login_password(make_context({
        "login_mode": "password_or_email_otp",
        "password": "KnownChatGPTPassword123!",
    })) == "KnownChatGPTPassword123!"
    assert _known_chatgpt_login_password(make_context({}, supplied=True)) == "GeneratedRegistrationPassword123!"


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
    assert [call[0] for call in session.calls] == ["GET", "POST", "GET"]
    assert session.calls[0][1].endswith("/api/accounts/email-otp/send")
    assert json.loads(session.calls[1][2]["data"]) == {"code": "654321"}
    assert session.calls[2][1].endswith("/api/accounts/client_auth_session_dump")


def test_protocol_email_otp_mfa_challenge_finishes_in_browser():
    engine = object.__new__(RegistrationEngine)
    engine._last_codex_error = ""
    engine._codex_direct_token_info = None
    logs = []
    engine._log = lambda message, level="info": logs.append(message)
    engine._complete_codex_login_password_in_browser = lambda: {
        "access_token": "at",
        "refresh_token": "rt",
    }

    callback = engine._complete_codex_protocol_mfa_challenge()

    assert callback == "browser-token-ready"
    assert engine._codex_direct_token_info["refresh_token"] == "rt"
    assert any("邮箱 OTP 后进入 MFA" in message for message in logs)


def test_protocol_email_otp_mfa_challenge_preserves_browser_error():
    engine = object.__new__(RegistrationEngine)
    engine._last_codex_error = ""
    engine._codex_direct_token_info = None
    engine._log = lambda message, level="info": None

    def fail_browser():
        engine._last_codex_error = "MFA only offers authenticator"
        return None

    engine._complete_codex_login_password_in_browser = fail_browser

    assert engine._complete_codex_protocol_mfa_challenge() is None
    assert engine._last_codex_error == "MFA only offers authenticator"


def test_stalled_browser_otp_reenters_same_oauth_url():
    class Page:
        url = "https://auth.openai.com/email-verification"

        def __init__(self):
            self.calls = []

        def goto(self, url, **kwargs):
            self.calls.append((url, kwargs))
            self.url = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"

    page = Page()
    logs = []
    oauth_url = "https://auth.openai.com/oauth/authorize?state=state_123"

    assert browser_register_module._recover_stalled_otp_submission(
        page,
        oauth_url,
        logs.append,
    ) is True
    assert page.calls == [
        (
            oauth_url,
            {"wait_until": "domcontentloaded", "timeout": 30000},
        )
    ]
    assert any("重新进入授权页" in message for message in logs)


def test_browser_login_otp_treats_mfa_route_transition_as_success(monkeypatch):
    class Target:
        def wait_for(self, **kwargs):
            return None

        def click(self, **kwargs):
            return None

        def fill(self, value):
            return None

        def type(self, value, **kwargs):
            return None

        def input_value(self):
            return "123456"

    class Candidate:
        first = Target()

    class Page:
        url = "https://auth.openai.com/email-verification"

        def locator(self, selector):
            return Candidate()

        def get_by_label(self, pattern):
            return Candidate()

        def get_by_role(self, role, name=None):
            return Candidate()

    page = Page()

    def click_continue(current_page, selectors, timeout=0):
        current_page.url = "https://auth.openai.com/mfa-challenge"
        return 'button[type="submit"]'

    monkeypatch.setattr(browser_register_module, "_click_first", click_continue)
    monkeypatch.setattr(browser_register_module, "_browser_pause", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        browser_register_module,
        "_derive_registration_state_from_page",
        lambda current_page: {"page_type": "email_otp_verification"},
    )

    result = browser_register_module._submit_otp_via_page(page, "123456", lambda message: None)

    assert result["ok"] is True
    assert result["status"] == 200
    assert result["url"].endswith("/mfa-challenge")


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


def test_url_only_password_page_uses_protocol_email_otp_before_browser():
    engine = object.__new__(RegistrationEngine)
    engine._has_supplied_login_password = False
    engine._last_codex_error = ""
    logs = []
    engine._log = lambda message, level="info": logs.append((level, message))
    calls = []
    engine._complete_codex_email_otp = lambda session, **kwargs: calls.append((session, kwargs)) or "sign_in_with_chatgpt_codex_consent"
    engine._complete_codex_login_password_in_browser = lambda: pytest.fail("browser fallback must not run")
    session = object()

    page_type, token_info = engine._complete_codex_login_password_page(session)

    assert page_type == "sign_in_with_chatgpt_codex_consent"
    assert token_info is None
    assert calls == [
        (
            session,
            {
                "send_code": True,
                "referer": "https://auth.openai.com/log-in/password",
            },
        )
    ]


def test_url_only_password_page_reports_protocol_and_browser_failures():
    engine = object.__new__(RegistrationEngine)
    engine._has_supplied_login_password = False
    engine._last_codex_error = ""
    engine._log = lambda message, level="info": None

    def fail_protocol(session, **kwargs):
        engine._last_codex_error = "OTP send status=403"
        return None

    def fail_browser():
        engine._last_codex_error = "未找到一次性验证码登录入口"
        return None

    engine._complete_codex_email_otp = fail_protocol
    engine._complete_codex_login_password_in_browser = fail_browser

    page_type, token_info = engine._complete_codex_login_password_page(object())

    assert page_type is None
    assert token_info is None
    assert "邮箱 OTP 与密码重置分支均未完成" in engine._last_codex_error
    assert "协议分支=OTP send status=403" in engine._last_codex_error
    assert "浏览器分支=未找到一次性验证码登录入口" in engine._last_codex_error


def test_password_mfa_page_does_not_use_email_otp_protocol():
    engine = object.__new__(RegistrationEngine)
    engine._has_supplied_login_password = True
    engine._log = lambda message, level="info": None
    engine._complete_codex_email_otp = lambda *args, **kwargs: pytest.fail("password/MFA must not use email OTP")
    engine._complete_codex_login_password_in_browser = lambda: {"access_token": "at", "refresh_token": "rt"}

    page_type, token_info = engine._complete_codex_login_password_page(object())

    assert page_type == ""
    assert token_info == {"access_token": "at", "refresh_token": "rt"}


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


def test_browser_reuses_cached_mfa_email_code_when_openai_sends_no_second_message(monkeypatch):
    engine = object.__new__(RegistrationEngine)
    engine.email = "user@icloud.com"
    engine.password = "GeneratedRegistrationPassword123!"
    engine._is_existing_account = True
    engine._has_supplied_login_password = False
    engine.totp_secret = ""
    engine.totp_url = ""
    engine.proxy_url = None
    engine.phone_callback = None
    engine._last_codex_error = ""
    logs = []
    engine._log = lambda message, level="info": logs.append(message)
    timeouts = []

    def get_code(timeout=120):
        timeouts.append(timeout)
        return "654321" if len(timeouts) == 1 else None

    engine._get_verification_code = get_code

    def retry(self, email, password):
        assert password == ""
        assert self.otp_callback(purpose="mfa") == "654321"
        assert self.otp_callback(purpose="mfa") == "654321"
        return {"access_token": "at", "refresh_token": "rt"}

    monkeypatch.setattr(browser_register_module.ChatGPTBrowserRegister, "_retry_oauth_fresh_browser", retry)

    assert engine._complete_codex_login_password_in_browser() == {"access_token": "at", "refresh_token": "rt"}
    assert timeouts == [120, 20]
    assert any("复用本次会话" in message for message in logs)


def test_mfa_browser_login_keeps_email_otp_fallback_without_using_it(monkeypatch):
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
        assert callable(self.otp_callback)
        assert callable(self.mfa_callback)
        assert self.mfa_callback().isdigit()
        return {"access_token": "at", "refresh_token": "rt"}

    monkeypatch.setattr(browser_register_module.ChatGPTBrowserRegister, "_retry_oauth_fresh_browser", retry)

    token_info = engine._complete_codex_login_password_in_browser()

    assert token_info == {"access_token": "at", "refresh_token": "rt"}


@pytest.mark.parametrize("initial_password", ["", "WrongPassword123!"])
def test_password_reset_then_email_mfa_and_add_phone_flow(monkeypatch, initial_password):
    oauth_start = SimpleNamespace(
        auth_url="https://auth.openai.com/oauth/authorize?state=state_123",
        state="state_123",
        code_verifier="verifier_123",
        redirect_uri="http://localhost:1455/auth/callback",
        client_id="client_123",
    )

    class FakePage:
        url = "about:blank"

        def goto(self, url, **kwargs):
            if "oauth/authorize" in url:
                self.url = "https://auth.openai.com/log-in"
            else:
                self.url = url

        def evaluate(self, script):
            if "navigator.userAgent" in script:
                return "Test User Agent"
            return ""

    page = FakePage()
    events = []
    otp_codes = iter(["111111", "222222"])
    auth_context = {}

    monkeypatch.setattr("platforms.chatgpt.oauth.generate_oauth_url", lambda **kwargs: oauth_start)

    def derive(page):
        url = page.url
        if url.endswith("/log-in"):
            page_type = "login_email"
        elif url.endswith("/log-in/password"):
            page_type = "login_password"
        elif url.endswith("/reset-password/otp"):
            page_type = "reset_password_otp"
        elif url.endswith("/reset-password/new-password"):
            page_type = "reset_password_new_password"
        elif url.endswith("/mfa"):
            page_type = "mfa_challenge"
        elif url.endswith("/email-verification"):
            page_type = "email_otp_verification"
        elif url.endswith("/add-phone"):
            page_type = "add_phone"
        else:
            page_type = "oauth_callback" if "code=" in url else ""
        return {"page_type": page_type, "continue_url": ""}

    monkeypatch.setattr(browser_register_module, "_derive_oauth_state_from_page", derive)
    monkeypatch.setattr(browser_register_module, "_get_page_oauth_url", lambda page: "")

    def submit_email(page, email, log, allow_passwordless=True):
        events.append(("email", email, allow_passwordless))
        page.url = "https://auth.openai.com/log-in/password"
        return {"ok": True, "status": 200, "text": ""}

    def submit_password(page, password, log):
        events.append(("login_password", password))
        if password == "WrongPassword123!":
            return {"ok": False, "status": 400, "text": "Incorrect email address or password"}
        page.url = "https://auth.openai.com/mfa"
        return {"ok": True, "status": 200, "text": ""}

    def start_reset(page, log, otp_sent_callback=None):
        events.append("reset_start")
        otp_sent_callback()
        page.url = "https://auth.openai.com/reset-password/otp"
        return True

    def submit_otp(page, code, log):
        events.append(("email_otp", code))
        if "/reset-password/otp" in page.url:
            page.url = "https://auth.openai.com/reset-password/new-password"
        else:
            page.url = "https://auth.openai.com/add-phone"
        return {"ok": True, "status": 200, "text": ""}

    def submit_reset_password(page, password, log):
        events.append(("reset_password", password))
        page.url = "https://auth.openai.com/log-in/password"
        return {"ok": True, "status": 200, "text": ""}

    def switch_mfa(page, log, otp_sent_callback=None):
        events.append("mfa_email")
        otp_sent_callback()
        page.url = "https://auth.openai.com/email-verification"
        return True

    def add_phone(page, callback, **kwargs):
        events.append("add_phone")
        page.url = "http://localhost:1455/auth/callback?code=done&state=state_123"

    monkeypatch.setattr(browser_register_module, "_submit_login_email_via_page", submit_email)
    monkeypatch.setattr(browser_register_module, "_switch_login_password_to_otp", lambda *args, **kwargs: False)
    monkeypatch.setattr(browser_register_module, "_submit_oauth_password_direct", submit_password)
    monkeypatch.setattr(browser_register_module, "_start_password_reset", start_reset)
    monkeypatch.setattr(browser_register_module, "_submit_otp_via_page", submit_otp)
    monkeypatch.setattr(browser_register_module, "_submit_reset_password_via_page", submit_reset_password)
    monkeypatch.setattr(browser_register_module, "_switch_mfa_to_email_otp", switch_mfa)
    monkeypatch.setattr(browser_register_module, "_handle_add_phone_challenge", add_phone)
    monkeypatch.setattr(
        browser_register_module,
        "_submit_callback_result",
        lambda callback_url, oauth_start, proxy: {"callback_url": callback_url},
    )

    result = browser_register_module._do_codex_oauth(
        page,
        {},
        "user@example.com",
        initial_password,
        lambda: next(otp_codes),
        object(),
        None,
        lambda message: None,
        reset_password="FreshPassword123!",
        otp_sent_callback=lambda: events.append("otp_sent"),
        auth_context=auth_context,
    )

    assert result["callback_url"].endswith("code=done&state=state_123")
    assert auth_context["effective_password"] == "FreshPassword123!"
    assert events.count("reset_start") == 1
    assert events.count("mfa_email") == 1
    assert events.count("add_phone") == 1
    assert ("reset_password", "FreshPassword123!") in events
    assert ("login_password", "FreshPassword123!") in events
    if initial_password:
        assert ("login_password", initial_password) in events


def test_password_reset_detects_same_url_otp_text_before_input_is_resolvable():
    class TextOnlyResetPage:
        url = "https://auth.openai.com/reset-password"

        def query_selector(self, selector):
            return None

        def evaluate(self, script):
            if "document.body?.innerText" in script:
                return "Check your inbox\nEnter the verification code we just sent to user@example.com"
            return ""

    assert (
        browser_register_module._password_reset_page_type(TextOnlyResetPage())
        == "reset_password_otp"
    )


def test_password_reset_accepts_shared_email_verification_route():
    class SharedVerificationPage:
        url = "https://auth.openai.com/log-in/password"

        def __init__(self):
            self.stage = "password"

        def evaluate(self, script):
            if "querySelectorAll('a[href], button')" in script:
                return "https://auth.openai.com/reset-password"
            if "document.body?.innerText" in script:
                if self.stage == "otp":
                    return "Check your inbox Enter the verification code we just sent"
                return "Reset password Click Continue to reset your password"
            return ""

        def goto(self, url, **kwargs):
            self.url = url
            self.stage = "reset_start"

        def query_selector(self, selector):
            if self.stage == "reset_start" and "send_otp" in selector:
                return object()
            if self.stage == "otp" and (
                "inputmode='numeric'" in selector or "name*='code'" in selector
            ):
                return object()
            return None

        def click(self, selector):
            self.stage = "otp"
            self.url = "https://auth.openai.com/email-verification"

    assert browser_register_module._start_password_reset(
        SharedVerificationPage(),
        lambda message: None,
    )


def test_mfa_route_detects_email_code_form_from_dom():
    class EmailMfaPage:
        url = "https://auth.openai.com/mfa-challenge"

        def query_selector(self, selector):
            if "inputmode='numeric'" in selector:
                return object()
            return None

        def evaluate(self, script):
            if "document.body?.innerText" in script:
                return "Check your inbox Enter the code sent to user@example.com"
            return ""

    assert (
        browser_register_module._derive_registration_state_from_page(EmailMfaPage())["page_type"]
        == "email_otp_verification"
    )


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
        assert callable(self.otp_callback)
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


def test_protocol_mailbox_worker_starts_url_only_mailbox_with_codex_auth():
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
    captured = {}
    worker.engine.login_existing_via_codex_auth = lambda **kwargs: captured.update(kwargs) or SimpleNamespace(success=True)
    worker.engine.run = lambda: pytest.fail("URL-only mailbox must start with Codex OAuth")

    assert worker.run(email=account.email, password="generated-password").success is True
    assert captured == {
        "email": "user@icloud.com",
        "password": "",
        "totp_secret": "",
        "totp_url": "",
    }


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


def test_fresh_browser_oauth_retries_callback_failure_once(monkeypatch):
    class FakeBrowser:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def new_page(self):
            return object()

    calls = []

    def oauth(*args, **kwargs):
        calls.append("oauth")
        if len(calls) == 1:
            raise RuntimeError("Codex OAuth consent/workspace 未完成 callback")
        return {"access_token": "at", "refresh_token": "rt"}

    monkeypatch.setattr(browser_register_module, "Camoufox", lambda **kwargs: FakeBrowser())
    monkeypatch.setattr(browser_register_module, "_do_codex_oauth", oauth)
    monkeypatch.setattr(browser_register_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr("core.config_store.config_store.get", lambda key, default="": "2")
    worker = browser_register_module.ChatGPTBrowserRegister(headless=True, log_fn=lambda message: None)

    result = worker._retry_oauth_fresh_browser("user@example.com", "Secret123!")

    assert result["refresh_token"] == "rt"
    assert calls == ["oauth", "oauth"]


def test_fresh_browser_oauth_does_not_retry_password_rejection(monkeypatch):
    class FakeBrowser:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def new_page(self):
            return object()

    calls = []

    def oauth(*args, **kwargs):
        calls.append("oauth")
        raise RuntimeError("Incorrect email address or password")

    monkeypatch.setattr(browser_register_module, "Camoufox", lambda **kwargs: FakeBrowser())
    monkeypatch.setattr(browser_register_module, "_do_codex_oauth", oauth)
    monkeypatch.setattr("core.config_store.config_store.get", lambda key, default="": "2")
    worker = browser_register_module.ChatGPTBrowserRegister(headless=True, log_fn=lambda message: None)

    assert worker._retry_oauth_fresh_browser("user@example.com", "wrong") is None
    assert calls == ["oauth"]


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
