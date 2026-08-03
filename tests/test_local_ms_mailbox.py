from __future__ import annotations

from types import SimpleNamespace
import json

import pytest

from core.base_mailbox import MailboxAccount
from core.local_ms_mailbox import (
    FLYSMS_MESSAGES_URL,
    FLYSMS_OTP_INGESTION_GRACE_SECONDS,
    LocalMicrosoftMailboxEntry,
    LocalMicrosoftMailboxPool,
    OUTLOOK_IMAP_SCOPE,
    OUTLOOK_TOKEN_URL,
    parse_xinlan_common_rows,
)
from core.base_identity import MailboxIdentityProvider


def _entry() -> LocalMicrosoftMailboxEntry:
    return LocalMicrosoftMailboxEntry(
        email="user@outlook.com",
        login_account="user@outlook.com",
        client_id="client-id",
        refresh_token="refresh-token",
    )


@pytest.mark.parametrize("delimiter", ["---", "----", "-----", "------"])
def test_icloud_relay_accepts_three_or_more_hyphens(delimiter):
    text = (
        f"relay@icloud.com{delimiter}"
        "https://flysms.xyz/icloud/pickup#email=relay%40icloud.com&key=tok_test-key"
    )

    entries = parse_xinlan_common_rows(text)

    assert len(entries) == 1
    assert entries[0].source == "icloud_api"
    assert entries[0].icloud_api_ready
    assert entries[0].icloud_api_url.startswith("https://flysms.xyz/icloud/pickup#")


def test_icloud_relay_preserves_hyphen_runs_inside_url_token():
    entries = parse_xinlan_common_rows(
        "relay@icloud.com------"
        "https://flysms.xyz/icloud/pickup#email=relay%40icloud.com&key=tok_test---key"
    )

    assert len(entries) == 1
    assert entries[0].icloud_api_url.endswith("key=tok_test---key")


def test_flysms_pickup_scans_message_list_when_newer_notice_hides_otp(monkeypatch):
    entry = parse_xinlan_common_rows(
        "relay@icloud.com------"
        "https://flysms.xyz/icloud/pickup#email=relay%40icloud.com&key=tok_test-key"
    )[0]
    captured = []

    class Response:
        headers = {"content-type": "application/json"}

        def __init__(self, payload, status_code=200):
            self.payload = payload
            self.status_code = status_code

        def json(self):
            return self.payload

    listing = {
        "email": "relay@icloud.com",
        "messages": [
            {
                "mailbox": "INBOX",
                "uid": 43,
                "subject": "New sign-in to your OpenAI account",
                "from": "OpenAI <noreply@example.com>",
                "date": "2026-08-03T13:57:41.000Z",
                "preview": "No action is needed if this was you.",
            },
            {
                "mailbox": "INBOX",
                "uid": 42,
                "subject": "Your temporary ChatGPT login code",
                "from": "ChatGPT <noreply@example.com>",
                "date": "2026-08-03T13:57:40.000Z",
                "preview": "Your temporary login code",
            },
        ],
    }
    details = {
        43: {
            "email": "relay@icloud.com",
            "message": {
                "mailbox": "INBOX",
                "uid": 43,
                "subject": "New sign-in to your OpenAI account",
                "date": "2026-08-03T13:57:41.000Z",
                "text": "No action is needed if this was you.",
            },
        },
        42: {
            "email": "relay@icloud.com",
            "entitlementStatus": "active",
            "message": {
                "email": "relay@icloud.com",
                "mailbox": "INBOX",
                "uid": 42,
                "subject": "Your temporary ChatGPT login code",
                "from": "ChatGPT <noreply@example.com>",
                "date": "2026-08-03T13:57:39.000Z",
                "mailboxReceivedAt": "2026-08-03T13:57:40.000Z",
                "text": "Your login code is 123456",
                "html": "<strong>123456</strong>",
            },
        },
    }

    def fake_get(url, *, headers, params, proxies, timeout):
        captured.append((url, headers, params, proxies, timeout))
        if url == FLYSMS_MESSAGES_URL:
            return Response(listing)
        uid = int(url.rsplit("/", 1)[-1])
        return Response(details[uid])

    monkeypatch.setattr("core.local_ms_mailbox.requests.get", fake_get)

    mailbox = LocalMicrosoftMailboxPool()
    messages = mailbox._icloud_api_messages(entry)
    cached_messages = mailbox._icloud_api_messages(entry)

    assert captured[0][0] == FLYSMS_MESSAGES_URL
    assert captured[0][1]["authorization"] == "Bearer tok_test-key"
    assert captured[0][1]["x-mailbox-email"] == "relay@icloud.com"
    assert captured[0][1]["cache-control"] == "no-cache, no-store"
    assert captured[0][1]["pragma"] == "no-cache"
    assert captured[0][2] == {"limit": 10}
    assert [call[0] for call in captured] == [
        FLYSMS_MESSAGES_URL,
        f"{FLYSMS_MESSAGES_URL}/43",
        f"{FLYSMS_MESSAGES_URL}/42",
        FLYSMS_MESSAGES_URL,
    ]
    assert captured[1][2] == {"mailbox": "INBOX"}
    assert messages[0]["subject"] == "New sign-in to your OpenAI account"
    assert "123456" in messages[1]["bodyPreview"]
    assert messages[1]["receivedDateTime"] == "2026-08-03T13:57:40.000Z"
    assert cached_messages == messages


def test_flysms_pickup_retries_detail_until_ingestion_finishes(monkeypatch):
    entry = parse_xinlan_common_rows(
        "relay@icloud.com------"
        "https://flysms.xyz/icloud/pickup#email=relay%40icloud.com&key=tok_test-key"
    )[0]
    listing = {
        "email": "relay@icloud.com",
        "messages": [{
            "mailbox": "INBOX",
            "uid": 44,
            "subject": "Your temporary ChatGPT login code",
            "date": "2026-08-03T15:04:52.000Z",
            "preview": "Message is still being ingested",
        }],
    }
    detail_calls = 0

    class Response:
        headers = {"content-type": "application/json"}

        def __init__(self, payload, status_code=200):
            self.payload = payload
            self.status_code = status_code

        def json(self):
            return self.payload

    def fake_get(url, **kwargs):
        nonlocal detail_calls
        if url == FLYSMS_MESSAGES_URL:
            return Response(listing)
        detail_calls += 1
        if detail_calls == 1:
            return Response({}, status_code=404)
        return Response({
            "email": "relay@icloud.com",
            "message": {
                "mailbox": "INBOX",
                "uid": 44,
                "subject": "Your temporary ChatGPT login code",
                "mailboxReceivedAt": "2026-08-03T15:04:52.000Z",
                "text": "Enter this temporary verification code to continue: 108174",
            },
        })

    monkeypatch.setattr("core.local_ms_mailbox.requests.get", fake_get)
    mailbox = LocalMicrosoftMailboxPool()

    pending = mailbox._icloud_api_messages(entry)
    ingested = mailbox._icloud_api_messages(entry)

    assert pending[0]["_detail_pending"] is True
    assert "108174" not in pending[0]["bodyPreview"]
    assert ingested[0]["_detail_pending"] is False
    assert "108174" in ingested[0]["bodyPreview"]
    assert detail_calls == 2


def test_flysms_wait_for_code_adds_ingestion_grace(monkeypatch):
    entry = parse_xinlan_common_rows(
        "relay@icloud.com------"
        "https://flysms.xyz/icloud/pickup#email=relay%40icloud.com&key=tok_test-key"
    )[0]
    mailbox = LocalMicrosoftMailboxPool()
    account = MailboxAccount(email=entry.email)
    clock = [0.0]

    monkeypatch.setattr(mailbox, "_entry_for_account", lambda _account: entry)
    monkeypatch.setattr(mailbox, "_messages", lambda _account: [])
    monkeypatch.setattr("core.local_ms_mailbox.time.time", lambda: clock[0])
    monkeypatch.setattr(
        "core.local_ms_mailbox.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )

    expected_timeout = 120 + FLYSMS_OTP_INGESTION_GRACE_SECONDS
    with pytest.raises(TimeoutError, match=rf"\({expected_timeout}s\)"):
        mailbox.wait_for_code(account, timeout=120)


def test_flysms_pickup_returns_empty_for_mailbox_without_messages(monkeypatch):
    entry = parse_xinlan_common_rows(
        "relay@icloud.com----"
        "https://flysms.xyz/icloud/pickup#email=relay%40icloud.com&key=tok_test-key"
    )[0]

    class Response:
        status_code = 404
        headers = {}

    monkeypatch.setattr("core.local_ms_mailbox.requests.get", lambda *args, **kwargs: Response())

    assert LocalMicrosoftMailboxPool()._icloud_api_messages(entry) == []


def test_flysms_pickup_rejects_mismatched_email_before_request(monkeypatch):
    entry = LocalMicrosoftMailboxEntry(
        email="relay@icloud.com",
        login_account="relay@icloud.com",
        receive_provider="icloud_api",
        icloud_api_url=(
            "https://flysms.xyz/icloud/pickup#"
            "email=other%40icloud.com&key=tok_test-key"
        ),
    )
    requested = False

    def fake_get(*args, **kwargs):
        nonlocal requested
        requested = True

    monkeypatch.setattr("core.local_ms_mailbox.requests.get", fake_get)

    with pytest.raises(RuntimeError, match="邮箱与账号池邮箱不一致"):
        LocalMicrosoftMailboxPool()._icloud_api_messages(entry)
    assert not requested


def test_three_column_login_mfa_row_ignores_product_description():
    entries = parse_xinlan_common_rows(
        "account@icloud.com----LoginPassword123----JBSWY3DPEHPK3PXP\n"
        "**商品说明**\n"
        "MFA验证码获取地址：https://2fa.fun/index.html"
    )

    assert len(entries) == 1
    assert entries[0].email == "account@icloud.com"
    assert entries[0].password == "LoginPassword123"
    assert entries[0].login_account == "account@icloud.com"
    assert entries[0].totp_secret == "JBSWY3DPEHPK3PXP"
    assert not entries[0].graph_ready
    assert not entries[0].imap_ready


def test_pipe_login_mfa_row_preserves_plus_email_and_password_spaces():
    entries = parse_xinlan_common_rows(
        "x+y@icloud.com| password with spaces |JBSWY3DPEHPK3PXP\n"
        "登录教程：https://example.com"
    )

    assert len(entries) == 1
    assert entries[0].email == "x+y@icloud.com"
    assert entries[0].password == " password with spaces "
    assert entries[0].totp_secret == "JBSWY3DPEHPK3PXP"


def test_pipe_login_mfa_row_uses_first_and_last_separator():
    entries = parse_xinlan_common_rows(
        "account@icloud.com|password|with|pipes|JBSWY3DPEHPK3PXP"
    )

    assert len(entries) == 1
    assert entries[0].password == "password|with|pipes"
    assert entries[0].totp_secret == "JBSWY3DPEHPK3PXP"


def test_pipe_login_mfa_row_ignores_trailing_account_status(tmp_path):
    pool_text = (
        "user@gmail.com|password|with|pipes|"
        "TZ75BLYLJZWSN2SLXM6POOEUGTL26ZOI|Trial"
    )
    entries = parse_xinlan_common_rows(pool_text)

    assert len(entries) == 1
    assert entries[0].email == "user@gmail.com"
    assert entries[0].password == "password|with|pipes"
    assert entries[0].totp_secret == "TZ75BLYLJZWSN2SLXM6POOEUGTL26ZOI"
    assert entries[0].existing_login_ready

    mailbox = LocalMicrosoftMailboxPool(
        pool_text=pool_text,
        state_file=str(tmp_path / "mailbox-state.json"),
    )
    account = mailbox.get_email()
    credentials = account.extra["provider_account"]["credentials"]
    assert account.email == "user@gmail.com"
    assert credentials["password"] == "password|with|pipes"
    assert credentials["totp_secret"] == "TZ75BLYLJZWSN2SLXM6POOEUGTL26ZOI"


def test_hyphen_login_mfa_row_ignores_trailing_access_token(tmp_path):
    pool_text = (
        "user@gmail.com---Password123!---TZ75BLYLJZWSN2SLXM6POOEUGTL26ZOI---"
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature"
    )
    entries = parse_xinlan_common_rows(pool_text)

    assert len(entries) == 1
    assert entries[0].email == "user@gmail.com"
    assert entries[0].password == "Password123!"
    assert entries[0].totp_secret == "TZ75BLYLJZWSN2SLXM6POOEUGTL26ZOI"
    assert entries[0].login_mode == "password_mfa"
    assert not entries[0].graph_ready
    assert entries[0].existing_login_ready

    account = LocalMicrosoftMailboxPool(
        pool_text=pool_text,
        state_file=str(tmp_path / "mailbox-state.json"),
    ).get_email()
    credentials = account.extra["provider_account"]["credentials"]
    assert credentials["password"] == "Password123!"
    assert credentials["totp_secret"] == "TZ75BLYLJZWSN2SLXM6POOEUGTL26ZOI"


def test_registered_account_rows_ignore_trailing_plus_status_and_keep_credentials(tmp_path):
    rows = (
        "pipe@example.com|Password123!|JBSWY3DPEHPK3PXP|Plus\n"
        "triple@example.com---Password123!---JBSWY3DPEHPK3PXP---Plus\n"
        "quad@example.com----Password123!----JBSWY3DPEHPK3PXP----Plus\n"
        "csv@example.com,Password123!,JBSWY3DPEHPK3PXP,Plus\n"
        "mail@example.com----Password123!----https://example.com/inbox----Plus\n"
        "both@example.com----Password123!----https://example.com/inbox----https://example.com/totp----Plus"
    )

    entries = {entry.email: entry for entry in parse_xinlan_common_rows(rows)}

    for email in ("pipe@example.com", "triple@example.com", "quad@example.com", "csv@example.com"):
        assert entries[email].totp_secret == "JBSWY3DPEHPK3PXP"
        assert entries[email].login_mode == "password_mfa"
    assert entries["mail@example.com"].login_mode == "password_or_email_otp"
    assert entries["mail@example.com"].credentials()["icloud_api_url"] == "https://example.com/inbox"
    assert entries["both@example.com"].login_mode == "password_mfa_url"
    assert entries["both@example.com"].totp_url == "https://example.com/totp"

    account = LocalMicrosoftMailboxPool(
        pool_text="mail@example.com----Password123!----https://example.com/inbox----Plus",
        state_file=str(tmp_path / "mailbox-state.json"),
    ).get_email()
    assert account.extra["provider_account"]["credentials"]["icloud_api_url"] == "https://example.com/inbox"


def test_space_delimited_and_chinese_labeled_mfa_rows_are_supported():
    entries = parse_xinlan_common_rows(
        "spaces@example.com Password123! JBSWY3DPEHPK3PXP\n"
        "chatgpt谷歌邮箱：labeled@example.com chatgpt密码：Secret123! 一次性安全码密钥：JBSWY3DPEHPK3PXP"
    )

    assert [(entry.email, entry.password, entry.totp_secret) for entry in entries] == [
        ("spaces@example.com", "Password123!", "JBSWY3DPEHPK3PXP"),
        ("labeled@example.com", "Secret123!", "JBSWY3DPEHPK3PXP"),
    ]


def test_password_login_row_with_inbox_url_keeps_both_capabilities(tmp_path):
    row = (
        "adults-tarpons1q@icloud.com----redacted-password@@----"
        "https://icloud-first-mail-link.example/m/token"
    )
    entries = parse_xinlan_common_rows(row)

    assert len(entries) == 1
    assert entries[0].password == "redacted-password@@"
    assert entries[0].login_mode == "password_or_email_otp"
    assert entries[0].icloud_api_ready

    account = LocalMicrosoftMailboxPool(
        pool_text=row,
        state_file=str(tmp_path / "mailbox-state.json"),
    ).get_email()
    credentials = account.extra["provider_account"]["credentials"]
    assert credentials["login_mode"] == "password_or_email_otp"
    assert credentials["icloud_api_url"].endswith("/token")


def test_password_login_row_with_inbox_and_totp_urls_keeps_all_capabilities(tmp_path):
    row = (
        "account@icloud.com----redacted-password----"
        "https://mail.example/inbox?email=account%40icloud.com&token=mail-token----"
        "https://2fa.example/view?token=totp-token&email=account%40icloud.com"
    )
    entries = parse_xinlan_common_rows(row)

    assert len(entries) == 1
    assert entries[0].password == "redacted-password"
    assert entries[0].login_mode == "password_mfa_url"
    assert entries[0].icloud_api_url.startswith("https://mail.example/inbox?")
    assert entries[0].totp_url.startswith("https://2fa.example/view?")
    assert entries[0].icloud_api_ready
    assert entries[0].existing_login_ready

    account = LocalMicrosoftMailboxPool(
        pool_text=row,
        state_file=str(tmp_path / "mailbox-state.json"),
    ).get_email()
    credentials = account.extra["provider_account"]["credentials"]
    assert credentials["login_mode"] == "password_mfa_url"
    assert credentials["totp_url"].startswith("https://2fa.example/view?")


def test_three_hyphen_icloud_relay_rows_preserve_email_and_code_url():
    entries = parse_xinlan_common_rows(
        "odds.04alibi+hfi0vu5u890a8x24@icloud.com---"
        "https://mail.20000408.xyz/show/token/odds.04alibi%2Bhfi0vu5u890a8x24@icloud.com\n"
        "frame-squawk4r@icloud.com---"
        "https://mail.20000408.xyz/show/token/frame-squawk4r@icloud.com"
    )

    assert len(entries) == 2
    assert entries[0].email == "odds.04alibi+hfi0vu5u890a8x24@icloud.com"
    assert entries[0].receive_provider == "icloud_api"
    assert entries[0].icloud_api_url == (
        "https://mail.20000408.xyz/show/token/"
        "odds.04alibi%2Bhfi0vu5u890a8x24@icloud.com"
    )
    assert entries[0].icloud_api_ready
    assert entries[1].email == "frame-squawk4r@icloud.com"
    assert entries[1].icloud_api_ready


def test_four_hyphen_icloud_relay_format_remains_supported():
    entries = parse_xinlan_common_rows(
        "account@icloud.com----https://mail.example.com/show/token/account@icloud.com"
    )

    assert len(entries) == 1
    assert entries[0].email == "account@icloud.com"
    assert entries[0].icloud_api_ready


def test_four_hyphen_tokenized_icloud_api_format_is_supported():
    entries = parse_xinlan_common_rows(
        "account@icloud.com----"
        "https://email.example.com/icloud/sample_access_token"
    )

    assert len(entries) == 1
    assert entries[0].email == "account@icloud.com"
    assert entries[0].receive_provider == "icloud_api"
    assert entries[0].icloud_api_url == (
        "https://email.example.com/icloud/sample_access_token"
    )
    assert entries[0].icloud_api_ready


def test_many_hyphen_icloud_relay_row_preserves_fragment_url():
    entries = parse_xinlan_common_rows(
        "bottles_ballots.5j@icloud.com----------------"
        "http://2.27.174.158:4173/check.html#mls_IYANC1AhhKaiPLpxyQgavX1TlFaJ8o4XrNl33J2GSfc"
    )

    assert len(entries) == 1
    assert entries[0].email == "bottles_ballots.5j@icloud.com"
    assert entries[0].icloud_api_url == (
        "http://2.27.174.158:4173/check.html#"
        "mls_IYANC1AhhKaiPLpxyQgavX1TlFaJ8o4XrNl33J2GSfc"
    )
    assert entries[0].icloud_api_ready


def test_tokenized_icloud_api_reads_root_code_from_json(monkeypatch):
    class Response:
        status_code = 200
        headers = {"content-type": "application/json; charset=utf-8"}

        def __init__(self, payload: dict):
            self.payload = payload
            self.text = json.dumps(payload)

        def json(self):
            return self.payload

    responses = iter([
        Response({
            "found": False,
            "message": "No verification email found",
            "email": "account@icloud.com",
        }),
        Response({
            "found": True,
            "message": "Verification email found",
            "email": "account@icloud.com",
            "code": "654321",
        }),
    ])
    captured = []

    def fake_get(url, **kwargs):
        captured.append((url, kwargs))
        return next(responses)

    monkeypatch.setattr("core.local_ms_mailbox.requests.get", fake_get)
    entry = LocalMicrosoftMailboxEntry(
        email="account@icloud.com",
        receive_provider="icloud_api",
        icloud_api_url="https://email.example.com/icloud/sample_access_token",
    )
    mailbox = LocalMicrosoftMailboxPool()

    before = mailbox._icloud_api_messages(entry)[0]
    received = mailbox._icloud_api_messages(entry)[0]

    assert captured[0][0] == entry.icloud_api_url
    assert captured[0][1]["headers"]["cache-control"] == "no-cache, no-store"
    assert "654321" in received["bodyPreview"]
    assert received["id"] != before["id"]


def test_mailroom_fragment_link_calls_public_api_and_reads_root_code(monkeypatch):
    class Response:
        status_code = 200
        headers = {"content-type": "application/json; charset=utf-8"}
        text = ""

        def __init__(self, code: str):
            self.code = code

        def json(self):
            return {
                "ok": True,
                "codes": [self.code],
                "messages": [{"id": "1", "body": "success"}],
            }

    responses = iter([Response("111111"), Response("222222")])
    captured = []

    def fake_post(url, **kwargs):
        captured.append((url, kwargs))
        return next(responses)

    monkeypatch.setattr("core.local_ms_mailbox.requests.post", fake_post)
    entry = LocalMicrosoftMailboxEntry(
        email="account@icloud.com",
        receive_provider="icloud_api",
        icloud_api_url="http://mail.example.com/check.html#mls_share-token",
    )
    mailbox = LocalMicrosoftMailboxPool()

    first = mailbox._icloud_api_messages(entry)[0]
    second = mailbox._icloud_api_messages(entry)[0]

    assert captured[0][0] == "http://mail.example.com/public-api/v1/check"
    assert captured[0][1]["headers"]["authorization"] == "Bearer mls_share-token"
    assert "111111" in first["bodyPreview"]
    assert "222222" in second["bodyPreview"]
    assert first["id"] != second["id"]


def test_icloud_relay_message_id_ignores_dynamic_page_markup(monkeypatch):
    class Response:
        status_code = 200
        headers = {"content-type": "text/html; charset=utf-8"}

        def __init__(self, nonce: str, code: str):
            self.text = (
                f"<html><script nonce='{nonce}'>window.requestId='{nonce}'</script>"
                "<p>Your temporary ChatGPT login code</p>"
                f"<p>Enter this temporary verification code to continue: {code}</p></html>"
            )

    responses = iter([
        Response("dynamic-a", "111111"),
        Response("dynamic-b", "111111"),
        Response("dynamic-c", "222222"),
    ])
    captured = []

    def fake_get(url, **kwargs):
        captured.append((url, kwargs))
        return next(responses)

    monkeypatch.setattr("core.local_ms_mailbox.requests.get", fake_get)
    entry = LocalMicrosoftMailboxEntry(
        email="account@icloud.com",
        receive_provider="icloud_api",
        icloud_api_url="https://mail.example.com/show/token/account@icloud.com",
    )
    mailbox = LocalMicrosoftMailboxPool()

    old_first = mailbox._icloud_api_messages(entry)[0]
    old_second = mailbox._icloud_api_messages(entry)[0]
    new_message = mailbox._icloud_api_messages(entry)[0]

    assert old_first["id"] == old_second["id"]
    assert new_message["id"] != old_first["id"]
    assert captured[0][1]["headers"]["cache-control"] == "no-cache, no-store"
    assert "_" in captured[0][1]["params"]


def test_outlook_imap_token_uses_consumers_endpoint_and_imap_scope(monkeypatch):
    captured = {}

    class Response:
        status_code = 200
        text = ""

        @staticmethod
        def json():
            return {"access_token": "imap-access-token"}

    def fake_post(url, *, data, proxies, timeout):
        captured.update(url=url, data=data, proxies=proxies, timeout=timeout)
        return Response()

    monkeypatch.setattr("core.local_ms_mailbox.requests.post", fake_post)

    mailbox = LocalMicrosoftMailboxPool()
    token = mailbox._outlook_imap_access_token(_entry())

    assert token == "imap-access-token"
    assert captured["url"] == OUTLOOK_TOKEN_URL
    assert captured["data"]["scope"] == OUTLOOK_IMAP_SCOPE


def test_graph_failure_falls_back_to_imap_and_caches_strategy(monkeypatch):
    mailbox = LocalMicrosoftMailboxPool()
    entry = _entry()
    account = SimpleNamespace(email=entry.email, extra={})
    calls = []

    monkeypatch.setattr(mailbox, "_entry_for_account", lambda _: entry)

    def graph_messages(_):
        calls.append("graph")
        raise RuntimeError("AADSTS70000")

    def imap_messages(_):
        calls.append("imap")
        return [{"id": "message-1"}]

    monkeypatch.setattr(mailbox, "_graph_messages", graph_messages)
    monkeypatch.setattr(mailbox, "_outlook_oauth_imap_messages", imap_messages)

    assert mailbox._messages(account) == [{"id": "message-1"}]
    assert mailbox._messages(account) == [{"id": "message-1"}]
    assert calls == ["graph", "imap", "imap"]


def test_failed_mailbox_is_released_for_immediate_retry(tmp_path):
    state_file = tmp_path / "mailbox-state.json"
    mailbox = LocalMicrosoftMailboxPool(
        pool_text=(
            "first@outlook.com----https://mail.example/inbox/first\n"
            "second@outlook.com----https://mail.example/inbox/second"
        ),
        state_file=str(state_file),
        failure_cooldown_seconds=1800,
    )

    first = mailbox.get_email()
    assert first.email == "first@outlook.com"
    assert mailbox.release_email(first)

    retried = mailbox.get_email()
    assert retried.email == "first@outlook.com"
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert not state.get("cooldowns")
    assert "first@outlook.com" in state["used"]


def test_exhaustive_run_attempts_each_mailbox_once(tmp_path):
    mailbox = LocalMicrosoftMailboxPool(
        pool_text=(
            "first@outlook.com----https://mail.example/inbox/first\n"
            "second@outlook.com----https://mail.example/inbox/second"
        ),
        state_file=str(tmp_path / "mailbox-state.json"),
        avoid_repeat=True,
    )

    first = mailbox.get_email()
    assert mailbox.release_email(first)
    second = mailbox.get_email()

    assert first.email == "first@outlook.com"
    assert second.email == "second@outlook.com"


def test_available_count_excludes_successfully_reserved_mailboxes(tmp_path):
    mailbox = LocalMicrosoftMailboxPool(
        pool_text=(
            "first@outlook.com----https://mail.example/inbox/first\n"
            "second@outlook.com----https://mail.example/inbox/second"
        ),
        state_file=str(tmp_path / "mailbox-state.json"),
    )

    assert mailbox.available_count() == 2
    mailbox.get_email()
    assert mailbox.available_count() == 1


def test_expired_failure_cooldown_allows_mailbox_reuse(tmp_path):
    state_file = tmp_path / "mailbox-state.json"
    state_file.write_text(
        json.dumps({
            "used": {},
            "cooldowns": {
                "first@outlook.com": {"cooldown_until": 1},
            },
        }),
        encoding="utf-8",
    )
    mailbox = LocalMicrosoftMailboxPool(
        pool_text="first@outlook.com----https://mail.example/inbox/first",
        state_file=str(state_file),
        failure_cooldown_seconds=1800,
    )

    assert mailbox.get_email().email == "first@outlook.com"


def test_network_failure_release_does_not_cool_down_mailbox(tmp_path):
    state_file = tmp_path / "mailbox-state.json"
    mailbox = LocalMicrosoftMailboxPool(
        pool_text="first@outlook.com----https://mail.example/inbox/first",
        state_file=str(state_file),
        failure_cooldown_seconds=1800,
    )

    account = mailbox.get_email()
    assert mailbox.release_email(account, cooldown=False)
    assert mailbox.peek_email() == "first@outlook.com"
    assert not mailbox._state().get("cooldowns")


def test_clear_failure_cooldowns(tmp_path):
    state_file = tmp_path / "mailbox-state.json"
    state_file.write_text(
        json.dumps({
            "used": {},
            "cooldowns": {
                "first@outlook.com": {"cooldown_until": 9999999999},
            },
        }),
        encoding="utf-8",
    )
    mailbox = LocalMicrosoftMailboxPool(
        pool_text="first@outlook.com----https://mail.example/inbox/first",
        state_file=str(state_file),
        failure_cooldown_seconds=1800,
    )

    assert mailbox.clear_failure_cooldowns(["first@outlook.com"]) == 1
    assert mailbox.peek_email() == "first@outlook.com"


def test_release_unsaved_reservations_keeps_saved_accounts(tmp_path):
    mailbox = LocalMicrosoftMailboxPool(
        pool_text=(
            "saved@outlook.com----https://mail.example/inbox/saved\n"
            "orphan@outlook.com----https://mail.example/inbox/orphan"
        ),
        state_file=str(tmp_path / "mailbox-state.json"),
    )
    mailbox.get_email()
    mailbox.get_email()

    released = mailbox.release_unsaved_reservations({"SAVED@outlook.com"})

    assert released == ["orphan@outlook.com"]
    assert mailbox.available_count() == 1
    assert "saved@outlook.com" in mailbox._state()["used"]
    assert "orphan@outlook.com" not in mailbox._state()["used"]


def test_release_unsaved_reservations_removes_completed_managed_rows(tmp_path):
    mailbox = LocalMicrosoftMailboxPool(
        state_file=str(tmp_path / "mailbox-state.json"),
    )
    mailbox.import_registration_rows(
        "saved@outlook.com----https://mail.example/inbox/saved\n"
        "orphan@outlook.com----https://mail.example/inbox/orphan"
    )
    mailbox.get_email()
    mailbox.get_email()

    released = mailbox.release_unsaved_reservations({"saved@outlook.com"})
    snapshot = mailbox.registration_pool_snapshot()

    assert released == ["orphan@outlook.com"]
    assert snapshot["new_count"] == 0
    assert snapshot["failed_count"] == 1
    assert snapshot["items"][0]["email"] == "orphan@outlook.com"


def test_managed_registration_pool_imports_without_provider_rows(tmp_path):
    mailbox = LocalMicrosoftMailboxPool(
        state_file=str(tmp_path / "mailbox-state.json"),
    )

    result = mailbox.import_registration_rows(
        "new-one@icloud.com----https://mail.example/inbox/new-one\n"
        "new-two@icloud.com----Password123----JBSWY3DPEHPK3PXP"
    )

    assert result == {
        "imported": 2,
        "duplicates": 0,
        "skipped_used": 0,
        "invalid": 0,
    }
    snapshot = mailbox.registration_pool_snapshot()
    assert snapshot["new_count"] == 2
    assert snapshot["failed_count"] == 0
    assert snapshot["available_count"] == 2
    assert {item["email"] for item in snapshot["items"]} == {
        "new-one@icloud.com",
        "new-two@icloud.com",
    }


def test_managed_registration_pool_moves_failure_and_removes_success(tmp_path):
    mailbox = LocalMicrosoftMailboxPool(
        state_file=str(tmp_path / "mailbox-state.json"),
    )
    mailbox.import_registration_rows(
        "retry@icloud.com----https://mail.example/inbox/retry\n"
        "success@icloud.com----https://mail.example/inbox/success"
    )

    failed = mailbox.get_email()
    assert failed.email == "retry@icloud.com"
    assert mailbox.release_email(failed, error="OAuth callback timeout")

    retried = mailbox.get_email()
    assert retried.email == "retry@icloud.com"
    assert mailbox.mark_email_succeeded(retried)

    snapshot = mailbox.registration_pool_snapshot()
    assert snapshot["new_count"] == 1
    assert snapshot["failed_count"] == 0
    assert snapshot["items"][0]["email"] == "success@icloud.com"


def test_managed_registration_pool_records_failure_details(tmp_path):
    mailbox = LocalMicrosoftMailboxPool(
        state_file=str(tmp_path / "mailbox-state.json"),
    )
    mailbox.import_registration_rows(
        "retry@icloud.com----https://mail.example/inbox/retry"
    )

    account = mailbox.get_email()
    assert mailbox.release_email(account, error="invalid_state")

    snapshot = mailbox.registration_pool_snapshot()
    assert snapshot["new_count"] == 0
    assert snapshot["failed_count"] == 1
    assert snapshot["available_count"] == 1
    assert snapshot["items"][0]["status"] == "failed"
    assert snapshot["items"][0]["attempts"] == 1
    assert snapshot["items"][0]["error"] == "invalid_state"


def test_get_email_by_address_reserves_the_requested_pool_row(tmp_path):
    mailbox = LocalMicrosoftMailboxPool(
        pool_text=(
            "first@icloud.com----https://mail.example/inbox/first\n"
            "target@icloud.com----https://mail.example/inbox/target"
        ),
        state_file=str(tmp_path / "mailbox-state.json"),
    )

    account = mailbox.get_email_by_address("TARGET@icloud.com")

    assert account.email == "target@icloud.com"
    state = mailbox._state()
    assert "target@icloud.com" in state["used"]
    assert "first@icloud.com" not in state["used"]


def test_mailbox_identity_uses_exact_address_lookup_when_supported(tmp_path):
    mailbox = LocalMicrosoftMailboxPool(
        pool_text=(
            "first@icloud.com----https://mail.example/inbox/first\n"
            "target@icloud.com----https://mail.example/inbox/target"
        ),
        state_file=str(tmp_path / "mailbox-state.json"),
    )
    mailbox.get_current_ids = lambda account: {"existing-message"}

    identity = MailboxIdentityProvider(mailbox=mailbox).resolve("TARGET@icloud.com")

    assert identity.email == "TARGET@icloud.com"
    assert identity.mailbox_account.email == "target@icloud.com"
    assert identity.before_ids == {"existing-message"}
