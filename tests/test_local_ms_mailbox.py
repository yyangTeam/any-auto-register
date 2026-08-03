from __future__ import annotations

from types import SimpleNamespace
import json

import pytest

from core.local_ms_mailbox import (
    FLYSMS_LATEST_MESSAGE_URL,
    LocalMicrosoftMailboxEntry,
    LocalMicrosoftMailboxPool,
    OUTLOOK_IMAP_SCOPE,
    OUTLOOK_TOKEN_URL,
    parse_xinlan_common_rows,
)


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


def test_flysms_pickup_uses_api_and_maps_latest_message(monkeypatch):
    entry = parse_xinlan_common_rows(
        "relay@icloud.com------"
        "https://flysms.xyz/icloud/pickup#email=relay%40icloud.com&key=tok_test-key"
    )[0]
    captured = {}

    class Response:
        status_code = 200
        headers = {"content-type": "application/json"}

        @staticmethod
        def json():
            return {
                "email": "relay@icloud.com",
                "entitlementStatus": "active",
                "message": {
                    "mailbox": "INBOX",
                    "uid": 42,
                    "subject": "Your temporary ChatGPT login code",
                    "from": "ChatGPT <noreply@example.com>",
                    "date": "2026-08-03T13:57:39.000Z",
                    "mailboxReceivedAt": "2026-08-03T13:57:40.000Z",
                    "text": "Your login code is 123456",
                    "html": "<strong>123456</strong>",
                },
            }

    def fake_get(url, *, headers, proxies, timeout):
        captured.update(url=url, headers=headers, proxies=proxies, timeout=timeout)
        return Response()

    monkeypatch.setattr("core.local_ms_mailbox.requests.get", fake_get)

    messages = LocalMicrosoftMailboxPool()._icloud_api_messages(entry)

    assert captured["url"] == FLYSMS_LATEST_MESSAGE_URL
    assert captured["headers"]["authorization"] == "Bearer tok_test-key"
    assert captured["headers"]["x-mailbox-email"] == "relay@icloud.com"
    assert messages[0]["subject"] == "Your temporary ChatGPT login code"
    assert "123456" in messages[0]["bodyPreview"]
    assert messages[0]["receivedDateTime"] == "2026-08-03T13:57:40.000Z"


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
        pool_text="first@outlook.com----password\nsecond@outlook.com----password",
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
        pool_text="first@outlook.com----password\nsecond@outlook.com----password",
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
        pool_text="first@outlook.com----password\nsecond@outlook.com----password",
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
        pool_text="first@outlook.com----password",
        state_file=str(state_file),
        failure_cooldown_seconds=1800,
    )

    assert mailbox.get_email().email == "first@outlook.com"


def test_network_failure_release_does_not_cool_down_mailbox(tmp_path):
    state_file = tmp_path / "mailbox-state.json"
    mailbox = LocalMicrosoftMailboxPool(
        pool_text="first@outlook.com----password",
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
        pool_text="first@outlook.com----password",
        state_file=str(state_file),
        failure_cooldown_seconds=1800,
    )

    assert mailbox.clear_failure_cooldowns(["first@outlook.com"]) == 1
    assert mailbox.peek_email() == "first@outlook.com"


def test_release_unsaved_reservations_keeps_saved_accounts(tmp_path):
    mailbox = LocalMicrosoftMailboxPool(
        pool_text="saved@outlook.com----password\norphan@outlook.com----password",
        state_file=str(tmp_path / "mailbox-state.json"),
    )
    mailbox.get_email()
    mailbox.get_email()

    released = mailbox.release_unsaved_reservations({"SAVED@outlook.com"})

    assert released == ["orphan@outlook.com"]
    assert mailbox.available_count() == 1
    assert "saved@outlook.com" in mailbox._state()["used"]
    assert "orphan@outlook.com" not in mailbox._state()["used"]
