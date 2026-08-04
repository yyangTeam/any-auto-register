from __future__ import annotations

from core.local_ms_mailbox import LocalMicrosoftMailboxPool


def test_update_mailbox_pool_row_api(client, monkeypatch, tmp_path):
    pool = LocalMicrosoftMailboxPool(
        state_file=str(tmp_path / "mailbox-state.json"),
    )
    pool.import_registration_rows(
        "old@icloud.com----https://mail.example/inbox/old"
    )
    monkeypatch.setattr(
        "api.sms._managed_mailbox_pool",
        lambda: ("local-mailbox", pool),
    )

    response = client.put(
        "/api/sms/mailbox-pool/old@icloud.com",
        json={
            "source_row": (
                "new@icloud.com------https://flysms.xyz/icloud/pickup#"
                "email=new%40icloud.com&key=tok_updated-key"
            ),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["provider_key"] == "local-mailbox"
    assert payload["updated"]["email"] == "new@icloud.com"
    assert payload["pool"]["items"][0]["email"] == "new@icloud.com"
