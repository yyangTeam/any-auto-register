from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from application.sub2api_sync import Sub2ApiClient, push_saved_account_to_sub2api
from application.tasks import _auto_push_sub2api
from domain.accounts import AccountRecord


def _response(status_code: int, payload: dict) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    response.text = str(payload)
    return response


def _account() -> AccountRecord:
    return AccountRecord(
        id=7,
        platform="chatgpt",
        email="user@example.com",
        password="password",
        user_id="account-id",
        credentials=[
            {"scope": "platform", "key": "access_token", "value": "access-token"},
            {"scope": "platform", "key": "refresh_token", "value": "refresh-token"},
        ],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def test_client_uses_admin_api_key_and_import_endpoint():
    group_response = _response(200, {
        "code": 0,
        "message": "success",
        "data": [{"id": 5, "name": "free", "platform": "openai"}],
    })
    import_response = _response(200, {
        "code": 0,
        "message": "success",
        "data": {"account_created": 1, "account_failed": 0},
    })
    account_response = _response(200, {
        "code": 0,
        "message": "success",
        "data": {"items": [{"id": 17, "name": "user@example.com"}]},
    })
    bind_response = _response(200, {
        "code": 0,
        "message": "success",
        "data": {"id": 17, "group_ids": [5]},
    })
    client = Sub2ApiClient("https://sub.example.com", "admin-key")
    data = {
        "type": "sub2api-data",
        "accounts": [{"name": "user@example.com"}],
    }

    with (
        patch("application.sub2api_sync.requests.get", side_effect=[group_response, account_response]) as get,
        patch("application.sub2api_sync.requests.post", return_value=import_response) as post,
        patch("application.sub2api_sync.requests.put", return_value=bind_response) as put,
    ):
        ok, message = client.import_data(data)

    assert ok is True
    assert "新增 1" in message
    assert "已绑定分组 free" in message
    assert get.call_args_list[0].args[0] == "https://sub.example.com/api/v1/admin/groups/all"
    assert get.call_args_list[0].kwargs["params"] == {"platform": "openai"}
    request = post.call_args
    assert request.args[0] == "https://sub.example.com/api/v1/admin/accounts/data"
    assert request.kwargs["headers"]["X-API-Key"] == "admin-key"
    assert request.kwargs["json"]["skip_default_group_bind"] is True
    assert get.call_args_list[1].kwargs["params"]["search"] == "user@example.com"
    assert put.call_args.args[0] == "https://sub.example.com/api/v1/admin/accounts/17"
    assert put.call_args.kwargs["json"] == {"group_ids": [5]}


def test_client_reports_api_failure():
    response = _response(401, {"code": "UNAUTHORIZED", "message": "bad key"})
    with patch("application.sub2api_sync.requests.get", return_value=response):
        ok, message = Sub2ApiClient("https://sub.example.com/api/v1", "bad").import_data({})

    assert ok is False
    assert message == "查询目标分组失败: bad key"


def test_client_stops_before_import_when_free_group_is_missing():
    response = _response(200, {
        "code": 0,
        "message": "success",
        "data": [{"id": 4, "name": "plus", "platform": "openai"}],
    })
    with (
        patch("application.sub2api_sync.requests.get", return_value=response),
        patch("application.sub2api_sync.requests.post") as post,
    ):
        ok, message = Sub2ApiClient("https://sub.example.com", "admin-key").import_data({})

    assert ok is False
    assert message == "未找到目标分组 free"
    post.assert_not_called()


def test_client_reports_group_binding_failure_after_import():
    group_response = _response(200, {
        "code": 0,
        "message": "success",
        "data": [{"id": 5, "name": "free", "platform": "openai"}],
    })
    import_response = _response(200, {
        "code": 0,
        "message": "success",
        "data": {"account_created": 1, "account_failed": 0},
    })
    account_response = _response(200, {
        "code": 0,
        "message": "success",
        "data": {"items": [{"id": 17, "name": "user@example.com"}]},
    })
    bind_response = _response(409, {
        "code": 409,
        "message": "group conflict",
    })
    data = {"accounts": [{"name": "user@example.com"}]}

    with (
        patch("application.sub2api_sync.requests.get", side_effect=[group_response, account_response]),
        patch("application.sub2api_sync.requests.post", return_value=import_response),
        patch("application.sub2api_sync.requests.put", return_value=bind_response),
    ):
        ok, message = Sub2ApiClient("https://sub.example.com", "admin-key").import_data(data)

    assert ok is False
    assert message == "绑定分组 free 失败: group conflict"


def test_push_saved_chatgpt_account_reuses_export_format():
    logs = []
    with (
        patch("application.sub2api_sync._get_sub2api_config", return_value=(True, "https://sub.example.com", "admin-key")),
        patch("application.sub2api_sync.AccountsRepository.get", return_value=_account()),
        patch.object(Sub2ApiClient, "import_data", return_value=(True, "同步成功（新增 1）")) as upload,
    ):
        assert push_saved_account_to_sub2api(7, log_fn=logs.append) is True

    data = upload.call_args.args[0]
    assert data["type"] == "sub2api-data"
    assert data["accounts"][0]["name"] == "user@example.com"
    assert data["accounts"][0]["credentials"]["refresh_token"] == "refresh-token"
    assert any("开始上传: user@example.com -> https://sub.example.com，目标分组: free" in line for line in logs)
    assert any("✓ user@example.com 同步成功（新增 1）" in line for line in logs)
    assert all("admin-key" not in line for line in logs)


def test_push_skips_when_not_configured():
    logs = []
    with patch("application.sub2api_sync._get_sub2api_config", return_value=(False, "", "")):
        assert push_saved_account_to_sub2api(7, log_fn=logs.append) is False

    assert logs == ["  [Sub2API] 未启用，跳过自动上传"]


def test_push_reports_upload_failure_without_leaking_key():
    logs = []
    with (
        patch("application.sub2api_sync._get_sub2api_config", return_value=(True, "https://sub.example.com/", "secret-key")),
        patch("application.sub2api_sync.AccountsRepository.get", return_value=_account()),
        patch.object(Sub2ApiClient, "import_data", return_value=(False, "HTTP 503")),
    ):
        assert push_saved_account_to_sub2api(7, log_fn=logs.append) is False

    assert any("开始上传: user@example.com -> https://sub.example.com，目标分组: free" in line for line in logs)
    assert any("✗ user@example.com HTTP 503" in line for line in logs)
    assert all("secret-key" not in line for line in logs)


def test_auto_push_exception_does_not_escape_registration_post_processing():
    class DetachedAccount:
        @property
        def id(self):
            raise RuntimeError("detached")

    task_logger = MagicMock()
    _auto_push_sub2api(task_logger, DetachedAccount())

    task_logger.log.assert_called_once()
    assert "自动推送异常: detached" in task_logger.log.call_args.args[0]
    assert task_logger.log.call_args.kwargs["level"] == "warning"
