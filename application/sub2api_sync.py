"""Upload saved ChatGPT accounts to a configured Sub2API instance."""
from __future__ import annotations

import logging
from typing import Any, Callable

import requests

from application.account_exports import _make_sub2api_json
from infrastructure.accounts_repository import AccountsRepository


logger = logging.getLogger(__name__)
DEFAULT_SUB2API_GROUP = "free"


def _ldxp_register_account_name(account: Any) -> str:
    extra = dict(getattr(account, "extra", {}) or {})
    trade_no = str(extra.get("source_trade_no") or "").strip()
    email = str(getattr(account, "email", "") or "").strip()
    return f"注册-{trade_no}-{email}" if trade_no and email else ""


class Sub2ApiClient:
    def __init__(self, base_url: str, api_key: str, *, timeout: int = 30):
        root = str(base_url or "").strip().rstrip("/")
        self.api_base = root if root.endswith("/api/v1") else f"{root}/api/v1"
        self.api_key = str(api_key or "").strip()
        self.timeout = timeout

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    @staticmethod
    def _payload(response: requests.Response) -> dict[str, Any]:
        try:
            payload = response.json()
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _response_error(response: requests.Response, payload: dict[str, Any]) -> str:
        detail = payload.get("message")
        return str(detail or f"HTTP {response.status_code}: {response.text[:200]}")

    def _resolve_group_id(self, group_name: str) -> tuple[int | None, str]:
        try:
            response = requests.get(
                f"{self.api_base}/admin/groups/all",
                headers=self._headers,
                params={"platform": "openai"},
                timeout=self.timeout,
            )
        except Exception as exc:
            return None, f"查询目标分组异常: {exc}"

        payload = self._payload(response)
        if response.status_code != 200 or payload.get("code") not in (None, 0):
            return None, f"查询目标分组失败: {self._response_error(response, payload)}"

        groups = payload.get("data") or []
        if isinstance(groups, dict):
            groups = groups.get("items") or []
        target = group_name.strip().casefold()
        for group in groups if isinstance(groups, list) else []:
            if not isinstance(group, dict) or str(group.get("name") or "").strip().casefold() != target:
                continue
            try:
                return int(group["id"]), ""
            except (KeyError, TypeError, ValueError):
                break
        return None, f"未找到目标分组 {group_name}"

    def _find_account_id(self, account_name: str) -> tuple[int | None, str]:
        try:
            response = requests.get(
                f"{self.api_base}/admin/accounts",
                headers=self._headers,
                params={
                    "page": 1,
                    "page_size": 100,
                    "platform": "openai",
                    "search": account_name,
                    "sort_by": "id",
                    "sort_order": "desc",
                },
                timeout=self.timeout,
            )
        except Exception as exc:
            return None, f"查询已上传账号异常: {exc}"

        payload = self._payload(response)
        if response.status_code != 200 or payload.get("code") not in (None, 0):
            return None, f"查询已上传账号失败: {self._response_error(response, payload)}"

        result = payload.get("data") or {}
        items = result.get("items") if isinstance(result, dict) else result
        target = account_name.strip().casefold()
        matches: list[int] = []
        for account in items if isinstance(items, list) else []:
            if not isinstance(account, dict) or str(account.get("name") or "").strip().casefold() != target:
                continue
            try:
                matches.append(int(account["id"]))
            except (KeyError, TypeError, ValueError):
                continue
        if not matches:
            return None, f"导入成功但未查到账号 {account_name}"
        return max(matches), ""

    def _bind_group(self, account_id: int, group_id: int, group_name: str) -> tuple[bool, str]:
        try:
            response = requests.put(
                f"{self.api_base}/admin/accounts/{account_id}",
                headers=self._headers,
                json={"group_ids": [group_id]},
                timeout=self.timeout,
            )
        except Exception as exc:
            return False, f"绑定分组 {group_name} 异常: {exc}"

        payload = self._payload(response)
        if response.status_code != 200 or payload.get("code") not in (None, 0):
            return False, f"绑定分组 {group_name} 失败: {self._response_error(response, payload)}"
        return True, ""

    def import_data(
        self,
        data: dict[str, Any],
        *,
        group_name: str = DEFAULT_SUB2API_GROUP,
    ) -> tuple[bool, str]:
        if not self.api_base or self.api_base == "/api/v1":
            return False, "Sub2API URL 未配置"
        if not self.api_key:
            return False, "Sub2API 管理密钥未配置"

        group_id, error = self._resolve_group_id(group_name)
        if group_id is None:
            return False, error

        try:
            response = requests.post(
                f"{self.api_base}/admin/accounts/data",
                headers=self._headers,
                json={"data": data, "skip_default_group_bind": True},
                timeout=self.timeout,
            )
        except Exception as exc:
            return False, f"请求异常: {exc}"

        payload = self._payload(response)
        if response.status_code not in (200, 201):
            return False, self._response_error(response, payload)
        if payload.get("code") not in (None, 0):
            return False, str(payload.get("message") or f"接口错误: {payload.get('code')}")

        result = payload.get("data", payload)
        if not isinstance(result, dict):
            return False, "Sub2API 导入响应格式异常"
        failed = int(result.get("account_failed") or 0)
        created = int(result.get("account_created") or 0)
        if failed:
            return False, f"导入失败 {failed} 个账号"

        accounts = data.get("accounts") or []
        account_name = str((accounts[0] if accounts else {}).get("name") or "").strip()
        if not account_name:
            return False, "导入成功但导入数据缺少账号名，未绑定分组"
        account_id, error = self._find_account_id(account_name)
        if account_id is None:
            return False, error
        bound, error = self._bind_group(account_id, group_id, group_name)
        if not bound:
            return False, error
        return True, f"同步成功（新增 {created}，已绑定分组 {group_name}）"


def _get_sub2api_config() -> tuple[bool, str, str]:
    try:
        from core.config_store import config_store

        base_url = config_store.get("sub2api_url", "").strip()
        api_key = config_store.get("sub2api_api_key", "").strip()
        enabled_value = config_store.get("sub2api_enabled", "").strip().lower()
        # Preserve the behavior of existing installations that already configured
        # Sub2API before the explicit enable switch was introduced.
        enabled = (
            enabled_value in {"1", "true", "yes", "on"}
            if enabled_value
            else bool(base_url and api_key)
        )
        return enabled, base_url, api_key
    except Exception:
        return False, "", ""


def push_saved_account_to_sub2api(
    account_id: int,
    *,
    log_fn: Callable[..., None] | None = None,
) -> bool:
    """Push one saved ChatGPT account and report every upload state."""
    log = log_fn or logger.info

    def emit(message: str, *, level: str = "info") -> None:
        try:
            log(message, level=level)
        except TypeError:
            log(message)

    enabled, base_url, api_key = _get_sub2api_config()
    if not enabled:
        emit("  [Sub2API] 未启用，跳过自动上传")
        return False
    if not base_url or not api_key:
        emit("  [Sub2API] 配置不完整，跳过自动上传", level="warning")
        return False

    account = AccountsRepository().get(int(account_id))
    if account is None:
        emit(f"  [Sub2API] 未找到账号 ID={account_id}，跳过自动上传", level="warning")
        return False
    if account.platform != "chatgpt":
        emit(f"  [Sub2API] {account.email} 不是 ChatGPT 账号，跳过自动上传")
        return False

    data = _make_sub2api_json(account)
    ldxp_name = _ldxp_register_account_name(account)
    if ldxp_name:
        accounts = data.get("accounts") if isinstance(data, dict) else None
        if accounts and isinstance(accounts, list) and isinstance(accounts[0], dict):
            accounts[0]["name"] = ldxp_name
    credentials = ((data.get("accounts") or [{}])[0].get("credentials") or {})
    if not credentials.get("access_token") or not credentials.get("refresh_token"):
        emit("  [Sub2API] 缺少 access_token 或 refresh_token，已跳过", level="warning")
        return False

    emit(
        f"  [Sub2API] 开始上传: {account.email} -> {base_url.rstrip('/')}，"
        f"目标分组: {DEFAULT_SUB2API_GROUP}"
    )
    ok, message = Sub2ApiClient(base_url, api_key).import_data(data)
    if ok:
        emit(f"  [Sub2API] ✓ {account.email} {message}")
    else:
        emit(f"  [Sub2API] ✗ {account.email} {message}", level="warning")
    return ok
