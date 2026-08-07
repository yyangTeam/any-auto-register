from __future__ import annotations

from types import SimpleNamespace

from core.base_platform import RegisterConfig
from core.registration import BrowserRegistrationAdapter, BrowserRegistrationFlow, RegistrationContext, RegistrationResult
import core.registration.flows as flows_module
import core.registration.helpers as helpers_module


def test_browser_flow_wires_phone_callback_and_runs_cleanup(monkeypatch):
    events = []

    def fake_build_phone_callbacks(ctx, *, service=None):
        events.append(("build", service))
        return (lambda: "18885551234", lambda: events.append(("cleanup", service)))

    monkeypatch.setattr(flows_module, "build_phone_callbacks", fake_build_phone_callbacks)

    ctx = RegistrationContext(
        platform_name="chatgpt",
        platform_display_name="ChatGPT",
        platform=SimpleNamespace(mailbox=None),
        identity=SimpleNamespace(
            email="user@example.com",
            has_mailbox=True,
            identity_provider="mailbox",
        ),
        config=RegisterConfig(executor_type="headless", extra={}),
        email="user@example.com",
        password="Secret123!",
        log_fn=lambda message: None,
    )

    def build_worker(ctx, artifacts):
        assert callable(artifacts.phone_callback)
        return SimpleNamespace(phone_callback=artifacts.phone_callback)

    def run_worker(worker, ctx, artifacts):
        events.append(("callback", worker.phone_callback()))
        return {"email": ctx.identity.email, "password": ctx.password}

    adapter = BrowserRegistrationAdapter(
        result_mapper=lambda ctx, raw: RegistrationResult(email=raw["email"], password=raw["password"]),
        browser_worker_builder=build_worker,
        browser_register_runner=run_worker,
    )

    result = BrowserRegistrationFlow(adapter).run(ctx)

    assert result.email == "user@example.com"
    assert ("build", "chatgpt") in events
    assert ("callback", "18885551234") in events
    assert ("cleanup", "chatgpt") in events


def test_mailbox_auxiliary_phone_url_overrides_global_sms_provider(monkeypatch):
    captured = {}

    def fake_create_phone_callbacks(provider_key, config, **kwargs):
        captured.update(provider_key=provider_key, config=config, kwargs=kwargs)
        return (lambda: "+573001112233", lambda: None)

    monkeypatch.setattr(helpers_module, "create_phone_callbacks", fake_create_phone_callbacks)
    logs = []
    ctx = RegistrationContext(
        platform_name="chatgpt",
        platform_display_name="ChatGPT",
        platform=SimpleNamespace(mailbox=object()),
        identity=SimpleNamespace(
            mailbox_account=SimpleNamespace(
                extra={
                    "provider_account": {
                        "credentials": {
                            "auxiliary_phone_url": "https://longnotes.cn/m/share_token",
                        }
                    }
                }
            )
        ),
        config=RegisterConfig(
            executor_type="protocol",
            proxy="http://proxy.example:8080",
            extra={"sms_provider": "herosms_api"},
        ),
        email="user@icloud.com",
        password="",
        log_fn=logs.append,
    )

    callback, cleanup = helpers_module.build_phone_callbacks(ctx, service="chatgpt")

    assert callable(callback)
    assert callable(cleanup)
    assert captured["provider_key"] == "longnotes_link"
    assert captured["config"]["longnotes_url"] == "https://longnotes.cn/m/share_token"
    assert captured["config"]["sms_proxy"] == "http://proxy.example:8080"
    assert any("邮箱记录自带" in message for message in logs)
