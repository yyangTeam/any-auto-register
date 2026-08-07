from __future__ import annotations

from application.tasks import _register_attempt_budget, _resolve_sms_provider_for_task
from infrastructure.provider_settings_repository import ProviderSettingsRepository


def test_resolve_sms_provider_for_task_uses_saved_herosms_default():
    repo = ProviderSettingsRepository()
    repo.definitions.ensure_seeded()
    repo.save(
        setting_id=None,
        provider_type="sms",
        provider_key="herosms",
        display_name="HeroSMS",
        auth_mode="api_key",
        enabled=True,
        is_default=True,
        config={
            "sms_service": "dr",
            "sms_country": "187",
            "register_phone_extra_max": "3",
            "register_account_max_attempts": "1",
        },
        auth={"herosms_api_key": "hero123"},
        metadata={},
    )

    provider_key, settings = _resolve_sms_provider_for_task({})

    assert provider_key == "herosms"
    assert settings["herosms_api_key"] == "hero123"
    assert settings["sms_service"] == "dr"
    assert settings["register_account_max_attempts"] == "1"


def test_resolve_sms_provider_for_task_allows_inline_override():
    provider_key, settings = _resolve_sms_provider_for_task({
        "sms_provider": "herosms",
        "herosms_api_key": "inline",
        "sms_country": "52",
    })

    assert provider_key == "herosms"
    assert settings["herosms_api_key"] == "inline"
    assert settings["sms_country"] == "52"


def test_herosms_register_attempt_budget_defaults_to_one_pass():
    assert _register_attempt_budget(
        count=2,
        exhaustive_mailbox_run=False,
        herosms_enabled=True,
        max_success=2,
        sms_settings={},
    ) == 2


def test_herosms_register_attempt_budget_is_configurable():
    assert _register_attempt_budget(
        count=2,
        exhaustive_mailbox_run=False,
        herosms_enabled=True,
        max_success=2,
        sms_settings={"register_account_max_attempts": "3"},
    ) == 6
