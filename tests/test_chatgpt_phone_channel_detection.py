from __future__ import annotations

import pytest

from platforms.chatgpt import browser_register as browser_register_module
from platforms.chatgpt.browser_register import (
    _click_sms_send_button,
    _whatsapp_verification_reason,
)


@pytest.mark.parametrize(
    "page_text",
    [
        "Verify your phone number. Send code via SMS. Send code via WhatsApp.",
        "Enter the SMS code. Didn't get it? Resend WhatsApp.",
        "Enter your verification code. Try WhatsApp instead.",
        "Text message selected. WhatsApp is also available.",
    ],
)
def test_whatsapp_option_does_not_count_as_whatsapp_verification(page_text):
    assert _whatsapp_verification_reason(page_text) == ""


@pytest.mark.parametrize(
    "page_text",
    [
        "We sent a verification code to your WhatsApp. Enter it below.",
        "Open WhatsApp to get your verification code.",
        "Enter the code from your WhatsApp account.",
        "Verification is required via WhatsApp.",
        "验证码已发送到 WhatsApp，请输入验证码。",
    ],
)
def test_explicit_whatsapp_verification_prompt_is_detected(page_text):
    assert _whatsapp_verification_reason(page_text)


def test_selected_whatsapp_channel_without_prompt_is_not_treated_as_required():
    assert _whatsapp_verification_reason("Enter your code", "whatsapp") == ""


def test_selected_sms_channel_is_not_treated_as_whatsapp():
    assert _whatsapp_verification_reason("Enter your SMS code. Try WhatsApp instead.", "sms") == ""


def test_initial_whatsapp_wording_does_not_block_phone_form_submission(monkeypatch):
    class FakePage:
        def evaluate(self, script):
            return {"ok": False, "text": ""}

    monkeypatch.setattr(browser_register_module, "_select_sms_phone_channel", lambda page, log: False)
    monkeypatch.setattr(browser_register_module, "_visible_button_texts", lambda page: [])
    monkeypatch.setattr(
        browser_register_module,
        "_get_visible_page_text",
        lambda page: "Verify your phone number with WhatsApp",
    )
    monkeypatch.setattr(browser_register_module.time, "sleep", lambda seconds: None)

    assert _click_sms_send_button(FakePage(), lambda message, level="info": None) is None
