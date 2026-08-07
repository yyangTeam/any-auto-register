"""SMS provider unit tests."""
from __future__ import annotations

import pytest
import threading
import time
from core.base_sms import (
    HeroSmsProvider,
    LongNotesSmsProvider,
    SmsActivation,
    SmsActivateProvider,
    create_sms_provider,
    create_phone_callbacks,
    SMS_ACTIVATE_SERVICES,
    SMS_ACTIVATE_COUNTRIES,
)
import core.base_sms as sms_module


class TestSmsActivateServiceMapping:
    def test_cursor_maps_to_ot(self):
        assert SMS_ACTIVATE_SERVICES["cursor"] == "ot"

    def test_chatgpt_maps_to_dr(self):
        assert SMS_ACTIVATE_SERVICES["chatgpt"] == "dr"

    def test_default_exists(self):
        assert "default" in SMS_ACTIVATE_SERVICES


class TestSmsActivateCountryMapping:
    def test_us_maps_to_187(self):
        assert SMS_ACTIVATE_COUNTRIES["us"] == "187"

    def test_ru_maps_to_0(self):
        assert SMS_ACTIVATE_COUNTRIES["ru"] == "0"

    def test_th_maps_to_52(self):
        assert SMS_ACTIVATE_COUNTRIES["th"] == "52"

    def test_default_exists(self):
        assert "default" in SMS_ACTIVATE_COUNTRIES


class TestCreateSmsProvider:
    def test_sms_activate(self):
        provider = create_sms_provider("sms_activate", {"sms_activate_api_key": "test123"})
        assert isinstance(provider, SmsActivateProvider)
        assert provider.api_key == "test123"

    def test_sms_activate_missing_key(self):
        with pytest.raises(RuntimeError, match="未配置"):
            create_sms_provider("sms_activate", {})

    def test_herosms(self):
        provider = create_sms_provider("herosms", {"herosms_api_key": "hero123"})
        assert isinstance(provider, HeroSmsProvider)
        assert provider.api_key == "hero123"
        assert provider.default_service == "dr"
        assert provider.default_country == "187"

    def test_herosms_reuse_flag_parses_string_false(self):
        provider = create_sms_provider(
            "herosms",
            {
                "herosms_api_key": "hero123",
                "register_reuse_phone_to_max": "false",
            },
        )
        assert isinstance(provider, HeroSmsProvider)
        assert provider.reuse_phone_to_max is False

    def test_herosms_missing_key(self):
        with pytest.raises(RuntimeError, match="HeroSMS 未配置"):
            create_sms_provider("herosms", {})

    def test_unknown_provider(self):
        with pytest.raises(RuntimeError, match="未知"):
            create_sms_provider("unknown", {})

    def test_longnotes_link(self):
        provider = create_sms_provider(
            "longnotes_link",
            {"longnotes_url": "https://longnotes.cn/m/share_token"},
        )
        assert isinstance(provider, LongNotesSmsProvider)


def test_longnotes_provider_gets_number_and_sms_code(monkeypatch):
    class Response:
        status_code = 200
        text = ""

        def __init__(self, payload=None):
            self.payload = payload or {}

        def json(self):
            return self.payload

    states = iter([
        Response({"data": {"orderState": "CANCELED", "phoneNumber": None, "smsMessages": []}}),
        Response({"data": {"orderState": "NUMBER_WAITING", "phoneNumber": None, "smsMessages": []}}),
        Response({"data": {"orderState": "PHONE_ACTIVE", "phoneNumber": "573001112233", "smsMessages": []}}),
        Response({"data": {"orderState": "SMS_RECEIVED", "phoneNumber": "573001112233", "smsMessages": [{"smsCode": "482913"}]}}),
        Response({"data": {"orderState": "CANCELED", "phoneNumber": None, "smsMessages": []}}),
    ])
    events = []

    class Session:
        proxies = {}

        def get(self, url, **kwargs):
            events.append(("get", url))
            return Response()

        def post(self, url, **kwargs):
            events.append(("post", url.rsplit("/", 1)[-1]))
            return next(states)

    provider = LongNotesSmsProvider("https://longnotes.cn/m/share_token", poll_interval=0.5)
    provider.session = Session()
    monkeypatch.setattr("core.base_sms.time.sleep", lambda seconds: None)

    activation = provider.get_number(service="chatgpt")
    code = provider.get_code(activation.activation_id, timeout=10)

    assert activation.phone_number == "+573001112233"
    assert code == "482913"
    assert provider.cancel(activation.activation_id) is True
    assert events == [
        ("get", "https://longnotes.cn/m/share_token"),
        ("post", "state"),
        ("post", "number"),
        ("post", "state"),
        ("post", "state"),
        ("post", "cancel"),
    ]


class TestCreatePhoneCallbacks:
    @pytest.fixture(autouse=True)
    def isolate_used_phone_registry(self, monkeypatch):
        monkeypatch.setattr(sms_module, "is_phone_number_used", lambda _number: False)
        monkeypatch.setattr(sms_module, "mark_phone_number_used", lambda *args, **kwargs: None)

    def test_returns_tuple(self):
        # This will fail on actual API call, but we can test the structure
        callback, cleanup = create_phone_callbacks(
            "sms_activate",
            {"sms_activate_api_key": "test"},
            service="cursor",
        )
        assert callable(callback)
        assert callable(cleanup)

    def test_provider_is_created_lazily_and_cleanup_cancels_pending_activation(self, monkeypatch):
        events = []
        logs = []

        class FakeProvider:
            def get_number(self, *, service: str, country: str = ""):
                events.append(("get_number", service, country))
                return SmsActivation(activation_id="act_1", phone_number="+15551234567")

            def get_code(self, activation_id: str, *, timeout: int = 120) -> str:
                events.append(("get_code", activation_id, timeout))
                return ""

            def cancel(self, activation_id: str) -> bool:
                events.append(("cancel", activation_id))
                return True

            def report_success(self, activation_id: str) -> bool:
                events.append(("report_success", activation_id))
                return True

        monkeypatch.setattr("core.base_sms.create_sms_provider", lambda provider_key, config: FakeProvider())

        callback, cleanup = create_phone_callbacks(
            "sms_activate",
            {"sms_activate_api_key": "test"},
            service="chatgpt",
            country="us",
            log_fn=logs.append,
        )

        assert events == []
        assert callback() == "+15551234567"
        cleanup()
        assert ("get_number", "chatgpt", "us") in events
        assert ("cancel", "act_1") in events
        assert any("正在租用手机号" in item for item in logs)
        assert any("租号成功" in item for item in logs)
        assert any("已释放未使用号码" in item for item in logs)

    def test_cleanup_does_not_cancel_after_success(self, monkeypatch):
        events = []
        logs = []

        class FakeProvider:
            def get_number(self, *, service: str, country: str = ""):
                events.append(("get_number", service, country))
                return SmsActivation(activation_id="act_2", phone_number="+15557654321")

            def get_code(self, activation_id: str, *, timeout: int = 120) -> str:
                events.append(("get_code", activation_id, timeout))
                return "123456"

            def cancel(self, activation_id: str) -> bool:
                events.append(("cancel", activation_id))
                return True

            def report_success(self, activation_id: str) -> bool:
                events.append(("report_success", activation_id))
                return True

        monkeypatch.setattr("core.base_sms.create_sms_provider", lambda provider_key, config: FakeProvider())

        callback, cleanup = create_phone_callbacks(
            "sms_activate",
            {"sms_activate_api_key": "test"},
            service="chatgpt",
            log_fn=logs.append,
        )

        assert callback() == "+15557654321"
        assert callback() == "123456"
        cleanup()
        assert ("report_success", "act_2") in events
        assert ("cancel", "act_2") not in events
        assert any("等待短信验证码" in item for item in logs)
        assert any("短信验证成功" in item for item in logs)

    def test_deferred_success_provider_reports_on_cleanup_for_legacy_callers(self, monkeypatch):
        events = []

        class FakeProvider:
            auto_report_success_on_code = False

            def get_number(self, *, service: str, country: str = ""):
                events.append(("get_number", service, country))
                return SmsActivation(activation_id="act_deferred", phone_number="+15550001111")

            def get_code(self, activation_id: str, *, timeout: int = 120) -> str:
                events.append(("get_code", activation_id, timeout))
                return "111222"

            def cancel(self, activation_id: str) -> bool:
                events.append(("cancel", activation_id))
                return True

            def report_success(self, activation_id: str) -> bool:
                events.append(("report_success", activation_id))
                return True

        monkeypatch.setattr("core.base_sms.create_sms_provider", lambda provider_key, config: FakeProvider())

        callback, cleanup = create_phone_callbacks(
            "herosms",
            {"herosms_api_key": "test"},
            service="cursor",
        )

        assert callback() == "+15550001111"
        assert callback() == "111222"
        cleanup()
        assert ("report_success", "act_deferred") in events
        assert ("cancel", "act_deferred") not in events

    def test_first_number_fetch_failure_does_not_poison_future_retries(self, monkeypatch):
        events = []

        class FakeProvider:
            def __init__(self):
                self.calls = 0

            def get_number(self, *, service: str, country: str = ""):
                self.calls += 1
                events.append(("get_number", self.calls, service, country))
                if self.calls == 1:
                    raise RuntimeError("temporary failure")
                return SmsActivation(activation_id="act_retry", phone_number="+66123456789")

            def get_code(self, activation_id: str, *, timeout: int = 120) -> str:
                events.append(("get_code", activation_id, timeout))
                return "654321"

            def cancel(self, activation_id: str) -> bool:
                events.append(("cancel", activation_id))
                return True

            def report_success(self, activation_id: str) -> bool:
                events.append(("report_success", activation_id))
                return True

        provider = FakeProvider()
        monkeypatch.setattr("core.base_sms.create_sms_provider", lambda provider_key, config: provider)

        callback, cleanup = create_phone_callbacks(
            "sms_activate",
            {"sms_activate_api_key": "test"},
            service="chatgpt",
            country="th",
        )

        assert callback() == "+66123456789"
        assert provider.calls == 2
        assert callback() == "654321"
        cleanup()
        assert ("report_success", "act_retry") in events

    def test_herosms_number_fetch_failure_releases_verify_lock(self, monkeypatch):
        class FakeProvider:
            def get_number(self, *, service: str, country: str = ""):
                raise RuntimeError("temporary failure")

        monkeypatch.setattr("core.base_sms.create_sms_provider", lambda provider_key, config: FakeProvider())

        callback, cleanup = create_phone_callbacks(
            "herosms",
            {"herosms_api_key": "test"},
            service="chatgpt",
        )

        with pytest.raises(RuntimeError, match="temporary failure"):
            callback()

        assert callback._verify_lock_acquired is False
        cleanup()

    def test_herosms_without_reuse_does_not_wait_for_verify_lock(self, monkeypatch):
        lock_ready = threading.Event()
        release_lock = threading.Event()

        def hold_lock():
            with sms_module._HERO_SMS_VERIFY_LOCK:
                lock_ready.set()
                release_lock.wait(timeout=2)

        holder = threading.Thread(target=hold_lock)
        holder.start()
        assert lock_ready.wait(timeout=1)

        class FakeProvider:
            reuse_phone_to_max = False

            def get_number(self, *, service: str, country: str = ""):
                return SmsActivation(activation_id="act_parallel", phone_number="+19990000001")

            def cancel(self, activation_id: str) -> bool:
                return True

        monkeypatch.setattr("core.base_sms.create_sms_provider", lambda provider_key, config: FakeProvider())
        monkeypatch.setattr("core.base_sms.is_phone_number_used", lambda _number: False)
        monkeypatch.setattr("core.base_sms.mark_phone_number_used", lambda *args, **kwargs: None)

        callback, cleanup = create_phone_callbacks(
            "herosms",
            {"herosms_api_key": "test", "register_reuse_phone_to_max": "false"},
            service="chatgpt",
        )
        try:
            started = time.monotonic()
            assert callback() == "+19990000001"
            assert time.monotonic() - started < 0.5
            assert callback._verify_lock_acquired is False
        finally:
            cleanup()
            release_lock.set()
            holder.join(timeout=1)

    def test_reuse_lock_wait_aborts_when_task_is_cancelled(self, monkeypatch):
        lock_ready = threading.Event()
        release_lock = threading.Event()
        cancelled = threading.Event()
        result: dict[str, object] = {}

        def hold_lock():
            with sms_module._HERO_SMS_VERIFY_LOCK:
                lock_ready.set()
                release_lock.wait(timeout=2)

        class FakeProvider:
            reuse_phone_to_max = True

            def get_number(self, *, service: str, country: str = ""):
                raise AssertionError("cancelled waiter must not rent a number")

        monkeypatch.setattr("core.base_sms.create_sms_provider", lambda provider_key, config: FakeProvider())
        holder = threading.Thread(target=hold_lock)
        holder.start()
        assert lock_ready.wait(timeout=1)

        callback, cleanup = create_phone_callbacks(
            "herosms",
            {"herosms_api_key": "test", "register_reuse_phone_to_max": "true"},
            service="chatgpt",
            cancel_check=cancelled.is_set,
        )

        def run_callback():
            try:
                callback()
            except Exception as exc:
                result["error"] = exc

        worker = threading.Thread(target=run_callback)
        worker.start()
        time.sleep(0.1)
        cancelled.set()
        worker.join(timeout=1)
        release_lock.set()
        holder.join(timeout=1)
        cleanup()

        assert not worker.is_alive()
        assert "任务已取消" in str(result.get("error") or "")

    def test_mark_send_succeeded_delegates_to_provider(self, monkeypatch):
        events = []

        class FakeProvider:
            def get_number(self, *, service: str, country: str = ""):
                return SmsActivation(activation_id="act_sent", phone_number="+15551234567")

            def mark_send_succeeded(self, activation_id: str) -> None:
                events.append(("mark_send_succeeded", activation_id))

            def cancel(self, activation_id: str) -> bool:
                events.append(("cancel", activation_id))
                return True

        monkeypatch.setattr("core.base_sms.create_sms_provider", lambda provider_key, config: FakeProvider())

        callback, cleanup = create_phone_callbacks(
            "herosms",
            {"herosms_api_key": "test"},
            service="chatgpt",
        )

        assert callback() == "+15551234567"
        callback.mark_send_succeeded()
        cleanup()
        assert ("mark_send_succeeded", "act_sent") in events


class TestSmsActivateProviderCountryResolution:
    def test_get_number_accepts_numeric_country_id(self, monkeypatch):
        captured = {}

        def fake_request(self, action: str, **params):
            captured["action"] = action
            captured["params"] = params
            return "NO_NUMBERS"

        monkeypatch.setattr(SmsActivateProvider, "_request", fake_request)
        provider = SmsActivateProvider("test123", default_country="ru")

        with pytest.raises(RuntimeError, match="NO_NUMBERS|无可用号码"):
            provider.get_number(service="chatgpt", country="52")

        assert captured["action"] == "getNumber"
        assert captured["params"]["country"] == "52"


class TestHeroSmsProvider:
    def test_non_reuse_number_request_does_not_wait_for_verify_lock(self, monkeypatch):
        lock_ready = threading.Event()
        release_lock = threading.Event()

        def hold_lock():
            with sms_module._HERO_SMS_VERIFY_LOCK:
                lock_ready.set()
                release_lock.wait(timeout=2)

        holder = threading.Thread(target=hold_lock)
        holder.start()
        assert lock_ready.wait(timeout=1)

        provider = HeroSmsProvider("hero123", reuse_phone_to_max=False)
        monkeypatch.setattr(provider, "_request_number_raw", lambda service, country: {
            "activationId": "act_parallel_real",
            "phoneNumber": "19990000002",
            "countryPhoneCode": "",
        })
        try:
            started = time.monotonic()
            activation = provider.get_number(service="chatgpt", country="187")
            assert time.monotonic() - started < 0.5
            assert activation.activation_id == "act_parallel_real"
        finally:
            release_lock.set()
            holder.join(timeout=1)

    def test_get_code_respects_caller_timeout_instead_of_activation_lifetime(self, monkeypatch):
        captured = {}
        provider = HeroSmsProvider("hero123")

        def fake_wait(activation_id: str, *, timeout: int = 180, poll_interval: int = 3):
            captured.update(activation_id=activation_id, timeout=timeout)
            return None

        monkeypatch.setattr(provider, "wait_for_code", fake_wait)
        assert provider.get_code("act_timeout", timeout=17) == ""
        assert captured == {"activation_id": "act_timeout", "timeout": 17}

    def test_wait_for_code_checks_task_cancellation_before_polling(self):
        provider = HeroSmsProvider("hero123")
        provider.cancel_check = lambda: True

        with pytest.raises(RuntimeError, match="任务已取消"):
            provider.wait_for_code("act_cancelled", timeout=90)

    def test_get_number_uses_v2_json(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sms_module, "hero_sms_cache_file", lambda: tmp_path / ".herosms_phone_cache.json")
        monkeypatch.setattr(sms_module, "_HERO_SMS_CACHE", None)
        calls = []

        class FakeResp:
            text = '{"activationId":"act_1","phoneNumber":"5551234","countryPhoneCode":"1","activationCost":"0.6"}'

            def raise_for_status(self):
                return None

            def json(self):
                return {"activationId": "act_1", "phoneNumber": "5551234", "countryPhoneCode": "1", "activationCost": "0.6"}

        def fake_get(url, params, timeout=30, proxies=None):
            calls.append(params)
            return FakeResp()

        monkeypatch.setattr("core.base_sms.requests.get", fake_get)
        provider = HeroSmsProvider("hero123")
        activation = provider.get_number(service="chatgpt", country="187")

        assert activation.activation_id == "act_1"
        assert activation.phone_number == "+15551234"
        assert [call["action"] for call in calls] == ["getPrices", "getNumberV2"]

    def test_get_number_falls_back_to_v1_text(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sms_module, "hero_sms_cache_file", lambda: tmp_path / ".herosms_phone_cache.json")
        monkeypatch.setattr(sms_module, "_HERO_SMS_CACHE", None)
        calls = []

        class FakeResp:
            def __init__(self, text):
                self.text = text

            def raise_for_status(self):
                return None

            def json(self):
                raise ValueError("not json")

        def fake_get(url, params, timeout=30, proxies=None):
            calls.append(params["action"])
            if params["action"] == "getNumberV2":
                return FakeResp("BAD")
            return FakeResp("ACCESS_NUMBER:act_2:15557654321")

        monkeypatch.setattr("core.base_sms.requests.get", fake_get)
        provider = HeroSmsProvider("hero123")
        activation = provider.get_number(service="chatgpt", country="187")

        assert activation.activation_id == "act_2"
        assert activation.phone_number == "+15557654321"
        assert calls == ["getPrices", "getNumberV2", "getNumber"]

    def test_get_code_skips_attempted_sms_event(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sms_module, "hero_sms_cache_file", lambda: tmp_path / ".herosms_phone_cache.json")
        monkeypatch.setattr(sms_module, "_HERO_SMS_CACHE", {
            "api_key_hash": sms_module._hash_secret("hero123"),
            "service": "dr",
            "country": "187",
            "activation_id": "act_3",
            "phone_number": "+15550000000",
            "acquired_at": sms_module.time.time(),
            "use_count": 0,
            "used_codes": set(),
            "attempted_sms_keys": set(),
            "reuse_stopped": False,
        })
        provider = HeroSmsProvider("hero123")
        first = {"status": "ok", "code": "111111", "sms_key": "sms_1", "allow_same_code": True}
        second = {"status": "ok", "code": "222222", "sms_key": "sms_2", "allow_same_code": True}
        results = [first, second]

        monkeypatch.setattr(provider, "get_status_v2", lambda activation_id: results.pop(0))
        monkeypatch.setattr(provider, "get_status", lambda activation_id: {"status": "wait_code"})
        monkeypatch.setattr(provider, "get_active_activations", lambda: [])
        monkeypatch.setattr(provider, "request_resend_sms", lambda activation_id: True)

        assert provider.get_code("act_3", timeout=1) == "111111"
        provider.mark_code_failed("act_3", "invalid otp")
        assert provider.get_code("act_3", timeout=1) == "222222"

    def test_mark_send_succeeded_sets_sms_sent_status(self, monkeypatch):
        calls = []
        provider = HeroSmsProvider("hero123")
        monkeypatch.setattr(provider, "set_status", lambda activation_id, status: calls.append((activation_id, status)) or "ACCESS_READY")

        provider.mark_send_succeeded("act_4")

        assert calls == [("act_4", 1)]

    def test_mark_code_failed_triggers_openai_and_herosms_resend(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sms_module, "hero_sms_cache_file", lambda: tmp_path / ".herosms_phone_cache.json")
        monkeypatch.setattr(sms_module, "_HERO_SMS_CACHE", {
            "api_key_hash": sms_module._hash_secret("hero123"),
            "service": "dr",
            "country": "187",
            "activation_id": "act_5",
            "phone_number": "+15550000000",
            "acquired_at": sms_module.time.time(),
            "use_count": 0,
            "used_codes": set(),
            "attempted_sms_keys": set(),
            "reuse_stopped": False,
        })
        events = []
        provider = HeroSmsProvider("hero123")
        provider.last_code_result = {"code": "333333", "sms_key": "sms_3"}
        provider.set_resend_callback(lambda: events.append(("openai_resend",)))
        monkeypatch.setattr(provider, "request_resend_sms", lambda activation_id: events.append(("hero_resend", activation_id)) or True)

        provider.mark_code_failed("act_5", "invalid otp")

        assert ("openai_resend",) in events
        assert ("hero_resend", "act_5") in events
        assert "333333" in sms_module._HERO_SMS_CACHE["used_codes"]
        assert "sms_3" in sms_module._HERO_SMS_CACHE["attempted_sms_keys"]

    def test_report_success_finishes_activation_when_reuse_disabled(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sms_module, "hero_sms_cache_file", lambda: tmp_path / ".herosms_phone_cache.json")
        monkeypatch.setattr(sms_module, "_HERO_SMS_CACHE", {
            "api_key_hash": sms_module._hash_secret("hero123"),
            "service": "dr",
            "country": "187",
            "activation_id": "act_6",
            "phone_number": "+15550000000",
            "acquired_at": sms_module.time.time(),
            "use_count": 0,
            "used_codes": set(),
            "attempted_sms_keys": set(),
            "reuse_stopped": False,
        })
        events = []
        provider = HeroSmsProvider("hero123", reuse_phone_to_max=False)
        provider.last_code_result = {"code": "444444", "sms_key": "sms_4"}
        monkeypatch.setattr(provider, "finish_activation", lambda activation_id: events.append(("finish", activation_id)) or True)

        assert provider.report_success("act_6") is True

        assert events == [("finish", "act_6")]
        assert sms_module._HERO_SMS_CACHE is None


class TestSmsActivation:
    def test_dataclass(self):
        a = SmsActivation(activation_id="123", phone_number="+79001234567")
        assert a.activation_id == "123"
        assert a.phone_number == "+79001234567"
        assert a.country == ""

    def test_with_country(self):
        a = SmsActivation(activation_id="1", phone_number="+1555", country="us")
        assert a.country == "us"
