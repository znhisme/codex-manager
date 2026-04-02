import base64
import json

from src.config.constants import EmailServiceType
from src.core.register import RegistrationEngine, _extract_account_id_from_jwt
from src.services.base import BaseEmailService


class FakeEmailService(BaseEmailService):
    def __init__(self):
        super().__init__(EmailServiceType.TEMPMAIL)

    def create_email(self, config=None):
        return {"email": "tester@example.com", "service_id": "mailbox-1"}

    def get_verification_code(
        self,
        email,
        email_id=None,
        timeout=120,
        pattern=r"(?<!\d)(\d{6})(?!\d)",
        otp_sent_at=None,
    ):
        return "123456"

    def list_emails(self, **kwargs):
        return []

    def delete_email(self, email_id):
        return True

    def check_health(self):
        return True


def _make_jwt(payload: dict) -> str:
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return f"header.{payload_b64}.sig"


def test_extract_account_id_from_jwt_prefers_auth_claim():
    token = _make_jwt(
        {
            "https://api.openai.com/auth": {"chatgpt_account_id": "acct-auth-1"},
            "chatgpt_account_id": "acct-fallback",
        }
    )
    assert _extract_account_id_from_jwt(token) == "acct-auth-1"


def test_extract_account_id_from_jwt_invalid_returns_empty():
    assert _extract_account_id_from_jwt("not-a-jwt") == ""


def test_registration_engine_get_oauth_tokens_returns_none():
    engine = RegistrationEngine(FakeEmailService(), token_mode="oauth")
    assert engine.get_oauth_tokens() is None
    assert any("已拦截旧 get_oauth_tokens 调用" in line for line in engine.logs)


def test_registration_engine_run_returns_disabled_result_with_cookie_fallback():
    engine = RegistrationEngine(FakeEmailService(), token_mode="oauth")
    engine.email = "tester@example.com"
    engine.password = "pass-1234"
    engine.session.cookies.set(
        "__Secure-next-auth.session-token",
        "session-token-1",
        domain="chatgpt.com",
    )

    result = engine.run()

    assert result.success is False
    assert result.session_token == "session-token-1"
    assert result.metadata.get("legacy_engine_removed") is True
