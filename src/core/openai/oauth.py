"""
OpenAI OAuth 授权模块
从 main.py 中提取的 OAuth 相关函数
"""

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from curl_cffi import requests as cffi_requests

from ...config.constants import (
    OPENAI_IMPERSONATE,
    OPENAI_SEC_CH_UA,
    OPENAI_SEC_CH_UA_MOBILE,
    OPENAI_SEC_CH_UA_PLATFORM,
    OPENAI_USER_AGENT,
    OAUTH_CLIENT_ID,
    OAUTH_AUTH_URL,
    OAUTH_TOKEN_URL,
    OAUTH_REDIRECT_URI,
    OAUTH_SCOPE,
)


def _b64url_no_pad(raw: bytes) -> str:
    """Base64 URL 编码（无填充）"""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    """SHA256 哈希后 Base64 URL 编码"""
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    """生成随机 state"""
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    """生成 PKCE code_verifier"""
    return secrets.token_urlsafe(64)


def _parse_callback_url(callback_url: str) -> Dict[str, str]:
    """解析回调 URL"""
    candidate = callback_url.strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}

    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"

    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)

    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip():
            query[key] = values

    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()

    code = get1("code")
    state = get1("state")
    error = get1("error")
    error_description = get1("error_description")

    if code and not state and "#" in code:
        code, state = code.split("#", 1)

    if not error and error_description:
        error, error_description = error_description, ""

    return {
        "code": code,
        "state": state,
        "error": error,
        "error_description": error_description,
    }


def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    """解析 JWT ID Token（不验证签名）"""
    if not id_token or id_token.count(".") < 2:
        return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}


def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    """解码 JWT 片段"""
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def _to_int(v: Any) -> int:
    """转换为整数"""
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _normalize_claim_list(value: Any) -> List[str]:
    """将 JWT claim 规范化为字符串列表。"""
    if isinstance(value, (list, tuple, set)):
        result: List[str] = []
        for item in value:
            text = str(item or "").strip()
            if text:
                result.append(text)
        return result
    text = str(value or "").strip()
    return [text] if text else []


def is_oauth_token_source(token_source: Optional[str]) -> bool:
    """判断 token_source 是否属于 OAuth 授权来源。"""
    source = str(token_source or "").strip().lower()
    return source in {"oauth", "browser_oauth", "codex_oauth"}


def extract_token_binding_profile(
    *,
    access_token: str = "",
    id_token: str = "",
    scope: str = "",
) -> Dict[str, Any]:
    """
    提取 Token 绑定信息（client_id/audience/scope）。

    说明：
    - 优先从 id_token 读取 claim；
    - id_token 不足时回退到 access_token；
    - 不验证签名，仅做本地结构校验与字段提取。
    """
    id_claims = _jwt_claims_no_verify(id_token)
    access_claims = _jwt_claims_no_verify(access_token)

    issued_client_id = ""
    for candidate in (
        id_claims.get("azp"),
        id_claims.get("client_id"),
        access_claims.get("azp"),
        access_claims.get("client_id"),
    ):
        text = str(candidate or "").strip()
        if text:
            issued_client_id = text
            break

    audiences = _normalize_claim_list(id_claims.get("aud"))
    if not audiences:
        audiences = _normalize_claim_list(access_claims.get("aud"))

    scope_text = str(
        scope
        or id_claims.get("scope")
        or access_claims.get("scope")
        or access_claims.get("scp")
        or ""
    ).strip()

    return {
        "issued_client_id": issued_client_id,
        "audiences": audiences,
        "scope": scope_text,
        "id_claims": id_claims,
        "access_claims": access_claims,
    }


def validate_token_binding(
    *,
    expected_client_id: str,
    access_token: str = "",
    id_token: str = "",
    refresh_token: str = "",
    token_source: str = "",
    scope: str = "",
    require_refresh_token: bool = False,
    require_oauth_source: bool = False,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    校验 Token 与目标 OAuth Client 的绑定关系。

    Returns:
        (is_valid, reason, profile)
    """
    profile = extract_token_binding_profile(
        access_token=access_token,
        id_token=id_token,
        scope=scope,
    )

    if require_refresh_token and not str(refresh_token or "").strip():
        return False, "缺少 refresh_token", profile

    source = str(token_source or "").strip().lower()
    if require_oauth_source and source and not is_oauth_token_source(source):
        return False, f"token_source={source} 非 OAuth 来源", profile

    expected = str(expected_client_id or "").strip()
    if not expected:
        return True, "", profile

    issued_client_id = str(profile.get("issued_client_id") or "").strip()
    if issued_client_id and issued_client_id != expected:
        return False, f"token client_id 不匹配: {issued_client_id}", profile

    audiences = profile.get("audiences") or []
    if audiences and (expected not in audiences) and not issued_client_id:
        return False, f"token audience 不匹配: {audiences}", profile

    return True, "", profile


def _post_form(
    url: str,
    data: Dict[str, str],
    timeout: int = 30,
    proxy_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    发送 POST 表单请求

    Args:
        url: 请求 URL
        data: 表单数据
        timeout: 超时时间
        proxy_url: 代理 URL

    Returns:
        响应 JSON 数据
    """
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": OPENAI_USER_AGENT,
        "sec-ch-ua": OPENAI_SEC_CH_UA,
        "sec-ch-ua-mobile": OPENAI_SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": OPENAI_SEC_CH_UA_PLATFORM,
    }

    try:
        response = cffi_requests.post(
            url,
            data=data,
            headers=headers,
            timeout=timeout,
            proxies=proxies,
            impersonate=OPENAI_IMPERSONATE,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"token exchange failed: {response.status_code}: {response.text}"
            )

        return response.json()

    except cffi_requests.RequestsError as e:
        raise RuntimeError(f"token exchange failed: network error: {e}") from e


@dataclass(frozen=True)
class OAuthStart:
    """OAuth 开始信息"""
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str


def generate_oauth_url(
    *,
    redirect_uri: str = OAUTH_REDIRECT_URI,
    scope: str = OAUTH_SCOPE,
    client_id: str = OAUTH_CLIENT_ID
) -> OAuthStart:
    """
    生成 OAuth 授权 URL

    Args:
        redirect_uri: 回调地址
        scope: 权限范围
        client_id: OpenAI Client ID

    Returns:
        OAuthStart 对象，包含授权 URL 和必要参数
    """
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)

    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    auth_url = f"{OAUTH_AUTH_URL}?{urllib.parse.urlencode(params)}"
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )


def submit_callback_url(
    *,
    callback_url: str,
    expected_state: str,
    code_verifier: str,
    redirect_uri: str = OAUTH_REDIRECT_URI,
    client_id: str = OAUTH_CLIENT_ID,
    token_url: str = OAUTH_TOKEN_URL,
    proxy_url: Optional[str] = None
) -> str:
    """
    处理 OAuth 回调 URL，获取访问令牌

    Args:
        callback_url: 回调 URL
        expected_state: 预期的 state 值
        code_verifier: PKCE code_verifier
        redirect_uri: 回调地址
        client_id: OpenAI Client ID
        token_url: Token 交换地址
        proxy_url: 代理 URL

    Returns:
        包含访问令牌等信息的 JSON 字符串

    Raises:
        RuntimeError: OAuth 错误
        ValueError: 缺少必要参数或 state 不匹配
    """
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        desc = cb["error_description"]
        raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())

    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        token_url,
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        proxy_url=proxy_url
    )

    access_token = (token_resp.get("access_token") or "").strip()
    refresh_token = (token_resp.get("refresh_token") or "").strip()
    id_token = (token_resp.get("id_token") or "").strip()
    token_scope = str(token_resp.get("scope") or "").strip()
    expires_in = _to_int(token_resp.get("expires_in"))

    profile_ok, profile_reason, profile = validate_token_binding(
        expected_client_id=client_id,
        access_token=access_token,
        id_token=id_token,
        refresh_token=refresh_token,
        scope=token_scope,
        require_refresh_token=True,
    )
    if not profile_ok:
        raise RuntimeError(f"oauth token 绑定校验失败: {profile_reason}")

    claims = _jwt_claims_no_verify(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

    now = int(time.time())
    expired_rfc3339 = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0))
    )
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": now_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
        "issued_client_id": str(profile.get("issued_client_id") or "").strip(),
        "token_audience": profile.get("audiences") or [],
        "token_scope": token_scope or str(profile.get("scope") or "").strip(),
    }

    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


class OAuthManager:
    """OAuth 管理器"""

    def __init__(
        self,
        client_id: str = OAUTH_CLIENT_ID,
        auth_url: str = OAUTH_AUTH_URL,
        token_url: str = OAUTH_TOKEN_URL,
        redirect_uri: str = OAUTH_REDIRECT_URI,
        scope: str = OAUTH_SCOPE,
        proxy_url: Optional[str] = None
    ):
        self.client_id = client_id
        self.auth_url = auth_url
        self.token_url = token_url
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.proxy_url = proxy_url

    def start_oauth(self) -> OAuthStart:
        """开始 OAuth 流程"""
        return generate_oauth_url(
            redirect_uri=self.redirect_uri,
            scope=self.scope,
            client_id=self.client_id
        )

    def handle_callback(
        self,
        callback_url: str,
        expected_state: str,
        code_verifier: str
    ) -> Dict[str, Any]:
        """处理 OAuth 回调"""
        result_json = submit_callback_url(
            callback_url=callback_url,
            expected_state=expected_state,
            code_verifier=code_verifier,
            redirect_uri=self.redirect_uri,
            client_id=self.client_id,
            token_url=self.token_url,
            proxy_url=self.proxy_url
        )
        return json.loads(result_json)

    def extract_account_info(self, id_token: str) -> Dict[str, Any]:
        """从 ID Token 中提取账户信息"""
        claims = _jwt_claims_no_verify(id_token)
        email = str(claims.get("email") or "").strip()
        auth_claims = claims.get("https://api.openai.com/auth") or {}
        account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

        return {
            "email": email,
            "account_id": account_id,
            "claims": claims
        }
