from typing import Any, Dict, Optional
import httpx

async def make_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    token: Optional[str] = None,
    auth_header_prefix: str = "Bearer",
    **kwargs
) -> httpx.Response:
    """
    Make an authenticated request.
    Supports different Authorization header styles.
    """
    headers = kwargs.pop("headers", {})

    if token:
        if auth_header_prefix.lower() == "raw":
            headers["Authorization"] = token
        else:
            headers["Authorization"] = f"{auth_header_prefix} {token}"

    response = await client.request(
        method=method.upper(),
        url=url,
        headers=headers,
        **kwargs
    )
    return response

def is_success(status_code: int) -> bool:
    return 200 <= status_code < 300

def is_unauthorized(status_code: int) -> bool:
    return status_code in (401, 403)

def response_similarity(content1: bytes, content2: bytes) -> float:
    """
    Very basic similarity check based on length.
    Returns a value between 0 and 1.
    """
    len1 = len(content1)
    len2 = len(content2)

    if len1 == 0 and len2 == 0:
        return 1.0
    if len1 == 0 or len2 == 0:
        return 0.0

    diff = abs(len1 - len2)
    max_len = max(len1, len2)
    return 1.0 - (diff / max_len)