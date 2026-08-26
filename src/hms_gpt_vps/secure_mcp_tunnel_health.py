from __future__ import annotations

from dataclasses import dataclass
import http.client
from pathlib import Path
from urllib.parse import urlsplit

from .qualification_file_authority import read_file_pinned

_MAX_URL = 512
_MAX_BODY = 4096


class TunnelHealthError(RuntimeError):
    pass


@dataclass(frozen=True)
class TunnelHealthResponse:
    status_code: int
    body: bytes
    content_type: str


def parse_health_base_url(path: Path) -> str:
    try:
        raw = read_file_pinned(path,max_bytes=_MAX_URL,label="tunnel health URL handshake",allow_empty=False)
        text = raw.decode("ascii",errors="strict")
    except Exception as exc:
        raise TunnelHealthError("tunnel health URL handshake could not be read safely") from exc
    if text != text.strip(): raise TunnelHealthError("tunnel health URL handshake has whitespace drift")
    parsed=urlsplit(text)
    try: port=parsed.port
    except ValueError as exc: raise TunnelHealthError("tunnel health URL handshake port is invalid") from exc
    if (parsed.scheme!="http" or parsed.hostname!="127.0.0.1" or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment or port is None or not 1<=port<=65535 or text!=f"http://127.0.0.1:{port}"):
        raise TunnelHealthError("tunnel health URL handshake escaped canonical loopback authority")
    return text


def default_health_probe(readiness_url: str, timeout_seconds: float) -> TunnelHealthResponse:
    parsed=urlsplit(readiness_url)
    try: port=parsed.port
    except ValueError as exc: raise TunnelHealthError("tunnel readiness URL port is invalid") from exc
    if parsed.scheme!="http" or parsed.hostname!="127.0.0.1" or parsed.path!="/readyz" or parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None or port is None:
        raise TunnelHealthError("tunnel readiness URL escaped loopback authority")
    connection=http.client.HTTPConnection("127.0.0.1",port,timeout=timeout_seconds)
    try:
        connection.request("GET","/readyz",headers={"Accept":"text/plain"})
        response=connection.getresponse(); body=response.read(_MAX_BODY+1)
        if len(body)>_MAX_BODY: raise TunnelHealthError("tunnel readiness body exceeds safety bound")
        return TunnelHealthResponse(int(response.status),body,response.getheader("Content-Type", ""))
    finally: connection.close()


def readiness_response_is_ready(response: TunnelHealthResponse) -> bool:
    if not isinstance(response,TunnelHealthResponse) or response.status_code!=200: return False
    media=response.content_type.split(";",1)[0].strip().lower() if response.content_type else ""
    if media not in ("","text/plain"): return False
    try: body=response.body.decode("utf-8",errors="strict")
    except UnicodeError: return False
    if body!=body.strip(): return False
    if body == "ready":
        return True
    return body.startswith("ready (mcp initialize requires auth: ") and body.endswith(")")
