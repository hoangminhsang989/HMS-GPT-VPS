from __future__ import annotations

from dataclasses import dataclass

from .mcp_tunnel_ingress import (
    MCP_EXTRA_HEADERS_ENV,
    MCP_TUNNEL_INGRESS_TOKEN_ENV,
    build_mcp_tunnel_ingress_child_environment,
)
from .secure_mcp_tunnel import (
    HMS_MCP_SERVER_URL,
    OPENAI_TUNNEL_CLIENT_ASSET,
    OPENAI_TUNNEL_CLIENT_ASSET_SIZE,
    OPENAI_TUNNEL_CLIENT_SHA256,
    OPENAI_TUNNEL_CLIENT_VERSION,
    TunnelClientPackagePin,
    build_tunnel_child_environment,
)

OPENAI_TUNNEL_UPSTREAM_REPOSITORY = "openai/tunnel-client"
OPENAI_TUNNEL_UPSTREAM_TAG = "v0.0.12"
OPENAI_TUNNEL_UPSTREAM_TAG_OBJECT_SHA = "5cdcc62932cbf21bd94c4321ab337b0ede51103a"
OPENAI_TUNNEL_UPSTREAM_COMMIT_SHA = "881c9a8fed7cccbe6607cd419863bbca506b8215"
OPENAI_TUNNEL_UPSTREAM_TREE_SHA = "fee5968ecb711a6cd1dd4df9f322f62fae613b28"
OPENAI_TUNNEL_RELEASE_WORKFLOW_BLOB_SHA = "56fb83cad8682db8190ab837d1c3fdce523996f4"
OPENAI_TUNNEL_RELEASE_ASSET_ID = 521784635
OPENAI_TUNNEL_RELEASE_ASSET = "tunnel-client-runtime-v0.0.12-windows-amd64.zip"
OPENAI_TUNNEL_RELEASE_ASSET_SIZE = 6_950_001
OPENAI_TUNNEL_RELEASE_ASSET_SHA256 = "0721098f9edda72cc36f938adcb12cd6a0c49c6c0be7ad6ab6e412f966585f2e"
OPENAI_TUNNEL_DEFAULT_CONTROL_PLANE_BASE_URL = "https://api.openai.com"
OPENAI_TUNNEL_ORIGIN_KIND = "OPENAI_TUNNEL_CONTROL_PLANE_COMMAND"

# Exact reviewed v0.0.12 source blobs that establish the closed production path.
OPENAI_TUNNEL_AUDITED_SOURCE_BLOBS = {
    ".github/workflows/release.yml": OPENAI_TUNNEL_RELEASE_WORKFLOW_BLOB_SHA,
    "cmd/client-runtime/root_command.go": "162a87b83d1a134d8f29f411d2c98009147473d4",
    "docs/protocol.md": "6e3bcbc36f8311dae9d83ae4c88020eb9933ac57",
    "pkg/controlplane/wiretypes/wire.go": "2be2b906b936aa2b0c3cf38c5046f30436eb12a4",
    "pkg/controlplane/polled_command.go": "574cd9097c255e14d5eb33a47dffae3c135c4102",
    "pkg/controlplane/internal/command_parser.go": "058d3cfe1c203c6dfbbbd17b099a7a3a1c81e3a9",
    "pkg/controlplane/internal/poller.go": "23e27940017a7aeef9959083a44d42802c189c2a",
    "pkg/controlplane/fx/fxmodule.go": "5d51ff0782d0797672521449fcf7ac374557c0be",
    "pkg/dispatcher/fxmodule.go": "96508f6a91019cff4fb964bd9c16f4c151d6a326",
    "pkg/dispatcher/internal/queue_listener.go": "d0c7f044ce26b9e3e9d3e44f3a6c84d2410781b6",
    "pkg/dispatcher/internal/processor.go": "d98d57606c035da7cc9a3747d387e39b8b41a111",
    "pkg/mcpclient/internal/context.go": "3731c4170848d57263be0fadbaa321d96966a26d",
    "pkg/mcpclient/forwarding_transport_impl.go": "34c34c29e5ba0c590da8aa692c42943fc77de355",
    "pkg/mcpclient/internal/static_headers.go": "fcdc682542f860c49807b721854e11cd32b3d62e",
    "pkg/runtimeconfig/config.go": "d74c29a8c34b3bf0dc00a570c699c18fb6cc7484",
    "pkg/runtimeconfig/profile.go": "c72acdb3935caa89de2b26c3952a201c6c21b64c",
}

_FORBIDDEN_INHERITED_ENV = frozenset(
    {
        "CONTROL_PLANE_BASE_URL",
        "TUNNEL_CLIENT_CONFIG",
        "TUNNEL_CLIENT_PROFILE",
        "TUNNEL_CLIENT_PROFILE_FILE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    }
)
_ALLOWED_PARENT_ENV = frozenset({"SystemRoot", "WINDIR", "ComSpec", "TEMP", "TMP"})
_REQUIRED_RUNTIME_ENV = frozenset(
    {
        "CONTROL_PLANE_TUNNEL_ID",
        "CONTROL_PLANE_API_KEY",
        "MCP_SERVER_URL",
        MCP_TUNNEL_INGRESS_TOKEN_ENV,
        MCP_EXTRA_HEADERS_ENV,
    }
)


class OpenAiControlPlaneOriginAuthorityError(RuntimeError):
    pass


def _canonical_git_sha(value: object, *, length: int, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise OpenAiControlPlaneOriginAuthorityError(f"{name} is noncanonical")
    return value


def _validate_audited_source_blobs() -> None:
    if len(OPENAI_TUNNEL_AUDITED_SOURCE_BLOBS) != 16:
        raise OpenAiControlPlaneOriginAuthorityError("audited source blob set is incomplete")
    for path, sha in OPENAI_TUNNEL_AUDITED_SOURCE_BLOBS.items():
        if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
            raise OpenAiControlPlaneOriginAuthorityError("audited upstream path is invalid")
        _canonical_git_sha(sha, length=40, name=f"audited blob {path}")


def _validate_hms_launch_environment_isolation() -> None:
    hostile = {
        "SystemRoot": r"C:\\Windows",
        "WINDIR": r"C:\\Windows",
        "ComSpec": r"C:\\Windows\\System32\\cmd.exe",
        "TEMP": r"C:\\Temp",
        "TMP": r"C:\\Temp",
        "CONTROL_PLANE_BASE_URL": "http://127.0.0.1:9",
        "TUNNEL_CLIENT_CONFIG": r"C:\\evil.yaml",
        "TUNNEL_CLIENT_PROFILE": "evil",
        "TUNNEL_CLIENT_PROFILE_FILE": r"C:\\evil-profiles.yaml",
        "HTTP_PROXY": "http://127.0.0.1:8080",
        "HTTPS_PROXY": "http://127.0.0.1:8080",
        "ALL_PROXY": "socks5://127.0.0.1:1080",
        "NO_PROXY": "*",
        "UNRELATED_HOST_SECRET": "must-not-inherit",
    }
    child = build_tunnel_child_environment(
        hostile,
        tunnel_id="tunnel_" + "1" * 32,
        api_key="qualification-api-key",
    )
    child = build_mcp_tunnel_ingress_child_environment(
        child,
        token="2" * 64,
    )
    forbidden = {key.casefold() for key in _FORBIDDEN_INHERITED_ENV}
    if any(key.casefold() in forbidden for key in child):
        raise OpenAiControlPlaneOriginAuthorityError(
            "HMS tunnel child inherited a control-plane override environment variable"
        )
    if "UNRELATED_HOST_SECRET" in child:
        raise OpenAiControlPlaneOriginAuthorityError("HMS tunnel child inherited arbitrary host environment")
    expected = _ALLOWED_PARENT_ENV | _REQUIRED_RUNTIME_ENV
    if frozenset(child) != expected:
        raise OpenAiControlPlaneOriginAuthorityError("HMS tunnel child environment key set drifted")
    if child.get("MCP_SERVER_URL") != HMS_MCP_SERVER_URL:
        raise OpenAiControlPlaneOriginAuthorityError("HMS MCP loopback target drifted")


@dataclass(frozen=True)
class OpenAiControlPlaneStaticAuthority:
    upstream_repository: str
    upstream_tag: str
    upstream_tag_object_sha: str
    upstream_commit_sha: str
    upstream_tree_sha: str
    release_workflow_blob_sha: str
    release_asset_id: int
    release_asset: str
    release_asset_size: int
    release_asset_sha256: str
    default_control_plane_base_url: str
    origin_kind: str

    def validate(self) -> None:
        if self.upstream_repository != OPENAI_TUNNEL_UPSTREAM_REPOSITORY:
            raise OpenAiControlPlaneOriginAuthorityError("upstream repository drifted")
        if self.upstream_tag != OPENAI_TUNNEL_UPSTREAM_TAG:
            raise OpenAiControlPlaneOriginAuthorityError("upstream tag drifted")
        _canonical_git_sha(self.upstream_tag_object_sha, length=40, name="upstream tag object")
        _canonical_git_sha(self.upstream_commit_sha, length=40, name="upstream commit")
        _canonical_git_sha(self.upstream_tree_sha, length=40, name="upstream tree")
        _canonical_git_sha(self.release_workflow_blob_sha, length=40, name="release workflow blob")
        if self.upstream_tag_object_sha != OPENAI_TUNNEL_UPSTREAM_TAG_OBJECT_SHA:
            raise OpenAiControlPlaneOriginAuthorityError("upstream tag object differs")
        if self.upstream_commit_sha != OPENAI_TUNNEL_UPSTREAM_COMMIT_SHA:
            raise OpenAiControlPlaneOriginAuthorityError("upstream commit differs")
        if self.upstream_tree_sha != OPENAI_TUNNEL_UPSTREAM_TREE_SHA:
            raise OpenAiControlPlaneOriginAuthorityError("upstream tree differs")
        if self.release_workflow_blob_sha != OPENAI_TUNNEL_RELEASE_WORKFLOW_BLOB_SHA:
            raise OpenAiControlPlaneOriginAuthorityError("release workflow blob differs")
        if isinstance(self.release_asset_id, bool) or self.release_asset_id != OPENAI_TUNNEL_RELEASE_ASSET_ID:
            raise OpenAiControlPlaneOriginAuthorityError("release asset id differs")
        if self.release_asset != OPENAI_TUNNEL_RELEASE_ASSET:
            raise OpenAiControlPlaneOriginAuthorityError("release asset name differs")
        if self.release_asset_size != OPENAI_TUNNEL_RELEASE_ASSET_SIZE:
            raise OpenAiControlPlaneOriginAuthorityError("release asset size differs")
        if self.release_asset_sha256 != OPENAI_TUNNEL_RELEASE_ASSET_SHA256:
            raise OpenAiControlPlaneOriginAuthorityError("release asset SHA-256 differs")
        if self.default_control_plane_base_url != OPENAI_TUNNEL_DEFAULT_CONTROL_PLANE_BASE_URL:
            raise OpenAiControlPlaneOriginAuthorityError("OpenAI control-plane default URL differs")
        if self.origin_kind != OPENAI_TUNNEL_ORIGIN_KIND:
            raise OpenAiControlPlaneOriginAuthorityError("origin kind differs")
        _validate_audited_source_blobs()
        TunnelClientPackagePin().validate()
        if (
            OPENAI_TUNNEL_CLIENT_VERSION != OPENAI_TUNNEL_UPSTREAM_TAG
            or OPENAI_TUNNEL_CLIENT_ASSET != OPENAI_TUNNEL_RELEASE_ASSET
            or OPENAI_TUNNEL_CLIENT_ASSET_SIZE != OPENAI_TUNNEL_RELEASE_ASSET_SIZE
            or OPENAI_TUNNEL_CLIENT_SHA256 != OPENAI_TUNNEL_RELEASE_ASSET_SHA256
        ):
            raise OpenAiControlPlaneOriginAuthorityError("HMS tunnel package pin differs from audited release")
        _validate_hms_launch_environment_isolation()


def current_openai_control_plane_static_authority() -> OpenAiControlPlaneStaticAuthority:
    authority = OpenAiControlPlaneStaticAuthority(
        upstream_repository=OPENAI_TUNNEL_UPSTREAM_REPOSITORY,
        upstream_tag=OPENAI_TUNNEL_UPSTREAM_TAG,
        upstream_tag_object_sha=OPENAI_TUNNEL_UPSTREAM_TAG_OBJECT_SHA,
        upstream_commit_sha=OPENAI_TUNNEL_UPSTREAM_COMMIT_SHA,
        upstream_tree_sha=OPENAI_TUNNEL_UPSTREAM_TREE_SHA,
        release_workflow_blob_sha=OPENAI_TUNNEL_RELEASE_WORKFLOW_BLOB_SHA,
        release_asset_id=OPENAI_TUNNEL_RELEASE_ASSET_ID,
        release_asset=OPENAI_TUNNEL_RELEASE_ASSET,
        release_asset_size=OPENAI_TUNNEL_RELEASE_ASSET_SIZE,
        release_asset_sha256=OPENAI_TUNNEL_RELEASE_ASSET_SHA256,
        default_control_plane_base_url=OPENAI_TUNNEL_DEFAULT_CONTROL_PLANE_BASE_URL,
        origin_kind=OPENAI_TUNNEL_ORIGIN_KIND,
    )
    authority.validate()
    return authority
