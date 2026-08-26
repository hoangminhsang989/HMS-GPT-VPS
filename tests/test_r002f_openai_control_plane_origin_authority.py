from dataclasses import replace

import pytest

import hms_gpt_vps.openai_control_plane_origin_authority as mod


def test_current_static_authority_is_exact_and_launch_environment_is_closed():
    authority = mod.current_openai_control_plane_static_authority()
    assert authority.upstream_repository == "openai/tunnel-client"
    assert authority.upstream_tag == "v0.0.12"
    assert authority.upstream_commit_sha == "881c9a8fed7cccbe6607cd419863bbca506b8215"
    assert authority.upstream_tree_sha == "fee5968ecb711a6cd1dd4df9f322f62fae613b28"
    assert authority.release_asset_id == 521784635
    assert authority.release_asset_sha256 == "0721098f9edda72cc36f938adcb12cd6a0c49c6c0be7ad6ab6e412f966585f2e"
    assert authority.default_control_plane_base_url == "https://api.openai.com"
    assert len(mod.OPENAI_TUNNEL_AUDITED_SOURCE_BLOBS) == 16


def test_static_authority_drift_fails_closed():
    authority = mod.current_openai_control_plane_static_authority()
    for changed in (
        replace(authority, upstream_commit_sha="0" * 40),
        replace(authority, release_asset_sha256="0" * 64),
        replace(authority, default_control_plane_base_url="https://example.invalid"),
        replace(authority, release_asset_id=1),
    ):
        with pytest.raises(mod.OpenAiControlPlaneOriginAuthorityError):
            changed.validate()
