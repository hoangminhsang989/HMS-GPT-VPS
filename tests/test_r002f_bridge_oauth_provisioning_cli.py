from __future__ import annotations

import pytest

from hms_gpt_vps.bridge_cli import build_parser


def test_provision_command_accepts_no_secret_options():
    args = build_parser().parse_args(
        ["provision-oauth-introspection-credential"]
    )
    assert args.command == "provision-oauth-introspection-credential"


@pytest.mark.parametrize(
    "argv",
    [
        ["provision-oauth-introspection-credential", "--client-secret", "secret"],
        ["provision-oauth-introspection-credential", "--secret-path", r"C:\x"],
        ["provision-oauth-introspection-credential", "secret"],
    ],
)
def test_provision_command_rejects_argv_secret_or_path_surface(argv):
    with pytest.raises(SystemExit):
        build_parser().parse_args(argv)
