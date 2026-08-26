from __future__ import annotations

from typing import Mapping

from .bridge_composite_activation_runner import (
    BOOTSTRAP_PASSWORD_ENV,
    BOOTSTRAP_USERNAME_ENV,
)


def sanitize_git_control_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Remove caller-controlled Git authority redirects from a child environment."""

    env: dict[str, str] = {}
    for raw_key, raw_value in source.items():
        key = str(raw_key)
        if not key or "=" in key or "\x00" in key:
            raise ValueError("invalid environment variable name")
        value = str(raw_value)
        if "\x00" in value:
            raise ValueError("environment variable value contains NUL")
        if key.casefold().startswith("git_"):
            continue
        env[key] = value
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    return env


def checkout_validation_environment(source: Mapping[str, str]) -> dict[str, str]:
    env = sanitize_git_control_environment(source)
    secret_names = {
        BOOTSTRAP_USERNAME_ENV.casefold(),
        BOOTSTRAP_PASSWORD_ENV.casefold(),
    }
    for key in list(env):
        if key.casefold() in secret_names:
            env.pop(key, None)
    return env
