from __future__ import annotations

from dataclasses import dataclass, field
import secrets
import string


_SYMBOLS = "!#$%_-"
_ALLOWED = string.ascii_letters + string.digits + _SYMBOLS


@dataclass(frozen=True)
class BootstrapCredential:
    username: str
    password: str = field(repr=False)


def generate_bootstrap_password(length: int = 32) -> str:
    """Generate a Windows-compatible high-entropy setup password.

    At least one upper-case, lower-case, digit and symbol is guaranteed. The
    alphabet avoids quotes/backslashes so the transient value is easier to
    handle across XML/PowerShell boundaries, while XML escaping is still used.
    """
    if length < 20:
        raise ValueError("bootstrap password length must be at least 20")
    if length > 127:
        raise ValueError("bootstrap password length must be <= 127")

    chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(_SYMBOLS),
    ]
    chars.extend(secrets.choice(_ALLOWED) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_bootstrap_credential(
    username: str = "hmsbootstrap",
    *,
    password_length: int = 32,
) -> BootstrapCredential:
    if not username.strip():
        raise ValueError("bootstrap username is required")
    return BootstrapCredential(
        username=username,
        password=generate_bootstrap_password(password_length),
    )
