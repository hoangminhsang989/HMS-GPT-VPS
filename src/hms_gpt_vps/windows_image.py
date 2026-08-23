from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib


@dataclass(frozen=True)
class WindowsImage:
    source: Path
    sha256: str | None = None

    def validate(self) -> None:
        if self.source.suffix.lower() != ".iso":
            raise ValueError("Windows installation image must be an ISO file")
        if not self.source.exists():
            raise FileNotFoundError(self.source)
        if self.sha256:
            actual = sha256_file(self.source)
            if actual.lower() != self.sha256.lower():
                raise ValueError("Windows ISO SHA-256 mismatch")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()
