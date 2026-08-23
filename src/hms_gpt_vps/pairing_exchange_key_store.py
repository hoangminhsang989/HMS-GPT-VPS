from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from .pairing_exchange import PAIRING_EXCHANGE_KEY_BYTES, PairingExchangeKey
from .windows_dpapi import protect_bytes, unprotect_bytes


PAIRING_EXCHANGE_KEY_STORE_MAGIC = b"HMS-PXK-V1\x00"
MAX_PROTECTED_KEY_FILE_BYTES = 64 * 1024
_DPAPI_DESCRIPTION = "HMS-GPT-VPS pairing exchange key v1"


class PairingExchangeKeyStoreError(RuntimeError):
    pass


class PairingExchangeKeyStoreIntegrityError(PairingExchangeKeyStoreError):
    pass


ProtectFn = Callable[[bytes], bytes]
UnprotectFn = Callable[[bytes], bytes]


def _default_protect(data: bytes) -> bytes:
    return protect_bytes(data, description=_DPAPI_DESCRIPTION)


def _default_unprotect(data: bytes) -> bytes:
    return unprotect_bytes(data)


class PairingExchangeKeyStore:
    """Create-once protected storage for the persistent Bridge exchange key.

    Production defaults to current-user Windows DPAPI.  The on-disk file holds
    only a small non-secret format marker plus DPAPI ciphertext.  Creation uses
    an fsynced same-directory temporary file followed by an atomic hard-link
    publish that refuses to overwrite an existing key.  If an existing file is
    corrupt or cannot be unprotected, loading fails closed; a replacement key
    is never generated silently because that would invalidate crash recovery.

    `protector` / `unprotector` are dependency-injection seams for deterministic
    cross-platform tests. Product callers should use the defaults.
    """

    def __init__(
        self,
        path: Path,
        *,
        protector: ProtectFn | None = None,
        unprotector: UnprotectFn | None = None,
    ) -> None:
        self.path = path.expanduser().absolute()
        self._protect = protector or _default_protect
        self._unprotect = unprotector or _default_unprotect

    def exists(self) -> bool:
        return self.path.is_file()

    def _decode_file(self, raw: bytes) -> PairingExchangeKey:
        if len(raw) > MAX_PROTECTED_KEY_FILE_BYTES:
            raise PairingExchangeKeyStoreIntegrityError(
                "protected pairing exchange key file exceeds maximum size"
            )
        if not raw.startswith(PAIRING_EXCHANGE_KEY_STORE_MAGIC):
            raise PairingExchangeKeyStoreIntegrityError(
                "protected pairing exchange key file has an invalid format marker"
            )
        protected = raw[len(PAIRING_EXCHANGE_KEY_STORE_MAGIC) :]
        if not protected:
            raise PairingExchangeKeyStoreIntegrityError(
                "protected pairing exchange key payload is empty"
            )
        try:
            plain = self._unprotect(protected)
        except Exception as exc:
            raise PairingExchangeKeyStoreIntegrityError(
                "pairing exchange key could not be unprotected"
            ) from exc
        if len(plain) != PAIRING_EXCHANGE_KEY_BYTES:
            raise PairingExchangeKeyStoreIntegrityError(
                "pairing exchange key has an invalid plaintext length"
            )
        return PairingExchangeKey(bytes(plain))

    def load(self) -> PairingExchangeKey:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            raise
        if stat.st_size <= len(PAIRING_EXCHANGE_KEY_STORE_MAGIC):
            raise PairingExchangeKeyStoreIntegrityError(
                "protected pairing exchange key file is incomplete"
            )
        if stat.st_size > MAX_PROTECTED_KEY_FILE_BYTES:
            raise PairingExchangeKeyStoreIntegrityError(
                "protected pairing exchange key file exceeds maximum size"
            )
        return self._decode_file(self.path.read_bytes())

    def load_or_create(self) -> PairingExchangeKey:
        """Load the stable key or publish exactly one new protected key.

        Concurrent creators are safe: only one hard-link publish wins.  Losers
        discard their temporary ciphertext and load the already-published key.
        An existing but invalid file is never replaced automatically.
        """
        if self.path.exists():
            return self.load()

        key = PairingExchangeKey.generate()
        protected = self._protect(key.export_for_secret_store())
        if not protected:
            raise PairingExchangeKeyStoreError(
                "protector returned an empty pairing exchange key payload"
            )
        envelope = PAIRING_EXCHANGE_KEY_STORE_MAGIC + protected
        if len(envelope) > MAX_PROTECTED_KEY_FILE_BYTES:
            raise PairingExchangeKeyStoreError(
                "protected pairing exchange key payload exceeds maximum size"
            )

        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            with NamedTemporaryFile(
                "wb",
                dir=self.path.parent,
                prefix=self.path.name + ".",
                suffix=".tmp",
                delete=False,
            ) as handle:
                handle.write(envelope)
                handle.flush()
                os.fsync(handle.fileno())
                temp_path = Path(handle.name)

            try:
                # Atomic create-only publication on the same filesystem.  Do
                # not use replace(): overwriting the persistent root key would
                # destroy pairing-exchange recovery semantics.
                os.link(temp_path, self.path)
            except FileExistsError:
                return self.load()

            try:
                os.chmod(self.path, 0o600)
            except OSError:
                # DPAPI remains the confidentiality boundary on Windows; chmod
                # support varies by filesystem. Failure to chmod does not turn
                # ciphertext into plaintext, so keep the successfully published
                # key rather than rotating it implicitly.
                pass
            return key
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
