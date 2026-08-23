from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os

import pytest

from hms_gpt_vps.pairing_exchange import PAIRING_EXCHANGE_KEY_BYTES
from hms_gpt_vps.pairing_exchange_key_store import (
    PAIRING_EXCHANGE_KEY_STORE_MAGIC,
    PairingExchangeKeyStore,
    PairingExchangeKeyStoreError,
    PairingExchangeKeyStoreIntegrityError,
)


def xor_protect(data: bytes) -> bytes:
    return b"TEST" + bytes(value ^ 0xA5 for value in data)


def xor_unprotect(data: bytes) -> bytes:
    if not data.startswith(b"TEST"):
        raise ValueError("invalid test ciphertext")
    return bytes(value ^ 0xA5 for value in data[4:])


def make_store(tmp_path) -> PairingExchangeKeyStore:
    return PairingExchangeKeyStore(
        tmp_path / "pairing-exchange-key.dpapi",
        protector=xor_protect,
        unprotector=xor_unprotect,
    )


def test_load_or_create_persists_one_stable_key_without_plaintext(tmp_path) -> None:
    store = make_store(tmp_path)
    created = store.load_or_create()
    loaded = store.load_or_create()

    assert loaded == created
    assert len(created.export_for_secret_store()) == PAIRING_EXCHANGE_KEY_BYTES
    raw = store.path.read_bytes()
    assert raw.startswith(PAIRING_EXCHANGE_KEY_STORE_MAGIC)
    assert created.export_for_secret_store() not in raw


def test_existing_corrupt_file_is_not_replaced_or_regenerated(tmp_path) -> None:
    store = make_store(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    corrupt = b"NOT-A-VALID-PROTECTED-KEY"
    store.path.write_bytes(corrupt)

    with pytest.raises(PairingExchangeKeyStoreIntegrityError, match="format marker"):
        store.load_or_create()
    assert store.path.read_bytes() == corrupt


def test_unprotect_failure_fails_closed(tmp_path) -> None:
    path = tmp_path / "pairing-exchange-key.dpapi"
    path.write_bytes(PAIRING_EXCHANGE_KEY_STORE_MAGIC + b"bad-ciphertext")
    store = PairingExchangeKeyStore(
        path,
        protector=xor_protect,
        unprotector=lambda _raw: (_ for _ in ()).throw(ValueError("bad")),
    )

    with pytest.raises(PairingExchangeKeyStoreIntegrityError, match="could not be unprotected"):
        store.load_or_create()


def test_wrong_plaintext_length_fails_closed(tmp_path) -> None:
    store = make_store(tmp_path)
    store.path.write_bytes(PAIRING_EXCHANGE_KEY_STORE_MAGIC + xor_protect(b"short"))

    with pytest.raises(PairingExchangeKeyStoreIntegrityError, match="plaintext length"):
        store.load()


def test_empty_protector_result_is_rejected_without_publishing(tmp_path) -> None:
    path = tmp_path / "pairing-exchange-key.dpapi"
    store = PairingExchangeKeyStore(
        path,
        protector=lambda _raw: b"",
        unprotector=xor_unprotect,
    )

    with pytest.raises(PairingExchangeKeyStoreError, match="empty"):
        store.load_or_create()
    assert not path.exists()


def test_concurrent_load_or_create_returns_single_published_key(tmp_path) -> None:
    path = tmp_path / "pairing-exchange-key.dpapi"

    def create_or_load() -> bytes:
        store = PairingExchangeKeyStore(
            path,
            protector=xor_protect,
            unprotector=xor_unprotect,
        )
        return store.load_or_create().export_for_secret_store()

    with ThreadPoolExecutor(max_workers=8) as pool:
        keys = list(pool.map(lambda _index: create_or_load(), range(16)))

    assert len(set(keys)) == 1
    assert path.is_file()
    assert keys[0] not in path.read_bytes()


@pytest.mark.skipif(os.name != "nt", reason="native DPAPI is Windows-only")
def test_native_windows_dpapi_exchange_key_round_trip(tmp_path) -> None:
    store = PairingExchangeKeyStore(tmp_path / "pairing-exchange-key.dpapi")
    created = store.load_or_create()
    loaded = PairingExchangeKeyStore(store.path).load()

    assert loaded == created
    assert created.export_for_secret_store() not in store.path.read_bytes()
