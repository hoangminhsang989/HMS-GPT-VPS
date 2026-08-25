from __future__ import annotations

import argparse
import json
from pathlib import Path

from hms_gpt_vps.native_scm_qualification_evidence import validate_native_scm_proof


_MAX_PROOF_BYTES = 1024 * 1024


def verify(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    if len(payload) > _MAX_PROOF_BYTES:
        raise RuntimeError("native SCM proof exceeds verification bound")
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("native SCM proof is not valid UTF-8 JSON") from exc
    return validate_native_scm_proof(raw)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify strict native Windows SCM proof")
    parser.add_argument("proof", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    proof = verify(args.proof.resolve(strict=True))
    print(json.dumps(proof, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
