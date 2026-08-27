from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def _path_chain_has_redirect(path: Path) -> bool:
    current = path.expanduser().absolute()
    chain = []
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        if candidate.is_symlink():
            return True
        try:
            attributes = int(
                getattr(candidate.lstat(), "st_file_attributes", 0)
            )
        except FileNotFoundError:
            continue
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return True
    return False


def _bootstrap(argv: list[str]) -> Path:
    if sys.flags.isolated != 1 or sys.flags.dont_write_bytecode != 1:
        raise SystemExit("sealed preflight must use Python -I -B")
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--execution-root", required=True, type=Path)
    args, _ = parser.parse_known_args(argv)
    root = args.execution_root.expanduser().absolute()
    src = (root / "src").absolute()
    scripts = (root / "scripts").absolute()
    if (
        _path_chain_has_redirect(root)
        or _path_chain_has_redirect(src)
        or _path_chain_has_redirect(scripts)
        or not src.is_dir()
        or not scripts.is_dir()
    ):
        raise SystemExit("sealed preflight bootstrap authority is invalid")
    sys.path.insert(0, str(src))
    return root


_BOOTSTRAP_ROOT = _bootstrap(sys.argv[1:])

from hms_gpt_vps.r002f_sealed_preflight_entrypoint import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:], bootstrap_root=_BOOTSTRAP_ROOT))
