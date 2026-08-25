#!/usr/bin/env bash
set -euo pipefail

EXPECTED_HEAD="1fc5ad20068444446f154f72ed44eb7ec5a0ee5f"
EXPECTED_WORKFLOW_PATH=".github/workflows/ci.yml"

fail() {
  printf 'HMS Linux self-hosted preflight failed: %s\n' "$*" >&2
  exit 1
}

if [[ $# -ne 1 ]]; then
  fail "usage: $0 /absolute/path/to/exact-head-candidate"
fi

candidate_root="$1"
[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
[[ "$(id -u)" -ne 0 ]] || fail "run preflight as a non-root user"

arch="$(uname -m)"
[[ "$arch" == "x86_64" || "$arch" == "amd64" ]] || fail "x64 Linux is required; observed $arch"

for command in git bash curl tar python3 sort head tr; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done

[[ "$candidate_root" == /* ]] || fail "candidate root must be an absolute path"
[[ -d "$candidate_root" ]] || fail "candidate root does not exist or is not a directory"
physical_root="$(cd "$candidate_root" && pwd -P)"
lexical_root="$(python3 - "$candidate_root" <<'PY'
import os, sys
print(os.path.abspath(sys.argv[1]))
PY
)"
[[ "$physical_root" == "$lexical_root" ]] || fail "candidate checkout path traverses a symlink: lexical=$lexical_root physical=$physical_root"

if [[ -L "$HOME" ]]; then
  fail "HOME must not be a symlink"
fi

[[ -r /etc/os-release ]] || fail "/etc/os-release is required"
# shellcheck disable=SC1091
. /etc/os-release
id_lower="${ID,,}"
version_id="${VERSION_ID:-}"
[[ -n "$version_id" ]] || fail "VERSION_ID is missing from /etc/os-release"

version_ge() {
  local have="$1" need="$2"
  [[ "$(printf '%s\n%s\n' "$need" "$have" | sort -V | head -n1)" == "$need" ]]
}

case "$id_lower" in
  ubuntu) version_ge "$version_id" "20.04" || fail "Ubuntu 20.04+ is required" ;;
  debian) version_ge "$version_id" "10" || fail "Debian 10+ is required" ;;
  rhel|centos|ol) version_ge "$version_id" "8" || fail "RHEL/CentOS/Oracle Linux 8+ is required" ;;
  fedora) version_ge "$version_id" "29" || fail "Fedora 29+ is required" ;;
  linuxmint) version_ge "$version_id" "20" || fail "Linux Mint 20+ is required" ;;
  opensuse-leap) version_ge "$version_id" "15.2" || fail "openSUSE Leap 15.2+ is required" ;;
  sles) version_ge "$version_id" "15.2" || fail "SLES 15.2+ is required" ;;
  *) fail "distribution is outside the reviewed support floor: ID=$id_lower VERSION_ID=$version_id" ;;
esac

root="$physical_root"
top_level="$(git -C "$root" rev-parse --show-toplevel)"
top_level_physical="$(cd "$top_level" && pwd -P)"
[[ "$top_level_physical" == "$root" ]] || fail "candidate root must be the exact git top-level directory"

head_sha="$(git -C "$root" rev-parse HEAD | tr '[:upper:]' '[:lower:]')"
[[ "$head_sha" == "$EXPECTED_HEAD" ]] || fail "candidate HEAD mismatch: expected $EXPECTED_HEAD, observed $head_sha"

status="$(git -C "$root" status --porcelain=v1 --untracked-files=all)"
[[ -z "$status" ]] || fail "candidate worktree is not clean"

git -C "$root" diff --check >/dev/null || fail "git diff --check failed"

workflow_file="$root/$EXPECTED_WORKFLOW_PATH"
[[ -f "$workflow_file" && ! -L "$workflow_file" ]] || fail "candidate workflow file is missing or redirected"
workflow_blob_commit="$(git -C "$root" rev-parse "$EXPECTED_HEAD:$EXPECTED_WORKFLOW_PATH" | tr '[:upper:]' '[:lower:]')"
[[ "$workflow_blob_commit" =~ ^[0-9a-f]{40}$ ]] || fail "candidate workflow blob id is malformed"
workflow_blob_worktree="$(git -C "$root" hash-object -- "$EXPECTED_WORKFLOW_PATH" | tr '[:upper:]' '[:lower:]')"
[[ "$workflow_blob_worktree" == "$workflow_blob_commit" ]] || fail "worktree workflow bytes differ from the frozen exact-head workflow blob"

printf 'ready_for_runner_registration=True\n'
printf 'candidate_root=%s\n' "$root"
printf 'exact_head=%s\n' "$head_sha"
printf 'workflow_blob=%s\n' "$workflow_blob_commit"
printf 'worktree_clean=True\n'
printf 'diff_check_clean=True\n'
printf 'linux_x64=True\n'
printf 'non_root=True\n'
printf 'distribution=%s\n' "$id_lower"
printf 'distribution_version=%s\n' "$version_id"
printf 'note=preflight does not prove tests, package attestation, native Windows SCM, or Hyper-V guest qualification\n'
