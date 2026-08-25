#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="${HOME}/.local/share/hms-gpt-vps/github-runner-linux"
CHECK_ONLY="${1:-}"

fail() {
  printf 'HMS Linux self-hosted runner start failed: %s\n' "$1" >&2
  exit 1
}

assert_no_symlink_chain() {
  local path="$1"
  while [[ "$path" != "/" && -n "$path" ]]; do
    if [[ -L "$path" ]]; then
      fail "authority path traverses a symbolic link: $path"
    fi
    path="$(dirname "$path")"
  done
}

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
[[ "$(uname -m)" == "x86_64" ]] || fail "Linux x64 is required"
[[ "$(id -u)" -ne 0 ]] || fail "do not run the qualification runner as root"

assert_no_symlink_chain "$HOME"
assert_no_symlink_chain "$INSTALL_ROOT"
[[ -d "$INSTALL_ROOT" ]] || fail "runner install root is missing"
[[ ! -e "$INSTALL_ROOT/.service" ]] || fail "foreground qualification runner must not be configured as a persistent service"

for required in "$INSTALL_ROOT/.runner" "$INSTALL_ROOT/.credentials" "$INSTALL_ROOT/run.sh"; do
  [[ -f "$required" && ! -L "$required" ]] || fail "runner state is incomplete or redirected: $required"
done

if [[ "$CHECK_ONLY" == "--check-only" ]]; then
  printf 'ready_to_start=True\n'
  printf 'foreground=True\n'
  printf 'root_user=False\n'
  printf 'install_root=%s\n' "$INSTALL_ROOT"
  printf 'run_command=%s\n' "$INSTALL_ROOT/run.sh"
  printf 'service_mode=False\n'
  exit 0
fi
if [[ -n "$CHECK_ONLY" ]]; then
  fail "only optional argument is --check-only"
fi

printf '%s\n' 'HMS Linux self-hosted runner foreground qualification mode'
printf '%s\n' 'Keep this shell open only for the frozen qualification window.'
printf '%s\n' 'Stop the runner after required jobs finish, then remove its GitHub registration.'

cd "$INSTALL_ROOT"
exec ./run.sh
