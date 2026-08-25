#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="${HOME}/.local/share/hms-gpt-vps/github-runner-linux"

fail() {
  printf 'HMS Linux self-hosted runner removal failed: %s\n' "$1" >&2
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
[[ "$(id -u)" -ne 0 ]] || fail "do not remove the foreground runner as root"
assert_no_symlink_chain "$HOME"
assert_no_symlink_chain "$INSTALL_ROOT"
[[ -d "$INSTALL_ROOT" ]] || fail "runner install root is missing"

for required in "$INSTALL_ROOT/config.sh" "$INSTALL_ROOT/.runner" "$INSTALL_ROOT/.credentials"; do
  [[ -f "$required" && ! -L "$required" ]] || fail "runner removal state is incomplete or redirected: $required"
done

remove_token="${HMS_GITHUB_RUNNER_REMOVE_TOKEN:-}"
unset HMS_GITHUB_RUNNER_REMOVE_TOKEN
[[ -n "${remove_token//[[:space:]]/}" ]] || fail "set a fresh repository runner removal token in HMS_GITHUB_RUNNER_REMOVE_TOKEN"

pushd "$INSTALL_ROOT" >/dev/null
set +e
./config.sh remove --token "$remove_token"
remove_exit=$?
set -e
remove_token=''
popd >/dev/null
[[ "$remove_exit" -eq 0 ]] || fail "config.sh remove returned exit code $remove_exit"

[[ ! -e "$INSTALL_ROOT/.runner" ]] || fail "runner .runner configuration still exists after official removal"
[[ ! -e "$INSTALL_ROOT/.credentials" ]] || fail "runner .credentials still exists after official removal"
assert_no_symlink_chain "$INSTALL_ROOT"

printf 'deregistered=True\n'
printf 'local_root_preserved=True\n'
printf 'install_root=%s\n' "$INSTALL_ROOT"
printf 'filesystem_cleanup_performed=False\n'
