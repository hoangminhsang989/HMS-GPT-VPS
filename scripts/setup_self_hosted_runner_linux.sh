#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_URL="https://github.com/hoangminhsang989/HMS-GPT-VPS"
CUSTOM_LABEL="hms-gpt-vps-linux"
INSTALL_ROOT="${HOME}/.local/share/hms-gpt-vps/github-runner-linux"
RUNNER_NAME="${HMS_GITHUB_RUNNER_NAME:-$(hostname)-HMS-GPT-VPS-Linux}"

fail() {
  printf 'HMS Linux self-hosted runner setup failed: %s\n' "$1" >&2
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

version_ge() {
  python3 - "$1" "$2" <<'PY'
import sys

def parts(value: str):
    out = []
    for item in value.split('.'):
        digits = ''.join(ch for ch in item if ch.isdigit())
        out.append(int(digits or '0'))
    return tuple(out)

actual = parts(sys.argv[1])
minimum = parts(sys.argv[2])
width = max(len(actual), len(minimum))
actual += (0,) * (width - len(actual))
minimum += (0,) * (width - len(minimum))
raise SystemExit(0 if actual >= minimum else 1)
PY
}

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
[[ "$(uname -m)" == "x86_64" ]] || fail "Linux x64 is required"
[[ "$(id -u)" -ne 0 ]] || fail "do not configure the qualification runner as root"
[[ "$RUNNER_NAME" =~ ^[A-Za-z0-9._-]{1,80}$ ]] || fail "runner name contains unsupported characters or is too long"

for command in curl python3 tar sha256sum stat; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done

[[ -r /etc/os-release ]] || fail "/etc/os-release is required"
# shellcheck disable=SC1091
source /etc/os-release
DISTRO_ID="${ID:-}"
DISTRO_VERSION="${VERSION_ID:-}"
[[ -n "$DISTRO_ID" && -n "$DISTRO_VERSION" ]] || fail "Linux distribution identity/version is unavailable"

case "$DISTRO_ID" in
  ubuntu) min_version="20.04" ;;
  debian) min_version="10" ;;
  rhel|centos|ol) min_version="8" ;;
  fedora) min_version="29" ;;
  linuxmint) min_version="20" ;;
  opensuse-leap|sles) min_version="15.2" ;;
  *) fail "distribution is not in the reviewed GitHub self-hosted runner support set: $DISTRO_ID" ;;
esac
version_ge "$DISTRO_VERSION" "$min_version" || fail "distribution version $DISTRO_VERSION is below reviewed minimum $min_version"

registration_token="${HMS_GITHUB_RUNNER_TOKEN:-}"
unset HMS_GITHUB_RUNNER_TOKEN
[[ -n "${registration_token//[[:space:]]/}" ]] || fail "set a fresh repository runner registration token in HMS_GITHUB_RUNNER_TOKEN"

assert_no_symlink_chain "$HOME"
assert_no_symlink_chain "$INSTALL_ROOT"
if [[ -e "$INSTALL_ROOT" ]]; then
  [[ -d "$INSTALL_ROOT" ]] || fail "runner install root exists but is not a directory"
  if [[ -n "$(find "$INSTALL_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    fail "runner install root must be absent or empty; refusing to replace existing/partial state"
  fi
else
  mkdir -p "$INSTALL_ROOT"
fi
assert_no_symlink_chain "$INSTALL_ROOT"

release_json="$INSTALL_ROOT/actions-runner-release.json"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  -H 'Accept: application/vnd.github+json' \
  -H 'User-Agent: HMS-GPT-VPS-self-hosted-runner-bootstrap' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  'https://api.github.com/repos/actions/runner/releases/latest' \
  -o "$release_json"
assert_no_symlink_chain "$release_json"

metadata="$(python3 - "$release_json" <<'PY'
import json
import re
import sys

path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as handle:
    release = json.load(handle)
tag = release.get('tag_name')
if not isinstance(tag, str) or re.fullmatch(r'v([0-9]+\.[0-9]+\.[0-9]+)', tag) is None:
    raise SystemExit('malformed actions/runner release tag')
version = tag[1:]
name = f'actions-runner-linux-x64-{version}.tar.gz'
assets = [item for item in release.get('assets', []) if isinstance(item, dict) and item.get('name') == name]
if len(assets) != 1:
    raise SystemExit('expected exactly one Linux x64 runner asset')
asset = assets[0]
size = asset.get('size')
digest = asset.get('digest')
url = asset.get('browser_download_url')
if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
    raise SystemExit('runner asset size is invalid')
if not isinstance(digest, str) or re.fullmatch(r'sha256:[0-9A-Fa-f]{64}', digest) is None:
    raise SystemExit('runner asset SHA-256 digest is invalid')
expected_prefix = f'https://github.com/actions/runner/releases/download/{tag}/'
if not isinstance(url, str) or not url.startswith(expected_prefix) or not url.endswith('/' + name):
    raise SystemExit('runner asset URL is outside exact official release namespace')
for value in (tag, name, str(size), digest.lower(), url):
    print(value)
PY
)" || fail "could not validate official actions/runner release metadata"

mapfile -t meta <<< "$metadata"
[[ "${#meta[@]}" -eq 5 ]] || fail "runner release metadata field count mismatch"
tag="${meta[0]}"
asset_name="${meta[1]}"
asset_size="${meta[2]}"
asset_digest="${meta[3]#sha256:}"
asset_url="${meta[4]}"

archive="$INSTALL_ROOT/$asset_name"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error "$asset_url" -o "$archive"
assert_no_symlink_chain "$archive"
[[ "$(stat -c '%s' "$archive")" == "$asset_size" ]] || fail "downloaded runner archive size mismatch"
actual_digest="$(sha256sum "$archive" | awk '{print tolower($1)}')"
[[ "$actual_digest" == "$asset_digest" ]] || fail "downloaded runner archive SHA-256 mismatch"

tar -xzf "$archive" -C "$INSTALL_ROOT"
rm -f -- "$archive" "$release_json"
assert_no_symlink_chain "$INSTALL_ROOT"

for required in "$INSTALL_ROOT/config.sh" "$INSTALL_ROOT/run.sh" "$INSTALL_ROOT/bin/Runner.Listener"; do
  [[ -f "$required" && ! -L "$required" ]] || fail "runner archive is missing or redirected required file: $required"
done

pushd "$INSTALL_ROOT" >/dev/null
set +e
./config.sh \
  --unattended \
  --url "$REPOSITORY_URL" \
  --token "$registration_token" \
  --name "$RUNNER_NAME" \
  --labels "$CUSTOM_LABEL" \
  --work '_work' \
  --disableupdate
config_exit=$?
set -e
registration_token=''
popd >/dev/null
[[ "$config_exit" -eq 0 ]] || fail "config.sh returned exit code $config_exit"

for required in "$INSTALL_ROOT/.runner" "$INSTALL_ROOT/.credentials"; do
  [[ -f "$required" && ! -L "$required" ]] || fail "runner registration state is missing or redirected: $required"
done
[[ ! -e "$INSTALL_ROOT/.service" ]] || fail "foreground fallback must not install a persistent runner service"

printf 'registered=True\n'
printf 'repository=%s\n' "$REPOSITORY_URL"
printf 'runner_name=%s\n' "$RUNNER_NAME"
printf 'install_root=%s\n' "$INSTALL_ROOT"
printf 'custom_label=%s\n' "$CUSTOM_LABEL"
printf 'foreground_required=True\n'
printf 'run_command=%s\n' "$INSTALL_ROOT/run.sh"
printf 'automatic_updates_disabled=True\n'
printf 'distro=%s %s\n' "$DISTRO_ID" "$DISTRO_VERSION"
printf 'release=%s\n' "$tag"
printf 'trust_boundary=keep runner offline except during one frozen exact-head qualification window\n'
