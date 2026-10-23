#!/usr/bin/env bash
# Run the test suites the way a CI runner does: as a user whose uid is NOT 1000 (the Snort image's own user), driving the
# host Docker daemon. On a machine where your uid happens to be 1000 everything can pass locally while failing for most
# other people; this reproduces that situation.
#
# Linux only. Needs Docker, network access (to pull a Python+uv image once and fetch dependencies), and a statically
# linked Docker CLI (Docker Desktop's and the official static builds are).
#
#   scripts/ci_parity.sh                 # integration tests as uid 1001
#   scripts/ci_parity.sh unit            # lint and unit tests as uid 1001
#   CI_UID=2000 scripts/ci_parity.sh     # a different uid
set -euo pipefail

MODE="${1:-integration}"
CI_UID="${CI_UID:-1001}"
IMAGE="ghcr.io/astral-sh/uv:python3.12-bookworm-slim"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="${DOCKER_SOCKET:-/var/run/docker.sock}"
DOCKER_CLI="$(readlink -f "$(command -v docker)")"

[ -S "$SOCK" ] || { echo "no Docker socket at $SOCK (set DOCKER_SOCKET)" >&2; exit 2; }
SOCK_GID="$(stat -c %g "$SOCK")"
WORK="$(mktemp -d /tmp/dw-ci-parity.XXXXXX)"

cleanup() {  # files created by the other uid cannot be removed by you, so remove them from inside a container
  docker run --rm --entrypoint sh -v "$WORK:$WORK" "$IMAGE" -c "rm -rf '$WORK'/* '$WORK'/.[!.]* 2>/dev/null; true" >/dev/null 2>&1 || true
  rmdir "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

docker pull -q "$IMAGE" >/dev/null
mkdir -p "$WORK/bin" "$WORK/home" "$WORK/tmp"
# a copy of the project as git sees it: tracked files plus new ones, with your uncommitted edits, minus anything ignored
(cd "$REPO" && git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf -) | tar -xf - -C "$WORK"
cp "$DOCKER_CLI" "$WORK/bin/docker"
chmod -R a+rwX "$WORK"
chmod a+rx "$WORK/bin/docker"

case "$MODE" in
  integration) CMD="DW_INTEGRATION=1 uv run pytest -q tests/integration --basetemp=$WORK/tmp -p no:cacheprovider ${*:2}" ;;
  unit)        CMD="uv run ruff check src tests scripts && uv run pytest -q --basetemp=$WORK/tmp -p no:cacheprovider ${*:2}" ;;
  *) echo "usage: $0 [integration|unit] [pytest args]" >&2; exit 2 ;;
esac

# The work directory is mounted at the same path inside and out, so the bind mounts that the workbench asks the host
# daemon for refer to real host paths.
docker run --rm --entrypoint sh --user "$CI_UID:$CI_UID" --group-add "$SOCK_GID" \
  -v "$WORK:$WORK" -w "$WORK" -v "$SOCK:/var/run/docker.sock" \
  -e HOME="$WORK/home" -e UV_CACHE_DIR="$WORK/home/.uvcache" -e UV_PROJECT_ENVIRONMENT="$WORK/venv" \
  -e UV_PYTHON_DOWNLOADS=never -e UV_LINK_MODE=copy -e PATH="$WORK/bin:/usr/local/bin:/usr/bin:/bin" \
  "$IMAGE" -c "echo \"running as: \$(id)\"; uv sync --locked -q && $CMD"
