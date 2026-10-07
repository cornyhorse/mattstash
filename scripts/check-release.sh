#!/usr/bin/env bash
# Check that a release tag is consistent before (and after) it is created.
#
# Usage:
#   scripts/check-release.sh vX.Y.Z --preflight   # before tagging: run from the commit you are about to tag
#   scripts/check-release.sh vX.Y.Z               # after tagging: run by the release workflow on the tag's checkout
#
# Both modes require:
#   * the tag is vMAJOR.MINOR.PATCH,
#   * `version` in pyproject.toml equals the tag without the leading "v",
#   * the commit is on origin/main (releases are cut from main, never from a branch).
# --preflight additionally requires HEAD to BE origin/main and the tag to not exist yet, locally or on origin.
# Without it, the tag must exist and point at HEAD.
#
# It never changes anything: it only reads the working tree and the git history.
set -euo pipefail

fail() {
    echo "release check failed: $*" >&2
    exit 1
}

tag="${1:-}"
mode="${2:-verify}"
[[ -n "$tag" ]] || fail "usage: $0 vX.Y.Z [--preflight]"
[[ "$mode" == "verify" || "$mode" == "--preflight" ]] || fail "unknown option '$mode' (only --preflight is supported)"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "'$tag' is not of the form vMAJOR.MINOR.PATCH"
version="${tag#v}"

cd "$(git rev-parse --show-toplevel)"

file_version="$(python3 - <<'PY'
import re

match = re.search(r'^version\s*=\s*"(\d+\.\d+\.\d+)"', open("pyproject.toml", encoding="utf-8").read(), re.M)
print(match.group(1) if match else "")
PY
)"
[[ -n "$file_version" ]] || fail "could not read a MAJOR.MINOR.PATCH version from pyproject.toml"
[[ "$file_version" == "$version" ]] || fail "pyproject.toml says version $file_version but the tag is $tag"

if [[ "$mode" == "--preflight" ]]; then
    # A stale origin/main would make every later check meaningless, so a failed fetch is fatal here.
    git fetch --quiet origin main || fail "could not fetch origin/main"
else
    # In CI the checkout has already fetched every branch (and has no credentials to fetch again).
    git fetch --quiet origin main 2>/dev/null || true
fi
head_sha="$(git rev-parse HEAD)"
main_sha="$(git rev-parse --verify --quiet refs/remotes/origin/main)" || fail "origin/main is not available in this checkout"
git merge-base --is-ancestor "$head_sha" "$main_sha" || fail "commit ${head_sha:0:7} is not on origin/main"

if [[ "$mode" == "--preflight" ]]; then
    [[ "$head_sha" == "$main_sha" ]] || fail "HEAD (${head_sha:0:7}) is not the tip of origin/main (${main_sha:0:7}); update your checkout"
    if git rev-parse --quiet --verify "refs/tags/$tag" >/dev/null; then
        fail "tag $tag already exists locally"
    fi
    if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
        fail "tag $tag already exists on origin; versions are never reused (delete it only if it was never released)"
    fi
    echo "ok: $tag can be created at ${head_sha:0:7} (the tip of origin/main, version $file_version)"
else
    tag_sha="$(git rev-parse --verify "refs/tags/$tag^{commit}" 2>/dev/null)" || fail "tag $tag does not exist in this checkout"
    [[ "$tag_sha" == "$head_sha" ]] || fail "tag $tag points at ${tag_sha:0:7} but this checkout is ${head_sha:0:7}"
    echo "ok: $tag is at ${head_sha:0:7}, on origin/main, and matches pyproject.toml ($file_version)"
fi
