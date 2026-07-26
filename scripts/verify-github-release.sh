#!/bin/bash
# Verify an exact draft or immutable GitHub Release against local asset bytes.

set -euo pipefail

REPOSITORY="${1:-}"
RELEASE_TAG="${2:-}"
RELEASE_COMMIT="${3:-}"
ASSET_DIR="${4:-}"
EXPECTED_STATE="${5:-}"

if [[ ! "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "Repository must use the owner/name form." >&2
    exit 1
fi
if [[ ! "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Release tag must be a full semantic version." >&2
    exit 1
fi
if [[ ! "$RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Release commit must be a full lowercase SHA-1." >&2
    exit 1
fi
if [ ! -d "$ASSET_DIR" ]; then
    echo "Release asset directory does not exist: $ASSET_DIR" >&2
    exit 1
fi
if [ "$EXPECTED_STATE" != "draft" ] \
    && [ "$EXPECTED_STATE" != "immutable" ]
then
    echo "Expected state must be draft or immutable." >&2
    exit 1
fi
for required_command in gh jq shasum; do
    command -v "$required_command" >/dev/null 2>&1 || {
        echo "Required command is unavailable: $required_command" >&2
        exit 1
    }
done

VERIFY_DIR="$(mktemp -d)"
trap 'rm -rf "$VERIFY_DIR"' EXIT
RELEASE_JSON="$VERIFY_DIR/release.json"
TAG_REF_JSON="$VERIFY_DIR/tag-ref.json"
TAG_OBJECT_JSON="$VERIFY_DIR/tag-object.json"
API_VERSION="2026-03-10"

gh release view "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --json assets,isDraft,isImmutable,tagName,targetCommitish \
    > "$RELEASE_JSON"

if ! jq -e \
    --arg tag "$RELEASE_TAG" \
    '.tagName == $tag' \
    "$RELEASE_JSON" >/dev/null
then
    echo "Release tag does not match the reviewed input." >&2
    exit 1
fi

# targetCommitish is metadata and is not authoritative when a tag already
# exists. Resolve the protected annotated tag itself on every draft and
# post-publication check.
gh api \
    -H "X-GitHub-Api-Version: $API_VERSION" \
    "repos/${REPOSITORY}/git/ref/tags/${RELEASE_TAG}" \
    > "$TAG_REF_JSON"
if ! TAG_OBJECT_SHA="$(
    jq -er \
        '
          select(.object.type == "tag")
          | .object.sha
          | select(test("^[0-9a-f]{40}$"))
        ' \
        "$TAG_REF_JSON"
)"; then
    echo "Release tag is not one exact annotated tag object." >&2
    exit 1
fi

gh api \
    -H "X-GitHub-Api-Version: $API_VERSION" \
    "repos/${REPOSITORY}/git/tags/${TAG_OBJECT_SHA}" \
    > "$TAG_OBJECT_JSON"
if ! jq -e \
    --arg commit "$RELEASE_COMMIT" \
    '
      .object.type == "commit"
      and .object.sha == $commit
      and .verification.verified == true
      and .verification.reason == "valid"
    ' \
    "$TAG_OBJECT_JSON" >/dev/null
then
    echo "Signed release tag does not resolve to the reviewed commit." >&2
    exit 1
fi

if [ "$EXPECTED_STATE" = "draft" ]; then
    jq -e '.isDraft == true and .isImmutable == false' \
        "$RELEASE_JSON" >/dev/null || {
        echo "Release is not an unsealed draft." >&2
        exit 1
    }
else
    jq -e '.isDraft == false and .isImmutable == true' \
        "$RELEASE_JSON" >/dev/null || {
        echo "Release is not published and immutable." >&2
        exit 1
    }
fi

EXPECTED_COUNT="$(
    find "$ASSET_DIR" -type f | wc -l | tr -d '[:space:]'
)"
if [ "$EXPECTED_COUNT" -lt 1 ]; then
    echo "Release asset directory is empty." >&2
    exit 1
fi
ACTUAL_COUNT="$(jq '.assets | length' "$RELEASE_JSON")"
if [ "$ACTUAL_COUNT" != "$EXPECTED_COUNT" ]; then
    echo "GitHub Release asset count does not match local assets." >&2
    exit 1
fi

while IFS= read -r file; do
    NAME="$(basename "$file")"
    EXPECTED_DIGEST="sha256:$(shasum -a 256 "$file" | awk '{print $1}')"
    if ! ACTUAL_DIGEST="$(
        jq -er \
            --arg name "$NAME" \
            '
              [.assets[] | select(.name == $name)]
              | select(length == 1)
              | .[0].digest
              | select(type == "string")
            ' \
            "$RELEASE_JSON"
    )"; then
        echo "GitHub Release is missing one exact asset named $NAME." >&2
        exit 1
    fi
    if [ "$ACTUAL_DIGEST" != "$EXPECTED_DIGEST" ]; then
        echo "GitHub digest mismatch for $NAME." >&2
        exit 1
    fi
done < <(find "$ASSET_DIR" -type f -print | sort)
