#!/bin/bash
# Fail closed unless the repository's remote release protections are active.

set -euo pipefail

REPOSITORY="${1:-}"
RELEASE_TAG="${2:-}"
POLICY_FILE="${3:-.github/release-policy.json}"
WORKFLOW_RUN_ID="${4:-}"
WORKFLOW_RUN_ATTEMPT="${5:-}"
DISPATCHER_USER_ID="${6:-}"
API_VERSION="2026-03-10"
TIME_ZONE_HEADER="Time-Zone: UTC"

if [[ ! "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "Repository must use the owner/name form." >&2
    exit 1
fi
if [[ ! "$RELEASE_TAG" =~ ^(home|app|sensor)-v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Release tag must be home-vX.Y.Z, app-vX.Y.Z, or sensor-vX.Y.Z." >&2
    exit 1
fi
if [[ ! "$WORKFLOW_RUN_ID" =~ ^[1-9][0-9]*$ ]]; then
    echo "Workflow run ID must be a positive integer." >&2
    exit 1
fi
if [ "$WORKFLOW_RUN_ATTEMPT" != "1" ]; then
    echo "Release workflow reruns are forbidden; start a fresh dispatch." >&2
    exit 1
fi
if [[ ! "$DISPATCHER_USER_ID" =~ ^[1-9][0-9]*$ ]]; then
    echo "Dispatcher User ID must be a positive integer." >&2
    exit 1
fi
for required_command in gh jq python3; do
    command -v "$required_command" >/dev/null 2>&1 || {
        echo "Required command is unavailable: $required_command" >&2
        exit 1
    }
done

if [ ! -f "$POLICY_FILE" ]; then
    echo "Release policy pin is missing: $POLICY_FILE" >&2
    exit 1
fi
if ! jq -e '.schema_version == 3' "$POLICY_FILE" >/dev/null; then
    echo "Release policy schema is not the reviewed version 3." >&2
    exit 1
fi
if ! EXPECTED_RULESET_ID="$(
    jq -er \
        '.tag_ruleset.id
         | select(type == "number" and . > 0)' \
        "$POLICY_FILE"
)"; then
    echo "Pin the reviewed tag ruleset ID in $POLICY_FILE." >&2
    exit 1
fi
if ! EXPECTED_RULESET_UPDATED_AT="$(
    jq -er \
        '.tag_ruleset.updated_at
         | select(
             type == "string"
             and test(
               "^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
               + "[0-9]{2}:[0-9]{2}:[0-9]{2}"
               + "(\\.[0-9]+)?Z$"
             )
           )' \
        "$POLICY_FILE"
)"; then
    echo "Pin the reviewed tag ruleset update time in $POLICY_FILE." >&2
    exit 1
fi
if ! EXPECTED_BYPASS_USER_ID="$(
    jq -er \
        '.tag_bypass_user_id
         | select(type == "number" and . > 0)' \
        "$POLICY_FILE"
)"; then
    echo "Pin the dedicated tag-bypass User actor ID in $POLICY_FILE." >&2
    exit 1
fi
if ! EXPECTED_REVIEWER_TYPE="$(
    jq -er \
        '.release_environment.reviewer.type
         | select(. == "User")' \
        "$POLICY_FILE"
)"; then
    echo "Pin a dedicated release-reviewer User in $POLICY_FILE." >&2
    exit 1
fi
if ! EXPECTED_REVIEWER_ID="$(
    jq -er \
        '.release_environment.reviewer.id
         | select(type == "number" and . > 0)' \
        "$POLICY_FILE"
)"; then
    echo "Pin the release environment reviewer actor ID in $POLICY_FILE." >&2
    exit 1
fi
if [ "$EXPECTED_REVIEWER_ID" = "$EXPECTED_BYPASS_USER_ID" ]; then
    echo "Release reviewer User must differ from the tag-bypass User." >&2
    exit 1
fi
if [ "$DISPATCHER_USER_ID" != "$EXPECTED_BYPASS_USER_ID" ]; then
    echo "Only the pinned tag-bypass User may dispatch a release." >&2
    exit 1
fi
if ! EXPECTED_ENVIRONMENT_ID="$(
    jq -er \
        '.release_environment.id
         | select(type == "number" and . > 0)' \
        "$POLICY_FILE"
)"; then
    echo "Pin the release environment numeric ID in $POLICY_FILE." >&2
    exit 1
fi
if ! EXPECTED_ENVIRONMENT_NAME="$(
    jq -er \
        '.release_environment.name
         | select(. == "release")' \
        "$POLICY_FILE"
)"; then
    echo "Pin the release environment name in $POLICY_FILE." >&2
    exit 1
fi
if ! EXPECTED_ENVIRONMENT_UPDATED_AT="$(
    jq -er \
        '.release_environment.updated_at
         | select(
             type == "string"
             and test(
               "^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
               + "[0-9]{2}:[0-9]{2}:[0-9]{2}"
               + "(\\.[0-9]+)?Z$"
             )
           )' \
        "$POLICY_FILE"
)"; then
    echo "Pin the reviewed release environment update time in $POLICY_FILE." >&2
    exit 1
fi
if ! EXPECTED_MAIN_RULESET_ID="$(
    jq -er \
        '.main_ruleset.id
         | select(type == "number" and . > 0)' \
        "$POLICY_FILE"
)"; then
    echo "Pin the reviewed main branch ruleset ID in $POLICY_FILE." >&2
    exit 1
fi
if ! EXPECTED_MAIN_RULESET_UPDATED_AT="$(
    jq -er \
        '.main_ruleset.updated_at
         | select(
             type == "string"
             and test(
               "^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
               + "[0-9]{2}:[0-9]{2}:[0-9]{2}"
               + "(\\.[0-9]+)?Z$"
             )
           )' \
        "$POLICY_FILE"
)"; then
    echo "Pin the reviewed main branch ruleset update time in $POLICY_FILE." >&2
    exit 1
fi
if ! EXPECTED_REQUIRED_CHECK_INTEGRATION_ID="$(
    jq -er \
        '.main_ruleset.required_check_integration_id
         | select(type == "number" and . > 0)' \
        "$POLICY_FILE"
)"; then
    echo \
        "Pin the GitHub Actions App integration ID for the required check." \
        >&2
    exit 1
fi

CONTROL_DIR="$(mktemp -d)"
trap 'rm -rf "$CONTROL_DIR"' EXIT

TAG_REF_JSON="$CONTROL_DIR/release-tag-ref.json"
gh api \
    -H "X-GitHub-Api-Version: $API_VERSION" \
    "repos/${REPOSITORY}/git/ref/tags/${RELEASE_TAG}" \
    > "$TAG_REF_JSON"
TAG_OBJECT_TYPE="$(jq -r '.object.type // "missing"' "$TAG_REF_JSON")"
TAG_OBJECT_SHA="$(jq -r '.object.sha // "missing"' "$TAG_REF_JSON")"
if [ "$TAG_OBJECT_TYPE" != "tag" ] \
    || [[ ! "$TAG_OBJECT_SHA" =~ ^[0-9a-f]{40}$ ]]
then
    echo "Release tag must be an annotated, cryptographically signed tag." >&2
    exit 1
fi

TAG_OBJECT_JSON="$CONTROL_DIR/release-tag-object.json"
gh api \
    -H "X-GitHub-Api-Version: $API_VERSION" \
    "repos/${REPOSITORY}/git/tags/${TAG_OBJECT_SHA}" \
    > "$TAG_OBJECT_JSON"
if ! jq -e '
    .object.type == "commit"
    and .verification.verified == true
    and .verification.reason == "valid"
' "$TAG_OBJECT_JSON" >/dev/null; then
    echo "GitHub must report the annotated release tag signature as valid." >&2
    exit 1
fi

IMMUTABILITY_ENABLED="$(
    gh api \
        -H "X-GitHub-Api-Version: $API_VERSION" \
        "repos/${REPOSITORY}/immutable-releases" \
        --jq '.enabled'
)"
if [ "$IMMUTABILITY_ENABLED" != "true" ]; then
    echo "GitHub release immutability must be enabled." >&2
    exit 1
fi

ENVIRONMENT_JSON="$CONTROL_DIR/release-environment.json"
gh api \
    -H "X-GitHub-Api-Version: $API_VERSION" \
    -H "$TIME_ZONE_HEADER" \
    "repos/${REPOSITORY}/environments/release" \
    > "$ENVIRONMENT_JSON"

ACTUAL_ENVIRONMENT_UPDATED_AT="$(
    jq -r '.updated_at // "missing"' "$ENVIRONMENT_JSON"
)"
if [ "$ACTUAL_ENVIRONMENT_UPDATED_AT" != "$EXPECTED_ENVIRONMENT_UPDATED_AT" ]; then
    echo "release environment changed since independent review." >&2
    exit 1
fi
if ! jq -e \
    --argjson environment_id "$EXPECTED_ENVIRONMENT_ID" \
    --arg environment_name "$EXPECTED_ENVIRONMENT_NAME" \
    '
      .id == $environment_id
      and .name == $environment_name
    ' \
    "$ENVIRONMENT_JSON" >/dev/null
then
    echo "release environment identity does not match the reviewed pin." >&2
    exit 1
fi

PROTECTED_BRANCHES="$(
    jq -r \
        '.deployment_branch_policy.protected_branches // false' \
        "$ENVIRONMENT_JSON"
)"
CAN_ADMINS_BYPASS="$(
    jq -r \
        'if has("can_admins_bypass")
         then .can_admins_bypass
         else "missing"
         end' \
        "$ENVIRONMENT_JSON"
)"

if ! jq -e \
    --arg reviewer_type "$EXPECTED_REVIEWER_TYPE" \
    --argjson reviewer_id "$EXPECTED_REVIEWER_ID" \
    '
      [
        .protection_rules[]?
        | select(.type == "required_reviewers")
      ] as $rules
      | ($rules | length == 1)
      and $rules[0].prevent_self_review == true
      and (
        [
          $rules[0].reviewers[]?
          | {
              type: .type,
              id: .reviewer.id
            }
        ]
        == [
          {
            type: $reviewer_type,
            id: $reviewer_id
          }
        ]
      )
    ' \
    "$ENVIRONMENT_JSON" >/dev/null
then
    echo "release environment reviewer or self-review policy changed." >&2
    exit 1
fi
if [ "$PROTECTED_BRANCHES" != "true" ]; then
    echo "release environment must allow only protected branches." >&2
    exit 1
fi
if [ "$CAN_ADMINS_BYPASS" != "false" ]; then
    echo "release environment must explicitly disallow administrator bypass." >&2
    exit 1
fi

WORKFLOW_RUN_JSON="$CONTROL_DIR/workflow-run.json"
gh api \
    -H "X-GitHub-Api-Version: $API_VERSION" \
    "repos/${REPOSITORY}/actions/runs/${WORKFLOW_RUN_ID}" \
    > "$WORKFLOW_RUN_JSON"
if ! jq -e \
    --argjson run_id "$WORKFLOW_RUN_ID" \
    --argjson dispatcher_id "$DISPATCHER_USER_ID" \
    '
      .id == $run_id
      and .run_attempt == 1
      and .event == "workflow_dispatch"
      and .head_branch == "main"
      and (
        .path == ".github/workflows/release.yml"
        or (.path | startswith(".github/workflows/release.yml@"))
        or .path == ".github/workflows/release-sensor.yml"
        or (.path | startswith(".github/workflows/release-sensor.yml@"))
      )
      and .actor.type == "User"
      and .actor.id == $dispatcher_id
      and .triggering_actor.type == "User"
      and .triggering_actor.id == $dispatcher_id
    ' \
    "$WORKFLOW_RUN_JSON" >/dev/null
then
    echo "Workflow run identity does not match the fresh reviewed dispatch." >&2
    exit 1
fi

APPROVALS_JSON="$CONTROL_DIR/workflow-run-approvals.json"
APPROVAL_VERIFIED=0
for APPROVAL_ATTEMPT in 1 2 3 4 5 6; do
    if gh api \
        -H "X-GitHub-Api-Version: $API_VERSION" \
        "repos/${REPOSITORY}/actions/runs/${WORKFLOW_RUN_ID}/approvals" \
        > "$APPROVALS_JSON" \
        && jq -e \
            --argjson environment_id "$EXPECTED_ENVIRONMENT_ID" \
            --arg environment_name "$EXPECTED_ENVIRONMENT_NAME" \
            --argjson reviewer_id "$EXPECTED_REVIEWER_ID" \
            '
              [
                .[]? as $review
                | $review.environments[]?
                | select(
                    .id == $environment_id
                    and .name == $environment_name
                  )
                | {
                    state: $review.state,
                    user_type: $review.user.type,
                    user_id: $review.user.id
                  }
              ] as $decisions
              | ($decisions | length >= 1)
              and all(
                $decisions[];
                .state == "approved"
                and .user_type == "User"
                and .user_id == $reviewer_id
              )
            ' \
            "$APPROVALS_JSON" >/dev/null
    then
        APPROVAL_VERIFIED=1
        break
    fi
    if [ "$APPROVAL_ATTEMPT" -lt 6 ]; then
        sleep 2
    fi
done
if [ "$APPROVAL_VERIFIED" -ne 1 ]; then
    echo \
        "This fresh run lacks exact approval by the pinned release reviewer." \
        >&2
    exit 1
fi

RULESET_JSON="$CONTROL_DIR/tag-ruleset.json"
gh api \
    -H "X-GitHub-Api-Version: $API_VERSION" \
    -H "$TIME_ZONE_HEADER" \
    "repos/${REPOSITORY}/rulesets/${EXPECTED_RULESET_ID}?includes_parents=true" \
    > "$RULESET_JSON"

ACTUAL_RULESET_UPDATED_AT="$(
    jq -r '.updated_at // "missing"' "$RULESET_JSON"
)"
if [ "$ACTUAL_RULESET_UPDATED_AT" != "$EXPECTED_RULESET_UPDATED_AT" ]; then
    echo \
        "Tag ruleset changed since its bypass actors were independently reviewed." \
        >&2
    exit 1
fi

if ! jq -e \
    --arg repository "$REPOSITORY" \
    --argjson ruleset_id "$EXPECTED_RULESET_ID" \
    '
      .id == $ruleset_id
      and .source_type == "Repository"
      and .source == $repository
      and .target == "tag"
      and .enforcement == "active"
      and .current_user_can_bypass == "never"
      and (
        (.conditions.ref_name.include // []) as $included
        | (
            ($included | any(. == "refs/tags/home-v*" or . == "~ALL"))
            and
            ($included | any(. == "refs/tags/app-v*" or . == "~ALL"))
            and
            ($included | any(. == "refs/tags/sensor-v*" or . == "~ALL"))
          )
      )
      and ((.conditions.ref_name.exclude // []) | length == 0)
      and (([.rules[]?.type] | index("creation")) != null)
      and (([.rules[]?.type] | index("update")) != null)
      and (([.rules[]?.type] | index("deletion")) != null)
    ' \
    "$RULESET_JSON" >/dev/null
then
    echo "The pinned component-tag ruleset changed from its reviewed configuration." >&2
    exit 1
fi

MAIN_RULESET_JSON="$CONTROL_DIR/main-ruleset.json"
gh api \
    -H "X-GitHub-Api-Version: $API_VERSION" \
    -H "$TIME_ZONE_HEADER" \
    "repos/${REPOSITORY}/rulesets/${EXPECTED_MAIN_RULESET_ID}?includes_parents=true" \
    > "$MAIN_RULESET_JSON"

ACTUAL_MAIN_RULESET_UPDATED_AT="$(
    jq -r '.updated_at // "missing"' "$MAIN_RULESET_JSON"
)"
if [ "$ACTUAL_MAIN_RULESET_UPDATED_AT" != "$EXPECTED_MAIN_RULESET_UPDATED_AT" ]; then
    echo "Main branch ruleset changed since independent review." >&2
    exit 1
fi

if ! jq -e \
    --arg repository "$REPOSITORY" \
    --argjson ruleset_id "$EXPECTED_MAIN_RULESET_ID" \
    --argjson check_integration_id "$EXPECTED_REQUIRED_CHECK_INTEGRATION_ID" \
    '
      .id == $ruleset_id
      and .source_type == "Repository"
      and .source == $repository
      and .target == "branch"
      and .enforcement == "active"
      and .current_user_can_bypass == "never"
      and (
        (.conditions.ref_name.include // [])
        | any(
            . == "refs/heads/main"
            or . == "~DEFAULT_BRANCH"
            or . == "~ALL"
          )
      )
      and ((.conditions.ref_name.exclude // []) | length == 0)
      and (([.rules[]?.type] | index("deletion")) != null)
      and (([.rules[]?.type] | index("non_fast_forward")) != null)
      and any(
        .rules[]?;
        .type == "pull_request"
        and (.parameters.required_approving_review_count // 0) >= 1
        and .parameters.dismiss_stale_reviews_on_push == true
        and .parameters.require_last_push_approval == true
        and .parameters.required_review_thread_resolution == true
      )
      and (
        [
          .rules[]?
          | select(.type == "required_status_checks")
        ] as $status_rules
        | ($status_rules | length == 1)
        and (
          $status_rules[0].parameters
            .strict_required_status_checks_policy == true
        )
        and (
          [
            $status_rules[0].parameters.required_status_checks[]?
            | select(
                .context
                  == "Verify release and package controls"
              )
          ] as $release_checks
          | ($release_checks | length == 1)
          and $release_checks[0].integration_id == $check_integration_id
        )
      )
    ' \
    "$MAIN_RULESET_JSON" >/dev/null
then
    echo "The pinned main ruleset does not enforce reviewed branch protections." >&2
    exit 1
fi
