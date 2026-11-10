#!/usr/bin/env bash
# Checks (default) or applies the scan workspace repo settings described in setup/README.md.
#
#   SCAN_REPO=owner/name ./configure_repo.sh --check     read-only drift report, exit 1 on drift
#   SCAN_REPO=owner/name ./configure_repo.sh --apply     change settings, then report again
#
# Needs the gh CLI logged in as a repo admin. Optional environment:
#   SCAN_BYPASS_ACTOR_TYPE / SCAN_BYPASS_ACTOR_ID   who may write scan/** (Integration + App id in the real
#                                                   environment; default RepositoryRole 5 = repo admins)
#   DEFAULT_BRANCH_BYPASS=admin                     let repo admins push to the default branch (test repos only)
set -uo pipefail

MODE="${1:---check}"
REPO="${SCAN_REPO:?set SCAN_REPO=owner/name}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ALLOWED='["actions/checkout@*","actions/upload-artifact@*","github/codeql-action/*"]'
DRIFT=0

api() { gh api -H "X-GitHub-Api-Version: 2022-11-28" "$@" 2>/dev/null; }
row() { # name, actual, wanted
  if [ "$2" = "$3" ]; then printf '  ok     %-44s %s\n' "$1" "$2"
  elif [ "$2" = "n/a" ]; then printf '  n/a    %-44s not available on this repo or plan\n' "$1"
  else printf '  DRIFT  %-44s is "%s", want "%s"\n' "$1" "$2" "$3"; DRIFT=1; fi
}
get() { local out; out=$(api "$1" --jq "$2") && [ -n "$out" ] && echo "$out" || echo "n/a"; }
probe() { api "$1" >/dev/null && echo "$2" || echo "$3"; } # endpoint, value if it answers, value if it does not

report() {
  local vis; vis=$(get "repos/$REPO" .visibility)
  echo "Repository $REPO ($vis)"
  [ "$vis" = "public" ] && echo "  note   public repo: fine for a test with synthetic bundles, never for real artifacts"
  row "secret scanning"                 "$(get "repos/$REPO" '.security_and_analysis.secret_scanning.status')" enabled
  row "push protection"                 "$(get "repos/$REPO" '.security_and_analysis.secret_scanning_push_protection.status')" enabled
  row "generic secret patterns"         "$(get "repos/$REPO" '.security_and_analysis.secret_scanning_non_provider_patterns.status')" enabled
  [ "$vis" != "public" ] && row "code security licensed"      "$(get "repos/$REPO" '(.security_and_analysis.code_security // .security_and_analysis.advanced_security).status')" enabled
  [ "$vis" != "public" ] && row "forking"                     "$(get "repos/$REPO" .allow_forking)" false
  row "code scanning default setup"     "$(get "repos/$REPO/code-scanning/default-setup" .state)" not-configured
  row "dependency graph"                "$(probe "repos/$REPO/dependency-graph/sbom" enabled disabled)" enabled
  row "actions enabled"                 "$(get "repos/$REPO/actions/permissions" .enabled)" true
  row "allowed actions"                 "$(get "repos/$REPO/actions/permissions" .allowed_actions)" selected
  row "actions pinned to full SHA"      "$(get "repos/$REPO/actions/permissions" '.sha_pinning_required // "n/a"')" true
  row "allowed action patterns"         "$(get "repos/$REPO/actions/permissions/selected-actions" '.patterns_allowed | sort | tojson')" "$(echo "$ALLOWED" | jq -c 'sort')"
  row "default workflow token"          "$(get "repos/$REPO/actions/permissions/workflow" .default_workflow_permissions)" read
  row "actions may approve PRs"         "$(get "repos/$REPO/actions/permissions/workflow" .can_approve_pull_request_reviews)" false
  row "repository secrets"              "$(get "repos/$REPO/actions/secrets" .total_count)" 0
  row "artifact and log retention days" "$(get "repos/$REPO/actions/permissions/artifact-and-log-retention" .days)" 7
  for name in scan-protect-default scan-branches scan-push-rules; do
    row "ruleset $name" "$(get "repos/$REPO/rulesets" "[.[] | select(.name==\"$name\") | .enforcement][0] // \"missing\"")" active
  done
  row "workflow on default branch"      "$(probe "repos/$REPO/contents/.github/workflows/scan.yml" present missing)" present
}

ruleset() { # file, bypass json
  local file="$1" bypass="$2" name id payload
  name=$(jq -r .name "$file")
  payload=$(jq -c --argjson bypass "$bypass" '. + {bypass_actors: $bypass}' "$file")
  id=$(api "repos/$REPO/rulesets" --jq "[.[] | select(.name==\"$name\") | .id][0] // empty")
  if [ -n "$id" ]; then echo "$payload" | gh api -X PUT "repos/$REPO/rulesets/$id" --input - >/dev/null
  else echo "$payload" | gh api -X POST "repos/$REPO/rulesets" --input - >/dev/null; fi \
    && echo "  set    ruleset $name" || echo "  skip   ruleset $name (not supported on this repo or plan)"
}

apply() {
  echo "Applying settings to $REPO"
  gh api -X PATCH "repos/$REPO" --input - >/dev/null <<'JSON' || echo "  skip   secret protection (already on, or not available on this plan)"
{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"},"secret_scanning_non_provider_patterns":{"status":"enabled"}}}
JSON
  gh api -X PATCH "repos/$REPO/code-scanning/default-setup" -f state=not-configured >/dev/null 2>&1 || true
  gh api -X PUT "repos/$REPO/actions/permissions" -F enabled=true -f allowed_actions=selected -F sha_pinning_required=true >/dev/null
  echo "{\"github_owned_allowed\":false,\"verified_allowed\":false,\"patterns_allowed\":$ALLOWED}" \
    | gh api -X PUT "repos/$REPO/actions/permissions/selected-actions" --input - >/dev/null
  gh api -X PUT "repos/$REPO/actions/permissions/workflow" -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false >/dev/null
  gh api -X PUT "repos/$REPO/actions/permissions/artifact-and-log-retention" -F days=7 >/dev/null 2>&1 || echo "  skip   retention (set it in the UI)"
  gh api -X PUT "repos/$REPO/vulnerability-alerts" >/dev/null 2>&1 || true

  local scan_bypass default_bypass="[]"
  scan_bypass="[{\"actor_type\":\"${SCAN_BYPASS_ACTOR_TYPE:-RepositoryRole}\",\"actor_id\":${SCAN_BYPASS_ACTOR_ID:-5},\"bypass_mode\":\"always\"}]"
  [ "${DEFAULT_BRANCH_BYPASS:-}" = "admin" ] && default_bypass='[{"actor_type":"RepositoryRole","actor_id":5,"bypass_mode":"always"}]'
  ruleset "$HERE/rulesets/protect-default.json" "$default_bypass"
  ruleset "$HERE/rulesets/scan-branches.json" "$scan_bypass"
  ruleset "$HERE/rulesets/push-rules.json" '[{"actor_type":"RepositoryRole","actor_id":5,"bypass_mode":"always"}]'
}

command -v gh >/dev/null && command -v jq >/dev/null || { echo "gh and jq are required"; exit 2; }
case "$MODE" in
  --check) report ;;
  --apply) apply; echo; report ;;
  *) echo "usage: SCAN_REPO=owner/name $0 [--check|--apply]"; exit 2 ;;
esac
[ "$DRIFT" -eq 0 ] && echo "No drift." || { echo "Drift found."; exit 1; }
