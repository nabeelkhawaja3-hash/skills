#!/bin/bash

# Fail closed: without jq we cannot inspect the command, so deny rather than
# silently allowing everything through.
if ! command -v jq >/dev/null 2>&1; then
  echo "BLOCKED: jq not found, so git guardrails cannot inspect this command." >&2
  exit 2
fi

INPUT=$(cat)
if ! COMMAND=$(printf '%s' "$INPUT" | jq -er '.tool_input.command'); then
  echo "BLOCKED: could not parse hook input to extract the command." >&2
  exit 2
fi

# Normalise before matching so trivial spacing tricks cannot slip a pattern:
#   - collapse tabs and repeated spaces   (git<TAB>push)
#   - drop leading env assignments        (GIT_DIR=… git push)
#   - drop global git options             (git -C path push, git --git-dir=… push)
COMMAND_NORM=$(printf '%s' "$COMMAND" | tr '\t' ' ' | tr -s ' ')
COMMAND_NORM=$(printf '%s' "$COMMAND_NORM" |
  sed -E 's/(^|[;&|(] *)([A-Za-z_][A-Za-z0-9_]*=[^ ]* +)+/\1/g')
COMMAND_NORM=$(printf '%s' "$COMMAND_NORM" |
  sed -E 's/\bgit( +(-c +[^ ]+|-C +[^ ]+|--git-dir=[^ ]+|--work-tree=[^ ]+|--no-pager|-P))+/git/g')

DANGEROUS_PATTERNS=(
  "git push"
  "git reset --hard"
  "git clean -fd"
  "git clean -f"
  "git branch -D"
  "git checkout \."
  "git restore \."
  "push --force"
  "reset --hard"
)

for pattern in "${DANGEROUS_PATTERNS[@]}"; do
  if printf '%s' "$COMMAND_NORM" | grep -qE "$pattern"; then
    echo "BLOCKED: '$COMMAND' matches dangerous pattern '$pattern'. The user has prevented you from doing this." >&2
    exit 2
  fi
done

exit 0
