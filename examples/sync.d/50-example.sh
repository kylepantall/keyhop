#!/usr/bin/env bash
# keyhop sync script.
#
# Print secrets on stdout as NAME=value lines (or one JSON object). Steps run
# in number order — built-in 00-<tool> steps, then 10-…, 20-… — and a later
# step overrides a name set earlier. stderr is shown only if the script fails.
# Exit non-zero to stop the sync; the vault is then left as it was.
set -euo pipefail

# A short-lived token from another CLI:
# printf 'CODEARTIFACT_AUTH_TOKEN=%s\n' "$(aws codeartifact get-authorization-token \
#   --domain my-domain --query authorizationToken --output text)"

# A value kept in a local file:
# printf 'OPENAI_API_KEY=%s\n' "$(cat "$HOME/.secrets/openai")"
