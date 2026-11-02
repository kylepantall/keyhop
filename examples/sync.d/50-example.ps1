# keyhop sync script.
#
# Print secrets on stdout as NAME=value lines (or one JSON object). Steps run
# in number order - built-in 00-<tool> steps, then 10-..., 20-... - and a later
# step overrides a name set earlier. stderr is shown only if the script fails.
# Exit non-zero to stop the sync; the vault is then left as it was.
$ErrorActionPreference = 'Stop'

# A short-lived token from another CLI:
# $token = aws codeartifact get-authorization-token --domain my-domain --query authorizationToken --output text
# "CODEARTIFACT_AUTH_TOKEN=$token"

# A credential from Windows Credential Manager (needs the CredentialManager module):
# $cred = Get-StoredCredential -Target 'my-api'
# "MY_API_KEY=$($cred.GetNetworkCredential().Password)"
