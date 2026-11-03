# keyhop-auth.ps1: Windows Hello-gated secret for the keyhop vault.
#
#   keyhop-auth.ps1 create                 -> {"peer": b64}
#   keyhop-auth.ps1 derive <unlock|change|grant>  stdin {"peer"} -> b64 secret
#
# create makes a Windows Hello key (TPM-backed where available) named "keyhop".
# derive asks Windows Hello to sign the stored challenge; RSA PKCS#1 v1.5
# signatures are deterministic, so the signature is a stable secret that only
# this user's Hello key can produce.
#
# Runs under Windows PowerShell 5.1 (powershell.exe), which projects WinRT.
# Exit codes: 0 ok, 1 error, 2 cancelled, 3 key exists (create without --replace).
#
# Windows Hello's signing prompt can't show custom text, so unlock and change
# prompts look the same; only approve a prompt you expected.
$ErrorActionPreference = 'Stop'
$command = $args[0]
$replace = $args -contains '--replace'

function Fail([string]$Message, [int]$Code = 1) {
  [Console]::Error.WriteLine($Message)
  exit $Code
}

try {
  . (Join-Path $PSScriptRoot 'keyhop-buffers.ps1')
  $null = [Windows.Security.Credentials.KeyCredentialManager, Windows.Security.Credentials, ContentType = WindowsRuntime]
  $asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
  } | Select-Object -First 1

  function Wait-Operation($Operation, [Type]$ResultType) {
    $task = $asTask.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
    $null = $task.Wait(-1)
    return $task.Result
  }

  function Assert-Status($Status) {
    if ("$Status" -eq 'UserCanceled') { Fail 'Authentication was cancelled.' 2 }
    if ("$Status" -eq 'NotFound') { Fail 'No keyhop Windows Hello key; run: keyhop init' }
    if ("$Status" -ne 'Success') { Fail "Windows Hello returned $Status." }
  }

  $manager = [Windows.Security.Credentials.KeyCredentialManager]
  $retrieval = [Windows.Security.Credentials.KeyCredentialRetrievalResult]
  $name = 'keyhop'
  if (-not (Wait-Operation ($manager::IsSupportedAsync()) ([bool]))) {
    Fail 'Windows Hello is not set up. Turn it on in Settings > Accounts > Sign-in options.'
  }

  switch ($command) {
    'create' {
      # Never clobber an existing key unless asked: it may still guard a vault.
      $option = if ($replace) { 'ReplaceExisting' } else { 'FailIfExists' }
      $created = Wait-Operation ($manager::RequestCreateAsync($name, [Windows.Security.Credentials.KeyCredentialCreationOption]::$option)) $retrieval
      if ("$($created.Status)" -eq 'CredentialAlreadyExists') { Fail 'A keyhop Windows Hello key already exists.' 3 }
      Assert-Status $created.Status
      $peer = New-Object byte[] 32
      [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($peer)
      @{ peer = [Convert]::ToBase64String($peer) } | ConvertTo-Json -Compress
    }
    'derive' {
      $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
      if (-not $request.peer) { Fail 'Input needs peer.' }
      $buffer = ConvertTo-WinRtBuffer ([Convert]::FromBase64String($request.peer))
      $opened = Wait-Operation ($manager::OpenAsync($name)) $retrieval
      Assert-Status $opened.Status
      $signed = Wait-Operation ($opened.Credential.RequestSignAsync($buffer)) ([Windows.Security.Credentials.KeyCredentialOperationResult])
      Assert-Status $signed.Status
      [Convert]::ToBase64String((ConvertFrom-WinRtBuffer $signed.Result))
    }
    default { Fail 'Usage: keyhop-auth.ps1 create | derive <unlock|change|grant>' }
  }
} catch {
  Fail $_.Exception.Message
}
