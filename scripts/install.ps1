# Installs keyhop on Windows from a GitHub Release: keyhop.exe and the
# keyhop-hello.exe Windows Hello helper, checked against the release's
# SHA256SUMS. Then runs "keyhop setup" on a first install.
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/kylepantall/keyhop/main/scripts/install.ps1)))
#
# KEYHOP_RELEASE_DIR installs from a folder holding the zip and SHA256SUMS
# (used by CI) instead of downloading.
[CmdletBinding()]
param(
  [string]$Version = 'latest',
  [switch]$Claude,
  [switch]$NoSetup,
  [switch]$Help
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Asset = 'keyhop-windows-x64.zip'

function Write-Step([string]$Text) { Write-Host "`n==> $Text" }
function Write-Info([string]$Text) { Write-Host "    $Text" }

function Install-Keyhop {
  $repo = if ($env:KEYHOP_REPO) { $env:KEYHOP_REPO } else { 'kylepantall/keyhop' }
  if ($Help) {
    Write-Host 'Usage: install.ps1 [-Version <x.y.z>] [-Claude] [-NoSetup]'
    Write-Host "Installs a $repo release (default latest) under %LOCALAPPDATA%\keyhop\app and adds it to your user PATH."
    Write-Host '-Claude registers it with Claude Code (user scope) without asking.'
    return
  }
  if ($Version -ne 'latest' -and $Version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid version: $Version" }
  $label = if ($env:KEYHOP_RELEASE_DIR) { $env:KEYHOP_RELEASE_DIR } elseif ($Version -eq 'latest') { "$repo (latest release)" } else { "$repo v$Version" }
  Write-Host "keyhop installer - $label"

  $installDir = if ($env:KEYHOP_INSTALL_DIR) { $env:KEYHOP_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'keyhop' }
  New-Item -ItemType Directory -Force -Path $installDir | Out-Null
  $installDir = (Resolve-Path -LiteralPath $installDir).Path.TrimEnd('\')
  $app = Join-Path $installDir 'app'
  $temp = Join-Path ([IO.Path]::GetTempPath()) ('keyhop-install-' + [Guid]::NewGuid())
  New-Item -ItemType Directory -Path $temp | Out-Null

  try {
    Write-Step 'Downloading'
    $zip = Join-Path $temp $Asset
    $sums = Join-Path $temp 'SHA256SUMS'
    if ($env:KEYHOP_RELEASE_DIR) {
      Copy-Item (Join-Path $env:KEYHOP_RELEASE_DIR $Asset) $zip
      Copy-Item (Join-Path $env:KEYHOP_RELEASE_DIR 'SHA256SUMS') $sums
    } else {
      $base = if ($Version -eq 'latest') { "https://github.com/$repo/releases/latest/download" } else { "https://github.com/$repo/releases/download/v$Version" }
      Invoke-WebRequest "$base/SHA256SUMS" -OutFile $sums -UseBasicParsing
      Invoke-WebRequest "$base/$Asset" -OutFile $zip -UseBasicParsing
    }
    $line = Get-Content $sums | Where-Object { $_ -match "^[a-fA-F0-9]{64}\s+\*?$([regex]::Escape($Asset))$" } | Select-Object -First 1
    if (-not $line) { throw "SHA256SUMS does not list $Asset." }
    if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne ($line -split '\s+')[0].ToLower()) { throw 'Checksum mismatch: the download is not the published release.' }
    Write-Info 'Checksum verified'

    Write-Step 'Installing'
    # Unpack beside the install and swap it in, so a failure leaves the working
    # install untouched. Vault data lives in %APPDATA%\keyhop.
    $staging = Join-Path $installDir 'app.new'
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
    Expand-Archive $zip -DestinationPath $staging -Force
    if (-not (Test-Path (Join-Path $staging 'keyhop.exe'))) { throw 'The release is missing keyhop.exe.' }
    $old = Join-Path $installDir 'app.old'
    if (Test-Path $old) { Remove-Item $old -Recurse -Force }
    if (Test-Path $app) {
      try { Move-Item $app $old }
      catch { throw 'keyhop is running (Claude Code starts it). Quit Claude Code, then rerun the installer.' }
    }
    Move-Item $staging $app
    if (Test-Path $old) { Remove-Item $old -Recurse -Force -ErrorAction SilentlyContinue }
    $exe = Join-Path $app 'keyhop.exe'
    Write-Info "$exe (version $((& $exe --version 2>&1 | ForEach-Object { "$_" }) -join ' '))"

    # Earlier versions ran from source with a private Bun and a keyhop.cmd launcher.
    $oldBin = Join-Path $installDir 'bin'
    foreach ($leftover in $oldBin, (Join-Path $installDir 'runtime')) {
      if (Test-Path $leftover) { Remove-Item $leftover -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @(($userPath -split ';') | Where-Object { $_ -and $_ -ne $oldBin })
    if ($entries -notcontains $app) {
      $entries += $app
      $env:Path = "$env:Path;$app"
      Write-Info "Added $app to your user PATH (new terminals pick it up)."
    }
    [Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'User')

    if ($Claude) {
      Write-Step 'Registering with Claude Code'
      if (-not (Get-Command claude -ErrorAction SilentlyContinue)) { throw 'claude CLI not found.' }
      $previous = $ErrorActionPreference
      $ErrorActionPreference = 'Continue'
      try {
        & claude mcp get keyhop 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Info 'Already registered.' }
        else {
          & claude mcp add --transport stdio --scope user keyhop -- $exe serve 2>&1 | Out-Null
          if ($LASTEXITCODE -ne 0) { throw "Registration failed. Re-add it with: claude mcp add --transport stdio --scope user keyhop -- `"$exe`" serve" }
          Write-Info 'Added "keyhop" (user scope). Start a new Claude session to load it.'
        }
      } finally { $ErrorActionPreference = $previous }
    }

    $vault = Join-Path $env:APPDATA 'keyhop\vault.enc'
    if ($env:KEYHOP_HOME) { $vault = Join-Path $env:KEYHOP_HOME 'vault.enc' }
    if (-not $NoSetup -and -not (Test-Path $vault) -and [Environment]::UserInteractive) {
      Write-Step 'Setup'
      & $exe setup
      if ($LASTEXITCODE -ne 0) { Write-Info 'Setup did not finish; rerun it any time with: keyhop setup' }
    } else {
      Write-Host "`nkeyhop installed. Next: keyhop setup (first time) or keyhop doctor"
    }
  } finally {
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Install-Keyhop
