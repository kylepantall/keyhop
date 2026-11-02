# Installs keyhop from GitHub on Windows: a private Bun if needed, the app and a
# launcher, then runs "keyhop setup" on a first install. KEYHOP_SOURCE_DIR
# installs from a local checkout instead.
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/kylepantall/keyhop/main/scripts/install.ps1)))
[CmdletBinding()]
param(
  [string]$Ref = 'main',
  [switch]$Claude,
  [switch]$NoSetup,
  [switch]$Help
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$BunVersion = '1.4.3'

function Write-Step([string]$Text) { Write-Host "`n==> $Text" }
function Write-Info([string]$Text) { Write-Host "    $Text" }

# Runs a noisy native command quietly, showing its output only if it fails.
function Invoke-Quiet([string]$What, [scriptblock]$Command) {
  $previous = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $output = & $Command 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
  } finally { $ErrorActionPreference = $previous }
  if ($code -ne 0) {
    $output | ForEach-Object { Write-Host "    | $_" }
    throw "$What failed."
  }
}

function Install-Keyhop {
  $repo = if ($env:KEYHOP_REPO) { $env:KEYHOP_REPO } else { 'kylepantall/keyhop' }
  if ($Help) {
    Write-Host 'Usage: install.ps1 [-Ref <branch|tag|commit>] [-Claude] [-NoSetup]'
    Write-Host "Installs $repo (default main) under %LOCALAPPDATA%\keyhop and adds its bin folder to your user PATH."
    Write-Host '-Claude registers it with Claude Code (user scope) without asking.'
    Write-Host 'Override with KEYHOP_INSTALL_DIR, KEYHOP_REPO and KEYHOP_SOURCE_DIR.'
    return
  }
  if ($Ref -notmatch '^[A-Za-z0-9._/-]+$' -or $Ref.Contains('..') -or $Ref.StartsWith('/') -or $Ref.EndsWith('/')) {
    throw "Invalid ref: $Ref"
  }
  $sourceLabel = if ($env:KEYHOP_SOURCE_DIR) { $env:KEYHOP_SOURCE_DIR } else { "$repo@$Ref" }
  Write-Host "keyhop installer - $sourceLabel"

  Write-Step 'Checking tools'
  if (-not (Get-Command powershell.exe -ErrorAction SilentlyContinue)) { throw 'Windows PowerShell (powershell.exe) is required for Windows Hello.' }
  if (Get-Command op -ErrorAction SilentlyContinue) { Write-Info "1Password CLI: $((Get-Command op).Source)" }
  else { Write-Info '1Password CLI not found (optional): winget install AgileBits.1Password.CLI' }

  $installDir = if ($env:KEYHOP_INSTALL_DIR) { $env:KEYHOP_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'keyhop' }
  $binDir = Join-Path $installDir 'bin'
  New-Item -ItemType Directory -Force -Path $installDir, $binDir | Out-Null
  $installDir = (Resolve-Path -LiteralPath $installDir).Path.TrimEnd('\')
  $binDir = (Resolve-Path -LiteralPath $binDir).Path.TrimEnd('\')
  $temp = Join-Path ([IO.Path]::GetTempPath()) ('keyhop-install-' + [Guid]::NewGuid())
  New-Item -ItemType Directory -Path $temp | Out-Null

  try {
    Write-Step 'Bun runtime'
    $bun = $null
    $privateBun = Join-Path $installDir "runtime\bun-$BunVersion\bun.exe"
    $existing = Get-Command bun -ErrorAction SilentlyContinue
    if ($existing) {
      & $existing.Source -e "process.exit(Bun.semver.satisfies(Bun.version, '>=$BunVersion') ? 0 : 1)" 2>$null | Out-Null
      if ($LASTEXITCODE -eq 0) { $bun = $existing.Source; Write-Info "Using $bun" }
    }
    if (-not $bun -and (Test-Path $privateBun)) { $bun = $privateBun; Write-Info "Using private Bun $BunVersion from a previous install" }
    if (-not $bun) {
      $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { 'x64-baseline' }
      $archive = "bun-windows-$arch.zip"
      $base = "https://github.com/oven-sh/bun/releases/download/bun-v$BunVersion"
      Write-Info "Downloading a private Bun $BunVersion ($archive) and verifying its checksum"
      Invoke-WebRequest "$base/SHASUMS256.txt" -OutFile (Join-Path $temp 'SHASUMS256.txt') -UseBasicParsing
      $line = Get-Content (Join-Path $temp 'SHASUMS256.txt') | Where-Object { $_ -match "\s\*?$([regex]::Escape($archive))$" } | Select-Object -First 1
      if (-not $line) { throw 'Bun archive checksum not found.' }
      $expected = ($line -split '\s+')[0].ToLower()
      $zip = Join-Path $temp $archive
      Invoke-WebRequest "$base/$archive" -OutFile $zip -UseBasicParsing
      if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne $expected) { throw 'Bun checksum mismatch.' }
      Expand-Archive $zip -DestinationPath $temp -Force
      New-Item -ItemType Directory -Force -Path (Split-Path $privateBun) | Out-Null
      Copy-Item (Join-Path $temp "$($archive -replace '\.zip$','')\bun.exe") $privateBun -Force
      $bun = $privateBun
      Write-Info "Installed to $bun"
    }

    # Build into a fresh directory and swap it in, so a failure leaves the
    # working install untouched. Vault data lives in %APPDATA%\keyhop.
    $staging = Join-Path $installDir 'app.new'
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
    Write-Step 'Fetching source'
    if ($env:KEYHOP_SOURCE_DIR) {
      Write-Info "Copying $env:KEYHOP_SOURCE_DIR"
      New-Item -ItemType Directory -Path $staging | Out-Null
      Push-Location $env:KEYHOP_SOURCE_DIR
      try {
        foreach ($file in (git ls-files --cached --others --exclude-standard)) {
          $target = Join-Path $staging $file
          New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
          Copy-Item $file $target
        }
      } finally { Pop-Location }
    } else {
      Write-Info "Downloading github.com/$repo ($Ref)"
      $sourceZip = Join-Path $temp 'source.zip'
      Invoke-WebRequest "https://codeload.github.com/$repo/zip/$Ref" -OutFile $sourceZip -UseBasicParsing
      $extract = Join-Path $temp 'source'
      Expand-Archive $sourceZip -DestinationPath $extract -Force
      Move-Item (Get-ChildItem $extract -Directory | Select-Object -First 1).FullName $staging
    }

    Push-Location $staging
    try {
      Write-Step 'Installing dependencies'
      Invoke-Quiet 'bun install' { & $bun install --frozen-lockfile --production --ignore-scripts }
      Write-Info 'Done'
    } finally { Pop-Location }

    $app = Join-Path $installDir 'app'
    if (Test-Path $app) { Remove-Item $app -Recurse -Force }
    Move-Item $staging $app
    Write-Info "Installed into $app"

    Write-Step 'Installing launcher'
    # Paths relative to the launcher (%~dp0) keep a non-ASCII %LOCALAPPDATA%
    # working; cmd.exe reads .cmd files in the OEM code page.
    $launcher = Join-Path $binDir 'keyhop.cmd'
    $bunPath = if ($bun.StartsWith($installDir + '\', [StringComparison]::OrdinalIgnoreCase)) { '%~dp0..' + $bun.Substring($installDir.Length) } else { $bun }
    $lines = @(
      '@echo off',
      'set "KEYHOP_LAUNCHER=%~f0"',
      "`"$bunPath`" `"%~dp0..\app\src\index.ts`" %*"
    )
    $oem = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
    [IO.File]::WriteAllLines($launcher, [string[]]$lines, $oem)
    $version = (& $launcher --version 2>&1 | ForEach-Object { "$_" }) -join ' '
    Write-Info "$launcher (version $version)"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $binDir) {
      [Environment]::SetEnvironmentVariable('Path', ($(if ($userPath) { "$userPath;" } else { '' }) + $binDir), 'User')
      $env:Path = "$env:Path;$binDir"
      Write-Info "Added $binDir to your user PATH (new terminals pick it up)."
    }

    if ($Claude) {
      Write-Step 'Registering with Claude Code'
      if (-not (Get-Command claude -ErrorAction SilentlyContinue)) { throw 'claude CLI not found.' }
      $previous = $ErrorActionPreference
      $ErrorActionPreference = 'Continue'
      try {
        & claude mcp get keyhop 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Info 'Already registered.' }
        else {
          & claude mcp add --transport stdio --scope user keyhop -- cmd /c $launcher serve 2>&1 | Out-Null
          if ($LASTEXITCODE -ne 0) { throw "Registration failed. Re-add it with: claude mcp add --transport stdio --scope user keyhop -- cmd /c `"$launcher`" serve" }
          Write-Info 'Added "keyhop" (user scope). Start a new Claude session to load it.'
        }
      } finally { $ErrorActionPreference = $previous }
    }

    $vault = Join-Path $env:APPDATA 'keyhop\vault.enc'
    if ($env:KEYHOP_HOME) { $vault = Join-Path $env:KEYHOP_HOME 'vault.enc' }
    if (-not $NoSetup -and -not (Test-Path $vault) -and [Environment]::UserInteractive) {
      Write-Step 'Setup'
      & $launcher setup
      if ($LASTEXITCODE -ne 0) { Write-Info 'Setup did not finish; rerun it any time with: keyhop setup' }
    } else {
      Write-Host "`nkeyhop installed. Next: keyhop setup (first time) or keyhop doctor"
    }
  } finally {
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Install-Keyhop
