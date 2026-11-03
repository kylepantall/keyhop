# Installs keyhop on Windows from a GitHub Release: keyhop.exe and
# keyhop-hello.exe, each checked against the release's SHA256SUMS, into
# %LOCALAPPDATA%\keyhop\bin (added to your user PATH). Then runs "keyhop setup"
# on a first install. Nothing else is downloaded, and no script or PowerShell
# is left behind to run later. KEYHOP_RELEASE_DIR installs from a local folder
# holding those three files instead (CI, or your own build: bun run build:windows).
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/kylepantall/keyhop/main/scripts/install.ps1)))
[CmdletBinding()]
param(
  [string]$Version = 'latest',
  # Older keyhop update passes -Ref <commit>; a v1.2.3 tag is honoured, anything else means latest.
  [string]$Ref,
  [switch]$Claude,
  [switch]$NoSetup,
  [switch]$Help
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Assets = @('keyhop.exe', 'keyhop-hello.exe')

function Write-Step([string]$Text) { Write-Host "`n==> $Text" }
function Write-Info([string]$Text) { Write-Host "    $Text" }

# Runs a native command, returning its exit code without stopping on stderr.
function Invoke-Native([scriptblock]$Command) {
  $previous = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $output = & $Command 2>&1 | ForEach-Object { "$_" }
    return @{ Code = $LASTEXITCODE; Output = ($output -join "`n") }
  } finally { $ErrorActionPreference = $previous }
}

function Install-Keyhop {
  $repo = if ($env:KEYHOP_REPO) { $env:KEYHOP_REPO } else { 'kylepantall/keyhop' }
  if ($Help) {
    Write-Host 'Usage: install.ps1 [-Version <v1.2.3>] [-Claude] [-NoSetup]'
    Write-Host "Installs the $repo release (default latest) under %LOCALAPPDATA%\keyhop\bin and adds that folder to your user PATH."
    Write-Host '-Claude registers it with Claude Code (user scope) without asking.'
    Write-Host 'Override with KEYHOP_INSTALL_DIR, KEYHOP_REPO and KEYHOP_RELEASE_DIR.'
    return
  }
  if ($Ref -and $Ref -match '^v\d+\.\d+\.\d+') { $Version = $Ref }
  if ($Version -ne 'latest' -and $Version -notmatch '^v\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$') {
    throw "Invalid version: $Version (expected a release tag such as v0.4.0)"
  }
  $sourceLabel = if ($env:KEYHOP_RELEASE_DIR) { $env:KEYHOP_RELEASE_DIR } else { "$repo $Version release" }
  Write-Host "keyhop installer - $sourceLabel"

  Write-Step 'Checking tools'
  if (Get-Command op -ErrorAction SilentlyContinue) { Write-Info "1Password CLI: $((Get-Command op).Source)" }
  else { Write-Info '1Password CLI not found (optional): winget install AgileBits.1Password.CLI' }

  $installDir = if ($env:KEYHOP_INSTALL_DIR) { $env:KEYHOP_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'keyhop' }
  $binDir = Join-Path $installDir 'bin'
  New-Item -ItemType Directory -Force -Path $installDir, $binDir | Out-Null
  $installDir = (Resolve-Path -LiteralPath $installDir).Path.TrimEnd('\')
  $binDir = (Resolve-Path -LiteralPath $binDir).Path.TrimEnd('\')
  # Staged inside bin so the final moves are renames on the same drive.
  $staging = Join-Path $binDir ('.install-' + [Guid]::NewGuid())
  New-Item -ItemType Directory -Path $staging | Out-Null

  try {
    Write-Step 'Downloading keyhop'
    $names = @('SHA256SUMS') + $Assets
    if ($env:KEYHOP_RELEASE_DIR) {
      foreach ($name in $names) { Copy-Item (Join-Path $env:KEYHOP_RELEASE_DIR $name) (Join-Path $staging $name) }
      Write-Info "Copied from $env:KEYHOP_RELEASE_DIR"
    } else {
      $base = if ($Version -eq 'latest') { "https://github.com/$repo/releases/latest/download" } else { "https://github.com/$repo/releases/download/$Version" }
      foreach ($name in $names) {
        Write-Info "$base/$name"
        Invoke-WebRequest "$base/$name" -OutFile (Join-Path $staging $name) -UseBasicParsing
      }
    }

    Write-Step 'Verifying SHA-256 checksums'
    $sums = @{}
    foreach ($line in Get-Content (Join-Path $staging 'SHA256SUMS')) {
      if ($line -match '^([0-9a-fA-F]{64})\s+\*?(\S+)\s*$') { $sums[$Matches[2]] = $Matches[1].ToLower() }
    }
    foreach ($name in $Assets) {
      if (-not $sums.ContainsKey($name)) { throw "$name is not listed in SHA256SUMS." }
      $actual = (Get-FileHash (Join-Path $staging $name) -Algorithm SHA256).Hash.ToLower()
      if ($actual -ne $sums[$name]) { throw "$name does not match its checksum; nothing was installed." }
      Write-Info "$name  $actual"
    }

    Write-Step 'Installing'
    # A running keyhop.exe (Claude Code's MCP server) can't be overwritten but
    # can be renamed, so the old copy moves aside first.
    foreach ($name in $Assets) {
      $target = Join-Path $binDir $name
      $old = "$target.old"
      Remove-Item $old -Force -ErrorAction SilentlyContinue
      if (Test-Path $target) { Move-Item $target $old -Force }
      Move-Item (Join-Path $staging $name) $target
      Remove-Item $old -Force -ErrorAction SilentlyContinue
    }
    $keyhop = Join-Path $binDir 'keyhop.exe'
    $result = Invoke-Native { & $keyhop --version }
    if ($result.Code -ne 0) { throw "keyhop.exe did not start: $($result.Output)" }
    Write-Info "$keyhop (version $($result.Output.Trim()))"

    # Earlier versions ran Bun on the source through a keyhop.cmd launcher.
    $legacy = @((Join-Path $binDir 'keyhop.cmd'), (Join-Path $installDir 'app'), (Join-Path $installDir 'app.new'), (Join-Path $installDir 'runtime')) | Where-Object { Test-Path $_ }
    if ($legacy) {
      $legacy | ForEach-Object { Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue }
      Write-Info 'Removed the old keyhop.cmd launcher, source copy and private Bun.'
    }

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $binDir) {
      [Environment]::SetEnvironmentVariable('Path', ($(if ($userPath) { "$userPath;" } else { '' }) + $binDir), 'User')
      $env:Path = "$env:Path;$binDir"
      Write-Info "Added $binDir to your user PATH (new terminals pick it up)."
    }

    # Claude Code starts keyhop.exe directly. A registration from an earlier
    # install points at keyhop.cmd, which is gone, so it is replaced.
    if (Get-Command claude -ErrorAction SilentlyContinue) {
      $existing = Invoke-Native { & claude mcp get keyhop }
      $stale = $existing.Code -eq 0 -and $existing.Output -match 'keyhop\.cmd'
      if ($stale -or ($Claude -and $existing.Code -ne 0)) {
        Write-Step 'Registering with Claude Code'
        if ($stale) { Invoke-Native { & claude mcp remove keyhop --scope user } | Out-Null }
        $added = Invoke-Native { & claude mcp add --transport stdio --scope user keyhop -- $keyhop serve }
        if ($added.Code -ne 0) { throw "Registration failed. Re-add it with: claude mcp add --transport stdio --scope user keyhop -- `"$keyhop`" serve" }
        Write-Info 'Registered "keyhop" (user scope). Start a new Claude session to load it.'
      } elseif ($Claude) { Write-Info 'Already registered with Claude Code.' }
    } elseif ($Claude) { throw 'claude CLI not found.' }

    $vault = Join-Path $env:APPDATA 'keyhop\vault.enc'
    if ($env:KEYHOP_HOME) { $vault = Join-Path $env:KEYHOP_HOME 'vault.enc' }
    if (-not $NoSetup -and -not (Test-Path $vault) -and [Environment]::UserInteractive) {
      Write-Step 'Setup'
      & $keyhop setup
      if ($LASTEXITCODE -ne 0) { Write-Info 'Setup did not finish; rerun it any time with: keyhop setup' }
    } else {
      Write-Host "`nkeyhop installed. Next: keyhop setup (first time) or keyhop doctor"
    }
  } finally {
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Install-Keyhop
