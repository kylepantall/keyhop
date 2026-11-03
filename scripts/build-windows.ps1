# Builds the Windows release into dist\: keyhop.exe (Bun compiled),
# native\build\keyhop-hello.exe and the example sync scripts, zipped as
# keyhop-windows-x64.zip with SHA256SUMS. Used by CI and the release workflow.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
  $dist = Join-Path $root 'dist'
  $stage = Join-Path $dist 'keyhop'
  if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
  New-Item -ItemType Directory -Force -Path (Join-Path $stage 'native\build') | Out-Null

  dotnet build native/windows/KeyhopHello -c Release -o (Join-Path $stage 'native\build') --nologo
  if ($LASTEXITCODE -ne 0) { throw 'Building keyhop-hello.exe failed.' }
  # Only the exe and what it loads; no PDBs or build leftovers.
  Get-ChildItem (Join-Path $stage 'native\build') | Where-Object { $_.Extension -notin '.exe', '.dll', '.config' } | Remove-Item -Force

  # KEYHOP_COMPILED tells src/paths.ts to find native/ beside keyhop.exe. The starter
  # sync scripts are embedded (src/examples.ts), so no .ps1/.sh ships loose.
  # Never load bunfig.toml or .env from the working directory (often a project Claude can write to).
  bun build --compile --minify --target=bun-windows-x64-baseline --define KEYHOP_COMPILED=true `
    --no-compile-autoload-dotenv --no-compile-autoload-bunfig src/index.ts --outfile (Join-Path $stage 'keyhop.exe')
  if ($LASTEXITCODE -ne 0) { throw 'Compiling keyhop.exe failed.' }
  Copy-Item LICENSE, README.md $stage

  $zip = Join-Path $dist 'keyhop-windows-x64.zip'
  Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
  $hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  [IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS'), "$hash  keyhop-windows-x64.zip`n")
  Write-Host "Built $zip ($hash)"
} finally {
  Pop-Location
}
