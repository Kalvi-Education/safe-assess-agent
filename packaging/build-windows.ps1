param(
  [Parameter(Mandatory = $true)][string]$ExtensionIds,
  [switch]$Release
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$ids = $ExtensionIds.Split(',')
if (!$ids.Count -or ($ids | Where-Object { $_ -cnotmatch '^[a-p]{32}$' }) -or (@($ids | Select-Object -Unique).Count -ne $ids.Count)) { throw "Supply unique, exact Chrome extension IDs separated by commas" }
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
  $env:SAFEAGENT_ALLOWED_EXTENSION_IDS = $ExtensionIds
  if ($Release) {
    cargo run --locked --example validate-auth-config
    if ($LASTEXITCODE) { throw "AUTH_CONFIG_INVALID: signing blocked" }
  }
  cargo build --locked --release --target x86_64-pc-windows-msvc
  if ($LASTEXITCODE) { throw "Cargo build failed" }
  $binary = Join-Path $root 'target/x86_64-pc-windows-msvc/release/safeagent.exe'
  $version = (& $binary --version).Split(' ')[-1].Trim()
  if ($LASTEXITCODE -or $version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid agent version" }
  $out = Join-Path $root 'dist'
  New-Item -ItemType Directory -Force $out | Out-Null
  $origins = ($ids | ForEach-Object { '"chrome-extension://' + $_ + '/"' }) -join ','
  # The installer substitutes its actual per-user installation directory.
  $template = '{"name":"com.kalvium.safeagent","description":"Kalvium SafeAgent (local observations, not attestation)","path":"@BINARY@","type":"stdio","allowed_origins":[' + $origins + ']}'
  Set-Content -Path "$out/host-template.json" -Value $template -Encoding ascii
  $mode = 'UNSIGNED-DEV'
  if ($Release) {
    foreach ($key in @('WINDOWS_CERTIFICATE_BASE64','WINDOWS_CERTIFICATE_PASSWORD','WINDOWS_TIMESTAMP_URL')) {
      if (![Environment]::GetEnvironmentVariable($key)) { throw "Missing release secret: $key" }
    }
    $signtool = Get-ChildItem 'C:/Program Files (x86)/Windows Kits/10/bin/*/x64/signtool.exe' | Sort-Object FullName -Descending | Select-Object -First 1
    if (!$signtool) { throw 'Windows SDK signtool required' }
    $cert = Join-Path $env:RUNNER_TEMP ('safeagent-' + [guid]::NewGuid() + '.pfx')
    [IO.File]::WriteAllBytes($cert, [Convert]::FromBase64String($env:WINDOWS_CERTIFICATE_BASE64))
    $mode = 'SIGNED'
    & $signtool.FullName sign /fd SHA256 /f $cert /p $env:WINDOWS_CERTIFICATE_PASSWORD /tr $env:WINDOWS_TIMESTAMP_URL /td SHA256 $binary
    if ($LASTEXITCODE) { throw 'Binary signing failed' }
    & $signtool.FullName verify /pa /all $binary
    if ($LASTEXITCODE) { throw 'Binary signature verification failed' }
  }
  $iscc = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6/ISCC.exe'
  if (!(Test-Path $iscc)) { throw 'Inno Setup 6 is required to create the installer' }
  & $iscc "/DAgentVersion=$version" "/DAgentBinary=$binary" "/DOutputDir=$out" "/DArtifactMode=$mode" "$PSScriptRoot/windows.iss"
  if ($LASTEXITCODE) { throw 'Installer creation failed' }
  if ($Release) {
    $installer = "$out/safeagent-$version-windows-x64-$mode.exe"
    & $signtool.FullName sign /fd SHA256 /f $cert /p $env:WINDOWS_CERTIFICATE_PASSWORD /tr $env:WINDOWS_TIMESTAMP_URL /td SHA256 $installer
    if ($LASTEXITCODE) { throw 'Installer signing failed' }
    & $signtool.FullName verify /pa /all $installer
    if ($LASTEXITCODE) { throw 'Installer signature verification failed' }
  }
} finally {
  if (Get-Variable cert -ErrorAction SilentlyContinue) { Remove-Item $cert -Force -ErrorAction SilentlyContinue }
  Pop-Location
}
