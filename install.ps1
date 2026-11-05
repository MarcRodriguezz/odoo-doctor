# Installs odoo-doctor on Windows.
#
#   irm https://raw.githubusercontent.com/MarcRodriguezz/odoo-doctor/main/install.ps1 | iex
#
# It needs no administrator rights. It downloads one binary to %LOCALAPPDATA%\odoo-doctor,
# verifies its checksum and adds that folder to your user PATH.
# Settings: ODOO_DOCTOR_INSTALL_DIR, ODOO_DOCTOR_VERSION, ODOO_DOCTOR_BASE_URL.
$ErrorActionPreference = 'Stop'

$repo = 'MarcRodriguezz/odoo-doctor'
$installDir = if ($env:ODOO_DOCTOR_INSTALL_DIR) { $env:ODOO_DOCTOR_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'odoo-doctor' }
$version = if ($env:ODOO_DOCTOR_VERSION) { $env:ODOO_DOCTOR_VERSION } else { 'latest' }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x86_64' }
    'ARM64' { 'aarch64' }
    default { throw "Unsupported processor: $env:PROCESSOR_ARCHITECTURE" }
}
$asset = "odoo-doctor-windows-$arch.exe"

if ($env:ODOO_DOCTOR_BASE_URL) { $base = $env:ODOO_DOCTOR_BASE_URL }
elseif ($version -eq 'latest') { $base = "https://github.com/$repo/releases/latest/download" }
else { $base = "https://github.com/$repo/releases/download/$version" }

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("odoo-doctor-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    Write-Host "Downloading $asset"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $binary = Join-Path $temp $asset
    $sums = Join-Path $temp 'SHA256SUMS'
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $binary
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $sums

    $line = Get-Content $sums | Where-Object { $_ -match " $([regex]::Escape($asset))$" } | Select-Object -First 1
    if (-not $line) { throw "$asset is not listed in SHA256SUMS." }
    $expected = ($line -split ' ')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 $binary).Hash.ToLower()
    if ($expected -ne $actual) { throw 'Checksum mismatch. Nothing was installed.' }

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    $target = Join-Path $installDir 'odoo-doctor.exe'
    Move-Item -Force $binary $target
    Write-Host "Installed $(& $target --version) in $installDir"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $installDir) {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$installDir", 'User')
        Write-Host 'Added it to your PATH. Open a new terminal, then run: odoo-doctor'
    } else {
        Write-Host 'Run: odoo-doctor'
    }
} finally {
    Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
}
