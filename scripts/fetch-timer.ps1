# Clones the upstream exploit and drops the prebuilt binary into assets/.
#
# NOTE (this fork): assets/timer is the conf-driven Neo7 build compiled from
# native/timer.c. The binary this script downloads is hardcoded for 6.12.69 and
# cannot read a --conf profile, so running it here would silently break the app
# on 6.1. Refuses unless -Force is passed.
param([switch]$Force)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dst = Join-Path $root 'app/src/main/assets/timer'
if ((Test-Path $dst) -and -not $Force) {
    Write-Host "assets/timer already exists ($((Get-Item $dst).Length) bytes) - left untouched."
    Write-Host "This fork ships the conf-driven binary built from native/timer.c;"
    Write-Host "the upstream one is hardcoded for 6.12.69 and ignores --conf."
    Write-Host "Rebuild it with native/build.sh, or pass -Force to overwrite anyway."
    exit 0
}
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("cve98260-" + [guid]::NewGuid().ToString('N'))

git clone --depth 1 https://github.com/YuKongA/CVE-2026-98260.git $tmp
Copy-Item (Join-Path $tmp 'timer/timer') $dst -Force
Remove-Item $tmp -Recurse -Force
Write-Host "assets/timer: $((Get-Item $dst).Length) bytes"
