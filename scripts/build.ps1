# Builds and signs TimerRoot with only the Android SDK (no Gradle, no Maven).
#
#   git clone https://github.com/RikkaApps/Shizuku-API
#   scripts/build.ps1 -Sdk "$env:LOCALAPPDATA\Android\Sdk" -ShizukuApi ..\Shizuku-API
#
# Produces build/TimerRoot.apk.
param(
    [string]$Sdk = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$ShizukuApi = "",
    [string]$Out = "",
    [int]$VersionCode = 31,
    [string]$VersionName = "0.31",
    # 留空 = 自动选本机 SDK 里最高的 build-tools / platform
    [string]$BuildTools = "",
    [string]$Platform = ""
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Out) { $Out = Join-Path $root 'build' }
if (-not (Test-Path $Sdk)) { throw "Android SDK not found at $Sdk (pass -Sdk)" }

# build-tools：取版本号最大的那个（目录名形如 36.0.0 / 37.0.0）
if (-not $BuildTools) {
    $cand = Get-ChildItem (Join-Path $Sdk 'build-tools') -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'aapt2.exe') } |
        Sort-Object { try { [version]$_.Name } catch { [version]'0.0' } }
    if (-not $cand) { throw "no usable build-tools under $Sdk\build-tools" }
    $BuildTools = $cand[-1].Name
}
$bt = Join-Path $Sdk "build-tools/$BuildTools"

# platform：取有 android.jar + framework.aidl 的最高版本
# （android-36 / android-37.2 这类名字，按数字排序）
if (-not $Platform) {
    $cand = Get-ChildItem (Join-Path $Sdk 'platforms') -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            (Test-Path (Join-Path $_.FullName 'android.jar')) -and
            (Test-Path (Join-Path $_.FullName 'framework.aidl'))
        } |
        Sort-Object { $n = $_.Name -replace '^android-', ''; try { [double]$n } catch { 0 } }
    if (-not $cand) {
        throw "no platform with android.jar + framework.aidl under $Sdk\platforms " +
              "(install one, e.g. platforms;android-36)"
    }
    $Platform = $cand[-1].Name
}
$platformDir = Join-Path $Sdk "platforms/$Platform"
$androidJar = Join-Path $platformDir 'android.jar'
$framework = Join-Path $platformDir 'framework.aidl'
Write-Host "using build-tools $BuildTools, platform $Platform"
$aidlExe = Join-Path $bt 'aidl.exe'
$d8 = Join-Path $bt 'd8.bat'
$aapt2 = Join-Path $bt 'aapt2.exe'
$zipalign = Join-Path $bt 'zipalign.exe'
$apksigner = Join-Path $bt 'apksigner.bat'
$jar = Join-Path (Split-Path (Get-Command javac).Source -Parent) 'jar.exe'

if (-not $ShizukuApi) {
    $ShizukuApi = Join-Path $root '..\Shizuku-API'
}
if (-not (Test-Path $ShizukuApi)) {
    throw "Shizuku-API not found at $ShizukuApi (git clone https://github.com/RikkaApps/Shizuku-API)"
}
if (-not (Test-Path (Join-Path $root 'app/src/main/assets/timer'))) {
    throw ("app/src/main/assets/timer is missing. Either restore the committed one " +
           "(git checkout -- app/src/main/assets/timer) or rebuild it from " +
           "native/timer.c with native/build.sh")
}

$work = Join-Path $Out 'work'
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
$src = Join-Path $work 'src'
$gen = Join-Path $work 'gen'
$classes = Join-Path $work 'classes'
$dex = Join-Path $work 'dex'
New-Item -ItemType Directory -Force -Path $src, $gen, $classes, $dex | Out-Null

# Shizuku API + provider sources
Copy-Item (Join-Path $ShizukuApi 'api/src/main/java/*') $src -Recurse -Force
Copy-Item (Join-Path $ShizukuApi 'shared/src/main/java/*') $src -Recurse -Force
Copy-Item (Join-Path $ShizukuApi 'provider/src/main/java/*') $src -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $work 'aidl') | Out-Null
Copy-Item (Join-Path $ShizukuApi 'aidl/src/main/aidl/*') (Join-Path $work 'aidl') -Recurse -Force
Copy-Item (Join-Path $root 'app/src/main/java/*') $src -Recurse -Force

# androidx.annotation stubs (the API only uses the annotations)
$stub = Join-Path $work 'stubs/androidx/annotation'
New-Item -ItemType Directory -Force -Path $stub | Out-Null
@'
package androidx.annotation;
import java.lang.annotation.*;
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.METHOD, ElementType.PARAMETER, ElementType.FIELD, ElementType.LOCAL_VARIABLE, ElementType.TYPE_USE})
public @interface NonNull {}
'@ | Set-Content (Join-Path $stub 'NonNull.java') -Encoding ascii
@'
package androidx.annotation;
import java.lang.annotation.*;
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.METHOD, ElementType.PARAMETER, ElementType.FIELD, ElementType.LOCAL_VARIABLE, ElementType.TYPE_USE})
public @interface Nullable {}
'@ | Set-Content (Join-Path $stub 'Nullable.java') -Encoding ascii
@'
package androidx.annotation;
import java.lang.annotation.*;
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.CONSTRUCTOR, ElementType.FIELD, ElementType.PACKAGE})
public @interface RestrictTo { Scope[] value(); enum Scope { LIBRARY, LIBRARY_GROUP, LIBRARY_GROUP_PREFIX, TESTS, SUBCLASSES } }
'@ | Set-Content (Join-Path $stub 'RestrictTo.java') -Encoding ascii

# The API uses android.util.ArraySet (hidden); swap it for a HashSet.
$remote = Join-Path $src 'rikka/shizuku/ShizukuRemoteProcess.java'
$text = Get-Content $remote -Raw
$text = $text -replace 'import android\.util\.ArraySet;\r?\n', ''
$text = $text.Replace('new ArraySet<>()', 'new java.util.HashSet<>()')
Set-Content $remote -Value $text -NoNewline

# AIDL
foreach ($dir in @((Join-Path $work 'aidl'), (Join-Path $root 'app/src/main/aidl'))) {
    Get-ChildItem $dir -Recurse -Filter '*.aidl' | ForEach-Object {
        & $aidlExe "-I$dir" "-I$platformDir" "-p$framework" "-o$gen" $_.FullName
    }
}

# javac
$sources = Get-ChildItem $src, $gen, (Join-Path $work 'stubs') -Recurse -Filter '*.java' |
    ForEach-Object { $_.FullName -replace '\\', '/' }
$argfile = Join-Path $work 'sources.txt'
$sources | Set-Content $argfile -Encoding ascii
& javac -encoding UTF-8 -source 11 -target 11 -nowarn -classpath $androidJar -d ($classes -replace '\\', '/') "@$argfile"
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

# d8
$classFiles = Get-ChildItem $classes -Recurse -Filter '*.class' | ForEach-Object { $_.FullName -replace '\\', '/' }
$classArg = Join-Path $work 'classes.txt'
$classFiles | Set-Content $classArg -Encoding ascii
& $d8 --lib $androidJar --min-api 30 --output ($dex -replace '\\', '/') "@$classArg"
if ($LASTEXITCODE -ne 0) { throw "d8 failed" }

# resources + manifest
$resZip = Join-Path $work 'res.zip'
$base = Join-Path $work 'base.apk'
& $aapt2 compile --dir (Join-Path $root 'app/src/main/res') -o $resZip
& $aapt2 link -o $base -I $androidJar --manifest (Join-Path $root 'app/src/main/AndroidManifest.xml') `
    -A (Join-Path $root 'app/src/main/assets') --min-sdk-version 30 --target-sdk-version 36 `
    --version-code $VersionCode --version-name $VersionName $resZip
if ($LASTEXITCODE -ne 0) { throw "aapt2 failed" }

# dex + align + sign
$unsigned = Join-Path $work 'unsigned.apk'
$aligned = Join-Path $work 'aligned.apk'
Copy-Item $base $unsigned -Force
& $jar uf $unsigned -C $dex classes.dex
& $zipalign -f 4 $unsigned $aligned

# Keep the signing key outside build/ so every rebuild stays upgrade-compatible.
$keystore = Join-Path (Split-Path $PSScriptRoot -Parent) 'keystore/debug.jks'
if (-not (Test-Path (Split-Path $keystore -Parent))) {
    New-Item -ItemType Directory -Force -Path (Split-Path $keystore -Parent) | Out-Null
}
if (-not (Test-Path $keystore)) {
    & keytool -genkeypair -keystore $keystore -storepass android -keypass android `
        -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 `
        -dname "CN=Android Debug,O=Android,C=US"
}
$apk = Join-Path $Out 'TimerRoot.apk'
& $apksigner sign --ks $keystore --ks-pass pass:android --key-pass pass:android --out $apk $aligned
if ($LASTEXITCODE -ne 0) { throw "apksigner failed" }
Write-Host "built $apk"
