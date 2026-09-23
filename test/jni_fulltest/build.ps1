# Build libjnifull.so (arm64-v8a) + classes.dex and push to the device.
$ErrorActionPreference = "Stop"

$Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$NDK       = if ($env:NDK_HOME) { $env:NDK_HOME } else { "D:\Android\Sdk\ndk\26.1.10909125" }
$SDK       = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { "D:\Android\Sdk" }
$Clang     = Join-Path $NDK "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android33-clang.cmd"
$D8        = Join-Path $SDK "build-tools\34.0.0\d8.bat"
$AndroidJar= Join-Path $SDK "platforms\android-33\android.jar"
$Javac     = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME "bin\javac.exe" } else { "javac" }
$Adb       = "adb"

$SoOut     = Join-Path $Root "build\arm64-v8a\libjnifull.so"
$ClsDir    = Join-Path $Root "build\classes"
$DexDir    = Join-Path $Root "build\dex"
$RemoteDir = "/data/local/tmp/jnifull"

Write-Host "== [1/4] compiling native library (arm64-v8a) =="
New-Item -ItemType Directory -Force -Path (Split-Path $SoOut) | Out-Null
& $Clang -shared -fPIC -O2 -Wall -Wno-unused-function `
    -o $SoOut (Join-Path $Root "cpp\jnifull.c") -llog
if ($LASTEXITCODE -ne 0) { throw "clang failed ($LASTEXITCODE)" }
Write-Host "   -> $SoOut"

Write-Host "== [2/4] compiling java =="
Remove-Item -Recurse -Force $ClsDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $ClsDir | Out-Null
$sources = Get-ChildItem -Recurse -Filter *.java (Join-Path $Root "src") | ForEach-Object { $_.FullName }
& $Javac -source 8 -target 8 -encoding UTF-8 -classpath $AndroidJar -d $ClsDir $sources
if ($LASTEXITCODE -ne 0) { throw "javac failed ($LASTEXITCODE)" }

Write-Host "== [3/4] dexing =="
Remove-Item -Recurse -Force $DexDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $DexDir | Out-Null
$classes = Get-ChildItem -Recurse -Filter *.class $ClsDir | ForEach-Object { $_.FullName }
& $D8 --output $DexDir --lib $AndroidJar --min-api 33 $classes
if ($LASTEXITCODE -ne 0) { throw "d8 failed ($LASTEXITCODE)" }

Write-Host "== [4/4] pushing to device =="
& $Adb shell "mkdir -p $RemoteDir"
& $Adb push $SoOut "$RemoteDir/libjnifull.so"
& $Adb push (Join-Path $DexDir "classes.dex") "$RemoteDir/classes.dex"
& $Adb shell "chmod 755 $RemoteDir/libjnifull.so $RemoteDir/classes.dex"
& $Adb shell "ls -l $RemoteDir"

Write-Host "`nBuild + push done."
