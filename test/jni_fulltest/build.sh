#!/usr/bin/env bash
# Build the JNI full-coverage test artifacts for arm64 Android (build only, no run).
# Requires: Android NDK, Android SDK (build-tools + platform), JDK (javac).
#   ANDROID_SDK_ROOT=/path/to/sdk  NDK_HOME=$ANDROID_SDK_ROOT/ndk/26.1.10909125
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK="${ANDROID_SDK_ROOT:?set ANDROID_SDK_ROOT}"
NDK="${NDK_HOME:-$SDK/ndk/26.1.10909125}"
CLANG="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang"
D8="$SDK/build-tools/34.0.0/d8"
AJ="$SDK/platforms/android-33/android.jar"

OUT="$ROOT/build"
mkdir -p "$OUT/arm64-v8a" "$OUT/classes" "$OUT/dex"

echo "== [1/3] native library (arm64-v8a) =="
"$CLANG" -shared -fPIC -O2 -fno-omit-frame-pointer -Wall -Wno-unused-function \
    -o "$OUT/arm64-v8a/libjnifull.so" "$ROOT/cpp/jnifull.c" -llog

echo "== [2/3] java =="
rm -rf "$OUT/classes"; mkdir -p "$OUT/classes"
mapfile -t SRCS < <(find "$ROOT/src" -name '*.java')
javac -source 8 -target 8 -encoding UTF-8 -classpath "$AJ" -d "$OUT/classes" "${SRCS[@]}"

echo "== [3/3] dex =="
rm -rf "$OUT/dex"; mkdir -p "$OUT/dex"
mapfile -t CLS < <(find "$OUT/classes" -name '*.class')
"$D8" --output "$OUT/dex" --lib "$AJ" --min-api 33 "${CLS[@]}"

echo "built: $OUT/arm64-v8a/libjnifull.so  $OUT/dex/classes.dex"
