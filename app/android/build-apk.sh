#!/usr/bin/env bash
# Packages the native library into an installable, debug-signed APK. No Gradle, no Java code:
# the activity is Android's built-in NativeActivity, which loads libreverse_pp_app.so.
#
# Needs: the Android SDK (build-tools + a platform), keytool (any JDK), zip.
# Usage: app/android/build-apk.sh <path to jniLibs> <output.apk>
set -euo pipefail

JNI="$(cd "$1" && pwd)"
OUT="$(mkdir -p "$(dirname "$2")" && cd "$(dirname "$2")" && pwd)/$(basename "$2")"
HERE="$(cd "$(dirname "$0")" && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:?set ANDROID_HOME}}"
BT="$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)"
PLATFORM="$(ls -d "$SDK"/platforms/android-* | sort -V | tail -1)"
API="${PLATFORM##*-}"
echo "build-tools: $BT"
echo "platform:    $PLATFORM"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

"$BT/aapt2" link -o "$WORK/base.apk" -I "$PLATFORM/android.jar" \
    --manifest "$HERE/AndroidManifest.xml" \
    --min-sdk-version 26 --target-sdk-version "$API" \
    --version-code 1 --version-name 0.1.0

( cd "$JNI/.." && rm -rf "$WORK/stage" && mkdir -p "$WORK/stage" && cp -r "$JNI" "$WORK/stage/lib" )
( cd "$WORK/stage" && zip -r -q "$WORK/base.apk" lib )

"$BT/zipalign" -f -p 4 "$WORK/base.apk" "$WORK/aligned.apk"

KS="$WORK/debug.keystore"
keytool -genkeypair -keystore "$KS" -storepass android -keypass android -alias reversepp \
    -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Reverse++ debug" >/dev/null 2>&1
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
    --out "$OUT" "$WORK/aligned.apk"
"$BT/apksigner" verify --verbose "$OUT" | head -5
ls -l "$OUT"
