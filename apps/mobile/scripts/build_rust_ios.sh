#!/bin/sh
# Builds crates/secwet-ffi for iOS and packs ios/Frameworks/SecwetFFI.xcframework
# (static libraries plus the C header).
#
#   scripts/build_rust_ios.sh                  device and simulator
#   scripts/build_rust_ios.sh iphonesimulator  simulator only (Xcode passes $PLATFORM_NAME)
#   scripts/build_rust_ios.sh iphoneos         device only
#
# Runs as the Runner's "Build Rust" phase. Cargo is incremental, so an
# unchanged tree costs a few seconds. Always release: the crypto is slow
# unoptimized.
set -eu

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT="$ROOT/apps/mobile/ios/Frameworks/SecwetFFI.xcframework"
TARGET_DIR="$ROOT/target"
PLATFORM="${1:-all}"

# Xcode's environment points SDKROOT and friends at the iOS SDK, which breaks
# the host build scripts cargo runs. Rust picks the right SDK per target.
unset SDKROOT PLATFORM_DIR PLATFORM_DEVELOPER_SDK_DIR LIBRARY_PATH CPATH
export PATH="$HOME/.cargo/bin:$PATH"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"

build() {
  cargo build --manifest-path "$ROOT/Cargo.toml" -p secwet-ffi --release --target "$1"
}

DEVICE_LIB=""
SIM_LIB=""
case "$PLATFORM" in
  iphoneos|all)
    build aarch64-apple-ios
    ;;
esac
case "$PLATFORM" in
  iphonesimulator|all)
    build aarch64-apple-ios-sim
    build x86_64-apple-ios
    mkdir -p "$TARGET_DIR/ios-sim-universal"
    lipo -create \
      "$TARGET_DIR/aarch64-apple-ios-sim/release/libsecwet_ffi.a" \
      "$TARGET_DIR/x86_64-apple-ios/release/libsecwet_ffi.a" \
      -output "$TARGET_DIR/ios-sim-universal/libsecwet_ffi.a"
    ;;
esac

# Pack whichever slices exist, so a simulator-only build keeps an earlier device slice.
[ -f "$TARGET_DIR/aarch64-apple-ios/release/libsecwet_ffi.a" ] && DEVICE_LIB="$TARGET_DIR/aarch64-apple-ios/release/libsecwet_ffi.a"
[ -f "$TARGET_DIR/ios-sim-universal/libsecwet_ffi.a" ] && SIM_LIB="$TARGET_DIR/ios-sim-universal/libsecwet_ffi.a"

set --
[ -n "$DEVICE_LIB" ] && set -- "$@" -library "$DEVICE_LIB" -headers "$ROOT/crates/secwet-ffi/include"
[ -n "$SIM_LIB" ] && set -- "$@" -library "$SIM_LIB" -headers "$ROOT/crates/secwet-ffi/include"
if [ $# -eq 0 ]; then
  echo "error: no iOS slice was built" >&2
  exit 1
fi

TMP="$TARGET_DIR/xcframework-staging/SecwetFFI.xcframework"
rm -rf "$TMP"
mkdir -p "$(dirname "$TMP")"
xcodebuild -create-xcframework "$@" -output "$TMP" >/dev/null
rm -rf "$OUT"
mkdir -p "$(dirname "$OUT")"
mv "$TMP" "$OUT"
echo "secwet-ffi: wrote $OUT"
