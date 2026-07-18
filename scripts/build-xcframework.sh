#!/bin/bash
# Builds the cedar-ffi Rust crate, generates the UniFFI Swift bindings, and
# assembles artifacts/CedarFFI.xcframework.
#
# Slices included:
#   - macOS arm64 (always; add x86_64-apple-darwin via rustup for universal)
#   - iOS device + simulator, if the corresponding rust targets are installed:
#       rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#
# Usage: scripts/build-xcframework.sh [--debug]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_DIR="$ROOT/rust"
OUT_DIR="$ROOT/artifacts"
GEN_DIR="$ROOT/Sources/CedarFFI"
BUILD_DIR="$ROOT/.build-xcframework"

PROFILE=release
CARGO_PROFILE_FLAG=--release
if [[ "${1:-}" == "--debug" ]]; then
  PROFILE=debug
  CARGO_PROFILE_FLAG=""
fi

LIB_NAME=libcedar_ffi.a

installed_targets="$(rustup target list --installed)"
has_target() { grep -qx "$1" <<<"$installed_targets"; }

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$OUT_DIR" "$GEN_DIR"

# --- Build slices ---------------------------------------------------------

MACOS_LIBS=()
for t in aarch64-apple-darwin x86_64-apple-darwin; do
  if has_target "$t"; then
    echo "==> cargo build ($t)"
    (cd "$RUST_DIR" && cargo build $CARGO_PROFILE_FLAG --lib --target "$t")
    MACOS_LIBS+=("$RUST_DIR/target/$t/$PROFILE/$LIB_NAME")
  fi
done
if [[ ${#MACOS_LIBS[@]} -eq 0 ]]; then
  echo "error: no macOS rust target installed" >&2
  exit 1
fi

mkdir -p "$BUILD_DIR/macos"
if [[ ${#MACOS_LIBS[@]} -gt 1 ]]; then
  lipo -create "${MACOS_LIBS[@]}" -output "$BUILD_DIR/macos/$LIB_NAME"
else
  cp "${MACOS_LIBS[0]}" "$BUILD_DIR/macos/$LIB_NAME"
fi

IOS_LIB=""
if has_target aarch64-apple-ios; then
  echo "==> cargo build (aarch64-apple-ios)"
  (cd "$RUST_DIR" && cargo build $CARGO_PROFILE_FLAG --lib --target aarch64-apple-ios)
  IOS_LIB="$RUST_DIR/target/aarch64-apple-ios/$PROFILE/$LIB_NAME"
fi

IOS_SIM_LIBS=()
for t in aarch64-apple-ios-sim x86_64-apple-ios; do
  if has_target "$t"; then
    echo "==> cargo build ($t)"
    (cd "$RUST_DIR" && cargo build $CARGO_PROFILE_FLAG --lib --target "$t")
    IOS_SIM_LIBS+=("$RUST_DIR/target/$t/$PROFILE/$LIB_NAME")
  fi
done
if [[ ${#IOS_SIM_LIBS[@]} -gt 1 ]]; then
  mkdir -p "$BUILD_DIR/ios-sim"
  lipo -create "${IOS_SIM_LIBS[@]}" -output "$BUILD_DIR/ios-sim/$LIB_NAME"
elif [[ ${#IOS_SIM_LIBS[@]} -eq 1 ]]; then
  mkdir -p "$BUILD_DIR/ios-sim"
  cp "${IOS_SIM_LIBS[0]}" "$BUILD_DIR/ios-sim/$LIB_NAME"
fi

# --- Generate Swift bindings ----------------------------------------------

echo "==> uniffi-bindgen (swift)"
BINDINGS_DIR="$BUILD_DIR/bindings"
(cd "$RUST_DIR" && cargo run $CARGO_PROFILE_FLAG --features cli --bin uniffi-bindgen -- \
  generate --library "target/aarch64-apple-darwin/$PROFILE/libcedar_ffi.dylib" \
  --language swift --out-dir "$BINDINGS_DIR")

# The generated .swift file goes into the CedarPolicy source target; the
# header + modulemap go into the xcframework.
cp "$BINDINGS_DIR/CedarFFI.swift" "$GEN_DIR/CedarFFI.swift"

HEADERS_DIR="$BUILD_DIR/headers"
mkdir -p "$HEADERS_DIR"
cp "$BINDINGS_DIR"/*.h "$HEADERS_DIR/"
# uniffi emits <name>.modulemap; xcframework headers need module.modulemap
cat "$BINDINGS_DIR"/*.modulemap > "$HEADERS_DIR/module.modulemap"

# --- Assemble the xcframework ----------------------------------------------

echo "==> xcodebuild -create-xcframework"
rm -rf "$OUT_DIR/CedarFFI.xcframework"
ARGS=(-library "$BUILD_DIR/macos/$LIB_NAME" -headers "$HEADERS_DIR")
if [[ -n "$IOS_LIB" ]]; then
  ARGS+=(-library "$IOS_LIB" -headers "$HEADERS_DIR")
fi
if [[ -f "$BUILD_DIR/ios-sim/$LIB_NAME" ]]; then
  ARGS+=(-library "$BUILD_DIR/ios-sim/$LIB_NAME" -headers "$HEADERS_DIR")
fi
xcodebuild -create-xcframework "${ARGS[@]}" -output "$OUT_DIR/CedarFFI.xcframework"

echo "==> done: $OUT_DIR/CedarFFI.xcframework"
