#!/bin/bash
# Builds the cedar-ffi Rust crate for Linux, generates the UniFFI Swift
# bindings, and assembles artifacts/CedarFFI.artifactbundle — a SwiftPM
# static-library artifact bundle (SE-0482, requires Swift 6.3+ to consume).
#
# By default builds the host target only. Pass extra rust triples to build
# additional variants (they must be installed via rustup and have a working
# cross linker):
#
#   scripts/build-linux.sh [--debug] [triple ...]
#
# Supported triples: x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_DIR="$ROOT/rust"
OUT_DIR="$ROOT/artifacts"
GEN_DIR="$ROOT/Sources/CedarFFI"
BUNDLE="$OUT_DIR/CedarFFI.artifactbundle"
TARGET_DIR="${CARGO_TARGET_DIR:-$RUST_DIR/target}"

PROFILE=release
CARGO_PROFILE_FLAG=--release
if [[ "${1:-}" == "--debug" ]]; then
  PROFILE=debug
  CARGO_PROFILE_FLAG=""
  shift
fi

TRIPLES=("$@")
if [[ ${#TRIPLES[@]} -eq 0 ]]; then
  TRIPLES=("$(rustc -vV | sed -n 's/^host: //p')")
fi

# --- Build slices ---------------------------------------------------------

for t in "${TRIPLES[@]}"; do
  echo "==> cargo build ($t)"
  (cd "$RUST_DIR" && cargo build $CARGO_PROFILE_FLAG --lib --target "$t")
done

# --- Generate Swift bindings ----------------------------------------------

echo "==> uniffi-bindgen (swift)"
BINDINGS_DIR="$TARGET_DIR/bindings-linux"
rm -rf "$BINDINGS_DIR"
(cd "$RUST_DIR" && cargo run $CARGO_PROFILE_FLAG --features cli --bin uniffi-bindgen -- \
  generate --library "$TARGET_DIR/${TRIPLES[0]}/$PROFILE/libcedar_ffi.so" \
  --language swift --out-dir "$BINDINGS_DIR")

mkdir -p "$GEN_DIR"
cp "$BINDINGS_DIR/CedarFFI.swift" "$GEN_DIR/CedarFFI.swift"

# --- Assemble the artifact bundle -----------------------------------------

echo "==> assemble $BUNDLE"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/CedarFFIBinary/include"

cp "$BINDINGS_DIR"/*.h "$BUNDLE/CedarFFIBinary/include/"
# uniffi emits <name>.modulemap; the bundle references it as module.modulemap
cat "$BINDINGS_DIR"/*.modulemap > "$BUNDLE/CedarFFIBinary/include/module.modulemap"

VARIANTS_JSON=""
for t in "${TRIPLES[@]}"; do
  mkdir -p "$BUNDLE/CedarFFIBinary/$t"
  cp "$TARGET_DIR/$t/$PROFILE/libcedar_ffi.a" "$BUNDLE/CedarFFIBinary/$t/libcedar_ffi.a"
  [[ -n "$VARIANTS_JSON" ]] && VARIANTS_JSON+=","
  VARIANTS_JSON+="$(cat <<EOF

            {
                "path": "CedarFFIBinary/$t/libcedar_ffi.a",
                "supportedTriples": ["$t"],
                "staticLibraryMetadata": {
                    "headerPaths": ["CedarFFIBinary/include"],
                    "moduleMapPath": "CedarFFIBinary/include/module.modulemap"
                }
            }
EOF
)"
done

cat > "$BUNDLE/info.json" <<EOF
{
    "schemaVersion": "1.0",
    "artifacts": {
        "CedarFFIBinary": {
            "type": "staticLibrary",
            "version": "$(sed -n 's/^version = "\(.*\)"/\1/p' "$RUST_DIR/Cargo.toml" | head -1)",
            "variants": [$VARIANTS_JSON
            ]
        }
    }
}
EOF

echo "==> done: $BUNDLE"
