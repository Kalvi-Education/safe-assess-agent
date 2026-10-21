#!/bin/bash
set -euo pipefail
# Usage: bash packaging/build-macos.sh arm64|x64 exact-id[,exact-id] [--release]
arch=${1:?Supply arm64 or x64}
ids=${2:?Supply exact extension IDs}
mode=${3:---dev}
case "$arch" in
  arm64) target=aarch64-apple-darwin ;;
  x64) target=x86_64-apple-darwin ;;
  *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
case "$mode" in --dev|--release) ;; *) echo 'Use --dev or --release' >&2; exit 1 ;; esac
[[ "$ids" =~ ^[a-p]{32}(,[a-p]{32})*$ ]] || { echo 'Invalid extension IDs' >&2; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
export SAFEAGENT_ALLOWED_EXTENSION_IDS="$ids"
if [[ "$mode" == --release ]]; then
  cargo run --locked --example validate-auth-config
fi
cargo build --locked --release --target "$target"
binary="$root/target/$target/release/safeagent"
# Cross-built artifacts cannot always execute on the builder.
version=$(cargo metadata --no-deps --format-version 1 | /usr/bin/python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "safeagent"))')
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid version' >&2; exit 1; }
work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
payload="$work/payload"
install_dir='/Library/Application Support/Kalvium/SafeAgent'
manifest_dir='/Library/Google/Chrome/NativeMessagingHosts'
mkdir -p "$payload$install_dir" "$payload$manifest_dir" "$root/dist"
cp "$binary" "$payload$install_dir/safeagent"
chmod 755 "$payload$install_dir/safeagent"
/usr/bin/python3 "$root/packaging/write-manifest.py" "$ids" "$install_dir/safeagent" "$payload$manifest_dir/com.kalvium.safeagent.json"
cp "$root/packaging/uninstall-macos.sh" "$payload$install_dir/uninstall.sh"
chmod 755 "$payload$install_dir/uninstall.sh"
artifact_mode=UNSIGNED-DEV
if [[ "$mode" == --release ]]; then
  : "${MACOS_SIGNING_IDENTITY:?Developer ID Application identity required}"
  : "${MACOS_INSTALLER_IDENTITY:?Developer ID Installer identity required}"
  : "${APPLE_API_KEY_PATH:?App Store Connect key required}"
  : "${APPLE_API_KEY_ID:?App Store Connect key ID required}"
  : "${APPLE_API_ISSUER_ID:?App Store Connect issuer ID required}"
  codesign --force --options runtime --timestamp --sign "$MACOS_SIGNING_IDENTITY" "$payload$install_dir/safeagent"
  codesign --verify --strict --verbose=2 "$payload$install_dir/safeagent"
  artifact_mode=SIGNED-NOTARIZED
fi
pkgbuild --root "$payload" --scripts "$root/packaging/macos-scripts" --identifier com.kalvium.safeagent --version "$version" --install-location / "$work/component.pkg"
productbuild --synthesize --package "$work/component.pkg" "$work/distribution.xml"
/usr/bin/python3 "$root/packaging/configure-distribution.py" "$work/distribution.xml" "$arch"
cp "$root/packaging/installer-readme.txt" "$work/installer-readme.txt"
artifact="$root/dist/safeagent-$version-macos-$arch-$artifact_mode.pkg"
if [[ "$mode" == --release ]]; then
  productbuild --distribution "$work/distribution.xml" --resources "$work" --package-path "$work" --sign "$MACOS_INSTALLER_IDENTITY" "$artifact"
  pkgutil --check-signature "$artifact"
  xcrun notarytool submit "$artifact" --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID" --wait --output-format json > "$work/notarization.json"
  /usr/bin/python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); sys.exit(0 if r.get("status") == "Accepted" else 1)' "$work/notarization.json"
  xcrun stapler staple "$artifact"
  xcrun stapler validate "$artifact"
  spctl --assess --type install --verbose=2 "$artifact"
else
  productbuild --distribution "$work/distribution.xml" --resources "$work" --package-path "$work" "$artifact"
fi
printf '%s\n' "$artifact"
