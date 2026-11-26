#!/bin/bash
# Experimental Linux .deb (amd64/arm64). Unsigned; not a supported release channel.
# Usage: build-linux.sh <amd64|arm64> <extension-ids> [binary-path]
set -euo pipefail
arch=${1:?amd64 or arm64}
ids=${2:?comma-separated extension IDs}
root=$(cd "$(dirname "$0")/.." && pwd)
case "$arch" in
  amd64) target=x86_64-unknown-linux-gnu ;;
  arm64) target=aarch64-unknown-linux-gnu ;;
  *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
[[ "$ids" =~ ^[a-p]{32}(,[a-p]{32})*$ ]] || { echo 'Invalid extension IDs' >&2; exit 1; }
cd "$root"
binary=${3:-}
if [[ -z "$binary" ]]; then
  export SAFEAGENT_ALLOWED_EXTENSION_IDS="$ids"
  cargo build --locked --release --target "$target"
  binary="$root/target/$target/release/safeagent"
fi
version=$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "safeagent"))')
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid version' >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pkg="$work/pkg"
install_dir=/opt/kalvium/safeagent
mkdir -p "$pkg/DEBIAN" "$pkg$install_dir" "$root/dist"
install -m 755 "$binary" "$pkg$install_dir/safeagent"
python3 "$root/packaging/write-manifest.py" "$ids" "$install_dir/safeagent" "$pkg$install_dir/com.kalvium.safeagent.json"
chmod 644 "$pkg$install_dir/com.kalvium.safeagent.json"
cat > "$pkg/DEBIAN/control" <<CONTROL
Package: kalvium-safeagent
Version: $version
Architecture: $arch
Maintainer: Kalvium <noreply@kalvium.com>
Section: utils
Priority: optional
Depends: libc6 (>= 2.31)
Description: Kalvium SafeAgent native messaging host
 Read-only local observations for consented assessment setup, launched by
 Chrome on demand. No daemon, no network access, no service.
CONTROL
# Chrome and Chromium read system-wide host manifests from these folders. Symlinks keep one
# manifest to update; Snap/Flatpak browsers cannot use them (documented limitation).
cat > "$pkg/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
for dir in /etc/opt/chrome/native-messaging-hosts /etc/chromium/native-messaging-hosts; do
  mkdir -p "$dir"
  ln -sf /opt/kalvium/safeagent/com.kalvium.safeagent.json "$dir/com.kalvium.safeagent.json"
done
exit 0
POSTINST
cat > "$pkg/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
# Never kill a running check; refuse to remove while one is in progress.
if pgrep -x safeagent >/dev/null 2>&1; then
  echo 'A SafeAgent check is running. Wait a few seconds and try again.' >&2
  exit 1
fi
exit 0
PRERM
cat > "$pkg/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
case "$1" in
  remove|purge)
    for dir in /etc/opt/chrome/native-messaging-hosts /etc/chromium/native-messaging-hosts; do
      rm -f "$dir/com.kalvium.safeagent.json"
    done ;;
esac
exit 0
POSTRM
chmod 755 "$pkg/DEBIAN/postinst" "$pkg/DEBIAN/prerm" "$pkg/DEBIAN/postrm"
out="$root/dist/safeagent-$version-linux-$arch-UNSIGNED-EXPERIMENTAL.deb"
dpkg-deb --root-owner-group --build "$pkg" "$out" >/dev/null
echo "$out"
