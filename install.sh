#!/bin/sh
# Installs odoo-doctor on Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/MarcRodriguezz/odoo-doctor/main/install.sh | sh
#
# It needs no root access. It downloads one binary to ~/.local/bin and verifies its checksum.
# Settings: ODOO_DOCTOR_INSTALL_DIR, ODOO_DOCTOR_VERSION, ODOO_DOCTOR_BASE_URL.
set -eu

REPO="MarcRodriguezz/odoo-doctor"
INSTALL_DIR="${ODOO_DOCTOR_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${ODOO_DOCTOR_VERSION:-latest}"

fail() {
    echo "odoo-doctor install: $1" >&2
    exit 1
}

case "$(uname -s)" in
    Linux) os="linux" ;;
    Darwin) os="macos" ;;
    *) fail "unsupported system $(uname -s). On Windows, use install.ps1." ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch="x86_64" ;;
    arm64 | aarch64) arch="aarch64" ;;
    *) fail "unsupported processor $(uname -m)." ;;
esac
asset="odoo-doctor-$os-$arch"

if [ -n "${ODOO_DOCTOR_BASE_URL:-}" ]; then
    base="$ODOO_DOCTOR_BASE_URL"
elif [ "$VERSION" = "latest" ]; then
    base="https://github.com/$REPO/releases/latest/download"
else
    base="https://github.com/$REPO/releases/download/$VERSION"
fi

if command -v curl >/dev/null 2>&1; then
    download() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    download() { wget -q "$1" -O "$2"; }
else
    fail "curl or wget is required."
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $asset"
download "$base/$asset" "$tmp/$asset" || fail "could not download $base/$asset"
download "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download the checksums"

expected="$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
[ -n "$expected" ] || fail "$asset is not listed in SHA256SUMS."
if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/$asset" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)"
else
    fail "sha256sum or shasum is required to verify the download."
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch. Nothing was installed."

mkdir -p "$INSTALL_DIR"
chmod +x "$tmp/$asset"
mv "$tmp/$asset" "$INSTALL_DIR/odoo-doctor"
echo "Installed $("$INSTALL_DIR/odoo-doctor" --version) in $INSTALL_DIR"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) echo "Run: odoo-doctor" ;;
    *)
        echo "$INSTALL_DIR is not in your PATH. Run it directly with:"
        echo "  $INSTALL_DIR/odoo-doctor"
        ;;
esac
