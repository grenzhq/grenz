#!/bin/sh
# Grenz installer — downloads the latest release binary for your platform.
#
#   curl -fsSL https://github.com/grenzhq/grenz/releases/latest/download/install.sh | sh
#
# Override the install dir with GRENZ_INSTALL_DIR (default: /usr/local/bin).
#
# The binary is ALWAYS verified against the release's SHA256SUMS.txt. Every way
# that check can fail to happen — no checksums file, no entry for this asset, no
# hasher on the box — aborts the install. A verification that silently skips
# itself is worse than none: it reads as "verified" in the docs while installing
# whatever arrived. Set GRENZ_INSECURE_SKIP_VERIFY=1 to install unverified
# anyway (it says so, loudly).
set -eu

REPO="grenzhq/grenz"
INSTALL_DIR="${GRENZ_INSTALL_DIR:-/usr/local/bin}"
BASE="https://github.com/${REPO}/releases/latest/download"

os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux) os="linux" ;;
  Darwin) os="darwin" ;;
  *) echo "grenz: unsupported OS '$os' (linux/darwin only)" >&2; exit 1 ;;
esac
case "$arch" in
  x86_64 | amd64) arch="x64" ;;
  arm64 | aarch64) arch="arm64" ;;
  *) echo "grenz: unsupported architecture '$arch'" >&2; exit 1 ;;
esac

asset="grenz-${os}-${arch}"

# Portable temp file (bare `mktemp` is a GNU extension; BSD/macOS needs -t).
tmp="$(mktemp 2>/dev/null || mktemp -t grenz)"
cleanup() { rm -f "$tmp" "${tmp}.sums" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

echo "Downloading ${asset} ..."
if ! curl -fSL "${BASE}/${asset}" -o "$tmp"; then
  echo "grenz: download failed: ${BASE}/${asset}" >&2
  echo "If there is no release yet, build from source (requires Bun):" >&2
  echo "  git clone https://github.com/${REPO} && cd grenz" >&2
  echo "  bun install && cd proxy && bun run build   # -> proxy/dist/grenz" >&2
  exit 1
fi

# --- Integrity check (mandatory) ---------------------------------------------
# Every failure path here aborts. `abort_verify` names what went wrong and how
# to proceed deliberately, rather than installing an unchecked binary quietly.
abort_verify() {
  echo "grenz: cannot verify the download — $1" >&2
  echo "" >&2
  echo "Refusing to install an unverified binary. Either:" >&2
  echo "  • fix the cause above and re-run, or" >&2
  echo "  • build from source: git clone https://github.com/${REPO} && cd grenz" >&2
  echo "      bun install && cd proxy && bun run build   # -> proxy/dist/grenz" >&2
  echo "  • or, if you accept the risk: GRENZ_INSECURE_SKIP_VERIFY=1 <this command>" >&2
  exit 1
}

if [ "${GRENZ_INSECURE_SKIP_VERIFY:-0}" = "1" ]; then
  echo "grenz: WARNING — GRENZ_INSECURE_SKIP_VERIFY=1, installing WITHOUT checksum verification" >&2
else
  curl -fsSL "${BASE}/SHA256SUMS.txt" -o "${tmp}.sums" \
    || abort_verify "could not download ${BASE}/SHA256SUMS.txt"

  expected="$(grep " ${asset}\$" "${tmp}.sums" | awk '{print $1}' | head -n1)"
  [ -n "${expected:-}" ] || abort_verify "SHA256SUMS.txt has no entry for ${asset}"

  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$tmp" | awk '{print $1}')"
  elif command -v openssl >/dev/null 2>&1; then
    actual="$(openssl dgst -sha256 "$tmp" | awk '{print $NF}')"
  else
    abort_verify "no SHA-256 tool found (looked for sha256sum, shasum, openssl)"
  fi

  if [ "$actual" != "$expected" ]; then
    echo "grenz: CHECKSUM MISMATCH for ${asset} — refusing to install" >&2
    echo "  expected ${expected}" >&2
    echo "  got      ${actual}" >&2
    exit 1
  fi
  echo "checksum verified"
fi

chmod 755 "$tmp"
target="${INSTALL_DIR}/grenz"
if [ -w "$INSTALL_DIR" ]; then
  mv "$tmp" "$target"
else
  echo "Installing to ${target} (requires sudo) ..."
  sudo mv "$tmp" "$target"
fi
trap - EXIT INT TERM

echo "Installed: $("$target" version 2>/dev/null || echo grenz) -> ${target}"
echo "Next: grenz init"
