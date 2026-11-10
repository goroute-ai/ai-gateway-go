#!/bin/sh
# GoRoute AI Gateway Universal Installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/goroute-ai/ai-gateway-go/main/install.sh | bash
#   OR
#   curl -fsSL https://raw.githubusercontent.com/goroute-ai/ai-gateway-go/main/install.sh | bash -s -- v1.2.0

set -e

REPO="goroute-ai/ai-gateway-go"
BINARY="ai-gateway"
REQUESTED_VERSION="${1:-}"

# Text formatting
BOLD="$(tput bold 2>/dev/null || echo '')"
GREEN="$(tput setaf 2 2>/dev/null || echo '')"
YELLOW="$(tput setaf 3 2>/dev/null || echo '')"
RED="$(tput setaf 1 2>/dev/null || echo '')"
RESET="$(tput sgr0 2>/dev/null || echo '')"

info() {
  printf "${BOLD}${GREEN}==>${RESET} %s\n" "$1"
}

warn() {
  printf "${BOLD}${YELLOW}WARN:${RESET} %s\n" "$1"
}

error() {
  printf "${BOLD}${RED}ERROR:${RESET} %s\n" "$1" >&2
  exit 1
}

# 1. Detect Operating System
OS="$(uname -s)"
case "${OS}" in
  Darwin)
    TARGET_OS="darwin"
    ;;
  Linux)
    TARGET_OS="linux"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    TARGET_OS="windows"
    ;;
  *)
    error "Unsupported operating system: ${OS}"
    ;;
esac

# 2. Detect Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64)
    TARGET_ARCH="amd64"
    ;;
  arm64|aarch64)
    TARGET_ARCH="arm64"
    ;;
  *)
    error "Unsupported architecture: ${ARCH}"
    ;;
esac

# 3. Resolve Target Version
if [ -z "${REQUESTED_VERSION}" ]; then
  info "Fetching latest release version from GitHub..."
  LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  if [ -z "${LATEST_TAG}" ]; then
    VERSION="v1.2.0"
  else
    VERSION="${LATEST_TAG}"
  fi
else
  case "${REQUESTED_VERSION}" in
    v*) VERSION="${REQUESTED_VERSION}" ;;
    *)  VERSION="v${REQUESTED_VERSION}" ;;
  esac
fi

CLEAN_VERSION="${VERSION#v}"
info "Installing GoRoute AI Gateway ${VERSION} for ${TARGET_OS}/${TARGET_ARCH}..."

# 4. Prepare Temporary Download Workspace
TMP_DIR=$(mktemp -d -t ai-gateway-install.XXXXXX)
trap 'rm -rf "${TMP_DIR}"' EXIT INT TERM

if [ "${TARGET_OS}" = "windows" ]; then
  ARCHIVE_NAME="ai-gateway_${CLEAN_VERSION}_${TARGET_OS}_${TARGET_ARCH}.zip"
else
  ARCHIVE_NAME="ai-gateway_${CLEAN_VERSION}_${TARGET_OS}_${TARGET_ARCH}.tar.gz"
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE_NAME}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

info "Downloading ${ARCHIVE_NAME}..."
if ! curl -fsSL -o "${TMP_DIR}/${ARCHIVE_NAME}" "${DOWNLOAD_URL}"; then
  error "Failed to download release archive from: ${DOWNLOAD_URL}"
fi

info "Verifying SHA-256 checksum..."
if curl -fsSL -o "${TMP_DIR}/checksums.txt" "${CHECKSUMS_URL}"; then
  (
    cd "${TMP_DIR}"
    if command -v sha256sum >/dev/null 2>&1; then
      grep "${ARCHIVE_NAME}" checksums.txt | sha256sum -c - >/dev/null 2>&1 || error "Checksum verification failed!"
    elif command -v shasum >/dev/null 2>&1; then
      grep "${ARCHIVE_NAME}" checksums.txt | shasum -a 256 -c - >/dev/null 2>&1 || error "Checksum verification failed!"
    else
      warn "Neither sha256sum nor shasum found; skipping cryptographic verification."
    fi
  )
else
  warn "checksums.txt not available; skipping checksum verification."
fi

# 5. Extract Archive
info "Extracting binary..."
if [ "${TARGET_OS}" = "windows" ]; then
  unzip -q "${TMP_DIR}/${ARCHIVE_NAME}" -d "${TMP_DIR}"
  EXTRACTED_BIN="${TMP_DIR}/ai-gateway.exe"
else
  tar -xzf "${TMP_DIR}/${ARCHIVE_NAME}" -C "${TMP_DIR}"
  EXTRACTED_BIN="${TMP_DIR}/ai-gateway"
fi

if [ ! -f "${EXTRACTED_BIN}" ]; then
  error "Extracted binary ${EXTRACTED_BIN} not found."
fi
chmod +x "${EXTRACTED_BIN}"

# 6. Determine Target Directory
INSTALL_DIR="${INSTALL_DIR:-}"
USE_SUDO=0

if [ -n "${INSTALL_DIR}" ]; then
  mkdir -p "${INSTALL_DIR}"
  TARGET_PATH="${INSTALL_DIR}/${BINARY}"
elif [ -w "/usr/local/bin" ] || [ "$(id -u)" -eq 0 ]; then
  INSTALL_DIR="/usr/local/bin"
  TARGET_PATH="${INSTALL_DIR}/${BINARY}"
elif sudo -n true 2>/dev/null; then
  INSTALL_DIR="/usr/local/bin"
  USE_SUDO=1
  TARGET_PATH="${INSTALL_DIR}/${BINARY}"
else
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "${INSTALL_DIR}"
  TARGET_PATH="${INSTALL_DIR}/${BINARY}"
fi

info "Installing to ${TARGET_PATH}..."
if [ "${USE_SUDO}" -eq 1 ]; then
  sudo mv "${EXTRACTED_BIN}" "${TARGET_PATH}"
else
  mv "${EXTRACTED_BIN}" "${TARGET_PATH}"
fi

# 7. Post-Installation Verification
info "Verifying installation..."
if command -v "${BINARY}" >/dev/null 2>&1; then
  "${BINARY}" -version
  printf "\n${BOLD}${GREEN}✔ Successfully installed GoRoute AI Gateway!${RESET}\n"
  printf "Get started by running:\n"
  printf "  ${BOLD}%s --config config/gateway.yaml${RESET}\n\n" "${BINARY}"
else
  printf "\n${BOLD}${GREEN}✔ Successfully installed GoRoute AI Gateway to ${TARGET_PATH}!${RESET}\n"
  printf "${YELLOW}NOTE:${RESET} ${INSTALL_DIR} is not in your PATH.\n"
  printf "Add it to your shell configuration file:\n"
  printf "  export PATH=\"%s:\$PATH\"\n\n" "${INSTALL_DIR}"
fi
