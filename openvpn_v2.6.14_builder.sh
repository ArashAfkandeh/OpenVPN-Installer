#!/bin/bash

# ======================================================================================================= #
# OpenVPN v2.6.14 Builder Script for Ubuntu 22.04                                                         #
#                                                                                                         #
# This script compiles the latest stable release of the OpenVPN Community Edition                         #
# (version 2.6.14 as of April 2 2025【345961234927453†L160-L164】【129982999918125†L200-L205】) from source.  #
# It does **not** install OpenVPN on the host system.                                                     #
# Instead, it produces a self‑contained tar.gz archive containing the compiled                            #
# binaries, libraries, documentation and systemd service files.                                           #
#                                                                                                         #
# You can transfer the resulting archive to other compatible servers and extract it                       #
# at the root directory (`/`) to deploy OpenVPN without recompiling.                                      #
#                                                                                                         #
# Usage: Run this script as root (e.g. via sudo) on an Ubuntu 22.04 machine.                              #
#                                                                                                         #
# The script installs all necessary build dependencies, downloads the OpenVPN                             #
# tarball from the official community download location (or GitHub as a fallback),                        #
# compiles it with systemd support enabled, and then packages the output into a                           #
# relocatable archive.                                                                                    #
#                                                                                                         #
# Sources: The OpenVPN stable release table notes that version 2.6.14, released                           #
# 2 April 2025, is the latest stable version【345961234927453†L160-L164】. GitHub labels this release       #
# as “Latest” on the project’s releases page【129982999918125†L200-L205】. A FileHorse download page also   #
# lists the corresponding source tarball name as `openvpn-2.6.14.tar.gz`【318479869308710†L80-L87】.        #
# ======================================================================================================= #

set -euo pipefail

# Ensure the script is executed as root.
if [[ $(id -u) -ne 0 ]]; then
  echo "Please run this script as root or using sudo." >&2
  exit 1
fi

echo "Updating package lists and installing build dependencies..."
apt-get update
apt-get install -y \
  build-essential git pkg-config autoconf automake libtool \
  libssl-dev liblz4-dev liblzo2-dev libpam0g-dev libpkcs11-helper1-dev \
  libcap-ng-dev libsystemd-dev libnl-genl-3-dev libnl-route-3-dev \
  libreadline-dev iproute2 resolvconf python3-docutils

# Create a working directory under /usr/local/src
echo "Creating a working directory in /usr/local/src..."
mkdir -p /usr/local/src
cd /usr/local/src

# Define the version and tarball name. 2.6.14 is the latest stable OpenVPN release
# (released on 2 April 2025)【345961234927453†L160-L164】【129982999918125†L200-L205】.
VERSION="2.6.14"
TARBALL="openvpn-${VERSION}.tar.gz"

# Download the source tarball if it does not already exist.
if [[ ! -f "$TARBALL" ]]; then
  echo "Downloading OpenVPN source ${VERSION}..."
  # Primary download location (OpenVPN community site). If that fails due to
  # connectivity restrictions, fall back to the mirror hosted on GitHub.
  wget -O "$TARBALL" "https://swupdate.openvpn.org/community/releases/${TARBALL}" \
    || wget -O "$TARBALL" "https://swupdate.openvpn.net/community/releases/${TARBALL}" \
    || wget -O "$TARBALL" "https://github.com/OpenVPN/openvpn/archive/refs/tags/v${VERSION}.tar.gz"
fi

# Remove any existing source tree to ensure a clean build
rm -rf "openvpn-${VERSION}" || true

echo "Extracting source code..."
tar -xf "$TARBALL"

# GitHub archives may unpack to a directory named "openvpn-${VERSION#v}".  If the
# expected directory does not exist but a similarly named one does, rename it.
if [[ ! -d "openvpn-${VERSION}" ]]; then
  if [[ -d "openvpn-${VERSION#v}" ]]; then
    mv "openvpn-${VERSION#v}" "openvpn-${VERSION}"
  fi
fi

cd "openvpn-${VERSION}"

# Generate the configure script.  Some source tarballs come with a pre‑built
# configure script; however, running autoreconf ensures all aclocal/libtool
# artifacts are up to date.
echo "Generating the configure script..."
autoreconf -i -v -f

echo "Configuring the build (enabling systemd and async push support)..."
./configure --enable-systemd --enable-async-push --enable-iproute2

echo "Building OpenVPN using all available CPU cores..."
make -j"$(nproc)"

# Package the compiled artifacts.  Using DESTDIR avoids installing into the
# running system; everything goes into a temporary staging directory.
echo "Packaging all compiled files into a tar.gz archive..."
PKG_STAGE_DIR="/tmp/openvpn-package"
rm -rf "$PKG_STAGE_DIR"
mkdir -p "$PKG_STAGE_DIR"

make install DESTDIR="$PKG_STAGE_DIR"

# After installation, the systemd unit files reference /usr/sbin/openvpn.  Since
# we install into /usr/local, adjust ExecStart paths to point to the correct
# location.  Only attempt this if the service directory exists.
SERVICE_DIR="$PKG_STAGE_DIR/usr/local/lib/systemd/system"
if [[ -d "$SERVICE_DIR" ]]; then
  echo "Patching systemd service files to use /usr/local/sbin/openvpn..."
  # Use find and sed to replace /usr/sbin/openvpn with /usr/local/sbin/openvpn
  while IFS= read -r -d '' service; do
    sed -i 's#ExecStart=/usr/sbin/openvpn#ExecStart=/usr/local/sbin/openvpn#g' "$service" || true
  done < <(find "$SERVICE_DIR" -type f -name 'openvpn*.service' -print0)
fi

# Create the final archive.  Using -C makes paths inside the archive relative,
# e.g. usr/local/sbin/openvpn.
PACKAGE_TAR="/root/openvpn-${VERSION}-local.tar.gz"
tar -C "$PKG_STAGE_DIR" -czf "$PACKAGE_TAR" .

# Clean up the temporary staging area
rm -rf "$PKG_STAGE_DIR"

# Inform the user of success and provide installation instructions
GREEN=$(tput setaf 2 || true)
RESET=$(tput sgr0 || true)

echo "============================================================="
echo "OpenVPN build and packaging complete!"
echo ""
echo "Package created at: ${GREEN}${PACKAGE_TAR}${RESET}"
echo ""
echo "To deploy OpenVPN on a target system, copy the tarball to that machine and run:" 
echo "sudo tar -C / -xzf openvpn-${VERSION}-local.tar.gz"
echo "This will install all binaries, libraries, man pages and systemd units under /usr/local."
echo "============================================================="