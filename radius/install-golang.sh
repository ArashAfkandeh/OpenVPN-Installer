#!/bin/bash

# Automatic script to install the latest version of Golang on Ubuntu 22.04
# Author: Assistant (Fixed Version)
# Date: $(date)

set -e # Stop script if an error occurs

# Colors for nicer output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions to display messages (Redirected to stderr so they don't corrupt variable assignments)
info() { echo -e "${BLUE}[INFO]${NC} $1" >&2; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" >&2; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Check if script is run with sudo privileges
check_sudo() {
    if [[ $EUID -ne 0 ]]; then
        error "Please run the script with sudo: sudo ./go_installer.sh"
        exit 1
    fi
    info "Script is running with root privileges"
}

# Update system
update_system() {
    info "Updating system..."
    apt update -y
    success "System successfully updated"
}

# Install necessary dependencies
install_dependencies() {
    info "Installing necessary dependencies..."
    apt install -y wget curl git build-essential
    success "Dependencies successfully installed"
}

# Find the latest stable version of Go
get_latest_go_version() {
    # Get latest stable version from Go's website
    local latest_version=$(curl -s -L https://go.dev/VERSION?m=text | grep -E '^go[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed 's/go//')

    if [ -z "$latest_version" ]; then
        latest_version=$(curl -s https://golang.org/dl/ | grep -oP 'go[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed 's/go//')
    fi

    if [ -z "$latest_version" ]; then
        warning "Could not get latest version, using default 1.22.5"
        latest_version="1.26.4"
    fi

    # ONLY echo the version number to stdout
    echo "$latest_version"
}

# Download and install Go
install_go() {
    local GO_VERSION=$(get_latest_go_version)
    local GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
    local GO_URL="https://go.dev/dl/${GO_TAR}"

    info "Latest version found: ${GO_VERSION}"
    info "Downloading Go from: ${GO_URL}"

    cd /tmp
    if [ -f "$GO_TAR" ]; then
        rm -f "$GO_TAR"
    fi

    local max_retries=3
    local attempt=1
    while [ $attempt -le $max_retries ]; do
        if wget --progress=bar:force --timeout=30 $GO_URL; then
            success "Download completed"
            break
        else
            if [ $attempt -eq $max_retries ]; then
                error "Download failed after $max_retries attempts"
                exit 1
            fi
            warning "Retrying download ($((attempt+1))/$max_retries)..."
            sleep 2
            attempt=$((attempt + 1))
        fi
    done

    if [ -d "/usr/local/go" ]; then
        warning "Removing old Go installation..."
        rm -rf /usr/local/go
    fi

    info "Extracting files to /usr/local..."
    tar -C /usr/local -xzf "$GO_TAR"
    rm -f "$GO_TAR"
}

# Setup environment variables
setup_environment() {
    info "Setting up environment variables..."
    
    # We use a persistent file for all users
    cat > /etc/profile.d/go.sh << 'EOF'
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
EOF

    # Apply for the current session
    export GOROOT=/usr/local/go
    export GOPATH=$HOME/go
    export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
    
    mkdir -p "$GOPATH/bin" "$GOPATH/src" "$GOPATH/pkg"
    success "Environment variables configured"
}

verify_installation() {
    info "Verifying installation..."
    if /usr/local/go/bin/go version; then
        success "Go installed successfully: $(/usr/local/go/bin/go version)"
    else
        error "Installation check failed"
        exit 1
    fi
}

main() {
    echo -e "${GREEN}=== Automatic Go Installer ===${NC}\n"
    check_sudo
    update_system
    install_dependencies
    install_go
    setup_environment
    verify_installation

    echo -e "\n${GREEN}=== Installation Completed! ===${NC}"
    echo -e "${YELLOW}To start using Go, run:${NC} source /etc/profile.d/go.sh"
    echo -e "${YELLOW}Or just open a new terminal.${NC}"
}

main "$@"
