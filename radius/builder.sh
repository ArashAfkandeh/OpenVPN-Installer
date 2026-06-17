#!/bin/bash

# Update system and install prerequisites (except Go)
apt-get update
apt-get install -y git gcc make libc-dev

# Clone repository
git clone https://github.com/ArashAfkandeh/OpenVPN-Installer.git

# Navigate to radius directory
cd /root/OpenVPN-Installer/radius

# Build the binary
GOOS=linux GOARCH=amd64 go build -o ovpn-radius ovpn-radius.go
