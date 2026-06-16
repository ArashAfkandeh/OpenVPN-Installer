#!/bin/bash

# --- Strict Mode & Logging ---
set -eE -o pipefail
exec > >(tee -i /var/log/openvpn_installer.log) 2>&1

# --- UI Color Definitions ---
C_OFF='\033[0m'
C_GREEN='\033[0;32m'
C_RED='\033[0;31m'
C_YELLOW='\033[0;33m'

print_header() { echo -e "\n\033[0;35m\033[1m====== $1 ======\033[0m"; }
print_success() { echo -e "${C_GREEN}✔ $1${C_OFF}"; }
print_warning() { echo -e "${C_YELLOW}⚠ $1${C_OFF}"; }
print_error() { echo -e "${C_RED}✖ $1${C_OFF}" >&2; }

# --- GitHub Repo Definitions ---
GITHUB_REPO="ArashAfkandeh/OpenVPN-Installer"
PANEL_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/management_panel.sh"
RADIUS_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/ovpn-radius.sh"

# --- Uninstall Option ---
if [[ "$1" == "uninstall" ]]; then
    echo "Completely removing OpenVPN and settings..."
    systemctl stop openvpn-server@server.service 2>/dev/null || true
    systemctl disable openvpn-server@server.service 2>/dev/null || true
    
    # Stop & Remove Interim Timer
    systemctl stop openvpn-radius-interim.timer 2>/dev/null || true
    systemctl disable openvpn-radius-interim.timer 2>/dev/null || true
    rm -f /etc/systemd/system/openvpn-radius-interim.*
    
    rm -rf /etc/openvpn /var/log/openvpn* /etc/sysctl.d/30-openvpn-forward.conf /var/run/ovpn-radius
    sysctl --system >/dev/null 2>&1 || true
    
    if [[ -f /var/log/openvpn-installed-files.txt ]]; then
        while read -r entry; do
            target="/$entry"
            if [[ -e "$target" || -L "$target" ]]; then rm -rf "$target"; fi
        done < /var/log/openvpn-installed-files.txt
        rm -f /var/log/openvpn-installed-files.txt
        systemctl daemon-reload
    fi
    
    if [[ -e /etc/debian_version ]]; then
        apt-get remove --purge -y openvpn openvpn-auth-radius easy-rsa iptables-persistent >/dev/null 2>&1 || true
        apt-get autoremove -y >/dev/null 2>&1 || true
    else
        yum remove -y openvpn openvpn-auth-radius easy-rsa iptables-services >/dev/null 2>&1 || true
    fi
    
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
        for p in udp tcp; do ufw delete allow 1194/$p 2>/dev/null || true; ufw delete allow 1812/$p 2>/dev/null || true; ufw delete allow 1813/$p 2>/dev/null || true; done
    fi
    echo "Complete deletion was performed."
    exit 0
fi

# --- Initial Checks ---
if [[ "$EUID" -ne 0 ]]; then print_error "This script must be run as root."; exit 1; fi
if readlink /proc/$$/exe | grep -q "dash"; then print_error "This script must be run with bash, not sh."; exit 1; fi
if [[ ! -e /dev/net/tun ]]; then print_error "The TUN device is not enabled."; exit 1; fi

# --- OS Detection ---
if [[ -e /etc/debian_version ]]; then OS=debian; GROUPNAME=nogroup
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then OS=centos; GROUPNAME=nobody
else print_error "This script is optimized for Debian/Ubuntu/CentOS."; exit 1; fi

# --- Existing Installation Check ---
print_header "Checking for Existing OpenVPN"
if command -v openvpn >/dev/null || [[ -d /etc/openvpn ]] || systemctl list-unit-files | grep -q '^openvpn-server@server\.service' 2>/dev/null; then
    print_warning "An existing OpenVPN installation was detected."
    if [ -n "${1:-}" ]; then REPLY="y"; else read -p "  Do you want to remove it and continue? [y/N]: " -n 1 -r REPLY < /dev/tty || REPLY="n"; echo; fi

    if [[ "$REPLY" =~ ^[Yy]$ ]]; then
        print_success "Removing existing version safely..."
        systemctl stop openvpn-server@server.service >/dev/null 2>&1 || true
        systemctl disable openvpn-server@server.service >/dev/null 2>&1 || true
        systemctl stop openvpn-radius-interim.timer >/dev/null 2>&1 || true
        
        timeout=10
        while pgrep -x openvpn >/dev/null && [ "$timeout" -gt 0 ]; do sleep 1; ((timeout--)); done
        if pgrep -x openvpn >/dev/null; then killall -9 openvpn >/dev/null 2>&1 || true; fi

        apt-get remove --purge -y openvpn openvpn-auth-radius easy-rsa iptables-persistent >/dev/null 2>&1 || true
        rm -rf /etc/openvpn /var/log/openvpn /usr/local/sbin/openvpn* /usr/local/bin/ov-p || true
        apt-get autoremove -y >/dev/null 2>&1 || true
        systemctl daemon-reload
        print_success "Old configuration removed."
    else
        print_error "Installation aborted."
        exit 1
    fi
fi

# --- Download OpenVPN Package ---
download_package() {
    print_header "Finding the latest release..." >&2
    if ! command -v curl &>/dev/null; then
        if [[ "$OS" = 'debian' ]]; then apt-get update >/dev/null; apt-get install -y curl >/dev/null; else yum install -y curl >/dev/null 2>&1 || true; fi
    fi
    LATEST_RELEASE_URL=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep "browser_download_url" | cut -d '"' -f 4 | head -n1 || true)
    if [ -z "$LATEST_RELEASE_URL" ]; then print_error "Could not find the latest release."; exit 1; fi
    PACKAGE_NAME=$(basename "$LATEST_RELEASE_URL")
    TMP_DIR=$(mktemp -d)
    if ! curl -sSL "$LATEST_RELEASE_URL" -o "${TMP_DIR}/${PACKAGE_NAME}"; then print_error "Failed to download package"; exit 1; fi
    echo "${TMP_DIR}/${PACKAGE_NAME}"
}

clear; echo -e "\n${C_GREEN}OpenVPN with Radius Authentication Installer${C_OFF}\n"; sleep 1

LOCAL_PACKAGE_PATH="/root/openvpn-2.6.14-local.tar.gz"
PACKAGE_PATH=""
if [[ -f "$LOCAL_PACKAGE_PATH" ]]; then
    if [ -n "${1:-}" ]; then PACKAGE_PATH=$(download_package) || PACKAGE_PATH=""; else
        echo -e "  1) Download latest from GitHub\n  2) Use local package ($LOCAL_PACKAGE_PATH)"
        while true; do
            read -p "  Your choice [1-2]: " PACKAGE_CHOICE < /dev/tty || PACKAGE_CHOICE="1"
            case "$PACKAGE_CHOICE" in 1) PACKAGE_PATH=$(download_package) || PACKAGE_PATH=""; break ;; 2) PACKAGE_PATH="$LOCAL_PACKAGE_PATH"; break ;; esac
        done
    fi
else PACKAGE_PATH=$(download_package) || PACKAGE_PATH=""; fi
if [[ -z "$PACKAGE_PATH" || ! -f "$PACKAGE_PATH" ]]; then print_error "Failed to obtain package."; exit 1; fi

# --- User Input ---
PUBLICIP="$1"; PROTOCOL_CHOICE="$2"; PORT="$3"; RADIUSIP="$4"; RADIUSPASS="$5"; DNS="$6"; CLIENT="$7"
IP=$(ip -4 addr | grep 'inet' | grep -v '127.0.0.1' | cut -d' ' -f6 | cut -d'/' -f1 | head -n1)

if [[ -z "$PUBLICIP" ]]; then read -p "Public IP address: " -e -i "$IP" PUBLICIP < /dev/tty; fi
if [[ -z "$PROTOCOL_CHOICE" ]]; then echo -e "Select protocol:\n  1) UDP\n  2) TCP"; read -p "Protocol [1-2]: " -e -i 1 PROTOCOL_CHOICE < /dev/tty; fi
case $PROTOCOL_CHOICE in 1) PROTOCOL=udp ;; 2) PROTOCOL=tcp ;; *) PROTOCOL=udp ;; esac
if [[ -z "$PORT" ]]; then read -p "OpenVPN Port: " -e -i 1194 PORT < /dev/tty; fi
if [[ -z "$RADIUSIP" ]]; then read -p "Radius Server IP: " -e -i "127.0.0.1" RADIUSIP < /dev/tty; fi
if [[ -z "$RADIUSPASS" ]]; then read -s -p "Radius Shared Secret: " -e -i "radius_secret" RADIUSPASS < /dev/tty; echo; fi
if [[ -z "$DNS" ]]; then echo -e "Select DNS:\n  1) System\n  2) Google\n  3) Cloudflare\n  4) OpenDNS"; read -p "DNS [1-4]: " -e -i 2 DNS < /dev/tty; fi
if [[ -z "$CLIENT" ]]; then COUNTRY_CODE=$(curl -s --max-time 3 ifconfig.co/country-iso || echo "client"); read -p "Client config name: " -e -i "$COUNTRY_CODE" CLIENT < /dev/tty; fi

# --- Install Dependencies ---
print_header "Installing Dependencies"
if [[ "$OS" = 'debian' ]]; then
    apt-get update >/dev/null
    sed -i 's/^#\$nrconf{restart} = .*/\$nrconf{restart} = "a";/' /etc/needrestart/needrestart.conf 2>/dev/null || true
    export DEBIAN_FRONTEND=noninteractive
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt-get install -yq easy-rsa iptables-persistent wget lsb-release freeradius-utils liblzo2-2 curl gawk >/dev/null
else
    yum install -y epel-release >/dev/null
    yum install -y easy-rsa iptables-services wget freeradius-utils lzo curl gawk >/dev/null
fi
print_success "Dependencies installed."

# --- Extract OpenVPN ---
tar -tf "$PACKAGE_PATH" > /var/log/openvpn-installed-files.txt
tar -C / -xzf "$PACKAGE_PATH"
systemctl daemon-reload

# --- Setup Easy-RSA & PKI ---
print_header "Setting up PKI (tls-auth enabled)"
mkdir -p /etc/openvpn/server/easy-rsa
cp -r /usr/share/easy-rsa/* /etc/openvpn/server/easy-rsa/
cd /etc/openvpn/server/easy-rsa/

./easyrsa init-pki >/dev/null
./easyrsa --batch build-ca nopass >/dev/null
./easyrsa --batch gen-dh >/dev/null
EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full server nopass >/dev/null 2>&1
EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT" nopass >/dev/null 2>&1
EASYRSA_CRL_DAYS=3650 ./easyrsa --batch gen-crl >/dev/null

cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem pki/crl.pem /etc/openvpn/server/
chown nobody:"$GROUPNAME" /etc/openvpn/server/crl.pem

/usr/local/sbin/openvpn --genkey secret /etc/openvpn/server/ta.key
print_success "Certificates and tls-auth key generated."

# --- Radius Plugin & Config ---
print_header "Configuring RADIUS & Permissions"
mkdir -p /etc/openvpn/plugin /var/log/openvpn /var/run/ovpn-radius
touch /var/log/openvpn/radius-plugin.log
chown nobody:"$GROUPNAME" /var/log/openvpn/radius-plugin.log /var/run/ovpn-radius

cat > /etc/openvpn/plugin/config.json <<EOF
{
  "LogFile": "/var/log/openvpn/radius-plugin.log",
  "ServerInfo": { "Identifier": "OpenVPN", "IpAddress": "$IP", "PortType": "5", "ServiceType": "5" },
  "Radius": {
    "AuthenticationOnly": false,
    "Authentication": { "Server": "$RADIUSIP:1812", "Secret": "$RADIUSPASS" },
    "Accounting": { "Server": "$RADIUSIP:1813", "Secret": "$RADIUSPASS" }
  }
}
EOF
chmod 600 /etc/openvpn/plugin/config.json
chown nobody:"$GROUPNAME" /etc/openvpn/plugin/config.json

# Cache-Buster included to bypass GitHub CDN Cache
if ! curl -sSL "${RADIUS_URL}?v=$(date +%s)" -o /etc/openvpn/plugin/ovpn-radius.sh; then print_error "Failed to fetch radius script from GitHub."; exit 1; fi
chmod +x /etc/openvpn/plugin/ovpn-radius.sh
print_success "Radius plugin fetched and secured."

# --- Smart MTU Calculator ---
OUTGOING_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n 1 || true)
IFACE_MTU=1500
if [ -n "$OUTGOING_IFACE" ] && [ -f "/sys/class/net/$OUTGOING_IFACE/mtu" ]; then IFACE_MTU=$(cat "/sys/class/net/$OUTGOING_IFACE/mtu" 2>/dev/null || echo 1500); fi
MSS_FIX=$((IFACE_MTU - 100))
if [ "$MSS_FIX" -lt 1280 ]; then MSS_FIX=1280; fi

# --- OpenVPN Server Config ---
print_header "Creating OpenVPN Config"
cat > /etc/openvpn/server/server.conf <<EOF
port $PORT
proto $PROTOCOL
dev tun
tun-mtu $IFACE_MTU
mssfix $MSS_FIX
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem
auth SHA512
tls-auth /etc/openvpn/server/ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
server-ipv6 fd00:10:8::/112
ifconfig-pool-persist /etc/openvpn/server/ipp.txt
keepalive 10 120
cipher AES-256-CBC
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC
user nobody
group $GROUPNAME
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log 30
status-version 2
log-append /var/log/openvpn/openvpn.log
verb 3
crl-verify /etc/openvpn/server/crl.pem
script-security 3
auth-user-pass-verify "/etc/openvpn/plugin/ovpn-radius.sh" via-env
client-connect "/etc/openvpn/plugin/ovpn-radius.sh"
client-disconnect "/etc/openvpn/plugin/ovpn-radius.sh"
verify-client-cert none
username-as-common-name
push "redirect-gateway def1 bypass-dhcp"
push "route-ipv6 2000::/3"
push "route $RADIUSIP 255.255.255.255 net_gateway"
EOF

case $DNS in
    1) if grep -q "127.0.0.53" "/etc/resolv.conf"; then RESOLVCONF='/run/systemd/resolve/resolv.conf'; else RESOLVCONF='/etc/resolv.conf'; fi
       grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read -r line; do echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf; done ;;
    2) echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf; echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf ;;
    3) echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf; echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf ;;
    4) echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf; echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf ;;
esac

# --- RADIUS Interim Updates Timer ---
print_header "Setting up RADIUS Interim Updates (1min interval)"
cat > /etc/systemd/system/openvpn-radius-interim.service <<EOF
[Unit]
Description=OpenVPN RADIUS Interim Updates
[Service]
Type=oneshot
ExecStart=/etc/openvpn/plugin/ovpn-radius.sh interim
EOF

cat > /etc/systemd/system/openvpn-radius-interim.timer <<EOF
[Unit]
Description=Run OpenVPN RADIUS Interim Updates every 1 minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now openvpn-radius-interim.timer
print_success "Interim updates (Live IBSng traffic) enabled."

# --- Firewall & Sysctl (BBR & Dual-Stack IPv6) ---
print_header "Configuring Firewall, BBR & Dual-Stack IPv6"
cat > /etc/sysctl.d/30-openvpn-forward.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
sysctl -p /etc/sysctl.d/30-openvpn-forward.conf >/dev/null 2>&1 || true

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
    for proto in udp tcp; do ufw allow $PORT/$proto >/dev/null; ufw allow 1812/$proto >/dev/null; ufw allow 1813/$proto >/dev/null; done
    ufw allow from 10.8.0.0/24 >/dev/null; ufw allow from fd00:10:8::/112 >/dev/null
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw 2>/dev/null || true
    ufw reload >/dev/null 2>&1 || true
elif command -v nft >/dev/null 2>&1 && systemctl is-active nftables >/dev/null 2>&1; then
    nft add rule inet openvpn forward ip saddr 10.8.0.0/24 accept || true
    nft add rule inet openvpn postrouting ip saddr 10.8.0.0/24 oif "$OUTGOING_IFACE" masquerade || true
    nft add rule inet openvpn forward ip6 saddr fd00:10:8::/112 accept || true
    nft add rule inet openvpn postrouting ip6 saddr fd00:10:8::/112 oif "$OUTGOING_IFACE" masquerade || true
else
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$OUTGOING_IFACE" -j MASQUERADE
    iptables -A INPUT -p "$PROTOCOL" --dport "$PORT" -j ACCEPT
    iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    ip6tables -t nat -A POSTROUTING -s fd00:10:8::/112 -o "$OUTGOING_IFACE" -j MASQUERADE 2>/dev/null || true
    ip6tables -A FORWARD -s fd00:10:8::/112 -j ACCEPT 2>/dev/null || true
    ip6tables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null; fi
fi

SERVICE_FILE="/usr/local/lib/systemd/system/openvpn-server@.service"
if [ -f "$SERVICE_FILE" ]; then sed -i '/^LimitNPROC=10$/c\LimitNPROC=infinity\nTasksMax=infinity\nLimitNOFILE=524288' "$SERVICE_FILE"; systemctl daemon-reload; fi
systemctl enable --now openvpn-server@server.service >/dev/null

# --- Management Panel Download ---
if curl -sSL "${PANEL_URL}?v=$(date +%s)" -o /usr/local/bin/ov-p; then chmod +x /usr/local/bin/ov-p; print_success "Management panel installed (ov-p)."; else print_error "Failed to download panel."; fi

# --- Client Config Generation ---
{
    echo "client"
    echo "dev tun"
    echo "proto $PROTOCOL"
    echo "remote $PUBLICIP $PORT"
    echo "resolv-retry infinite"
    echo "nobind"
    echo "persist-key"
    echo "persist-tun"
    echo "remote-cert-tls server"
    echo "auth SHA512"
    echo "cipher AES-256-CBC"
    echo "data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC"
    echo "data-ciphers-fallback AES-256-CBC"
    echo "tun-mtu $IFACE_MTU"
    echo "mssfix $MSS_FIX"
    echo "key-direction 1"
    echo "verb 3"
    echo "auth-user-pass"
    echo "<ca>"; cat /etc/openvpn/server/ca.crt; echo "</ca>"
    echo "<cert>"; cat /etc/openvpn/server/easy-rsa/pki/issued/$CLIENT.crt; echo "</cert>"
    echo "<key>"; cat /etc/openvpn/server/easy-rsa/pki/private/$CLIENT.key; echo "</key>"
    echo "<tls-auth>"; cat /etc/openvpn/server/ta.key; echo "</tls-auth>"
} > "/root/$CLIENT.ovpn"

# --- Finalization ---
clear; print_success "Installation completed successfully!"
echo -e "\n======================================================="
echo -e "  Server IP:         ${C_GREEN}$PUBLICIP${C_OFF}"
echo -e "  Port:              ${C_GREEN}$PORT${C_OFF}"
echo -e "  Protocol:          ${C_GREEN}$PROTOCOL${C_OFF}"
echo -e "  Authentication:    ${C_GREEN}Radius + tls-auth${C_OFF}"
echo -e "======================================================="
echo -e "\nYour client profile is ready at: ${C_GREEN}/root/$CLIENT.ovpn${C_OFF}"
echo -e "Access the Management Panel by typing: ${C_GREEN}ov-p${C_OFF}\n"
