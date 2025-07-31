#!/bin/bash

set -e

# --- Uninstall Option ---
if [[ "$1" == "uninstall" ]]; then
    echo "در حال حذف کامل OpenVPN و تنظیمات..."
    systemctl stop openvpn-server@server.service 2>/dev/null || true
    systemctl disable openvpn-server@server.service 2>/dev/null || true
    if [[ -d /etc/openvpn ]]; then
        rm -rf /etc/openvpn
    fi
    if [[ -d /etc/openvpn/server ]]; then
        rm -rf /etc/openvpn/server
    fi
    if [[ -d /etc/openvpn/radius ]]; then
        rm -rf /etc/openvpn/radius
    fi
    # Remove ovpn-radius plugin directory if present
    if [[ -d /etc/openvpn/plugin ]]; then
        rm -rf /etc/openvpn/plugin
    fi
    if [[ -d /etc/openvpn/server/easy-rsa ]]; then
        rm -rf /etc/openvpn/server/easy-rsa
    fi
    if [[ -f /etc/sysctl.d/30-openvpn-forward.conf ]]; then
        rm -f /etc/sysctl.d/30-openvpn-forward.conf
        sysctl --system
    fi
    # Remove files installed from the extracted OpenVPN package.  When the
    # package was installed, a list of extracted files was recorded in
    # /var/log/openvpn-installed-files.txt.  Remove each file or directory
    # listed therein, then reload systemd unit definitions.  Ignore
    # missing files.  Finally delete the list itself.
    if [[ -f /var/log/openvpn-installed-files.txt ]]; then
        while read -r entry; do
            target="/$entry"
            if [[ -e "$target" || -L "$target" ]]; then
                rm -rf "$target"
            fi
        done < /var/log/openvpn-installed-files.txt
        rm -f /var/log/openvpn-installed-files.txt
        systemctl daemon-reload
    fi
    if [[ "$OS" = 'debian' ]]; then
        apt-get remove --purge -y openvpn openvpn-auth-radius easy-rsa iptables-persistent
        apt-get autoremove -y
    else
        yum remove -y openvpn openvpn-auth-radius easy-rsa iptables-services
    fi
    # حذف قوانین UFW
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
        for p in udp tcp; do
            ufw delete allow 1194/$p 2>/dev/null || true
            ufw delete allow 1812/$p 2>/dev/null || true
            ufw delete allow 1813/$p 2>/dev/null || true
        done
    fi
    echo "حذف کامل انجام شد."
    exit 0
fi

# --- Initial Checks ---
if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi

if readlink /proc/$$/exe | grep -q "dash"; then
    echo "ERROR: This script must be run with bash, not sh."
    exit 1
fi

if [[ ! -e /dev/net/tun ]]; then
    echo "ERROR: The TUN device is not enabled. Please enable it in your VPS control panel."
    exit 1
fi

# --- OS Detection ---
if [[ -e /etc/debian_version ]]; then
    OS=debian
    GROUPNAME=nogroup
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
    # Note: openvpn-auth-radius might not be in the default CentOS repos.
    # EPEL repository is required.
    OS=centos
    GROUPNAME=nobody
else
    echo "ERROR: This script is optimized for Debian/Ubuntu."
    exit 1
fi

# --- Check existing OpenVPN installation ---
if command -v openvpn >/dev/null || [[ -d /etc/openvpn ]] || systemctl list-unit-files | grep -q '^openvpn-server@server.service'; then
    print_warning "An existing OpenVPN installation was detected."
    read -p "  Do you want to remove it and continue with a fresh installation? [y/N]: " -n 1 -r REPLY
    echo    # رفتن به خط بعد
    if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
        print_error "Installation aborted by the user."
        exit 1
    fi
    print_success "Proceeding with removal of the existing version..."

    # توقف سرویس‌های موجود
    echo "  Stopping any existing OpenVPN services..."
    if systemctl list-unit-files | grep -q '^openvpn-server@server.service'; then
        systemctl stop openvpn-server@server.service || true
        systemctl disable openvpn-server@server.service || true
    fi
    # پایان دادن به پردازه‌های در حال اجرا
    killall -q -9 openvpn || true
    # کمی منتظر بمانید تا پردازه‌ها متوقف شوند
    timeout=20
    while pgrep -x openvpn >/dev/null && [ "$timeout" -gt 0 ]; do
        sleep 0.5
        ((timeout--))
    done
    if pgrep -x openvpn >/dev/null; then
        print_error "OpenVPN processes could not be terminated."
        exit 1
    fi
    print_success "All OpenVPN processes terminated."

    # حذف بسته‌ها و فایل‌های پیکربندی قدیمی
    echo "  Removing old packages and configurations..."
    apt-get remove --purge -y openvpn openvpn-auth-radius easy-rsa iptables-persistent >/dev/null 2>&1 || true
    rm -rf /etc/openvpn /var/log/openvpn /usr/local/sbin/openvpn*
    apt-get autoremove -y >/dev/null 2>&1
    systemctl daemon-reload
    print_success "Old packages and configurations removed."
fi

# --- Helper functions and variables for package download ---
# Define simple print helpers for consistency.  These functions output
# messages and allow future styling if needed.  print_error writes
# to stderr.
print_header() { echo -e "$1"; }
print_success() { echo -e "$1"; }
print_warning() { echo -e "$1"; }
print_error() { echo -e "$1" >&2; }

# Path to a locally built OpenVPN tarball.  If this file exists,
# the installer will offer the option to use it instead of
# downloading from GitHub.  Adjust this path if your local file
# resides elsewhere.
LOCAL_PACKAGE_PATH="/root/openvpn-2.6.14-local.tar.gz"

# GitHub repository containing the latest OpenVPN package.  The
# download_package function uses the GitHub API to find the latest
# release asset.  Replace the value of GITHUB_REPO with the
# appropriate owner/repo name as needed.
GITHUB_REPO="ArashAfkandeh/OpenVPN-Installer"

# download_package fetches the most recent release asset from the
# specified GitHub repository.  It prints progress messages to
# stderr, installs curl if necessary, and returns the path to the
# downloaded file via stdout.  If download fails, the function
# outputs an error and exits.
download_package() {
    print_header "Finding the latest release..."
    # Ensure curl is available.  Install it silently if missing.
    if ! command -v curl &>/dev/null; then
        if [[ "$OS" = 'debian' ]]; then
            apt-get update >/dev/null
            apt-get install -y curl >/dev/null
        else
            yum install -y curl >/dev/null 2>&1 || true
        fi
    fi
    # Query GitHub API for the latest release information
    LATEST_RELEASE_URL=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep "browser_download_url" | cut -d '"' -f 4 | head -n1)
    if [ -z "$LATEST_RELEASE_URL" ]; then
        print_error "Could not find the latest release."
        exit 1
    fi
    PACKAGE_NAME=$(basename "$LATEST_RELEASE_URL")
    print_header "Downloading latest release: $PACKAGE_NAME"
    TMP_DIR=$(mktemp -d)
    if ! curl -sSL "$LATEST_RELEASE_URL" -o "${TMP_DIR}/${PACKAGE_NAME}"; then
        print_error "Failed to download package from GitHub"
        rm -rf "$TMP_DIR"
        exit 1
    fi
    echo "${TMP_DIR}/${PACKAGE_NAME}"
}

# --- Function to generate client config ---
newclient() {
    cp /etc/openvpn/server/client-common.txt "/root/$1.ovpn"
    {
        echo "<ca>"
        cat /etc/openvpn/server/easy-rsa/pki/ca.crt
        echo "</ca>"
        echo "<cert>"
        cat /etc/openvpn/server/easy-rsa/pki/issued/$1.crt
        echo "</cert>"
        echo "<key>"
        cat /etc/openvpn/server/easy-rsa/pki/private/$1.key
        echo "</key>"
        echo "<tls-auth>"
        cat /etc/openvpn/server/ta.key
        echo "</tls-auth>"
    } >> "/root/$1.ovpn"
}

# --- Main Installation Logic ---
clear
echo 'OpenVPN with Radius Authentication Installer (Local or GitHub Package)'
echo
sleep 2

# --- Choose installation package source ---
# Determine whether to use a locally built OpenVPN archive or download
# the latest version from GitHub.  If a local package exists at
# LOCAL_PACKAGE_PATH, prompt the user for a choice.  Otherwise,
# download from GitHub by default.
PACKAGE_PATH=""
if [[ -f "$LOCAL_PACKAGE_PATH" ]]; then
    echo
    echo "  A local OpenVPN package was found."
    echo "  Please choose an installation source:"
    echo ""
    echo "     1) Download the latest version from GitHub"
    echo "     2) Use the local package ($LOCAL_PACKAGE_PATH)"
    while true; do
        read -p "  Your choice [1-2]: " PACKAGE_CHOICE
        case "$PACKAGE_CHOICE" in
            1)
                PACKAGE_PATH=$(download_package) || PACKAGE_PATH=""
                break
                ;;
            2)
                print_success "Using local package: $LOCAL_PACKAGE_PATH"
                PACKAGE_PATH="$LOCAL_PACKAGE_PATH"
                break
                ;;
            *)
                print_warning "Invalid choice. Please enter 1 or 2."
                ;;
        esac
    done
    echo
else
    # No local package found; download from GitHub
    PACKAGE_PATH=$(download_package) || PACKAGE_PATH=""
fi

if [[ -z "$PACKAGE_PATH" || ! -f "$PACKAGE_PATH" ]]; then
    print_error "Failed to obtain package file. The path specified was: '$PACKAGE_PATH'"
    exit 1
fi

# --- Get User Input ---
# خواندن آرگومان‌های ورودی
PUBLICIP="$1"
PROTOCOL_CHOICE="$2"
PORT="$3"
RADIUSIP="$4"
RADIUSPASS="$5"
DNS="$6"
CLIENT="$7"

IP=$(ip -4 addr | grep 'inet' | grep -v '127.0.0.1' | cut -d' ' -f6 | cut -d'/' -f1 | head -n1)
if [[ -z "$PUBLICIP" ]]; then
    read -p "Public IP address: " -e -i "$IP" PUBLICIP
fi

echo
if [[ -z "$PROTOCOL_CHOICE" ]]; then
    echo "Select the protocol for OpenVPN:"
    echo "   1) UDP (recommended)"
    echo "   2) TCP"
    read -p "Protocol [1-2]: " -e -i 1 PROTOCOL_CHOICE
fi
case $PROTOCOL_CHOICE in
    1) PROTOCOL=udp ;;
    2) PROTOCOL=tcp ;;
    *) PROTOCOL=udp ;;
esac

echo
if [[ -z "$PORT" ]]; then
    read -p "OpenVPN Port: " -e -i 1194 PORT
fi

# باز کردن پورت‌ها در UFW (در صورت فعال بودن)
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
    for proto in udp tcp; do
        ufw allow $PORT/$proto
        ufw allow 1812/$proto
        ufw allow 1813/$proto
    done
fi
echo
if [[ -z "$RADIUSIP" ]]; then
    read -p "Radius Server IP: " -e -i "127.0.0.1" RADIUSIP
fi
echo
if [[ -z "$RADIUSPASS" ]]; then
    read -p "Radius Shared Secret: " -e -i "radius_secret" RADIUSPASS
fi
echo
echo "Select the DNS to use for clients:"
echo "   1) Current system resolvers"
echo "   2) Cloudflare"
echo "   3) Google"
echo "   4) OpenDNS"
if [[ -z "$DNS" ]]; then
    read -p "DNS [1-4]: " -e -i 3 DNS
fi
echo
if [[ -z "$CLIENT" ]]; then
    read -p "Client config file name (one word, e.g., client): " -e -i client CLIENT
fi
echo
echo "-------------------------------------------"
echo "Installation will now begin. Please wait."
echo "-------------------------------------------"
sleep 3

# --- Install Dependencies ---
echo "Installing dependencies..."
if [[ "$OS" = 'debian' ]]; then
    apt-get update
    export DEBIAN_FRONTEND=noninteractive
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    # Install runtime dependencies.  The OpenVPN daemon will be extracted from
    # the package file selected earlier, so we do not install it from the
    # package manager.  freeradius-utils provides the radclient binary used
    # by our authentication script.
    apt-get install -y easy-rsa iptables-persistent wget lsb-release freeradius-utils
else # CentOS
    yum install -y epel-release
    # Install runtime dependencies.  Skip OpenVPN, go, git and sqlite
    # because the daemon will be provided by the downloaded or local package.
    yum install -y easy-rsa iptables-services wget freeradius-utils
fi

echo "Dependencies installed."
sleep 2

# --- Install the selected OpenVPN package ---
echo "Installing selected OpenVPN package from $PACKAGE_PATH..."
# Record the list of files contained within the archive for clean uninstallation later.
tar -tf "$PACKAGE_PATH" > /var/log/openvpn-installed-files.txt
# Extract the package into the root filesystem.  The archive contains
# usr/local/... directories, so files will be placed under /usr/local.
tar -C / -xzf "$PACKAGE_PATH"
# Reload systemd units so that the OpenVPN service files under
# /usr/local/lib/systemd/system are recognised by systemd.
systemctl daemon-reload
echo "OpenVPN package installed."
sleep 2

# --- Setup Easy-RSA and PKI ---
echo "Setting up Public Key Infrastructure (PKI) with Easy-RSA..."
mkdir -p /etc/openvpn/server/easy-rsa
cp -r /usr/share/easy-rsa/* /etc/openvpn/server/easy-rsa/
cd /etc/openvpn/server/easy-rsa/

./easyrsa init-pki
./easyrsa --batch build-ca nopass
./easyrsa --batch gen-dh
EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$CLIENT" nopass
EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem pki/crl.pem /etc/openvpn/server/
chown nobody:"$GROUPNAME" /etc/openvpn/server/crl.pem
openvpn --genkey --secret /etc/openvpn/server/ta.key
echo "PKI and certificates generated."
sleep 2

# --- Install ovpn-radius plugin ---
echo "Installing ovpn-radius plugin and preparing configuration..."
# Install a Bash-based RADIUS integration instead of the Go-based ovpn-radius plugin.
echo "Installing RADIUS authentication script and preparing configuration..."
# Create plugin and log directories
mkdir -p /etc/openvpn/plugin
mkdir -p /var/log/openvpn
# Create the plugin log file with proper ownership
touch /var/log/openvpn/radius-plugin.log
chown nobody:"$GROUPNAME" /var/log/openvpn/radius-plugin.log
# Generate a custom RADIUS configuration using the provided server details
cat > /etc/openvpn/plugin/config.json <<EOF
{
  "LogFile": "/var/log/openvpn/radius-plugin.log",
  "ServerInfo": {
    "Identifier": "OpenVPN",
    "IpAddress": "$IP",
    "PortType": "5",
    "ServiceType": "5"
  },
  "Radius": {
    "AuthenticationOnly": false,
    "Authentication": {
      "Server": "$RADIUSIP:1812",
      "Secret": "$RADIUSPASS"
    },
    "Accounting": {
      "Server": "$RADIUSIP:1813",
      "Secret": "$RADIUSPASS"
    }
  }
}
EOF
# Create a Bash script that handles RADIUS authentication and accounting using radclient.
cat > /etc/openvpn/plugin/ovpn-radius.sh <<'EOF'
#!/bin/bash

## Determine the action based on the OpenVPN-provided script_type environment variable.
# OpenVPN sets script_type to one of "auth-user-pass-verify", "client-connect",
# or "client-disconnect" before executing the script【148081712123785†L1175-L1179】.  We map these
# types to our internal actions.  For authentication, the temporary file
# containing the username and password is passed as $1.
case "$script_type" in
  # OpenVPN sets script_type to "user-pass-verify" (legacy) or
  # "auth-user-pass-verify" depending on version. Treat both as auth.
  user-pass-verify|auth-user-pass-verify)
    ACTION="auth"
    AUTHFILE="$1"
    ;;
  client-connect)
    ACTION="acct"
    ;;
  client-disconnect)
    ACTION="stop"
    ;;
  *)
    # Fall back to authentication when script_type is unset or unknown. Certain OpenVPN
    # versions may set script_type="user-pass-verify" or may not set it at all for
    # auth-user-pass-verify scripts. In such cases treat the call as auth and
    # read credentials from the first argument (the file path). Do not exit with
    # error, otherwise OpenVPN will reject the connection.
    ACTION="auth"
    AUTHFILE="$1"
    ;;
esac
CONFIG=/etc/openvpn/plugin/config.json

# Extract values from JSON configuration without requiring jq. The following
# helper searches for the first occurrence of a key in the JSON and returns
# its value. This simplistic parser assumes keys appear only once.
get_json_value() {
    local key="$1"
    grep -m1 "\"$key\"" "$CONFIG" | sed 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
}

##
# Extract RADIUS authentication and accounting endpoints separately.  The
# configuration defines "Authentication" and "Accounting" objects with their
# own Server and Secret keys.  Define helper functions to find the first
# occurrence of these keys following their parent section.

get_auth_server() {
    grep -A2 '"Authentication"' "$CONFIG" | grep -m1 '"Server"' | sed 's/.*"Server"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
}
get_auth_secret() {
    grep -A2 '"Authentication"' "$CONFIG" | grep -m1 '"Secret"' | sed 's/.*"Secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
}
get_acct_server() {
    grep -A2 '"Accounting"' "$CONFIG" | grep -m1 '"Server"' | sed 's/.*"Server"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
}
get_acct_secret() {
    grep -A2 '"Accounting"' "$CONFIG" | grep -m1 '"Secret"' | sed 's/.*"Secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
}

# Retrieve RADIUS servers/secrets.  Default variables RADIUS_SERVER and
# RADIUS_SECRET retain compatibility by pointing at the authentication
# server/secret.  These are used by the authentication branch.  The
# accounting branches will explicitly reference RADIUS_ACCT_SERVER and
# RADIUS_ACCT_SECRET.
RADIUS_AUTH_SERVER=$(get_auth_server)
RADIUS_AUTH_SECRET=$(get_auth_secret)
RADIUS_ACCT_SERVER=$(get_acct_server)
RADIUS_ACCT_SECRET=$(get_acct_secret)
NAS_IP=$(get_json_value IpAddress)
NAS_IDENTIFIER=$(get_json_value Identifier)
RADIUS_SERVER="$RADIUS_AUTH_SERVER"
RADIUS_SECRET="$RADIUS_AUTH_SECRET"

# Directory to store session identifiers between client-connect and client-disconnect
SESSION_DIR=/var/run/ovpn-radius
# NOTE: Do not attempt to create the session directory here. It must be
# pre-created by the installer with appropriate permissions. If it doesn't
# exist at runtime, session files will not be stored.

case "$ACTION" in
  auth)
    # Called by OpenVPN for username/password verification. Read credentials
    # from the file provided by OpenVPN (--auth-user-pass-verify via-file).
    # Determine username and password. When using via-file, OpenVPN passes a
    # temporary file path as $1. When using via-env, it exports the
    # variables 'username' and 'password'. Use whichever is available.
    if [[ -n "$AUTHFILE" && -f "$AUTHFILE" ]]; then
        # Read the first two lines: username and password
        local _u
        local _p
        _u=$(head -n1 "$AUTHFILE")
        _p=$(tail -n +2 "$AUTHFILE" | head -n1)
        username="$_u"
        password="$_p"
    else
        username="$username"
        password="$password"
        # If username is empty, fail authentication
        if [[ -z "$username" || -z "$password" ]]; then
            exit 1
        fi
    fi
    calling="$untrusted_ip"
    # Build Access-Request attributes
    ATTR="User-Name=\"$username\"\n"
    ATTR+="User-Password=\"$password\"\n"
    if [[ -n "$calling" ]]; then ATTR+="Calling-Station-Id=$calling\n"; fi
    ATTR+="NAS-IP-Address=$NAS_IP\n"
    ATTR+="NAS-Port-Type=Virtual\n"
    ATTR+="NAS-Identifier=$NAS_IDENTIFIER\n"
    ATTR+="Service-Type=Framed-User\n"
    ATTR+="Framed-Protocol=PPP\n"
    # Optional: uncomment if your RADIUS server requires Message-Authenticator
    # ATTR+="Message-Authenticator=0x00\n"
    # Send Access-Request and look for Access-Accept in the reply.  Reduce the
    # timeout and retries to further minimise authentication latency.  The
    # -t option sets the timeout in seconds (default is 3) and -r sets the
    # number of retries (default is 3).  We wait at most 1 second for a
    # reply, with a single attempt.  This speeds up connection times but
    # assumes the RADIUS server will respond promptly.  Adjust the timeout
    # upward if your RADIUS server has higher latency.
    if echo -e "$ATTR" | /usr/bin/radclient -t 1 -r 1 "$RADIUS_SERVER" auth "$RADIUS_SECRET" 2>&1 | grep -qi "Access-Accept"; then
        exit 0
    else
        exit 1
    fi
    ;;
  acct)
    # Client connected: send Accounting-Start
    username="$common_name"
    calling="$untrusted_ip"
    client_ip="$ifconfig_pool_remote_ip"
    # Create or reuse a session ID file for this user
    session_file="$SESSION_DIR/${username}.session"
    if [[ -s "$session_file" ]]; then
        session_id=$(cat "$session_file")
    else
        session_id=$(date +%s%N | head -c 10)
        echo "$session_id" > "$session_file"
    fi
    ATTR="Acct-Session-Id=$session_id\n"
    ATTR+="Acct-Status-Type=Start\n"
    ATTR+="User-Name=$username\n"
    if [[ -n "$calling" ]]; then ATTR+="Calling-Station-Id=$calling\n"; fi
    ATTR+="NAS-IP-Address=$NAS_IP\n"
    ATTR+="NAS-Identifier=$NAS_IDENTIFIER\n"
    if [[ -n "$client_ip" ]]; then ATTR+="Framed-IP-Address=$client_ip\n"; fi
    ATTR+="Service-Type=Framed-User\n"
    ATTR+="Framed-Protocol=PPP\n"
    # Send the accounting start asynchronously to avoid delaying the client
    # connection.  Use the accounting server/secret instead of the
    # authentication server.  We use a short timeout and a single retry.
    (echo -e "$ATTR" | /usr/bin/radclient -t 3 -r 1 "$RADIUS_ACCT_SERVER" acct "$RADIUS_ACCT_SECRET" >/dev/null 2>&1) &
    exit 0
    ;;
  stop)
    # Client disconnected: send Accounting-Stop
    username="$common_name"
    calling="$untrusted_ip"
    client_ip="$ifconfig_pool_remote_ip"
    session_file="$SESSION_DIR/${username}.session"
    if [[ -s "$session_file" ]]; then
        session_id=$(cat "$session_file")
        rm -f "$session_file"
    else
        session_id=$(date +%s%N | head -c 10)
    fi
    ATTR="Acct-Session-Id=$session_id\n"
    ATTR+="Acct-Status-Type=Stop\n"
    ATTR+="User-Name=$username\n"
    if [[ -n "$calling" ]]; then ATTR+="Calling-Station-Id=$calling\n"; fi
    ATTR+="NAS-IP-Address=$NAS_IP\n"
    ATTR+="NAS-Identifier=$NAS_IDENTIFIER\n"
    if [[ -n "$client_ip" ]]; then ATTR+="Framed-IP-Address=$client_ip\n"; fi
    ATTR+="Service-Type=Framed-User\n"
    ATTR+="Framed-Protocol=PPP\n"
    # Send the accounting stop asynchronously as well.  Use the accounting
    # server and secret instead of the authentication endpoint.
    (echo -e "$ATTR" | /usr/bin/radclient -t 3 -r 1 "$RADIUS_ACCT_SERVER" acct "$RADIUS_ACCT_SECRET" >/dev/null 2>&1) &
    exit 0
    ;;
  *)
    echo "Unknown action: $ACTION" >&2
    exit 1
    ;;
esac
EOF
chmod +x /etc/openvpn/plugin/ovpn-radius.sh
echo "RADIUS authentication script installed."

# Pre-create session directory for the RADIUS script. This directory must be
# writable by the OpenVPN runtime user (nobody:nogroup) so that session
# identifiers can be stored and removed. Without this, the script will
# encounter permission denied errors when handling accounting events.
mkdir -p /var/run/ovpn-radius
chown nobody:"$GROUPNAME" /var/run/ovpn-radius

# --- Configure OpenVPN Server (server.conf) ---
echo "Creating OpenVPN server configuration file..."
# Generate server.conf using cat <<EOF for better readability and include ovpn-radius script directives
cat > /etc/openvpn/server/server.conf <<EOF
port $PORT
proto $PROTOCOL
dev tun
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem
auth SHA512
tls-auth /etc/openvpn/server/ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /etc/openvpn/server/ipp.txt
duplicate-cn
keepalive 10 120
cipher AES-256-CBC
; Specify data ciphers to support negotiation with modern clients. Without this,
; OpenVPN 2.5+ will ignore the 'cipher' directive for data channel negotiations.
; AES-256-CBC is used as fallback for legacy clients.
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC
user nobody
group $GROUPNAME
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3
crl-verify /etc/openvpn/server/crl.pem
# Enable external script execution.  Level 3 is required to allow OpenVPN
# to pass the username and password to scripts via environment variables
# (the via-env method).  Lower levels do not permit environment-based
# credential passing【616714981170532†L340-L355】.
script-security 3
# Specify the RADIUS authentication script.  We use the via-env method to
# avoid writing the client's credentials to a temporary file, which can
# marginally improve connection speed.  The username and password will be
# provided via the environment variables 'username' and 'password'.
auth-user-pass-verify "/etc/openvpn/plugin/ovpn-radius.sh" via-env
client-connect "/etc/openvpn/plugin/ovpn-radius.sh"
client-disconnect "/etc/openvpn/plugin/ovpn-radius.sh"
verify-client-cert none
username-as-common-name
EOF

# Add DNS options
echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
echo "push \"route $RADIUSIP 255.255.255.255 net_gateway\"" >> /etc/openvpn/server/server.conf
case $DNS in
    1)
        if grep -q "127.0.0.53" "/etc/resolv.conf"; then RESOLVCONF='/run/systemd/resolve/resolv.conf'; else RESOLVCONF='/etc/resolv.conf'; fi
        grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read -r line; do
            echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf; done ;;
    2) echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf; echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf ;;
    3) echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf; echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf ;;
    4) echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf; echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf ;;
esac
echo "Server configuration complete."
sleep 2

# --- Networking and Firewall ---
echo "Configuring networking and firewall rules..."
mkdir -p /var/log/openvpn
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
sysctl -p /etc/sysctl.d/30-openvpn-forward.conf

NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

# --- مدیریت فایروال‌ها: UFW، firewalld، nftables، iptables ---
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
    for proto in udp tcp; do
        ufw allow $PORT/$proto
        ufw allow 1812/$proto
        ufw allow 1813/$proto
    done
    ufw allow from 10.8.0.0/24
elif pgrep firewalld >/dev/null 2>&1; then
    firewall-cmd --add-port="$PORT/$PROTOCOL"
    firewall-cmd --zone=trusted --add-source=10.8.0.0/24
    firewall-cmd --permanent --add-port="$PORT/$PROTOCOL"
    firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
    firewall-cmd --add-port=1812/udp
    firewall-cmd --add-port=1812/tcp
    firewall-cmd --add-port=1813/udp
    firewall-cmd --add-port=1813/tcp
    firewall-cmd --permanent --add-port=1812/udp
    firewall-cmd --permanent --add-port=1812/tcp
    firewall-cmd --permanent --add-port=1813/udp
    firewall-cmd --permanent --add-port=1813/tcp
    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 -o "$NIC" -j MASQUERADE
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 -o "$NIC" -j MASQUERADE
elif command -v nft >/dev/null 2>&1 && systemctl is-active nftables >/dev/null 2>&1; then
    nft add table inet openvpn || true
    nft add chain inet openvpn input { type filter hook input priority 0 \; } || true
    nft add chain inet openvpn forward { type filter hook forward priority 0 \; } || true
    nft add chain inet openvpn postrouting { type nat hook postrouting priority 100 \; } || true
    nft add rule inet openvpn input udp dport $PORT accept
    nft add rule inet openvpn input tcp dport $PORT accept
    nft add rule inet openvpn input udp dport 1812 accept
    nft add rule inet openvpn input tcp dport 1812 accept
    nft add rule inet openvpn input udp dport 1813 accept
    nft add rule inet openvpn input tcp dport 1813 accept
    nft add rule inet openvpn forward ip saddr 10.8.0.0/24 accept
    nft add rule inet openvpn postrouting ip saddr 10.8.0.0/24 oif "$NIC" masquerade
else
    # iptables
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$NIC" -j MASQUERADE
    iptables -A INPUT -p "$PROTOCOL" --dport "$PORT" -j ACCEPT
    iptables -A INPUT -p udp --dport 1812 -j ACCEPT
    iptables -A INPUT -p tcp --dport 1812 -j ACCEPT
    iptables -A INPUT -p udp --dport 1813 -j ACCEPT
    iptables -A INPUT -p tcp --dport 1813 -j ACCEPT
    iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    netfilter-persistent save
fi

if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing"; then
    if [[ "$PORT" != '1194' ]]; then semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"; fi
fi
echo "Networking configured."
sleep 2

# --- Start OpenVPN Service ---
echo "Starting OpenVPN service..."
systemctl enable --now openvpn-server@server.service
echo "OpenVPN service started."
sleep 2

# --- Generate Client Config File ---
echo "Generating client configuration file..."
cat > /etc/openvpn/server/client-common.txt <<EOF
client
dev tun
proto $PROTOCOL
remote $PUBLICIP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
; Data channel cipher negotiation for OpenVPN 2.5+. This list should mirror
; the server configuration and include AES-GCM and AES-CBC modes. The
; fallback directive ensures compatibility with legacy clients.
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC
key-direction 1
verb 3
auth-user-pass
EOF

newclient "$CLIENT"
echo "Client configuration generated."
sleep 2

# --- Final Output ---
clear
echo "Installation completed successfully!"
echo
echo "======================================================="
echo "  Server IP:         $PUBLICIP"
echo "  Port:              $PORT"
echo "  Protocol:          $PROTOCOL"
echo "  Authentication:    Radius (Username & Password)"
echo "======================================================="
echo
echo "The client configuration file is available at:"
echo "  /root/$CLIENT.ovpn"
echo
echo "You can share this single file with all your users."
echo "For best results, it is recommended to reboot the server now: reboot"
echo

# --- Management Panel Installation ---
# In order to provide a user-friendly way to manage OpenVPN after
# installation, install a lightweight interactive panel.  This panel
# mirrors the ocserv management panel included in the ocserv installer
# and allows administrators to view status, change configuration
# values (port, protocol, RADIUS settings, DNS), restart the
# service and even uninstall OpenVPN.  The panel is written to
# /usr/local/bin/ov-p and made executable.  It uses simple
# text‑based menus and colorised output similar to the ocserv panel.

cat > /usr/local/bin/ov-p <<'OVPNEOF'
#!/bin/bash
# OpenVPN Advanced Management Panel

# --- UI Color Definitions ---
C_OFF='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_PURPLE='\033[0;35m'
C_CYAN='\033[0;36m'
C_BOLD='\033[1m'
C_BLINK_GREEN='\033[5;32m'

# --- Config Paths ---
OV_CONF="/etc/openvpn/server/server.conf"
PLUGIN_CONF="/etc/openvpn/plugin/config.json"

# --- Helper Functions ---
get_port() {
    # Extract the port number from the OpenVPN server configuration
    grep -E '^port ' "$OV_CONF" | awk '{print $2}'
}
get_proto() {
    # Extract the protocol (udp/tcp) from the server configuration
    grep -E '^proto ' "$OV_CONF" | awk '{print $2}'
}
get_radius_ip() {
    # Extract the RADIUS IP from the plugin JSON configuration
    grep -A2 '"Authentication"' "$PLUGIN_CONF" | grep -m1 '"Server"' | \
        sed 's/.*"Server"[[:space:]]*:[[:space:]]*"\([^:]*\).*/\1/'
}
get_radius_secret() {
    # Extract the RADIUS shared secret from the plugin configuration
    grep -A2 '"Authentication"' "$PLUGIN_CONF" | grep -m1 '"Secret"' | \
        sed 's/.*"Secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
}
get_dns() {
    # Retrieve DNS servers pushed to clients
    grep '^push "dhcp-option DNS' "$OV_CONF" | \
        sed 's/.*DNS \([^\"]*\)\".*/\1/' | tr '\n' ',' | sed 's/,$//'
}

is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}
is_valid_ip() {
    [[ "$1" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]
}

restart_openvpn() {
    systemctl restart openvpn-server@server.service
    return $?
}

pause_for_error() {
    echo -e "\n    ${C_RED}✖ $1 Press any key to continue...${C_OFF}"
    read -n 1 -s
}
pause_for_success() {
    echo -e "\n    ${C_GREEN}✔ $1${C_OFF}"
    sleep 2
}

# --- Uninstallation Function ---
# This function removes OpenVPN and all of its configuration.
# It largely mirrors the uninstall path from the installer script.
uninstall_openvpn() {
    clear
    echo -e "\n${C_RED}+================== ${C_BOLD}DANGER ZONE${C_OFF}${C_RED} ==================+${C_OFF}"
    echo -e "${C_YELLOW}| This will ${C_BOLD}COMPLETELY REMOVE${C_OFF}${C_YELLOW} OpenVPN and all    |"
    echo -e "| configurations. This action is ${C_RED}${C_BOLD}IRREVERSIBLE${C_OFF}. |"
    echo -e "${C_RED}+==================================================+${C_OFF}"
    echo
    read -p "  To confirm, please type 'UNINSTALL': " confirmation
    if [[ "$confirmation" != "UNINSTALL" ]]; then
        echo -e "\n${C_GREEN}✔ Uninstall cancelled.${C_OFF}"
        sleep 2
        return
    fi
    echo -e "\n${C_YELLOW}Uninstalling OpenVPN...${C_OFF}"
    # Stop and disable service
    systemctl stop openvpn-server@server.service 2>/dev/null || true
    systemctl disable openvpn-server@server.service 2>/dev/null || true
    # Remove configuration directories
    if [[ -d /etc/openvpn ]]; then
        rm -rf /etc/openvpn
    fi
    if [[ -d /etc/openvpn/server ]]; then
        rm -rf /etc/openvpn/server
    fi
    if [[ -d /etc/openvpn/radius ]]; then
        rm -rf /etc/openvpn/radius
    fi
    if [[ -d /etc/openvpn/plugin ]]; then
        rm -rf /etc/openvpn/plugin
    fi
    if [[ -d /etc/openvpn/server/easy-rsa ]]; then
        rm -rf /etc/openvpn/server/easy-rsa
    fi
    # Clean sysctl forwarding configuration
    if [[ -f /etc/sysctl.d/30-openvpn-forward.conf ]]; then
        rm -f /etc/sysctl.d/30-openvpn-forward.conf
        sysctl --system
    fi
    # Detect OS and remove packages accordingly
    OS=""
    if [[ -e /etc/debian_version ]]; then
        OS=debian
    elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
        OS=centos
    fi
    if [[ "$OS" = 'debian' ]]; then
        apt-get remove --purge -y openvpn openvpn-auth-radius easy-rsa iptables-persistent >/dev/null 2>&1 || true
        apt-get autoremove -y >/dev/null 2>&1 || true
    elif [[ "$OS" = 'centos' ]]; then
        yum remove -y openvpn openvpn-auth-radius easy-rsa iptables-services >/dev/null 2>&1 || true
    fi
    # Remove firewall rules (UFW if active)
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
        for p in udp tcp; do
            # Remove default port 1194 rules as well as current port rules
            old_port=$(get_port)
            ufw delete allow ${old_port}/$p >/dev/null 2>&1 || true
            ufw delete allow 1194/$p >/dev/null 2>&1 || true
            ufw delete allow 1812/$p >/dev/null 2>&1 || true
            ufw delete allow 1813/$p >/dev/null 2>&1 || true
        done
    fi
    # Remove management panel itself
    rm -f /usr/local/bin/ov-p
    echo -e "\n${C_GREEN}✔ OpenVPN has been completely uninstalled.${C_OFF}"
    exit 0
}

# --- Main Menu Loop ---
while true; do
    clear
    if systemctl is-active --quiet openvpn-server@server.service; then
        status_display="${C_BLINK_GREEN}RUNNING${C_OFF}"
    else
        status_display="${C_RED}[STOPPED]${C_OFF}"
    fi
    port=$(get_port)
    proto=$(get_proto)
    radius_ip=$(get_radius_ip)
    dns=$(get_dns)
    echo -e "${C_BOLD}${C_CYAN}+--- OpenVPN Management Panel ---+${C_OFF}"
    echo
    echo -e "${C_BLUE}|---[ Information ]----------------------------------+${C_OFF}"
    echo
    printf "  %-14s : %b\n" "Service Status" "$status_display"
    printf "  %-14s : %b\n" "Port" "${C_CYAN}${port:-N/A}${C_OFF}"
    printf "  %-14s : %b\n" "Protocol" "${C_CYAN}${proto:-N/A}${C_OFF}"
    printf "  %-14s : %b\n" "RADIUS IP" "${C_CYAN}${radius_ip:-N/A}${C_OFF}"
    printf "  %-14s : %b\n" "DNS Servers" "${C_CYAN}${dns:-N/A}${C_OFF}"
    echo
    echo -e "${C_PURPLE}|---[ Configuration ]--------------------------------+${C_OFF}"
    echo
    echo -e "  ${C_CYAN}1)${C_OFF} Edit Port"
    echo -e "  ${C_CYAN}2)${C_OFF} Edit Protocol"
    echo -e "  ${C_CYAN}3)${C_OFF} Edit RADIUS IP"
    echo -e "  ${C_CYAN}4)${C_OFF} Edit RADIUS Secret"
    echo -e "  ${C_CYAN}5)${C_OFF} Change DNS Servers"
    echo
    echo -e "${C_PURPLE}|---[ Management ]-----------------------------------+${C_OFF}"
    echo
    echo -e "  ${C_CYAN}6)${C_OFF} Restart Service"
    echo -e "  ${C_CYAN}7)${C_OFF} ${C_RED}Uninstall OpenVPN${C_OFF}"
    echo
    echo -e "${C_PURPLE}+----------------------------------------------------+${C_OFF}"
    read -p "  Enter your choice [1-7, q for quit]: " choice
    case $choice in
        1)
            # Edit Port
            read -p " -> Enter new Port: " val
            if ! is_valid_port "$val"; then
                pause_for_error "Invalid port."
                continue
            fi
            old_port=$(get_port)
            # Update port directive in server.conf
            sed -i "s/^port .*/port $val/" "$OV_CONF"
            # Update firewall rules via UFW if active
            if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
                for proto_type in udp tcp; do
                    ufw delete allow ${old_port}/$proto_type >/dev/null 2>&1 || true
                    ufw allow ${val}/$proto_type >/dev/null 2>&1 || true
                done
            fi
            if restart_openvpn; then
                pause_for_success "Port updated."
            else
                pause_for_error "Service failed to restart."
            fi
            ;;
        2)
            # Edit Protocol
            read -p " -> Enter protocol (udp/tcp): " val
            val=$(echo "$val" | tr 'A-Z' 'a-z')
            if [[ "$val" != "udp" && "$val" != "tcp" ]]; then
                pause_for_error "Invalid protocol."
                continue
            fi
            # Update proto directive in server.conf
            sed -i "s/^proto .*/proto $val/" "$OV_CONF"
            # Adjust firewall rules through UFW if enabled
            port=$(get_port)
            if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
                # Remove existing rules for both protocols, then add rule for selected protocol
                for proto_type in udp tcp; do
                    ufw delete allow ${port}/$proto_type >/dev/null 2>&1 || true
                done
                ufw allow ${port}/${val} >/dev/null 2>&1 || true
            fi
            if restart_openvpn; then
                pause_for_success "Protocol updated."
            else
                pause_for_error "Service failed to restart."
            fi
            ;;
        3)
            # Edit RADIUS IP
            read -p " -> Enter new RADIUS IP: " val
            if ! is_valid_ip "$val"; then
                pause_for_error "Invalid IP format."
                continue
            fi
            # Update RADIUS IP in plugin config for both auth and accounting
            sed -i -E "s/\"Server\"[[:space:]]*:[[:space:]]*\"[0-9\.]+:1812\"/\"Server\": \"${val}:1812\"/" "$PLUGIN_CONF"
            sed -i -E "s/\"Server\"[[:space:]]*:[[:space:]]*\"[0-9\.]+:1813\"/\"Server\": \"${val}:1813\"/" "$PLUGIN_CONF"
            # Remove existing pushed route lines and append the new route for RADIUS
            sed -i '/^push \"route .* net_gateway\"/d' "$OV_CONF"
            echo "push \"route ${val} 255.255.255.255 net_gateway\"" >> "$OV_CONF"
            if restart_openvpn; then
                pause_for_success "RADIUS IP updated."
            else
                pause_for_error "Service failed to restart."
            fi
            ;;
        4)
            # Edit RADIUS Secret
            read -p " -> Enter new RADIUS Secret: " val
            if [[ -z "$val" ]]; then
                pause_for_error "Secret cannot be empty."
                continue
            fi
            # Update secret fields for both Authentication and Accounting in plugin config
            sed -i -E "s/\"Secret\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"Secret\": \"${val}\"/g" "$PLUGIN_CONF"
            if restart_openvpn; then
                pause_for_success "RADIUS Secret updated."
            else
                pause_for_error "Service failed to restart."
            fi
            ;;
        5)
            # Change DNS Servers
            clear
            echo
            echo -e "  ${C_CYAN}1)${C_OFF} System  ${C_CYAN}2)${C_OFF} Cloudflare  ${C_CYAN}3)${C_OFF} Google  ${C_CYAN}4)${C_OFF} OpenDNS"
            read -p " -> Enter DNS choice: " val
            # Remove existing DNS push statements
            sed -i '/^push "dhcp-option DNS/d' "$OV_CONF"
            case $val in
                1)
                    # Use system resolvers
                    if grep -q "127.0.0.53" "/etc/resolv.conf"; then
                        RESOLVCONF='/run/systemd/resolve/resolv.conf'
                    else
                        RESOLVCONF='/etc/resolv.conf'
                    fi
                    grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read -r line; do
                        echo "push \"dhcp-option DNS $line\"" >> "$OV_CONF"
                    done
                    ;;
                2)
                    echo 'push "dhcp-option DNS 1.1.1.1"' >> "$OV_CONF"
                    echo 'push "dhcp-option DNS 1.0.0.1"' >> "$OV_CONF"
                    ;;
                3)
                    echo 'push "dhcp-option DNS 8.8.8.8"' >> "$OV_CONF"
                    echo 'push "dhcp-option DNS 8.8.4.4"' >> "$OV_CONF"
                    ;;
                4)
                    echo 'push "dhcp-option DNS 208.67.222.222"' >> "$OV_CONF"
                    echo 'push "dhcp-option DNS 208.67.220.220"' >> "$OV_CONF"
                    ;;
                *)
                    pause_for_error "Invalid choice."
                    continue
                    ;;
            esac
            if restart_openvpn; then
                pause_for_success "DNS servers updated."
            else
                pause_for_error "Service failed to restart."
            fi
            ;;
        6)
            # Restart service
            if restart_openvpn; then
                pause_for_success "Service restarted."
            else
                pause_for_error "Service failed to restart."
            fi
            ;;
        7)
            # Uninstall OpenVPN
            uninstall_openvpn
            ;;
        q|Q)
            echo -e "\n    ${C_CYAN}Exiting panel. Goodbye!${C_OFF}"
            break
            ;;
        *)
            pause_for_error "Invalid option."
            ;;
    esac
done
OVPNEOF

# Ensure the management panel is executable
chmod +x /usr/local/bin/ov-p

echo -e "For future management, use the command:"
echo -e "  sudo ov-p"
