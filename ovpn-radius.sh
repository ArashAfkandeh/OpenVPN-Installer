#!/bin/bash

# OpenVPN Bash RADIUS Plugin
# Repository: https://github.com/ArashAfkandeh/OpenVPN-Installer

case "$script_type" in
  user-pass-verify|auth-user-pass-verify) ACTION="auth"; AUTHFILE="$1" ;;
  client-connect) ACTION="acct" ;;
  client-disconnect) ACTION="stop" ;;
  *) ACTION="auth"; AUTHFILE="$1" ;;
esac

CONFIG=/etc/openvpn/plugin/config.json

get_json_value() {
    local key="$1"
    grep -m1 "\"$key\"" "$CONFIG" | sed 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
}

get_auth_server() { grep -A2 '"Authentication"' "$CONFIG" | grep -m1 '"Server"' | sed 's/.*"Server"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'; }
get_auth_secret() { grep -A2 '"Authentication"' "$CONFIG" | grep -m1 '"Secret"' | sed 's/.*"Secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'; }
get_acct_server() { grep -A2 '"Accounting"' "$CONFIG" | grep -m1 '"Server"' | sed 's/.*"Server"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'; }
get_acct_secret() { grep -A2 '"Accounting"' "$CONFIG" | grep -m1 '"Secret"' | sed 's/.*"Secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'; }

RADIUS_AUTH_SERVER=$(get_auth_server)
RADIUS_AUTH_SECRET=$(get_auth_secret)
RADIUS_ACCT_SERVER=$(get_acct_server)
RADIUS_ACCT_SECRET=$(get_acct_secret)
NAS_IP=$(get_json_value IpAddress)
NAS_IDENTIFIER=$(get_json_value Identifier)
RADIUS_SERVER="$RADIUS_AUTH_SERVER"
RADIUS_SECRET="$RADIUS_AUTH_SECRET"
SESSION_DIR=/var/run/ovpn-radius

case "$ACTION" in
  auth)
    if [[ -n "$AUTHFILE" && -f "$AUTHFILE" ]]; then
        username=$(head -n1 "$AUTHFILE")
        password=$(tail -n +2 "$AUTHFILE" | head -n1)
    else
        username="$username"
        password="$password"
        if [[ -z "$username" || -z "$password" ]]; then exit 1; fi
    fi
    calling="$untrusted_ip"
    ATTR="User-Name=\"$username\"\nUser-Password=\"$password\"\n"
    if [[ -n "$calling" ]]; then ATTR+="Calling-Station-Id=$calling\n"; fi
    ATTR+="NAS-IP-Address=$NAS_IP\nNAS-Port-Type=Virtual\nNAS-Identifier=$NAS_IDENTIFIER\nService-Type=Framed-User\nFramed-Protocol=PPP\n"
    
    if echo -e "$ATTR" | /usr/bin/radclient -t 1 -r 1 "$RADIUS_SERVER" auth "$RADIUS_SECRET" 2>&1 | grep -qi "Access-Accept"; then
        exit 0
    else
        exit 1
    fi
    ;;
  acct)
    username="$common_name"
    calling="$untrusted_ip"
    client_ip="$ifconfig_pool_remote_ip"
    session_file="$SESSION_DIR/${username}.session"
    if [[ -s "$session_file" ]]; then session_id=$(cat "$session_file"); else session_id=$(date +%s%N | head -c 10); echo "$session_id" > "$session_file"; fi
    ATTR="Acct-Session-Id=$session_id\nAcct-Status-Type=Start\nUser-Name=$username\n"
    if [[ -n "$calling" ]]; then ATTR+="Calling-Station-Id=$calling\n"; fi
    ATTR+="NAS-IP-Address=$NAS_IP\nNAS-Identifier=$NAS_IDENTIFIER\n"
    if [[ -n "$client_ip" ]]; then ATTR+="Framed-IP-Address=$client_ip\n"; fi
    ATTR+="Service-Type=Framed-User\nFramed-Protocol=PPP\n"
    (echo -e "$ATTR" | /usr/bin/radclient -t 3 -r 1 "$RADIUS_ACCT_SERVER" acct "$RADIUS_ACCT_SECRET" >/dev/null 2>&1) &
    exit 0
    ;;
  stop)
    username="$common_name"
    calling="$untrusted_ip"
    client_ip="$ifconfig_pool_remote_ip"
    session_file="$SESSION_DIR/${username}.session"
    if [[ -s "$session_file" ]]; then session_id=$(cat "$session_file"); rm -f "$session_file"; else session_id=$(date +%s%N | head -c 10); fi
    ATTR="Acct-Session-Id=$session_id\nAcct-Status-Type=Stop\nUser-Name=$username\n"
    if [[ -n "$calling" ]]; then ATTR+="Calling-Station-Id=$calling\n"; fi
    ATTR+="NAS-IP-Address=$NAS_IP\nNAS-Identifier=$NAS_IDENTIFIER\n"
    if [[ -n "$client_ip" ]]; then ATTR+="Framed-IP-Address=$client_ip\n"; fi
    ATTR+="Service-Type=Framed-User\nFramed-Protocol=PPP\n"
    (echo -e "$ATTR" | /usr/bin/radclient -t 3 -r 1 "$RADIUS_ACCT_SERVER" acct "$RADIUS_ACCT_SECRET" >/dev/null 2>&1) &
    exit 0
    ;;
  *) exit 1 ;;
esac
