#!/bin/bash
# OpenVPN Bash RADIUS Plugin
# Repository: https://github.com/ArashAfkandeh/OpenVPN-Installer

ACTION=""
if [ "$1" == "interim" ]; then
    ACTION="interim"
else
    case "$script_type" in
      user-pass-verify|auth-user-pass-verify) ACTION="auth"; AUTHFILE="$1" ;;
      client-connect) ACTION="acct" ;;
      client-disconnect) ACTION="stop" ;;
      *) ACTION="auth"; AUTHFILE="$1" ;;
    esac
fi

CONFIG=/etc/openvpn/plugin/config.json
SESSION_DIR=/var/run/ovpn-radius

get_json_value() { local key="$1"; grep -m1 "\"$key\"" "$CONFIG" | sed 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'; }
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

case "$ACTION" in
  auth)
    if [[ -n "$AUTHFILE" && -f "$AUTHFILE" ]]; then
        username=$(head -n1 "$AUTHFILE"); password=$(tail -n +2 "$AUTHFILE" | head -n1)
    else
        if [[ -z "$username" || -z "$password" ]]; then exit 1; fi
    fi
    calling="$untrusted_ip"
    ATTR="User-Name=\"$username\"\nUser-Password=\"$password\"\n"
    if [[ -n "$calling" ]]; then ATTR+="Calling-Station-Id=$calling\n"; fi
    ATTR+="NAS-IP-Address=$NAS_IP\nNAS-Port-Type=Virtual\nNAS-Identifier=$NAS_IDENTIFIER\nService-Type=Framed-User\nFramed-Protocol=PPP\n"
    
    if echo -e "$ATTR" | /usr/bin/radclient -t 1 -r 1 "$RADIUS_AUTH_SERVER" auth "$RADIUS_AUTH_SECRET" 2>&1 | grep -qi "Access-Accept"; then exit 0; else exit 1; fi
    ;;

  acct)
    username="$common_name"
    calling="$untrusted_ip"
    client_ip="$ifconfig_pool_remote_ip"
    session_file="$SESSION_DIR/${username}.session"
    
    # Generate a robust unique Session-ID
    session_id=$(head -c 16 /dev/urandom | md5sum | head -c 16)
    echo "$session_id" > "$session_file"
    
    ATTR="Acct-Session-Id=$session_id\nAcct-Status-Type=Start\nUser-Name=$username\nAcct-Authentic=RADIUS\nAcct-Delay-Time=0\n"
    if [[ -n "$calling" ]]; then ATTR+="Calling-Station-Id=$calling\n"; fi
    ATTR+="NAS-IP-Address=$NAS_IP\nNAS-Identifier=$NAS_IDENTIFIER\n"
    if [[ -n "$client_ip" ]]; then ATTR+="Framed-IP-Address=$client_ip\n"; fi
    ATTR+="Service-Type=Framed-User\nFramed-Protocol=PPP\n"
    ATTR+="Acct-Input-Octets=0\nAcct-Output-Octets=0\nAcct-Input-Gigawords=0\nAcct-Output-Gigawords=0\n"
    
    (echo -e "$ATTR" | /usr/bin/radclient -t 3 -r 1 "$RADIUS_ACCT_SERVER" acct "$RADIUS_ACCT_SECRET" >/dev/null 2>&1) &
    exit 0
    ;;

  stop)
    username="$common_name"
    calling="$untrusted_ip"
    client_ip="$ifconfig_pool_remote_ip"
    
    # Safely get variables, default to 0
    bytes_in="${bytes_received:-0}"
    bytes_out="${bytes_sent:-0}"
    session_time="${time_duration:-0}"
    
    if [[ ! "$bytes_in" =~ ^[0-9]+$ ]]; then bytes_in=0; fi
    if [[ ! "$bytes_out" =~ ^[0-9]+$ ]]; then bytes_out=0; fi
    if [[ ! "$session_time" =~ ^[0-9]+$ ]]; then session_time=0; fi
    
    session_file="$SESSION_DIR/${username}.session"
    if [[ -s "$session_file" ]]; then session_id=$(cat "$session_file"); rm -f "$session_file"; else session_id=$(head -c 16 /dev/urandom | md5sum | head -c 16); fi
    
    in_octets=$((bytes_in % 4294967296)); in_giga=$((bytes_in / 4294967296))
    out_octets=$((bytes_out % 4294967296)); out_giga=$((bytes_out / 4294967296))

    ATTR="Acct-Session-Id=$session_id\nAcct-Status-Type=Stop\nUser-Name=$username\nAcct-Authentic=RADIUS\nAcct-Delay-Time=0\n"
    if [[ -n "$calling" ]]; then ATTR+="Calling-Station-Id=$calling\n"; fi
    ATTR+="NAS-IP-Address=$NAS_IP\nNAS-Identifier=$NAS_IDENTIFIER\n"
    if [[ -n "$client_ip" ]]; then ATTR+="Framed-IP-Address=$client_ip\n"; fi
    ATTR+="Service-Type=Framed-User\nFramed-Protocol=PPP\n"
    ATTR+="Acct-Session-Time=$session_time\n"
    ATTR+="Acct-Input-Octets=$in_octets\nAcct-Output-Octets=$out_octets\n"
    ATTR+="Acct-Input-Gigawords=$in_giga\nAcct-Output-Gigawords=$out_giga\n"
    
    (echo -e "$ATTR" | /usr/bin/radclient -t 3 -r 1 "$RADIUS_ACCT_SERVER" acct "$RADIUS_ACCT_SECRET" >/dev/null 2>&1) &
    exit 0
    ;;

  interim)
    STATUS_FILE=/var/log/openvpn/openvpn-status.log
    if [ ! -f "$STATUS_FILE" ]; then exit 0; fi
    
    # FIXED: Extract Field 8 (time_t) instead of Field 9 (Text Date) to prevent arithmetic failure
    awk -F ',' '$1 == "CLIENT_LIST" {print $2, $3, $4, $6, $7, $8}' "$STATUS_FILE" | while read -r username real_ip client_ip bytes_in bytes_out conn_time; do
        session_file="$SESSION_DIR/${username}.session"
        if [ -f "$session_file" ]; then
            session_id=$(cat "$session_file")
            real_ip_clean="${real_ip%:*}"
            
            current_time=$(date +%s)
            if [[ ! "$conn_time" =~ ^[0-9]+$ ]]; then conn_time=$current_time; fi
            
            session_time=$((current_time - conn_time))
            if [ "$session_time" -lt 0 ]; then session_time=0; fi
            
            if [[ ! "$bytes_in" =~ ^[0-9]+$ ]]; then bytes_in=0; fi
            if [[ ! "$bytes_out" =~ ^[0-9]+$ ]]; then bytes_out=0; fi
            
            in_octets=$((bytes_in % 4294967296)); in_giga=$((bytes_in / 4294967296))
            out_octets=$((bytes_out % 4294967296)); out_giga=$((bytes_out / 4294967296))

            ATTR="Acct-Session-Id=$session_id\nAcct-Status-Type=Alive\nUser-Name=$username\nAcct-Authentic=RADIUS\nAcct-Delay-Time=0\nCalling-Station-Id=$real_ip_clean\n"
            ATTR+="NAS-IP-Address=$NAS_IP\nNAS-Identifier=$NAS_IDENTIFIER\nFramed-IP-Address=$client_ip\n"
            ATTR+="Service-Type=Framed-User\nFramed-Protocol=PPP\n"
            ATTR+="Acct-Session-Time=$session_time\n"
            ATTR+="Acct-Input-Octets=$in_octets\nAcct-Output-Octets=$out_octets\n"
            ATTR+="Acct-Input-Gigawords=$in_giga\nAcct-Output-Gigawords=$out_giga\n"

            # Execute synchronously to guarantee Systemd Timer allows the process to finish
            echo -e "$ATTR" | /usr/bin/radclient -t 2 -r 1 "$RADIUS_ACCT_SERVER" acct "$RADIUS_ACCT_SECRET" >/dev/null 2>&1
        fi
    done
    exit 0
    ;;
  *) exit 1 ;;
esac
