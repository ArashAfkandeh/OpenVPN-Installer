#!/bin/bash
# OpenVPN Advanced Management Panel
# Repository: https://github.com/ArashAfkandeh/OpenVPN-Installer

# --- UI Color Definitions ---
C_OFF='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m';
C_BLUE='\033[0;34m'; C_PURPLE='\033[0;35m'; C_CYAN='\033[0;36m'; C_BOLD='\033[1m';
C_BLINK_GREEN='\033[5;32m'

# --- Pre-execution Check ---
if [[ $(id -u) -ne 0 ]]; then echo -e "${C_RED}✖ Please run as root.${C_OFF}"; exit 1; fi

OV_CONF="/etc/openvpn/server/server.conf"
PLUGIN_CONF="/etc/openvpn/plugin/config.json"

get_port() { grep -E '^port ' "$OV_CONF" | awk '{print $2}'; }
get_proto() { grep -E '^proto ' "$OV_CONF" | awk '{print $2}'; }
get_radius_ip() { grep -A2 '"Authentication"' "$PLUGIN_CONF" | grep -m1 '"Server"' | sed 's/.*"Server"[[:space:]]*:[[:space:]]*"\([^:]*\).*/\1/'; }
get_radius_secret() { grep -A2 '"Authentication"' "$PLUGIN_CONF" | grep -m1 '"Secret"' | sed 's/.*"Secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'; }
get_dns() { grep '^push "dhcp-option DNS' "$OV_CONF" | sed 's/.*DNS \([^\"]*\)\".*/\1/' | tr '\n' ',' | sed 's/,$//'; }

is_valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
restart_openvpn() { systemctl restart openvpn-server@server.service; return $?; }
pause_for_error() { echo -e "\n    ${C_RED}✖ $1 Press any key to continue...${C_OFF}"; read -n 1 -s; }
pause_for_success() { echo -e "\n    ${C_GREEN}✔ $1${C_OFF}"; sleep 2; }

uninstall_openvpn() {
    clear; echo -e "\n${C_RED}+================== ${C_BOLD}DANGER ZONE${C_OFF}${C_RED} ==================+${C_OFF}"
    echo -e "${C_YELLOW}| This will ${C_BOLD}COMPLETELY REMOVE${C_OFF}${C_YELLOW} OpenVPN.            |"; echo -e "| This action is ${C_RED}${C_BOLD}IRREVERSIBLE${C_OFF}.                 |"; echo -e "${C_RED}+==================================================+${C_OFF}\n"
    read -p "  Type 'UNINSTALL' to confirm: " confirmation
    if [[ "$confirmation" != "UNINSTALL" ]]; then echo -e "\n${C_GREEN}✔ Cancelled.${C_OFF}"; sleep 2; return; fi
    
    echo -e "\n${C_YELLOW}Uninstalling OpenVPN...${C_OFF}"
    systemctl stop openvpn-server@server.service 2>/dev/null || true
    systemctl disable openvpn-server@server.service 2>/dev/null || true
    systemctl stop openvpn-radius-interim.timer 2>/dev/null || true
    systemctl disable openvpn-radius-interim.timer 2>/dev/null || true
    rm -f /etc/systemd/system/openvpn-radius-interim.*
    rm -rf /etc/openvpn /var/log/openvpn* /etc/sysctl.d/30-openvpn-forward.conf
    
    OS=""; [[ -e /etc/debian_version ]] && OS=debian || OS=centos
    if [[ "$OS" = 'debian' ]]; then apt-get remove --purge -y openvpn openvpn-auth-radius easy-rsa iptables-persistent >/dev/null 2>&1 || true; apt-get autoremove -y >/dev/null 2>&1 || true
    else yum remove -y openvpn openvpn-auth-radius easy-rsa iptables-services >/dev/null 2>&1 || true; fi
    
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
        for p in udp tcp; do ufw delete allow $(get_port)/$p >/dev/null 2>&1 || true; ufw delete allow 1194/$p >/dev/null 2>&1 || true; ufw delete allow 1812/$p >/dev/null 2>&1 || true; ufw delete allow 1813/$p >/dev/null 2>&1 || true; done
    fi
    rm -f /usr/local/bin/ov-p
    systemctl daemon-reload
    echo -e "\n${C_GREEN}✔ OpenVPN completely uninstalled.${C_OFF}"; exit 0
}

while true; do
    clear
    if systemctl is-active --quiet openvpn-server@server.service; then status_display="${C_BLINK_GREEN}RUNNING${C_OFF}"; else status_display="${C_RED}[STOPPED]${C_OFF}"; fi
    
    port=$(get_port); proto=$(get_proto); radius_ip=$(get_radius_ip); dns=$(get_dns)
    echo -e "${C_BOLD}${C_CYAN}+--- OpenVPN Management Panel ---+${C_OFF}\n${C_BLUE}|---[ Information ]----------------------------------+${C_OFF}\n"
    printf "  %-14s : %b\n" "Service Status" "$status_display"
    printf "  %-14s : %b\n" "Port" "${C_CYAN}${port:-N/A}${C_OFF}"
    printf "  %-14s : %b\n" "Protocol" "${C_CYAN}${proto:-N/A}${C_OFF}"
    printf "  %-14s : %b\n" "RADIUS IP" "${C_CYAN}${radius_ip:-N/A}${C_OFF}"
    printf "  %-14s : %b\n" "DNS Servers" "${C_CYAN}${dns:-N/A}${C_OFF}"; echo
    
    echo -e "${C_PURPLE}|---[ Configuration ]--------------------------------+${C_OFF}\n"
    echo -e "  ${C_CYAN}1)${C_OFF} Edit Port       ${C_CYAN}2)${C_OFF} Edit Protocol"
    echo -e "  ${C_CYAN}3)${C_OFF} Edit RADIUS IP  ${C_CYAN}4)${C_OFF} Edit RADIUS Secret"
    echo -e "  ${C_CYAN}5)${C_OFF} Change DNS      \n"
    
    echo -e "${C_PURPLE}|---[ Management ]-----------------------------------+${C_OFF}\n"
    echo -e "  ${C_CYAN}6)${C_OFF} View Live Logs"
    echo -e "  ${C_CYAN}7)${C_OFF} Restart Service"
    echo -e "  ${C_CYAN}8)${C_OFF} Update Panel & Plugins from GitHub"
    echo -e "  ${C_CYAN}9)${C_OFF} ${C_RED}Uninstall OpenVPN${C_OFF}\n"
    echo -e "${C_PURPLE}+----------------------------------------------------+${C_OFF}"
    
    read -p "  Enter your choice [1-9, q for quit]: " choice
    case $choice in
        1) 
            read -p " -> Enter new Port: " val; if ! is_valid_port "$val"; then pause_for_error "Invalid port."; continue; fi
            old_port=$(get_port); sed -i "s/^port .*/port $val/" "$OV_CONF"
            if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then for p in udp tcp; do ufw delete allow ${old_port}/$p >/dev/null 2>&1 || true; ufw allow ${val}/$p >/dev/null 2>&1 || true; done; fi
            if restart_openvpn; then pause_for_success "Port updated."; else pause_for_error "Failed to restart."; fi ;;
        2) 
            read -p " -> Enter protocol (udp/tcp): " val; val=$(echo "$val" | tr 'A-Z' 'a-z'); if [[ "$val" != "udp" && "$val" != "tcp" ]]; then pause_for_error "Invalid protocol."; continue; fi
            sed -i "s/^proto .*/proto $val/" "$OV_CONF"; port=$(get_port)
            if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then for p in udp tcp; do ufw delete allow ${port}/$p >/dev/null 2>&1 || true; done; ufw allow ${port}/${val} >/dev/null 2>&1 || true; fi
            if restart_openvpn; then pause_for_success "Protocol updated."; else pause_for_error "Failed to restart."; fi ;;
        3) 
            read -p " -> Enter new RADIUS IP: " val; sed -i -E "s/\"Server\"[[:space:]]*:[[:space:]]*\"[0-9\.]+:1812\"/\"Server\": \"${val}:1812\"/" "$PLUGIN_CONF"; sed -i -E "s/\"Server\"[[:space:]]*:[[:space:]]*\"[0-9\.]+:1813\"/\"Server\": \"${val}:1813\"/" "$PLUGIN_CONF"
            sed -i '/^push \"route .* net_gateway\"/d' "$OV_CONF"; echo "push \"route ${val} 255.255.255.255 net_gateway\"" >> "$OV_CONF"
            if restart_openvpn; then pause_for_success "RADIUS IP updated."; else pause_for_error "Failed to restart."; fi ;;
        4) 
            read -s -p " -> Enter new RADIUS Secret: " val; echo; if [[ -z "$val" ]]; then pause_for_error "Secret cannot be empty."; continue; fi
            sed -i -E "s/\"Secret\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"Secret\": \"${val}\"/g" "$PLUGIN_CONF"
            if restart_openvpn; then pause_for_success "RADIUS Secret updated."; else pause_for_error "Failed to restart."; fi ;;
        5) 
            clear; echo -e "\n  ${C_CYAN}1)${C_OFF} System default  ${C_CYAN}2)${C_OFF} Google  ${C_CYAN}3)${C_OFF} Cloudflare  ${C_CYAN}4)${C_OFF} OpenDNS"; read -p " -> Enter DNS choice: " val
            sed -i '/^push "dhcp-option DNS/d' "$OV_CONF"
            case $val in 
                1) if grep -q "127.0.0.53" "/etc/resolv.conf"; then RESOLVCONF='/run/systemd/resolve/resolv.conf'; else RESOLVCONF='/etc/resolv.conf'; fi; grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read -r line; do echo "push \"dhcp-option DNS $line\"" >> "$OV_CONF"; done ;; 
                2) echo -e 'push "dhcp-option DNS 8.8.8.8"\npush "dhcp-option DNS 8.8.4.4"' >> "$OV_CONF" ;; 
                3) echo -e 'push "dhcp-option DNS 1.1.1.1"\npush "dhcp-option DNS 1.0.0.1"' >> "$OV_CONF" ;; 
                4) echo -e 'push "dhcp-option DNS 208.67.222.222"\npush "dhcp-option DNS 208.67.220.220"' >> "$OV_CONF" ;; 
                *) pause_for_error "Invalid choice."; continue ;; 
            esac
            if restart_openvpn; then pause_for_success "DNS updated."; else pause_for_error "Failed to restart."; fi ;;
        6) 
            clear; echo -e "${C_YELLOW}--- Live Logs (Press Ctrl+C to exit) ---${C_OFF}\n"; journalctl -u openvpn-server@server.service -f --output=cat; echo ;;
        7) 
            if restart_openvpn; then pause_for_success "Service restarted."; else pause_for_error "Failed to restart."; fi ;;
        8)
            echo "  -> Fetching latest updates from GitHub..."
            PANEL_URL="https://raw.githubusercontent.com/ArashAfkandeh/OpenVPN-Installer/main/management_panel.sh"
            RADIUS_URL="https://raw.githubusercontent.com/ArashAfkandeh/OpenVPN-Installer/main/ovpn-radius.sh"
            if curl -sSL "$PANEL_URL" -o /usr/local/bin/ov-p && curl -sSL "$RADIUS_URL" -o /etc/openvpn/plugin/ovpn-radius.sh; then
                chmod +x /usr/local/bin/ov-p /etc/openvpn/plugin/ovpn-radius.sh
                systemctl restart openvpn-server@server.service
                pause_for_success "Successfully updated! Restarting panel..."
                exec /usr/local/bin/ov-p
            else pause_for_error "Failed to download update."; fi ;;
        9) uninstall_openvpn ;;
        q|Q) echo -e "\n    ${C_CYAN}Exiting panel. Goodbye!${C_OFF}"; break ;;
        *) pause_for_error "Invalid option." ;;
    esac
done
