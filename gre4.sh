#!/usr/bin/env bash
set -euo pipefail

# gre4.sh - GRE tunnel + (Iran: DNAT only one port) + (Kharej: UFW restrict + conntrack tune)
# Repo: https://github.com/vahid162/gre-4
# Author: vahid162 (modified with hardening + port prompt)

TUN_IF="GRE"
IRAN_TUN_CIDR="172.16.1.1/30"
KHAREJ_TUN_CIDR="172.16.1.2/30"
CONF_FILE="/etc/gre4.conf"
APPLY_SCRIPT="/usr/local/sbin/gre4-apply.sh"
UNIT_FILE="/etc/systemd/system/gre4.service"

log()  { echo -e "\e[1;32m[+]\e[0m $*"; }
warn() { echo -e "\e[1;33m[!]\e[0m $*"; }
err()  { echo -e "\e[1;31m[-]\e[0m $*" >&2; }

need_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    err "This script must be run as root. Example: sudo bash gre4.sh"
    exit 1
  fi
}

validate_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r -a o <<<"$ip"
  for x in "${o[@]}"; do
    [[ "$x" -ge 0 && "$x" -le 255 ]] || return 1
  done
  return 0
}

validate_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]{1,5}$ ]] || return 1
  [[ "$p" -ge 1 && "$p" -le 65535 ]] || return 1
  return 0
}


normalize_ports_list() {
  local raw="$1"
  local cleaned token
  cleaned=$(echo "$raw" | tr ' ' ',' | tr -s ',')
  cleaned="${cleaned#,}"
  cleaned="${cleaned%,}"

  [[ -n "$cleaned" ]] || return 1

  local -A seen=()
  local out=()
  IFS=',' read -r -a tokens <<<"$cleaned"
  for token in "${tokens[@]}"; do
    [[ -n "$token" ]] || continue
    validate_port "$token" || return 1
    if [[ -z "${seen[$token]:-}" ]]; then
      out+=("$token")
      seen[$token]=1
    fi
  done

  [[ ${#out[@]} -gt 0 ]] || return 1
  (IFS=','; echo "${out[*]}")
}

prompt_default() {
  local prompt="$1" default="$2" var
  read -r -p "$prompt [$default]: " var || true
  if [[ -z "${var:-}" ]]; then
    echo "$default"
  else
    echo "$var"
  fi
}

load_current_conf() {
  [[ -f "$CONF_FILE" ]] || return 1
  # shellcheck disable=SC1090
  source "$CONF_FILE"
  SERVICE_PORTS="${SERVICE_PORTS:-${SERVICE_PORT:-}}"
  [[ -n "${SERVICE_PORTS:-}" ]] || return 1
  return 0
}

service_installed() {
  [[ -f "$UNIT_FILE" && -f "$APPLY_SCRIPT" ]]
}

show_current_settings() {
  if ! load_current_conf; then
    warn "No valid config found at $CONF_FILE"
    return 1
  fi

  echo
  echo "Current settings:"
  echo "  ROLE=$ROLE"
  echo "  LOCAL_PUBLIC_IP=$LOCAL_PUBLIC_IP"
  echo "  PEER_PUBLIC_IP=$PEER_PUBLIC_IP"
  echo "  SERVICE_PORTS=$SERVICE_PORTS"
  echo "  ALLOW_UDP=$ALLOW_UDP"
  echo
}

restart_service() {
  systemctl daemon-reload
  systemctl restart gre4.service
  log "Service restarted: gre4.service"
}

show_status() {
  if load_current_conf; then
    show_current_settings || true
  else
    warn "Config not found or invalid: $CONF_FILE"
  fi

  echo "Service status:"
  systemctl --no-pager --full status gre4.service 2>/dev/null || warn "gre4.service not installed/active"

  echo
  echo "Tunnel status:"
  ip a show "$TUN_IF" 2>/dev/null || warn "Tunnel interface $TUN_IF not found"
}

manage_ports_add() {
  load_current_conf || { err "Cannot load current config."; return 1; }
  local add normalized merged
  add=$(prompt_default "Ports to add (comma-separated)" "")
  normalized=$(normalize_ports_list "$add") || { err "Invalid port list."; return 1; }
  merged=$(normalize_ports_list "${SERVICE_PORTS},${normalized}") || { err "Failed to merge ports."; return 1; }
  write_conf "$ROLE" "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$merged" "$ALLOW_UDP"
  restart_service
}

manage_ports_remove() {
  load_current_conf || { err "Cannot load current config."; return 1; }
  local remove normalized p result=""
  remove=$(prompt_default "Ports to remove (comma-separated)" "")
  normalized=$(normalize_ports_list "$remove") || { err "Invalid port list."; return 1; }

  local -A rm=()
  IFS=',' read -r -a to_remove <<<"$normalized"
  for p in "${to_remove[@]}"; do rm["$p"]=1; done

  IFS=',' read -r -a current <<<"$SERVICE_PORTS"
  for p in "${current[@]}"; do
    if [[ -z "${rm[$p]:-}" ]]; then
      if [[ -z "$result" ]]; then result="$p"; else result="$result,$p"; fi
    fi
  done

  result="${result#,}"
  if [[ -z "$result" ]]; then
    err "Cannot remove all ports. At least one port must remain."
    return 1
  fi

  result=$(normalize_ports_list "$result") || { err "Resulting port list is invalid."; return 1; }
  write_conf "$ROLE" "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$result" "$ALLOW_UDP"
  restart_service
}

manage_replace_ports() {
  load_current_conf || { err "Cannot load current config."; return 1; }
  local ports
  ports=$(prompt_default "New service port(s), comma-separated" "$SERVICE_PORTS")
  ports=$(normalize_ports_list "$ports") || { err "Invalid port list."; return 1; }
  write_conf "$ROLE" "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$ports" "$ALLOW_UDP"
  restart_service
}

manage_change_ips() {
  load_current_conf || { err "Cannot load current config."; return 1; }
  local local_ip peer_ip
  local_ip=$(prompt_default "Local public IP" "$LOCAL_PUBLIC_IP")
  validate_ipv4 "$local_ip" || { err "Invalid local public IP."; return 1; }
  peer_ip=$(prompt_default "Peer public IP" "$PEER_PUBLIC_IP")
  validate_ipv4 "$peer_ip" || { err "Invalid peer public IP."; return 1; }
  write_conf "$ROLE" "$local_ip" "$peer_ip" "$SERVICE_PORTS" "$ALLOW_UDP"
  restart_service
}

manage_toggle_udp() {
  load_current_conf || { err "Cannot load current config."; return 1; }
  local udp
  udp=$(prompt_default "ALLOW_UDP (yes/no)" "$ALLOW_UDP")
  [[ "$udp" == "yes" || "$udp" == "no" ]] || { err "Only yes or no is allowed"; return 1; }
  write_conf "$ROLE" "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$SERVICE_PORTS" "$udp"
  restart_service
}

manage_menu() {
  service_installed || { err "gre4 is not installed yet."; return 1; }

  while true; do
    echo
    echo "Manage menu:"
    echo "1) Show current settings"
    echo "2) Add port(s)"
    echo "3) Remove port(s)"
    echo "4) Replace all ports"
    echo "5) Change local/peer IPs"
    echo "6) Toggle UDP (yes/no)"
    echo "7) Apply now (restart service)"
    echo "8) Status"
    echo "9) Back"
    echo
    local c
    read -r -p "Enter choice (1-9): " c
    case "$c" in
      1) show_current_settings ;;
      2) manage_ports_add ;;
      3) manage_ports_remove ;;
      4) manage_replace_ports ;;
      5) manage_change_ips ;;
      6) manage_toggle_udp ;;
      7) restart_service ;;
      8) show_status ;;
      9) break ;;
      *) err "Invalid option." ;;
    esac
  done
}

ensure_cmd() {
  local c="$1"
  command -v "$c" >/dev/null 2>&1 || {
    err "Required command '$c' was not found."
    exit 1
  }
}

write_conf() {
  local role="$1" local_pub="$2" peer_pub="$3" ports="$4" allow_udp="$5"
  cat > "$CONF_FILE" <<EOF
ROLE="$role"
LOCAL_PUBLIC_IP="$local_pub"
PEER_PUBLIC_IP="$peer_pub"
SERVICE_PORTS="$ports"
ALLOW_UDP="$allow_udp"
TUN_IF="$TUN_IF"
IRAN_TUN_CIDR="$IRAN_TUN_CIDR"
KHAREJ_TUN_CIDR="$KHAREJ_TUN_CIDR"
EOF
  chmod 600 "$CONF_FILE"
  log "Config saved to $CONF_FILE"
}

install_apply_script() {
  cat > "$APPLY_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="/etc/gre4.conf"
[[ -f "$CONF_FILE" ]] || { echo "Missing $CONF_FILE"; exit 1; }
# shellcheck disable=SC1090
source "$CONF_FILE"

# Backward compatibility with old config key
SERVICE_PORTS="${SERVICE_PORTS:-${SERVICE_PORT:-}}"
[[ -n "${SERVICE_PORTS:-}" ]] || { echo "Missing SERVICE_PORTS in $CONF_FILE"; exit 1; }

log()  { echo -e "\e[1;32m[+]\e[0m $*"; }
warn() { echo -e "\e[1;33m[!]\e[0m $*"; }
err()  { echo -e "\e[1;31m[-]\e[0m $*" >&2; }

ensure_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Missing command: $1"; exit 1; }; }

# iptables helpers (idempotent)
ipt_add() {
  # usage: ipt_add <table> <chain> <rule...>
  local table="$1"; shift
  local chain="$1"; shift
  if iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
    return 0
  fi
  iptables -t "$table" -A "$chain" "$@"
}

ipt_del_all() {
  # delete while exists
  local table="$1"; shift
  local chain="$1"; shift
  while iptables -t "$table" -C "$chain" "$@" 2>/dev/null; do
    iptables -t "$table" -D "$chain" "$@" || true
  done
}

sysctl_apply_file() {
  local file="$1"
  sysctl -p "$file" >/dev/null
}

tune_forwarding() {
  local f="/etc/sysctl.d/99-gre4-forward.conf"
  cat > "$f" <<CONF
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
CONF
  sysctl_apply_file "$f"
}

tune_conntrack_if_kharej() {
  # Only on kharej role (protects UFW + heavy inbound scans)
  [[ "$ROLE" == "kharej" ]] || return 0

  local mem_kb mem_mb target
  mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  mem_mb=$((mem_kb/1024))

  # Conservative values for low RAM (e.g. 1GB)
  if [[ "$mem_mb" -ge 2048 ]]; then
    target=262144
  elif [[ "$mem_mb" -ge 1024 ]]; then
    target=131072
  else
    target=65536
  fi

  local f="/etc/sysctl.d/99-gre4-conntrack.conf"
  cat > "$f" <<CONF
net.netfilter.nf_conntrack_max=$target
CONF
  sysctl_apply_file "$f"
  log "conntrack tuned: nf_conntrack_max=$target"
}

setup_gre() {
  ensure_cmd ip

  # recreate GRE safely
  if ip link show "$TUN_IF" >/dev/null 2>&1; then
    ip tunnel del "$TUN_IF" 2>/dev/null || true
  fi

  if [[ "$ROLE" == "iran" ]]; then
    ip tunnel add "$TUN_IF" mode gre remote "$PEER_PUBLIC_IP" local "$LOCAL_PUBLIC_IP"
    ip addr add "$IRAN_TUN_CIDR" dev "$TUN_IF"
  else
    ip tunnel add "$TUN_IF" mode gre remote "$PEER_PUBLIC_IP" local "$LOCAL_PUBLIC_IP"
    ip addr add "$KHAREJ_TUN_CIDR" dev "$TUN_IF"
  fi

  ip link set "$TUN_IF" mtu 1420
  ip link set "$TUN_IF" up

  log "GRE up: $TUN_IF local=$LOCAL_PUBLIC_IP remote=$PEER_PUBLIC_IP"
}

setup_iran_nat() {
  [[ "$ROLE" == "iran" ]] || return 0

  ensure_cmd iptables

  # Backup current rules (best-effort)
  iptables-save > "/root/iptables.backup.gre4.$(date +%F_%H%M%S).txt" 2>/dev/null || true

  # Remove old wide DNAT rules if present (the old bug)
  ipt_del_all nat PREROUTING -p tcp --dport 1:65535 -j DNAT --to-destination 172.16.1.2:1-65535
  ipt_del_all nat PREROUTING -p udp --dport 1:65535 -j DNAT --to-destination 172.16.1.2:1-65535

  # Remove old per-port rules to avoid duplicates
  local p
  IFS=',' read -r -a ports <<<"$SERVICE_PORTS"
  for p in "${ports[@]}"; do
    ipt_del_all nat PREROUTING -p tcp --dport "$p" -j DNAT --to-destination "172.16.1.2:${p}"
    ipt_del_all nat PREROUTING -p udp --dport "$p" -j DNAT --to-destination "172.16.1.2:${p}"
  done

  # Add selected port(s)
  for p in "${ports[@]}"; do
    ipt_add nat PREROUTING -p tcp --dport "$p" -j DNAT --to-destination "172.16.1.2:${p}"
    if [[ "$ALLOW_UDP" == "yes" ]]; then
      ipt_add nat PREROUTING -p udp --dport "$p" -j DNAT --to-destination "172.16.1.2:${p}"
    fi
  done

  # MASQUERADE only toward GRE and only to kharej tunnel IP
  # Do NOT wipe global MASQUERADE rules; only enforce our specific rule.
  ipt_add nat POSTROUTING -o "$TUN_IF" -d 172.16.1.2/32 -j MASQUERADE

  # Ensure FORWARD allows the DNATed traffic (safer if policies change)
  ipt_add filter FORWARD -i "$TUN_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  for p in "${ports[@]}"; do
    ipt_add filter FORWARD -o "$TUN_IF" -p tcp -d 172.16.1.2/32 --dport "$p" -j ACCEPT
    if [[ "$ALLOW_UDP" == "yes" ]]; then
      ipt_add filter FORWARD -o "$TUN_IF" -p udp -d 172.16.1.2/32 --dport "$p" -j ACCEPT
    fi
  done

  log "Iran NAT: DNAT selected port(s) $SERVICE_PORTS -> 172.16.1.2:(same ports)"
}

ufw_is_active() {
  command -v ufw >/dev/null 2>&1 || return 1
  ufw status 2>/dev/null | head -n1 | grep -qi "Status: active"
}

ufw_allow_gre_proto47() {
  # UFW doesn't have a simple "port" for GRE; safest is to add protocol 47 rules in before.rules with src/dst restriction
  # Ref: AskUbuntu method (proto 47 in ufw-before-input/output) with source restriction. (We do it automatically.)
  local before="/etc/ufw/before.rules"
  [[ -f "$before" ]] || return 0

  local begin="# gre4.sh BEGIN"
  local end="# gre4.sh END"
  local rule_in="-A ufw-before-input -p 47 -s ${PEER_PUBLIC_IP} -d ${LOCAL_PUBLIC_IP} -j ACCEPT"
  local rule_out="-A ufw-before-output -p 47 -s ${LOCAL_PUBLIC_IP} -d ${PEER_PUBLIC_IP} -j ACCEPT"

  # Remove old block if exists
  if grep -qF "$begin" "$before"; then
    awk -v b="$begin" -v e="$end" '
      $0==b{skip=1;next}
      $0==e{skip=0;next}
      !skip{print}
    ' "$before" > "${before}.tmp"
    mv "${before}.tmp" "$before"
  fi

  # Insert block before final COMMIT of filter table (best-effort: before last line "COMMIT")
  awk -v b="$begin" -v e="$end" -v rin="$rule_in" -v rout="$rule_out" '
    { lines[NR]=$0 }
    END {
      # find last COMMIT
      c=0
      for(i=NR;i>=1;i--) if(lines[i]=="COMMIT"){ c=i; break }
      if(c==0){
        for(i=1;i<=NR;i++) print lines[i]
        exit
      }
      for(i=1;i<c;i++) print lines[i]
      print b
      print rin
      print rout
      print e
      print "COMMIT"
      for(i=c+1;i<=NR;i++) print lines[i]
    }
  ' "$before" > "${before}.tmp"
  mv "${before}.tmp" "$before"
}

ufw_remove_gre_proto47_block() {
  local before="/etc/ufw/before.rules"
  [[ -f "$before" ]] || return 0

  local begin="# gre4.sh BEGIN"
  local end="# gre4.sh END"

  if grep -qF "$begin" "$before"; then
    awk -v b="$begin" -v e="$end" '
      $0==b{skip=1;next}
      $0==e{skip=0;next}
      !skip{print}
    ' "$before" > "${before}.tmp"
    mv "${before}.tmp" "$before"
  fi
}

ufw_delete_public_port_proto_rules() {
  # delete any numbered public rule containing "<port>/<proto>" (v4 & v6)
  local port="$1" proto="$2"
  mapfile -t nums < <(ufw status numbered | sed -n "s/^\\[\\s*\\([0-9]\\+\\)\\].*\\b${port}\\/${proto}\\b.*/\\1/p" | sort -rn)
  for n in "${nums[@]}"; do
    yes | ufw delete "$n" >/dev/null
  done
}

setup_kharej_ufw() {
  [[ "$ROLE" == "kharej" ]] || return 0
  ufw_is_active || return 0

  log "UFW active: hardening rules for GRE + port(s) $SERVICE_PORTS"

  # 1) Ensure GRE proto47 allowed only from peer public IP
  ufw_allow_gre_proto47

  # 2) Remove public allow for service port(s) (if any)
  local p
  IFS=',' read -r -a ports <<<"$SERVICE_PORTS"
  for p in "${ports[@]}"; do
    ufw_delete_public_port_proto_rules "$p" tcp
    ufw_delete_public_port_proto_rules "$p" udp
  done

  # 3) Allow service port(s) ONLY from Iran tunnel IP over GRE interface
  for p in "${ports[@]}"; do
    ufw allow in on "$TUN_IF" from 172.16.1.1 to any port "$p" proto tcp >/dev/null
    if [[ "$ALLOW_UDP" == "yes" ]]; then
      ufw allow in on "$TUN_IF" from 172.16.1.1 to any port "$p" proto udp >/dev/null
    fi
  done

  ufw reload >/dev/null || true
  log "UFW updated (port only over GRE)."
}

start_all() {
  tune_forwarding
  tune_conntrack_if_kharej
  setup_gre
  setup_iran_nat
  setup_kharej_ufw
  log "Start done."
}

stop_all() {
  ensure_cmd ip
  if ip link show "$TUN_IF" >/dev/null 2>&1; then
    ip tunnel del "$TUN_IF" 2>/dev/null || true
  fi

  local p
  IFS=',' read -r -a ports <<<"$SERVICE_PORTS"

  # Remove Iran rules if exist (best-effort)
  if command -v iptables >/dev/null 2>&1; then
    ipt_del_all nat PREROUTING -p tcp --dport 1:65535 -j DNAT --to-destination 172.16.1.2:1-65535
    ipt_del_all nat PREROUTING -p udp --dport 1:65535 -j DNAT --to-destination 172.16.1.2:1-65535
    for p in "${ports[@]}"; do
      ipt_del_all nat PREROUTING -p tcp --dport "$p" -j DNAT --to-destination "172.16.1.2:${p}"
      ipt_del_all nat PREROUTING -p udp --dport "$p" -j DNAT --to-destination "172.16.1.2:${p}"
      ipt_del_all filter FORWARD -o "$TUN_IF" -p tcp -d 172.16.1.2/32 --dport "$p" -j ACCEPT
      ipt_del_all filter FORWARD -o "$TUN_IF" -p udp -d 172.16.1.2/32 --dport "$p" -j ACCEPT
    done
    ipt_del_all nat POSTROUTING -o "$TUN_IF" -d 172.16.1.2/32 -j MASQUERADE
    ipt_del_all filter FORWARD -i "$TUN_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  fi

  # Remove kharej UFW rules if active
  if ufw_is_active; then
    for p in "${ports[@]}"; do
      ufw delete allow in on "$TUN_IF" from 172.16.1.1 to any port "$p" proto tcp >/dev/null 2>&1 || true
      ufw delete allow in on "$TUN_IF" from 172.16.1.1 to any port "$p" proto udp >/dev/null 2>&1 || true
    done
    ufw_remove_gre_proto47_block
    ufw reload >/dev/null 2>&1 || true
  fi

  log "Stop done."
}

case "${1:-start}" in
  start) start_all ;;
  stop)  stop_all  ;;
  *) echo "Usage: $0 {start|stop}" ; exit 1 ;;
esac
EOF

  chmod +x "$APPLY_SCRIPT"
  log "Installed: $APPLY_SCRIPT"
}

install_systemd_unit() {
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=GRE4 Tunnel (Iran/Kharej) + NAT/Firewall
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$APPLY_SCRIPT start
ExecStop=$APPLY_SCRIPT stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now gre4.service
  log "Systemd service enabled: gre4.service"
}

remove_everything() {
  warn "Removing GRE4 (service + tunnel + rules)..."

  # best-effort cleanup first
  if [[ -x "$APPLY_SCRIPT" && -f "$CONF_FILE" ]]; then
    "$APPLY_SCRIPT" stop || true
  fi

  systemctl disable --now gre4.service >/dev/null 2>&1 || true
  rm -f "$UNIT_FILE" "$APPLY_SCRIPT" "$CONF_FILE"
  systemctl daemon-reload || true
  warn "Removed files and disabled service."

  # Try to remove tunnel quickly
  ip tunnel del "$TUN_IF" 2>/dev/null || true

  warn "Done."
}

main_menu() {
  echo "Choose an option:"
  echo "1) Setup Iran (Gateway + DNAT for one or more ports)"
  echo "2) Setup Kharej (Server + UFW hardening + conntrack tuning)"
  echo "3) Remove everything"
  echo "4) Manage existing deployment"
  echo "5) Status"
  echo
}

main() {
  need_root
  ensure_cmd ip
  ensure_cmd sysctl

  main_menu
  local choice
  read -r -p "Enter choice (1/2/3/4/5): " choice

  case "$choice" in
    1)
      local iran_ip kharej_ip ports allow_udp
      iran_ip=$(prompt_default "Iran public IP" "")
      validate_ipv4 "$iran_ip" || { err "Invalid Iran IP."; exit 1; }
      kharej_ip=$(prompt_default "Kharej public IP" "")
      validate_ipv4 "$kharej_ip" || { err "Invalid Kharej IP."; exit 1; }

      ports=$(prompt_default "Service port(s), comma-separated (e.g. 2096 or 80,443)" "2096")
      ports=$(normalize_ports_list "$ports") || { err "Invalid port list."; exit 1; }

      allow_udp=$(prompt_default "Forward UDP as well? (yes/no)" "no")
      if [[ "$allow_udp" != "yes" && "$allow_udp" != "no" ]]; then
        err "Only yes or no is allowed"
        exit 1
      fi

      write_conf "iran" "$iran_ip" "$kharej_ip" "$ports" "$allow_udp"
      install_apply_script
      install_systemd_unit
      log "Iran configured. Test: ip a show $TUN_IF ; iptables -t nat -S"
      ;;
    2)
      local kharej_ip iran_ip ports allow_udp
      kharej_ip=$(prompt_default "Kharej public IP" "")
      validate_ipv4 "$kharej_ip" || { err "Invalid Kharej IP."; exit 1; }
      iran_ip=$(prompt_default "Iran public IP" "")
      validate_ipv4 "$iran_ip" || { err "Invalid Iran IP."; exit 1; }

      ports=$(prompt_default "Service port(s), comma-separated (e.g. 2096 or 80,443)" "2096")
      ports=$(normalize_ports_list "$ports") || { err "Invalid port list."; exit 1; }

      allow_udp=$(prompt_default "Allow UDP too? (yes/no)" "no")
      if [[ "$allow_udp" != "yes" && "$allow_udp" != "no" ]]; then
        err "Only yes or no is allowed"
        exit 1
      fi

      write_conf "kharej" "$kharej_ip" "$iran_ip" "$ports" "$allow_udp"
      install_apply_script
      install_systemd_unit
      log "Kharej configured. Test: ip a show $TUN_IF ; ufw status verbose (if active)"
      ;;
    3)
      remove_everything
      ;;
    4)
      manage_menu
      ;;
    5)
      show_status
      ;;
    *)
      err "Invalid option."
      exit 1
      ;;
  esac
}

main "$@"
