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
    err "این اسکریپت باید با root اجرا شود. مثال: sudo bash gre4.sh"
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

prompt_default() {
  local prompt="$1" default="$2" var
  read -r -p "$prompt [$default]: " var || true
  if [[ -z "${var:-}" ]]; then
    echo "$default"
  else
    echo "$var"
  fi
}

ensure_cmd() {
  local c="$1"
  command -v "$c" >/dev/null 2>&1 || {
    err "نیاز به دستور '$c' دارم ولی پیدا نشد."
    exit 1
  }
}

write_conf() {
  local role="$1" local_pub="$2" peer_pub="$3" port="$4" allow_udp="$5"
  cat > "$CONF_FILE" <<EOF
ROLE="$role"
LOCAL_PUBLIC_IP="$local_pub"
PEER_PUBLIC_IP="$peer_pub"
SERVICE_PORT="$port"
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

  # محافظه‌کارانه برای RAM کم (مثل 1GB)
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
  ipt_del_all nat PREROUTING -p tcp --dport "$SERVICE_PORT" -j DNAT --to-destination "172.16.1.2:${SERVICE_PORT}"
  ipt_del_all nat PREROUTING -p udp --dport "$SERVICE_PORT" -j DNAT --to-destination "172.16.1.2:${SERVICE_PORT}"

  # Add only selected port
  ipt_add nat PREROUTING -p tcp --dport "$SERVICE_PORT" -j DNAT --to-destination "172.16.1.2:${SERVICE_PORT}"
  if [[ "$ALLOW_UDP" == "yes" ]]; then
    ipt_add nat PREROUTING -p udp --dport "$SERVICE_PORT" -j DNAT --to-destination "172.16.1.2:${SERVICE_PORT}"
  fi

  # MASQUERADE only toward GRE and only to kharej tunnel IP
  ipt_del_all nat POSTROUTING -j MASQUERADE
  ipt_add nat POSTROUTING -o "$TUN_IF" -d 172.16.1.2/32 -j MASQUERADE

  # Ensure FORWARD allows the DNATed traffic (safer if policies change)
  ipt_add filter FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ipt_add filter FORWARD -o "$TUN_IF" -p tcp -d 172.16.1.2/32 --dport "$SERVICE_PORT" -j ACCEPT
  if [[ "$ALLOW_UDP" == "yes" ]]; then
    ipt_add filter FORWARD -o "$TUN_IF" -p udp -d 172.16.1.2/32 --dport "$SERVICE_PORT" -j ACCEPT
  fi

  log "Iran NAT: DNAT فقط پورت $SERVICE_PORT -> 172.16.1.2:$SERVICE_PORT"
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

ufw_delete_public_port_rules() {
  # delete any numbered rule containing "<port>/tcp" (v4 & v6)
  local port="$1"
  mapfile -t nums < <(ufw status numbered | sed -n "s/^\\[\\s*\\([0-9]\\+\\)\\].*\\b${port}\\/tcp\\b.*/\\1/p" | sort -rn)
  for n in "${nums[@]}"; do
    yes | ufw delete "$n" >/dev/null
  done
}

setup_kharej_ufw() {
  [[ "$ROLE" == "kharej" ]] || return 0
  ufw_is_active || return 0

  log "UFW active: hardening rules for GRE + port $SERVICE_PORT"

  # 1) Ensure GRE proto47 allowed only from peer public IP
  ufw_allow_gre_proto47

  # 2) Remove public allow for service port (if any)
  ufw_delete_public_port_rules "$SERVICE_PORT"

  # 3) Allow service port ONLY from Iran tunnel IP over GRE interface
  ufw allow in on "$TUN_IF" from 172.16.1.1 to any port "$SERVICE_PORT" proto tcp >/dev/null
  if [[ "$ALLOW_UDP" == "yes" ]]; then
    ufw allow in on "$TUN_IF" from 172.16.1.1 to any port "$SERVICE_PORT" proto udp >/dev/null
  fi

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

  # Remove Iran rules if exist (best-effort)
  if command -v iptables >/dev/null 2>&1; then
    ipt_del_all nat PREROUTING -p tcp --dport 1:65535 -j DNAT --to-destination 172.16.1.2:1-65535
    ipt_del_all nat PREROUTING -p udp --dport 1:65535 -j DNAT --to-destination 172.16.1.2:1-65535
    ipt_del_all nat PREROUTING -p tcp --dport "$SERVICE_PORT" -j DNAT --to-destination "172.16.1.2:${SERVICE_PORT}"
    ipt_del_all nat PREROUTING -p udp --dport "$SERVICE_PORT" -j DNAT --to-destination "172.16.1.2:${SERVICE_PORT}"
    ipt_del_all nat POSTROUTING -o "$TUN_IF" -d 172.16.1.2/32 -j MASQUERADE
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
  systemctl disable --now gre4.service >/dev/null 2>&1 || true
  rm -f "$UNIT_FILE" "$APPLY_SCRIPT" "$CONF_FILE"
  systemctl daemon-reload || true
  warn "Removed files and disabled service."

  # Try to remove tunnel quickly
  ip tunnel del "$TUN_IF" 2>/dev/null || true

  warn "Done."
}

main_menu() {
  echo "انتخاب کن:"
  echo "1) راه‌اندازی ایران (Gateway + DNAT فقط یک پورت)"
  echo "2) راه‌اندازی خارج (Server + UFW hardening + conntrack tune)"
  echo "3) حذف کامل (Remove)"
  echo
}

main() {
  need_root
  ensure_cmd ip
  ensure_cmd sysctl

  main_menu
  local choice
  read -r -p "Enter choice (1/2/3): " choice

  case "$choice" in
    1)
      local iran_ip kharej_ip port allow_udp
      iran_ip=$(prompt_default "IP عمومی ایران" "")
      validate_ipv4 "$iran_ip" || { err "IP ایران نامعتبر است."; exit 1; }
      kharej_ip=$(prompt_default "IP عمومی خارج" "")
      validate_ipv4 "$kharej_ip" || { err "IP خارج نامعتبر است."; exit 1; }

      port=$(prompt_default "پورت سرویس (مثلاً 2096)" "2096")
      validate_port "$port" || { err "پورت نامعتبر است."; exit 1; }

      allow_udp=$(prompt_default "UDP هم فوروارد شود؟ (yes/no)" "no")
      if [[ "$allow_udp" != "yes" && "$allow_udp" != "no" ]]; then
        err "فقط yes یا no"
        exit 1
      fi

      write_conf "iran" "$iran_ip" "$kharej_ip" "$port" "$allow_udp"
      install_apply_script
      install_systemd_unit
      log "Iran configured. Test: ip a show $TUN_IF ; iptables -t nat -S"
      ;;
    2)
      local kharej_ip iran_ip port allow_udp
      kharej_ip=$(prompt_default "IP عمومی خارج" "")
      validate_ipv4 "$kharej_ip" || { err "IP خارج نامعتبر است."; exit 1; }
      iran_ip=$(prompt_default "IP عمومی ایران" "")
      validate_ipv4 "$iran_ip" || { err "IP ایران نامعتبر است."; exit 1; }

      port=$(prompt_default "پورت سرویس (مثلاً 2096)" "2096")
      validate_port "$port" || { err "پورت نامعتبر است."; exit 1; }

      allow_udp=$(prompt_default "UDP هم اجازه داده شود؟ (yes/no)" "no")
      if [[ "$allow_udp" != "yes" && "$allow_udp" != "no" ]]; then
        err "فقط yes یا no"
        exit 1
      fi

      write_conf "kharej" "$kharej_ip" "$iran_ip" "$port" "$allow_udp"
      install_apply_script
      install_systemd_unit
      log "Kharej configured. Test: ip a show $TUN_IF ; ufw status verbose (if active)"
      ;;
    3)
      remove_everything
      ;;
    *)
      err "گزینه نامعتبر."
      exit 1
      ;;
  esac
}

main "$@"
