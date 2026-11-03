#!/usr/bin/env bash
set -euo pipefail

# gre4.sh - GRE tunnel + (Iran: DNAT only one port) + (Kharej: UFW restrict + conntrack tune)
# Repo: https://github.com/vahid162/gre-4
# Author: vahid162 (modified with manage menu + port prompt)

TUN_IF="GRE"
IRAN_TUN_CIDR="172.16.1.1/30"
KHAREJ_TUN_CIDR="172.16.1.2/30"
CONF_FILE="/etc/gre4.conf"
APPLY_SCRIPT="/usr/local/sbin/gre4-apply.sh"
UNIT_FILE="/etc/systemd/system/gre4.service"
STATE_DIR="/var/lib/gre4"
SYSCTL_DIR="/etc/sysctl.d"
UFW_DIR="/etc/ufw"
UFW_BEFORE_FILE="$UFW_DIR/before.rules"

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

update_conf() {
  # Cleanup must read the configuration that created the current rules.
  stop_deployment || return
  write_conf "$@" || return
  systemctl start gre4.service || return
  log "Configuration applied: gre4.service"
}

stop_deployment() {
  # Upgrade cleanup first: older installed helpers can hide firewall errors.
  if [[ -f "$CONF_FILE" ]]; then
    install_apply_script || return
  fi
  if [[ -f "$UNIT_FILE" ]]; then
    systemctl stop gre4.service || return
  fi
  # An inactive/failed unit may still have rules from an earlier failed cleanup.
  if [[ -x "$APPLY_SCRIPT" && -f "$CONF_FILE" ]]; then
    "$APPLY_SCRIPT" stop || return
  fi
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
  update_conf "$ROLE" "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$merged" "$ALLOW_UDP"
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
  update_conf "$ROLE" "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$result" "$ALLOW_UDP"
}

manage_replace_ports() {
  load_current_conf || { err "Cannot load current config."; return 1; }
  local ports
  ports=$(prompt_default "New service port(s), comma-separated" "$SERVICE_PORTS")
  ports=$(normalize_ports_list "$ports") || { err "Invalid port list."; return 1; }
  update_conf "$ROLE" "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$ports" "$ALLOW_UDP"
}

manage_change_ips() {
  load_current_conf || { err "Cannot load current config."; return 1; }
  local local_ip peer_ip
  local_ip=$(prompt_default "Local public IP" "$LOCAL_PUBLIC_IP")
  validate_ipv4 "$local_ip" || { err "Invalid local public IP."; return 1; }
  peer_ip=$(prompt_default "Peer public IP" "$PEER_PUBLIC_IP")
  validate_ipv4 "$peer_ip" || { err "Invalid peer public IP."; return 1; }
  update_conf "$ROLE" "$local_ip" "$peer_ip" "$SERVICE_PORTS" "$ALLOW_UDP"
}

manage_toggle_udp() {
  load_current_conf || { err "Cannot load current config."; return 1; }
  local udp
  udp=$(prompt_default "ALLOW_UDP (yes/no)" "$ALLOW_UDP")
  [[ "$udp" == "yes" || "$udp" == "no" ]] || { err "Only yes or no is allowed"; return 1; }
  update_conf "$ROLE" "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$SERVICE_PORTS" "$udp"
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
  local staged
  staged=$(mktemp "${CONF_FILE}.tmp.XXXXXX") || return
  cat > "$staged" <<EOF || { rm -f "$staged"; return 1; }
ROLE="$role"
LOCAL_PUBLIC_IP="$local_pub"
PEER_PUBLIC_IP="$peer_pub"
SERVICE_PORTS="$ports"
ALLOW_UDP="$allow_udp"
TUN_IF="$TUN_IF"
IRAN_TUN_CIDR="$IRAN_TUN_CIDR"
KHAREJ_TUN_CIDR="$KHAREJ_TUN_CIDR"
EOF
  chmod 600 "$staged" || { rm -f "$staged"; return 1; }
  mv -f "$staged" "$CONF_FILE" || { rm -f "$staged"; return 1; }
  log "Config saved to $CONF_FILE"
}

install_apply_script() {
  local staged
  staged=$(mktemp "${APPLY_SCRIPT}.tmp.XXXXXX") || return
  if ! printf '#!/usr/bin/env bash\nset -euo pipefail\n\nCONF_FILE=%q\nSTATE_DIR=%q\nSYSCTL_DIR=%q\nUFW_DIR=%q\nUFW_BEFORE_FILE=%q\n' \
    "$CONF_FILE" "$STATE_DIR" "$SYSCTL_DIR" "$UFW_DIR" "$UFW_BEFORE_FILE" > "$staged"; then
    rm -f "$staged"
    return 1
  fi
  cat >> "$staged" <<'EOF' || { rm -f "$staged"; return 1; }
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
  local rc
  if iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
    warn "Existing untagged iptables rule retained; GRE4 will not remove it: $table $chain $*"
    return 0
  else
    rc=$?
  fi
  # A missing rule returns 1; permission/lock failures must not create duplicates.
  [[ "$rc" == 1 ]] || return "$rc"
  if iptables -t "$table" -C "$chain" "$@" -m comment --comment gre4-managed 2>/dev/null; then
    return 0
  else
    rc=$?
    [[ "$rc" == 1 ]] || return "$rc"
  fi
  iptables -t "$table" -A "$chain" "$@" -m comment --comment gre4-managed
}

ipt_del_all() {
  # delete while exists
  local table="$1"; shift
  local chain="$1"; shift
  local rc
  while true; do
    if iptables -t "$table" -C "$chain" "$@" -m comment --comment gre4-managed 2>/dev/null; then
      iptables -t "$table" -D "$chain" "$@" -m comment --comment gre4-managed || return
    else
      rc=$?
      [[ "$rc" == 1 ]] && return 0
      return "$rc"
    fi
  done
}

# Recovery data stays separate from the removable deployment configuration.
sysctl_apply_file() {
  local name="$1" file="$2"; shift 2
  local root="$STATE_DIR/sysctl" state="$STATE_DIR/sysctl/$name" staged entry key value previous
  [[ ! -L "$STATE_DIR" && ! -L "$root" ]] || { err "Unsafe sysctl state directory: $root"; return 1; }
  mkdir -p "$root" || return
  [[ -O "$STATE_DIR" && -O "$root" ]] || { err "Sysctl state directory must belong to this user: $root"; return 1; }
  chmod 700 "$STATE_DIR" "$root" || return
  if [[ -e "$state" || -L "$state" ]]; then
    [[ -d "$state" && ! -L "$state" && -O "$state" && -f "$state/file" && ! -L "$state/file" ]] || return 1
    if [[ -e "$state/restore" || -e "$state/restored" ]]; then
      err "Sysctl recovery is pending; run stop successfully before starting again. State: $state"
      return 1
    fi
  else
    if [[ -e "$file" || -L "$file" ]]; then
      err "Refusing unowned sysctl file $file. Move it aside and recover its settings manually before retrying."
      return 1
    fi
    staged=$(mktemp -d "$root/.capture.XXXXXX") || return
    for entry in "$@"; do
      key=${entry%%=*}; value=${entry#*=}
      previous=$(sysctl -n "$key") || { rm -rf "$staged"; return 1; }
      [[ "$previous" =~ ^[0-9]+$ && "$value" =~ ^[0-9]+$ ]] || { rm -rf "$staged"; return 1; }
      printf '%s %s %s\n' "$key" "$previous" "$value" >> "$staged/values" || { rm -rf "$staged"; return 1; }
      printf '%s\n' "$entry" >> "$staged/file" || { rm -rf "$staged"; return 1; }
    done
    # Publish the complete recovery record before the first persistent/runtime change.
    mv -T "$staged" "$state" || { rm -rf "$staged"; return 1; }
  fi
  if [[ -e "$file" || -L "$file" ]]; then
    if [[ -L "$file" || ! -f "$file" ]] || ! cmp -s "$state/file" "$file"; then
      err "Preserving changed sysctl file $file; stop and resolve it manually before restarting."
      return 1
    fi
  else
    staged=$(mktemp "$SYSCTL_DIR/.gre4.XXXXXX") || return
    if ! cp "$state/file" "$staged" || ! chmod 644 "$staged" || ! ln "$staged" "$file"; then
      rm -f "$staged"
      return 1
    fi
    rm -f "$staged" || return
  fi
  sysctl -p "$file" >/dev/null
}

tune_forwarding() {
  sysctl_apply_file forward "$SYSCTL_DIR/99-gre4-forward.conf" \
    net.ipv4.ip_forward=1 net.ipv4.conf.all.forwarding=1
}

tune_conntrack_if_kharej() {
  [[ "$ROLE" == "kharej" ]] || return 0
  local mem_kb mem_mb target
  mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo) || return
  mem_mb=$((mem_kb/1024))
  if [[ "$mem_mb" -ge 2048 ]]; then target=262144
  elif [[ "$mem_mb" -ge 1024 ]]; then target=131072
  else target=65536
  fi
  sysctl_apply_file conntrack "$SYSCTL_DIR/99-gre4-conntrack.conf" \
    "net.netfilter.nf_conntrack_max=$target" || return
  log "conntrack tuned: nf_conntrack_max=$target"
}

restore_sysctl_file() {
  local name="$1" file="$2" state="$STATE_DIR/sysctl/$1"
  local key previous applied extra current wanted alternate staged index failed=0
  local -a keys=() originals=() targets=() desired=() observed=() alternatives=() expected=() now=()
  if [[ ! -e "$state" && ! -L "$state" ]]; then
    if [[ -e "$file" || -L "$file" ]]; then
      err "Unowned sysctl file $file has no recovery record; preserve it and recover settings manually."
      return 1
    fi
    return 0
  fi
  [[ -d "$state" && ! -L "$state" && -O "$state" ]] || { err "Unsafe sysctl recovery state: $state"; return 1; }
  [[ -f "$state/file" && ! -L "$state/file" ]] || return 1
  if [[ ! -e "$state/restored" ]]; then
    [[ -f "$state/values" && ! -L "$state/values" ]] || return 1
    case "$name" in
      forward) expected=(net.ipv4.ip_forward net.ipv4.conf.all.forwarding) ;;
      conntrack) expected=(net.netfilter.nf_conntrack_max) ;;
      *) return 1 ;;
    esac
    while read -r key previous applied extra; do
      index=${#keys[@]}
      [[ "$key" == "${expected[$index]:-}" && "$previous" =~ ^[0-9]+$ && "$applied" =~ ^[0-9]+$ && -z "$extra" ]] || return 1
      keys+=("$key"); originals+=("$previous"); targets+=("$applied")
    done < "$state/values"
    [[ ${#keys[@]} == "${#expected[@]}" ]] || return 1
    if [[ ! -e "$state/restore" && ! -L "$state/restore" ]]; then
      staged=$(mktemp "$state/.restore.XXXXXX") || return
      for index in "${!keys[@]}"; do
        current=$(sysctl -n "${keys[$index]}") || { rm -f "$staged"; return 1; }
        [[ "$current" =~ ^[0-9]+$ ]] || { rm -f "$staged"; return 1; }
        wanted="$current"
        [[ "$current" != "${targets[$index]}" ]] || wanted="${originals[$index]}"
        desired+=("$wanted")
        alternate="$current"
        # ip_forward resets all.forwarding; save both acceptable values before that write.
        [[ "${keys[$index]}" != net.ipv4.conf.all.forwarding ]] || alternate="${desired[0]}"
        printf '%s %s %s %s\n' "${keys[$index]}" "$wanted" "$current" "$alternate" >> "$staged" || { rm -f "$staged"; return 1; }
      done
      mv -T "$staged" "$state/restore" || { rm -f "$staged"; return 1; }
    fi
    [[ -f "$state/restore" && ! -L "$state/restore" ]] || return 1
    desired=()
    while read -r key wanted current alternate extra; do
      index=${#desired[@]}
      [[ "$key" == "${keys[$index]:-}" && "$wanted" =~ ^[0-9]+$ && "$current" =~ ^[0-9]+$ && "$alternate" =~ ^[0-9]+$ && -z "$extra" ]] || return 1
      desired+=("$wanted"); observed+=("$current"); alternatives+=("$alternate")
    done < "$state/restore"
    [[ ${#desired[@]} == "${#keys[@]}" ]] || return 1
    # Capture intervening administrator changes before ip_forward can reset them.
    for key in "${keys[@]}"; do
      current=$(sysctl -n "$key") || return
      [[ "$current" =~ ^[0-9]+$ ]] || return 1
      now+=("$current")
    done
    staged=$(mktemp "$state/.restore.XXXXXX") || return
    for index in "${!keys[@]}"; do
      current="${now[$index]}"
      if [[ "$current" != "${desired[$index]}" && "$current" != "${observed[$index]}" ]]; then
        if [[ "${keys[$index]}" != net.ipv4.conf.all.forwarding || "$current" != "${alternatives[$index]}" || "${now[0]}" != "${desired[0]}" ]]; then
          desired[$index]="$current"
          warn "Preserving administrator change to ${keys[$index]}."
        fi
      fi
      observed[$index]="$current"
      alternatives[$index]="$current"
      [[ "${keys[$index]}" != net.ipv4.conf.all.forwarding ]] || alternatives[$index]="${desired[0]}"
      printf '%s %s %s %s\n' "${keys[$index]}" "${desired[$index]}" "$current" "${alternatives[$index]}" >> "$staged" || { rm -f "$staged"; return 1; }
    done
    mv -T "$staged" "$state/restore" || { rm -f "$staged"; return 1; }
    # Remove persistence before restoring runtime, after validating recovery data.
    if [[ -e "$file" || -L "$file" ]]; then
      if [[ ! -L "$file" && -f "$file" ]] && cmp -s "$state/file" "$file"; then
        rm -f "$file" || return
      fi
    fi
    for index in "${!keys[@]}"; do
      key="${keys[$index]}"
      current=$(sysctl -n "$key") || { failed=1; continue; }
      if [[ "$current" == "${desired[$index]}" ]]; then continue; fi
      if [[ "$current" == "${observed[$index]}" || "$current" == "${alternatives[$index]}" ]]; then
        sysctl -w "$key=${desired[$index]}" >/dev/null || failed=1
      else
        warn "Preserving administrator change to $key."
      fi
    done
    [[ "$failed" == 0 ]] || { err "Sysctl recovery failed; state retained in $state for retry."; return 1; }
  fi
  touch "$state/restored" || return
  if [[ -e "$file" || -L "$file" ]]; then
    warn "Preserving administrator-modified $file (ownership record retained in $state)."
    return 0
  fi
  rm -rf "$state" || return
}

restore_sysctl() {
  local failed=0 root="$STATE_DIR/sysctl"
  if [[ -L "$STATE_DIR" || -L "$root" ]]; then err "Unsafe sysctl state directory: $root"; return 1; fi
  restore_sysctl_file forward "$SYSCTL_DIR/99-gre4-forward.conf" || failed=1
  restore_sysctl_file conntrack "$SYSCTL_DIR/99-gre4-conntrack.conf" || failed=1
  # Leave unrelated state, and ownership records for administrator-modified files.
  rmdir "$root" "$STATE_DIR" 2>/dev/null || true
  return "$failed"
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

  # Untagged legacy rules cannot be distinguished from administrator-owned rules.
  local p
  IFS=',' read -r -a ports <<<"$SERVICE_PORTS"

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
  local status
  status=$(LC_ALL=C ufw status 2>/dev/null) || return 2
  [[ "${status%%$'\n'*}" == "Status: active" ]]
}

ufw_before_rules_test() {
  local file="$1"
  command -v iptables-restore >/dev/null 2>&1 || return 0
  iptables-restore --test < "$file"
}

ufw_strip_gre_block() {
  awk '
    $0=="# gre4.sh BEGIN" { if (skip) exit 1; skip=1; next }
    $0=="# gre4.sh END" { if (!skip) exit 1; skip=0; next }
    !skip { print }
    END { if (skip) exit 1 }
  ' "$1"
}

ufw_allow_gre_proto47() {
  # UFW before.rules uses iptables-restore format; rules must be inserted inside *filter table before its COMMIT.
  local before="$UFW_BEFORE_FILE"
  [[ -f "$before" ]] || return 0

  local begin="# gre4.sh BEGIN"
  local end="# gre4.sh END"
  local rule_in="-A ufw-before-input -p 47 -s ${PEER_PUBLIC_IP} -d ${LOCAL_PUBLIC_IP} -j ACCEPT"
  local rule_out="-A ufw-before-output -p 47 -s ${LOCAL_PUBLIC_IP} -d ${PEER_PUBLIC_IP} -j ACCEPT"

  local clean staged
  clean=$(mktemp "${before}.clean.XXXXXX") || return
  staged=$(mktemp "${before}.tmp.XXXXXX") || { rm -f "$clean"; return 1; }
  if ! ufw_strip_gre_block "$before" > "$clean"; then
    rm -f "$clean" "$staged"
    err "Unbalanced GRE block in $before; keeping original file."
    return 1
  fi

  if ! awk -v b="$begin" -v e="$end" -v rin="$rule_in" -v rout="$rule_out" '
    {
      if($0=="*filter"){ in_filter=1 }
      if(in_filter && $0=="COMMIT" && !inserted){
        print b
        print rin
        print rout
        print e
        inserted=1
      }
      print
      if(in_filter && $0=="COMMIT"){ in_filter=0 }
    }
    END {
      if(!inserted) exit 42
    }
  ' "$clean" > "$staged"; then
    rm -f "$clean" "$staged"
    err "Cannot find a complete filter table in $before; keeping original file."
    return 1
  fi

  if ! ufw_before_rules_test "$staged"; then
    rm -f "$clean" "$staged"
    err "Invalid $before after GRE block insert; aborting UFW update."
    return 1
  fi

  if ! chmod --reference="$before" "$staged" || ! mv "$staged" "$before"; then
    rm -f "$clean" "$staged"
    return 1
  fi
  rm -f "$clean"
}

ufw_remove_gre_proto47_block() {
  local before="$UFW_BEFORE_FILE"
  [[ -f "$before" ]] || return 0

  local staged
  staged=$(mktemp "${before}.tmp.XXXXXX") || return
  if ! ufw_strip_gre_block "$before" > "$staged"; then
    rm -f "$staged"
    err "Unbalanced GRE block in $before; keeping original file."
    return 1
  fi

  if ! ufw_before_rules_test "$staged"; then
    rm -f "$staged"
    err "Invalid $before after GRE block removal; keeping original file."
    return 1
  fi

  if ! chmod --reference="$before" "$staged" || ! mv "$staged" "$before"; then
    rm -f "$staged"
    return 1
  fi
}

ufw_delete_managed_rules() {
  local status ssh_config key p n ssh_ports=""
  local -a nums=()
  status=$(ufw status numbered) || return
  if ! grep -Eq '^\[[[:space:]]*[0-9]+\].*#[[:space:]]*gre4-managed[[:space:]]*$' <<< "$status"; then
    return 0
  fi
  if [[ "${1:-}" == "preserve-ssh" ]] && command -v sshd >/dev/null 2>&1; then
    # Keep existing SSH allowances unchanged; never create broader access.
    if ! ssh_config=$(sshd -T 2>/dev/null); then
      warn "Cannot detect SSH ports; keeping managed UFW rules."
      return 1
    fi
    while read -r key p _; do
      case "$key" in
        port) ;;
        listenaddress) p="${p##*:}" ;;
        *) continue ;;
      esac
      if [[ ! "$p" =~ ^[0-9]{1,5}$ ]] || (( 10#$p < 1 || 10#$p > 65535 )); then
        warn "Invalid SSH port; keeping managed UFW rules."
        return 1
      fi
      ssh_ports+=" $((10#$p))/tcp"
    done <<< "$ssh_config"
    if [[ -z "$ssh_ports" ]]; then
      warn "No SSH ports detected; keeping managed UFW rules."
      return 1
    fi
  fi

  mapfile -t nums < <(awk -v keep="$ssh_ports " '
    /^\[[[:space:]]*[0-9]+\]/ && /#[[:space:]]*gre4-managed[[:space:]]*$/ {
      rule=$0
      sub(/#.*/, "", rule)
      sub(/^\[[[:space:]]*[0-9]+\][[:space:]]*/, "", rule)
      if (match(rule, /[[:space:]]ALLOW[[:space:]]+IN([[:space:]]|$)/)) {
        count=split(substr(rule, 1, RSTART-1), fields, /[[:space:]]+/)
        for (i=1; i<=count; i++) {
          if (index(keep, " " fields[i] " ")) next
        }
      }
      number=$0
      sub(/^\[[[:space:]]*/, "", number)
      sub(/\].*$/, "", number)
      print number
    }
  ' <<< "$status" | sort -rn)
  for n in "${nums[@]}"; do
    ufw --force delete "$n" >/dev/null || return
  done
}

ufw_check_inactive_cleanup() {
  # Inactive UFW still has persistent rules; do not discard their recovery files.
  local file
  for file in "$UFW_DIR/user.rules" "$UFW_DIR/user6.rules" "$UFW_BEFORE_FILE"; do
    [[ -e "$file" ]] || continue
    if [[ ! -r "$file" ]]; then
      err "Cannot inspect persistent UFW rules: $file"
      return 1
    fi
    if grep -Eq 'gre4-managed|677265342d6d616e61676564|^# gre4.sh (BEGIN|END)$' "$file"; then
      err "UFW is inactive but GRE4 rules remain in $file. Keep recovery files; clean the owned rules before retrying."
      return 1
    else
      local rc=$?
      [[ "$rc" == 1 ]] || return "$rc"
    fi
  done
}


ufw_ipv6_enabled() {
  [[ -d /proc/sys/net/ipv6 ]] || return 1
  local defaults="$1" config="$2"
  [[ -r "$defaults" && -r "$config" ]] || return 1
  awk -F= '
    /^[[:alnum:]_]+="?[[:alnum:]_]+"?/ && tolower($1)=="ipv6" {
      value=tolower($2)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      sub(/^["\047]+/, "", value)
      sub(/["\047]+$/, "", value)
    }
    END { exit value!="yes" }
  ' "$defaults" "$config"
}

ufw_has_public_allow() {
  local status="$1" port="$2" proto="$3" family="$4"
  awk -v port="$port" -v proto="$proto" -v family="$family" '
    BEGIN {
      destination=port "/" proto
      source="Anywhere"
      if (family==6) { destination=destination " (v6)"; source=source " (v6)" }
    }
    /^\[[[:space:]]*[0-9]+\]/ {
      rule=$0
      sub(/#.*/, "", rule)
      sub(/^\[[[:space:]]*[0-9]+\][[:space:]]*/, "", rule)
      if (!match(rule, /[[:space:]]+ALLOW[[:space:]]+IN[[:space:]]+/)) next
      dst=substr(rule, 1, RSTART-1)
      src=substr(rule, RSTART+RLENGTH)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", dst)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", src)
      sub(/[[:space:]]+\(log(-all)?\)$/, "", src)
      if (dst==destination && src==source) found=1
    }
    END { exit !found }
  ' <<< "$status"
}

setup_kharej_ufw() {
  [[ "$ROLE" == "kharej" ]] || return 0
  local state=0
  ufw_is_active || state=$?
  if [[ "$state" == 1 ]]; then return 0; fi
  if [[ "$state" != 0 ]]; then err "Cannot read UFW status."; return 1; fi

  log "UFW active: enabling public access for port(s) $SERVICE_PORTS"

  # 1) Ensure GRE proto47 allowed only from peer public IP
  ufw_allow_gre_proto47

  # 2) Remove old service rules without revoking existing SSH access.
  ufw_delete_managed_rules preserve-ssh || return

  # 3) Only claim new allowances; UFW replaces comments on identical rules.
  local p proto family destination status
  local -a protocols=(tcp) families=(4)
  [[ "$ALLOW_UDP" != "yes" ]] || protocols+=(udp)
  if ufw_ipv6_enabled /etc/default/ufw /etc/ufw/ufw.conf; then families+=(6); fi
  status=$(LC_ALL=C ufw status numbered) || return
  IFS=',' read -r -a ports <<<"$SERVICE_PORTS"
  for p in "${ports[@]}"; do
    for proto in "${protocols[@]}"; do
      for family in "${families[@]}"; do
        if ufw_has_public_allow "$status" "$p" "$proto" "$family"; then continue; fi
        destination=0.0.0.0/0
        if [[ "$family" == 6 ]]; then destination=::/0; fi
        ufw allow proto "$proto" from any to "$destination" port "$p" comment 'gre4-managed' >/dev/null || return
      done
    done
  done

  ufw_before_rules_test "$UFW_BEFORE_FILE"
  ufw reload >/dev/null || return
  log "UFW updated (public port access enabled)."
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
  local failed=0
  if ip link show "$TUN_IF" >/dev/null 2>&1; then
    ip tunnel del "$TUN_IF" 2>/dev/null || failed=1
  fi

  local p
  IFS=',' read -r -a ports <<<"$SERVICE_PORTS"

  # Attempt every cleanup step, but report any operational failure.
  if command -v iptables >/dev/null 2>&1; then
    for p in "${ports[@]}"; do
      ipt_del_all nat PREROUTING -p tcp --dport "$p" -j DNAT --to-destination "172.16.1.2:${p}" || failed=1
      ipt_del_all nat PREROUTING -p udp --dport "$p" -j DNAT --to-destination "172.16.1.2:${p}" || failed=1
      ipt_del_all filter FORWARD -o "$TUN_IF" -p tcp -d 172.16.1.2/32 --dport "$p" -j ACCEPT || failed=1
      ipt_del_all filter FORWARD -o "$TUN_IF" -p udp -d 172.16.1.2/32 --dport "$p" -j ACCEPT || failed=1
    done
    ipt_del_all nat POSTROUTING -o "$TUN_IF" -d 172.16.1.2/32 -j MASQUERADE || failed=1
    ipt_del_all filter FORWARD -i "$TUN_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || failed=1
  fi

  # Remove kharej UFW rules if active
  if ufw_is_active; then
    ufw_delete_managed_rules preserve-ssh || failed=1
    ufw_remove_gre_proto47_block || failed=1
    ufw_before_rules_test "$UFW_BEFORE_FILE" || failed=1
    ufw reload >/dev/null 2>&1 || failed=1
  else
    local state=$?
    if [[ "$state" == 1 ]]; then
      ufw_check_inactive_cleanup || failed=1
    else
      err "Cannot read UFW status during cleanup."
      failed=1
    fi
  fi

  restore_sysctl || failed=1

  if [[ "$failed" != 0 ]]; then
    err "Cleanup incomplete; keep the configuration and retry before replacing or removing it."
    return 1
  fi
  log "Stop done."
}

case "${1:-start}" in
  start) start_all ;;
  stop)  stop_all  ;;
  *) echo "Usage: $0 {start|stop}" ; exit 1 ;;
esac
EOF

  chmod +x "$staged" || { rm -f "$staged"; return 1; }
  mv -f "$staged" "$APPLY_SCRIPT" || { rm -f "$staged"; return 1; }
  log "Installed: $APPLY_SCRIPT"
}

install_systemd_unit() {
  cat > "$UNIT_FILE" <<EOF || return
[Unit]
Description=GRE4 Tunnel (Iran/Kharej) + NAT/Firewall
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$APPLY_SCRIPT start
ExecStopPost=$APPLY_SCRIPT stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload || return
  systemctl enable --now gre4.service || return
  log "Systemd service enabled: gre4.service"
}

setup_deployment() {
  if [[ -f "$CONF_FILE" || -f "$UNIT_FILE" ]]; then
    stop_deployment || return
  fi
  write_conf "$@" || return
  install_apply_script || return
  install_systemd_unit
}

remove_everything() {
  warn "Removing GRE4 (service + tunnel + rules)..."

  if [[ -f "$CONF_FILE" || -f "$UNIT_FILE" ]]; then
    stop_deployment || return
  fi

  if [[ -f "$UNIT_FILE" ]]; then
    systemctl disable gre4.service || return
  fi
  rm -f "$UNIT_FILE" "$APPLY_SCRIPT" "$CONF_FILE" || return
  systemctl daemon-reload || return
  warn "Removed files and disabled service."

  # Try to remove tunnel quickly
  ip tunnel del "$TUN_IF" 2>/dev/null || true

  warn "Done."
}

main_menu() {
  echo "Choose an option:"
  echo "1) Setup Iran (Gateway + DNAT for one or more ports)"
  echo "2) Setup Kharej (Server + UFW public access + conntrack tuning)"
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

      setup_deployment "iran" "$iran_ip" "$kharej_ip" "$ports" "$allow_udp" || return
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

      setup_deployment "kharej" "$kharej_ip" "$iran_ip" "$ports" "$allow_udp" || return
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
