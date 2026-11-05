#!/usr/bin/env bash
set -euo pipefail

# gre4.sh - independently managed GRE connections for Iran gateways and a Kharej hub
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
PROFILE_DIR="/etc/gre4/profiles"
LOCK_DIR="/run/lock/gre4"
TEMPLATE_FILE="/etc/systemd/system/gre4@.service"
LEGACY_CONF_FILE="/etc/gre4.conf"
UFW_DEFAULTS_FILE="/etc/default/ufw"
MIGRATION_BACKUP_DIR="/var/backups/gre4"

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
    (( 10#$x >= 0 && 10#$x <= 255 )) || return 1
  done
  return 0
}

validate_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]{1,5}$ ]] || return 1
  (( 10#$p >= 1 && 10#$p <= 65535 )) || return 1
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
    token=$((10#$token))
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

ensure_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Required command '$1' was not found."; return 1; }
}

validate_profile_id() {
  [[ ${1:-} =~ ^[a-z][a-z0-9_-]{0,9}$ ]]
}

private_directory() {
  local path="$1"
  [[ ! -L "$path" ]] || { err "Unsafe directory: $path"; return 1; }
  mkdir -p "$path" || return
  [[ -d "$path" && -O "$path" ]] || return 1
  chmod 700 "$path"
}

private_config_file() {
  local mode
  [[ -f "$1" && ! -L "$1" && -O "$1" ]] || { err "Unsafe configuration: $1"; return 1; }
  mode=$(stat -c '%a' "$1") || return
  (( (8#$mode & 077) == 0 )) || { err "Configuration must be private: $1"; return 1; }
}

ipv4_number() {
  local a b c d
  validate_ipv4 "$1" || return 1
  IFS=. read -r a b c d <<< "$1"
  printf '%s\n' "$(( (10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d ))"
}

number_ipv4() {
  local n="$1"
  printf '%s.%s.%s.%s\n' "$(( (n >> 24) & 255 ))" "$(( (n >> 16) & 255 ))" "$(( (n >> 8) & 255 ))" "$(( n & 255 ))"
}

cidr_bounds() {
  local address=${1%/*} prefix=${1#*/} n mask
  [[ "$1" == */* && "$prefix" =~ ^[0-9]{1,2}$ ]] || return 1
  prefix=$((10#$prefix)); (( prefix <= 32 )) || return 1
  n=$(ipv4_number "$address") || return
  mask=$(( (0xffffffff << (32-prefix)) & 0xffffffff ))
  printf '%s %s\n' "$((n & mask))" "$(( (n & mask) | (0xffffffff ^ mask) ))"
}

profile_subnet() {
  local base last
  [[ "$1" == */30 ]] || return 1
  read -r base last < <(cidr_bounds "$1")
  [[ -n "$base" ]] || return 1
  printf '%s/30\n' "$(number_ipv4 "$base")"
}

read_profile_file() {
  local file="$1" key value line required
  local -A seen=()
  private_config_file "$file" || return
  unset ROLE LOCAL_PUBLIC_IP PEER_PUBLIC_IP SERVICE_PORTS ALLOW_UDP TUN_IF IRAN_TUN_CIDR KHAREJ_TUN_CIDR
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == *=* ]] || { err "Invalid configuration line in $file"; return 1; }
    key=${line%%=*}; value=${line#*=}
    case "$key" in
      ROLE|LOCAL_PUBLIC_IP|PEER_PUBLIC_IP|SERVICE_PORTS|ALLOW_UDP|TUN_IF|IRAN_TUN_CIDR|KHAREJ_TUN_CIDR) ;;
      *) err "Unknown configuration key: $key"; return 1 ;;
    esac
    [[ ! ${seen[$key]:-} ]] || { err "Duplicate configuration key: $key"; return 1; }
    if [[ "$value" == \"*\" ]]; then value=${value:1:${#value}-2}; fi
    [[ "$value" =~ ^[a-zA-Z0-9_.,/-]+$ ]] || { err "Invalid value for $key"; return 1; }
    printf -v "$key" '%s' "$value"
    seen[$key]=1
  done < "$file"
  for required in ROLE LOCAL_PUBLIC_IP PEER_PUBLIC_IP SERVICE_PORTS ALLOW_UDP TUN_IF IRAN_TUN_CIDR KHAREJ_TUN_CIDR; do
    [[ ${seen[$required]:-} ]] || { err "Missing $required in $file"; return 1; }
  done
  [[ "$ROLE" == iran || "$ROLE" == kharej ]] || return 1
  validate_ipv4 "$LOCAL_PUBLIC_IP" && validate_ipv4 "$PEER_PUBLIC_IP" || return 1
  LOCAL_PUBLIC_IP=$(number_ipv4 "$(ipv4_number "$LOCAL_PUBLIC_IP")")
  PEER_PUBLIC_IP=$(number_ipv4 "$(ipv4_number "$PEER_PUBLIC_IP")")
  [[ "$LOCAL_PUBLIC_IP" != "$PEER_PUBLIC_IP" ]] || return 1
  SERVICE_PORTS=$(normalize_ports_list "$SERVICE_PORTS") || return
  [[ "$ALLOW_UDP" == yes || "$ALLOW_UDP" == no ]] || return 1
  [[ "$TUN_IF" =~ ^[a-zA-Z0-9_-]{1,15}$ ]] || return 1
  local base last iran kharej
  [[ "$IRAN_TUN_CIDR" == */30 && "$KHAREJ_TUN_CIDR" == */30 ]] || return 1
  read -r base last < <(cidr_bounds "$IRAN_TUN_CIDR")
  [[ -n "$base" ]] || return 1
  iran=$(ipv4_number "${IRAN_TUN_CIDR%/*}") || return
  kharej=$(ipv4_number "${KHAREJ_TUN_CIDR%/*}") || return
  (( iran == base+1 && kharej == base+2 )) || { err "Tunnel addresses must be the first two hosts of one /30."; return 1; }
}

load_profile() {
  validate_profile_id "$1" || { err "Invalid connection ID."; return 1; }
  PROFILE_ID="$1"
  CONF_FILE="$PROFILE_DIR/$PROFILE_ID.conf"
  read_profile_file "$CONF_FILE" || return
  [[ "$TUN_IF" == "g4-$PROFILE_ID" || ( "$PROFILE_ID" == legacy && "$TUN_IF" == GRE ) ]] || { err "Unexpected tunnel interface for $PROFILE_ID"; return 1; }
}

check_local_public_ip() {
  local wanted="$1" addresses
  validate_ipv4 "$wanted" || return 1
  wanted=$(number_ipv4 "$(ipv4_number "$wanted")")
  addresses=$(ip -o -4 addr show) || return
  if ! awk -v wanted="$wanted" '$3=="inet" {split($4,a,"/"); if(a[1]==wanted) found=1} END {exit !found}' <<< "$addresses"; then
    err "Local public IP is not assigned on this host: $wanted"; return 1
  fi
}

check_host_network_conflicts() {
  local subnet="$1" own_interface="${2:-}" base last address dev lo hi routes addresses
  read -r base last < <(cidr_bounds "$subnet")
  addresses=$(ip -o -4 addr show) || return
  routes=$(ip -4 route show table all) || return
  while read -r address dev; do
    [[ -n "$address" && "$dev" != "$own_interface" ]] || continue
    read -r lo hi < <(cidr_bounds "$address")
    [[ -n "$lo" ]] || continue
    if (( base <= hi && lo <= last )); then err "Tunnel subnet overlaps host network $address on $dev"; return 1; fi
  done < <(awk '$3=="inet" {print $4, $2}' <<< "$addresses"; awk '
    $1!="default" { address=$1; if($1=="local" || $1=="broadcast" || $1=="unreachable" || $1=="blackhole" || $1=="prohibit" || $1=="throw") address=$2;
      if(address !~ /^[0-9]+\./) next; if(address !~ /\//) address=address "/32";
      dev=""; for(i=1;i<NF;i++) if($i=="dev") dev=$(i+1); print address,dev }
  ' <<< "$routes")
}

profile_conflicts() (
  local id="$1" role="$2" local_ip="$3" peer="$4" subnet="$5" iface="$6" base last lo hi file other
  read -r base last < <(cidr_bounds "$subnet")
  shopt -s nullglob
  for file in "$PROFILE_DIR"/*.conf "$STATE_DIR"/profiles/*/applied.conf; do
    other=${file##*/}; other=${other%.conf}
    if [[ "$other" == applied ]]; then other=${file%/applied.conf}; other=${other##*/}; fi
    [[ "$other" != "$id" ]] || continue
    read_profile_file "$file" || return
    [[ "$ROLE" == "$role" && "$LOCAL_PUBLIC_IP" == "$local_ip" ]] || { err "All connections on this host must use the same role and local public IP."; return 1; }
    [[ "$PEER_PUBLIC_IP" != "$peer" ]] || { err "Peer already has a connection: $other"; return 1; }
    [[ "$TUN_IF" != "$iface" ]] || { err "Interface already belongs to $other"; return 1; }
    read -r lo hi < <(cidr_bounds "$IRAN_TUN_CIDR")
    if (( base <= hi && lo <= last )); then err "Tunnel subnet overlaps connection $other"; return 1; fi
  done
)

render_profile() (
  local id="$1" role="$2" local_ip="$3" peer="$4" ports="$5" udp="$6" subnet="$7" iface="${8:-g4-$1}" base last
  validate_profile_id "$id" || { err "Invalid connection ID."; return 1; }
  [[ "$role" == iran || "$role" == kharej ]] || return 1
  validate_ipv4 "$local_ip" && validate_ipv4 "$peer" || return 1
  local_ip=$(number_ipv4 "$(ipv4_number "$local_ip")")
  peer=$(number_ipv4 "$(ipv4_number "$peer")")
  [[ "$local_ip" != "$peer" ]] || return 1
  ports=$(normalize_ports_list "$ports") || return
  [[ "$udp" == yes || "$udp" == no ]] || return 1
  [[ "$iface" == "g4-$id" || ( "$id" == legacy && "$iface" == GRE ) ]] || return 1
  [[ "$subnet" == "$(profile_subnet "$subnet")" ]] || { err "Enter an aligned /30 network, such as 172.16.1.4/30."; return 1; }
  read -r base last < <(cidr_bounds "$subnet")
  [[ ! -L "$PROFILE_DIR" && ! -L "$STATE_DIR" && ! -L "$STATE_DIR/profiles" ]] || return 1
  profile_conflicts "$id" "$role" "$local_ip" "$peer" "$subnet" "$iface" || return
  check_host_network_conflicts "$subnet" "$iface" || return
  [[ ! -L "$PROFILE_DIR/$id.conf" ]] || return 1
  printf 'ROLE=%s\nLOCAL_PUBLIC_IP=%s\nPEER_PUBLIC_IP=%s\nSERVICE_PORTS=%s\nALLOW_UDP=%s\nTUN_IF=%s\nIRAN_TUN_CIDR=%s/30\nKHAREJ_TUN_CIDR=%s/30\n' \
    "$role" "$local_ip" "$peer" "$ports" "$udp" "$iface" "$(number_ipv4 "$((base+1))")" "$(number_ipv4 "$((base+2))")"
)

write_profile() {
  local id="$1" content staged
  content=$(render_profile "$@") || return
  private_directory "$PROFILE_DIR" || return
  staged=$(mktemp "$PROFILE_DIR/.$id.XXXXXX") || return
  if ! printf '%s\n' "$content" > "$staged" || ! chmod 600 "$staged" || ! mv -f "$staged" "$PROFILE_DIR/$id.conf"; then
    rm -f "$staged"; return 1
  fi
}

suggest_profile_subnet() (
  local file base last next=2886729984
  shopt -s nullglob
  for file in "$PROFILE_DIR"/*.conf "$STATE_DIR"/profiles/*/applied.conf; do
    read_profile_file "$file" || return
    read -r base last < <(cidr_bounds "$IRAN_TUN_CIDR")
    (( base < next )) || next=$((base+4))
  done
  (( next <= 4294967292 )) || return 1
  printf '%s/30\n' "$(number_ipv4 "$next")"
)

acquire_management_lock() {
  private_directory "$LOCK_DIR" || return
  [[ ! -L "$LOCK_DIR/gre4-management.lock" ]] || return 1
  [[ ! -e "$LOCK_DIR/gre4-management.lock" || -O "$LOCK_DIR/gre4-management.lock" ]] || return 1
  exec 9>"$LOCK_DIR/gre4-management.lock" || return
  flock -n 9 || { err "Another GRE4 management operation is running."; return 1; }
}

profile_runtime_lock() {
  private_directory "$LOCK_DIR" || return
  [[ ! -L "$LOCK_DIR/gre4-runtime.lock" ]] || return 1
  [[ ! -e "$LOCK_DIR/gre4-runtime.lock" || -O "$LOCK_DIR/gre4-runtime.lock" ]] || return 1
  exec 8>"$LOCK_DIR/gre4-runtime.lock" || return
  flock -w 30 8 || { err "Timed out waiting for another GRE4 runtime operation."; return 1; }
}

profile_edit_lock() {
  local id="${1:-}" file
  validate_profile_id "$id" || return 1
  file="$LOCK_DIR/gre4-edit-$id.lock"
  [[ ! -L "$file" && ( ! -e "$file" || -O "$file" ) ]] || return 1
  exec 7>"$file" || return
  flock -n 7 || { err "Configuration edit in progress for $id"; return 1; }
}

profile_state_directory() {
  private_directory "$STATE_DIR" && private_directory "$STATE_DIR/profiles" && private_directory "$STATE_DIR/profiles/$1"
}

profile_interface_owned() {
  local details
  details=$(ip -d -o link show dev "$TUN_IF") || return
  [[ " $details " == *" alias gre4:$PROFILE_ID "* ]]
}

profile_preflight() {
  local command status value
  for command in ip sysctl flock; do ensure_cmd "$command" || return 1; done
  if [[ "$ROLE" == iran ]]; then ensure_cmd iptables || return 1; fi
  if command -v ufw >/dev/null 2>&1; then
    status=$(LC_ALL=C ufw status 2>/dev/null) || { err "Cannot inspect UFW before starting."; return 1; }
    if [[ "${status%%$'\n'*}" == "Status: active" ]]; then
      ensure_cmd iptables-restore || return 1
    fi
  fi
  [[ "$ROLE" == kharej ]] || return 0
  if value=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null); then
    [[ "$value" =~ ^[0-9]+$ ]] && return 0
  fi
  if ! command -v modprobe >/dev/null 2>&1 || ! modprobe nf_conntrack; then
    err "Cannot prepare nf_conntrack. Check kmod, kernel support and module permissions before retrying."
    return 1
  fi
  if ! value=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null) || [[ ! "$value" =~ ^[0-9]+$ ]]; then
    err "nf_conntrack_max is unavailable after module preparation; this kernel or environment may restrict conntrack."
    return 1
  fi
}

profile_setup_gre() {
  local created_index details
  if ip link show "$TUN_IF" >/dev/null 2>&1; then
    profile_interface_owned || { err "Refusing interface not owned by $PROFILE_ID: $TUN_IF"; return 1; }
    ip tunnel del "$TUN_IF" || return
  fi
  ip link add name "$TUN_IF" alias "gre4:$PROFILE_ID" type gre remote "$PEER_PUBLIC_IP" local "$LOCAL_PUBLIC_IP" || return
  details=$(ip -d -o link show dev "$TUN_IF") || return
  created_index=${details%%:*}
  # Some kernels ignore the alias on creation; set and verify it separately.
  if ! ip link set dev "$TUN_IF" alias "gre4:$PROFILE_ID" || ! profile_interface_owned; then
    err "Cannot establish interface ownership: $TUN_IF"
    if details=$(ip -d -o link show dev "$TUN_IF") && [[ ${details%%:*} == "$created_index" ]] &&
        { [[ " $details " != *" alias "* ]] || [[ " $details " == *" alias gre4:$PROFILE_ID "* ]]; }; then
      ip tunnel del "$TUN_IF" || return
    else
      err "Interface changed during creation; preserving $TUN_IF for manual recovery."
    fi
    return 1
  fi
  if [[ "$ROLE" == iran ]]; then ip addr add "$IRAN_TUN_CIDR" dev "$TUN_IF" || return
  else ip addr add "$KHAREJ_TUN_CIDR" dev "$TUN_IF" || return; fi
  ip link set "$TUN_IF" mtu 1420 || return
  ip link set "$TUN_IF" up
}

profile_ipt_add() {
  local table="$1" chain="$2" rc; shift 2
  if iptables -t "$table" -C "$chain" "$@" -m comment --comment "gre4:$PROFILE_ID" 2>/dev/null; then return 0; else rc=$?; fi
  [[ "$rc" == 1 ]] || return "$rc"
  if iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
    warn "Matching administrator rule retained: $table $chain $*"; return 0
  else rc=$?; fi
  [[ "$rc" == 1 ]] || return "$rc"
  iptables -t "$table" -A "$chain" "$@" -m comment --comment "gre4:$PROFILE_ID"
}

profile_ipt_del() {
  local table="$1" chain="$2" rc; shift 2
  while true; do
    if iptables -t "$table" -C "$chain" "$@" -m comment --comment "gre4:$PROFILE_ID" 2>/dev/null; then
      iptables -t "$table" -D "$chain" "$@" -m comment --comment "gre4:$PROFILE_ID" || return
    else rc=$?; [[ "$rc" == 1 ]] && return 0; return "$rc"; fi
  done
}

profile_nat() {
  [[ "$ROLE" == iran ]] || return 0
  local action="$1" p proto target=${KHAREJ_TUN_CIDR%/*} failed=0 operation=profile_ipt_add
  [[ "$action" != stop ]] || operation=profile_ipt_del
  local -a ports protocols=(tcp)
  [[ "$ALLOW_UDP" != yes && "$action" != stop ]] || protocols+=(udp)
  IFS=, read -r -a ports <<< "$SERVICE_PORTS"
  for p in "${ports[@]}"; do
    for proto in "${protocols[@]}"; do
      "$operation" nat PREROUTING -d "$LOCAL_PUBLIC_IP/32" -p "$proto" --dport "$p" -j DNAT --to-destination "$target:$p" || failed=1
      "$operation" filter FORWARD -o "$TUN_IF" -p "$proto" -d "$target/32" --dport "$p" -j ACCEPT || failed=1
    done
  done
  "$operation" nat POSTROUTING -o "$TUN_IF" -d "$target/32" -j MASQUERADE || failed=1
  "$operation" filter FORWARD -i "$TUN_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || failed=1
  return "$failed"
}

profile_requirements() (
  local skip="${1:-}" file id p proto target
  local -a ports protocols
  shopt -s nullglob
  for file in "$STATE_DIR"/profiles/*/applied.conf; do
    id=${file%/applied.conf}; id=${id##*/}
    [[ "$id" != "$skip" ]] || continue
    validate_profile_id "$id" && read_profile_file "$file" || return
    printf 'gre -A ufw-before-input -p 47 -s %s -d %s -m comment --comment gre4:%s -j ACCEPT\n' "$PEER_PUBLIC_IP" "$LOCAL_PUBLIC_IP" "$id"
    printf 'gre -A ufw-before-output -p 47 -s %s -d %s -m comment --comment gre4:%s -j ACCEPT\n' "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$id"
    IFS=, read -r -a ports <<< "$SERVICE_PORTS"
    protocols=(tcp); [[ "$ALLOW_UDP" != yes ]] || protocols+=(udp)
    if [[ "$ROLE" == kharej ]]; then
      for p in "${ports[@]}"; do for proto in "${protocols[@]}"; do printf 'port %s %s\n' "$p" "$proto"; done; done
    else
      target=${KHAREJ_TUN_CIDR%/*}
      printf 'gre -A ufw-before-forward -i %s -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment gre4:%s -j ACCEPT\n' "$TUN_IF" "$id"
      for p in "${ports[@]}"; do for proto in "${protocols[@]}"; do
        printf 'gre -A ufw-before-forward -o %s -p %s -d %s/32 --dport %s -m comment --comment gre4:%s -j ACCEPT\n' "$TUN_IF" "$proto" "$target" "$p" "$id"
      done; done
    fi
  done
)

profile_write_ufw_block() {
  local requirements="$1" before="$UFW_BEFORE_FILE" clean staged
  [[ -f "$before" && ! -L "$before" ]] || { err "Missing or unsafe UFW before.rules"; return 1; }
  [[ -f "$requirements" && -r "$requirements" && ! -L "$requirements" ]] || { err "Cannot read UFW requirements."; return 1; }
  clean=$(mktemp "${before}.clean.XXXXXX") || return
  staged=$(mktemp "${before}.tmp.XXXXXX") || { rm -f "$clean"; return 1; }
  if ! awk '
    $0=="# gre4 profiles BEGIN" {if(skip) exit 1; skip=1; next}
    $0=="# gre4 profiles END" {if(!skip) exit 1; skip=0; next}
    !skip {print}
    END {if(skip) exit 1}
  ' "$before" > "$clean"; then err "Unbalanced GRE block in $before; keeping original file."; rm -f "$clean" "$staged"; return 1; fi
  if ! awk -v rules="$requirements" '
    {if($0=="*filter") filter=1
     if(filter && $0=="COMMIT" && !inserted) {
       any=0; while((getline line < rules)>0) if(substr(line,1,4)=="gre ") {if(!any++) print "# gre4 profiles BEGIN"; print substr(line,5)}
       close(rules); if(any) print "# gre4 profiles END"; inserted=1
     }
     print; if(filter && $0=="COMMIT") filter=0}
    END {if(!inserted) exit 1}
  ' "$clean" > "$staged"; then
    err "Cannot find a complete filter table in $before; keeping original file."
    rm -f "$clean" "$staged"; return 1
  fi
  if ! ufw_before_rules_test "$staged" || ! chmod --reference="$before" "$staged" || ! mv -f "$staged" "$before"; then
    err "Invalid or unwritable UFW rules; keeping original file."
    rm -f "$clean" "$staged"; return 1
  fi
  rm -f "$clean"
}

profile_shared_ssh_ports() {
  local config key value port found=0
  if ! command -v sshd >/dev/null 2>&1; then return 0; fi
  config=$(sshd -T) || { err "Cannot inspect SSH; keeping shared UFW rules."; return 1; }
  while read -r key value _; do
    case "${key,,}" in port) port=$value ;; listenaddress) port=${value##*:} ;; *) continue ;; esac
    validate_port "$port" || return 1
    printf '%s\n' "$((10#$port))"
    found=1
  done <<< "$config"
  [[ "$found" == 1 ]] || { err "Cannot detect SSH ports; keeping shared UFW rules."; return 1; }
}

profile_ufw_reconcile() {
  local skip="${1:-}" action="${2:-start}" requirements status state=0 p proto family destination n key file encoded id
  requirements=$(mktemp) || return
  if ! profile_requirements "$skip" > "$requirements"; then rm -f "$requirements"; return 1; fi
  ufw_is_active || state=$?
  if [[ "$state" == 1 ]]; then
    if [[ "$action" == stop ]]; then
      id="$skip"; encoded=$(printf 'gre4:%s' "$id" | od -An -tx1 | tr -d ' \n')
      for file in "$UFW_DIR/user.rules" "$UFW_DIR/user6.rules" "$UFW_BEFORE_FILE"; do
        [[ -e "$file" ]] || continue
        [[ -r "$file" ]] || { rm -f "$requirements"; return 1; }
        if grep -Eq "gre4:$id([[:space:]\"']|$)|$encoded([^[:xdigit:]]|$)" "$file"; then
          err "Inactive UFW retains rules for $id; keep recovery records and retry cleanup with UFW active."
          rm -f "$requirements"; return 1
        fi
      done
      # A shared public rule is obsolete only when no retained profile needs it.
      local -a removed_ports removed_protocols=(tcp)
      IFS=, read -r -a removed_ports <<< "$SERVICE_PORTS"
      [[ "$ALLOW_UDP" != yes ]] || removed_protocols+=(udp)
      for p in "${removed_ports[@]}"; do for proto in "${removed_protocols[@]}"; do
        if grep -Fxq "port $p $proto" "$requirements"; then continue; fi
        for file in "$UFW_DIR/user.rules" "$UFW_DIR/user6.rules"; do
          [[ -e "$file" ]] || continue
          if awk -v port="$p" -v proto="$proto" '
            /^### tuple ###/ {tuple=$0}
            /gre4-shared|677265342d736861726564/ {
              if(tuple ~ ("^### tuple ### allow " proto " " port "([[:space:]]|$)")) found=1
              if($0 ~ ("-p " proto "([[:space:]]|$)") && $0 ~ ("--dport " port "([[:space:]]|$)")) found=1
            }
            END {exit !found}
          ' "$file"; then
            err "Inactive UFW may retain obsolete shared port rules; keep recovery records."
            rm -f "$requirements"; return 1
          fi
        done
      done; done
    fi
    rm -f "$requirements"; return 0
  fi
  [[ "$state" == 0 ]] || { rm -f "$requirements"; err "Cannot read UFW status."; return 1; }
  local -A desired_allowances=() ssh=()
  local -a families=(4) obsolete=()
  if ufw_ipv6_enabled "$UFW_DEFAULTS_FILE" "$UFW_DIR/ufw.conf"; then families+=(6); fi
  while read -r key p proto; do
    [[ "$key" == port ]] || continue
    for family in "${families[@]}"; do desired_allowances["$family:$proto:$p"]=1; done
  done < "$requirements"
  status=$(LC_ALL=C ufw status numbered) || { rm -f "$requirements"; return 1; }
  # Add first so changing one connection never revokes a sibling's allowance.
  for key in "${!desired_allowances[@]}"; do
    IFS=: read -r family proto p <<< "$key"
    if ufw_has_public_allow "$status" "$p" "$proto" "$family"; then continue; fi
    destination=0.0.0.0/0; [[ "$family" != 6 ]] || destination=::/0
    if ! ufw allow proto "$proto" from any to "$destination" port "$p" comment gre4-shared >/dev/null; then rm -f "$requirements"; return 1; fi
  done
  # Added IPv4 rules shift the numbers of existing IPv6 rules.
  status=$(LC_ALL=C ufw status numbered) || { rm -f "$requirements"; return 1; }
  if ! profile_write_ufw_block "$requirements"; then rm -f "$requirements"; return 1; fi
  local ssh_list candidate
  while read -r n p proto family; do
    [[ -n "$n" ]] || continue
    [[ ${desired_allowances["$family:$proto:$p"]:-} ]] && continue
    obsolete+=("$n:$p:$proto")
  done < <(awk '
    /^\[[[:space:]]*[0-9]+\]/ && /#[[:space:]]*gre4-shared[[:space:]]*$/ {
      line=$0; number=line; sub(/^\[[[:space:]]*/,"",number); sub(/\].*$/,"",number);
      sub(/^\[[^]]*\][[:space:]]*/,"",line); split(line,a,/[[:space:]]+/); split(a[1],port,"/");
      if(port[1] !~ /^[0-9]+$/ || port[2] !~ /^(tcp|udp)$/) next;
      family=(line ~ /\(v6\)/ ? 6 : 4);
      sub(/#.*/, "", line);
      if(!match(line, /[[:space:]]+ALLOW[[:space:]]+IN[[:space:]]+/)) next;
      dst=substr(line,1,RSTART-1); src=substr(line,RSTART+RLENGTH);
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", dst); gsub(/^[[:space:]]+|[[:space:]]+$/, "", src);
      expected=port[1] "/" port[2]; source="Anywhere";
      if(family==6) {expected=expected " (v6)"; source=source " (v6)"}
      if(dst!=expected || src!=source) next;
      print number,port[1],port[2],family
    }
  ' <<< "$status" | sort -rn)
  if [[ ${#obsolete[@]} -gt 0 ]]; then
    ssh_list=$(profile_shared_ssh_ports) || { rm -f "$requirements"; return 1; }
    while read -r p; do [[ -z "$p" ]] || ssh[$p]=1; done <<< "$ssh_list"
  fi
  for candidate in "${obsolete[@]}"; do
    IFS=: read -r n p proto <<< "$candidate"
    [[ "$proto" == tcp && ${ssh[$p]:-} ]] && continue
    if ! ufw --force delete "$n" >/dev/null; then rm -f "$requirements"; return 1; fi
  done
  rm -f "$requirements"
  ufw reload >/dev/null
}

profile_reapply_sysctl() {
  local name="$1" file="$2" state="$STATE_DIR/sysctl/$1" key original applied extra current changed=no index=0 expected_file=""
  local -a expected
  case "$name" in forward) expected=(net.ipv4.ip_forward net.ipv4.conf.all.forwarding) ;; conntrack) expected=(net.netfilter.nf_conntrack_max) ;; *) return 1 ;; esac
  [[ -d "$STATE_DIR/sysctl" && ! -L "$STATE_DIR/sysctl" && -O "$STATE_DIR/sysctl" ]] || return 1
  [[ -d "$state" && ! -L "$state" && -f "$state/file" && ! -L "$state/file" && -f "$state/values" && ! -L "$state/values" ]] || return 1
  [[ -O "$state" && -O "$state/file" && -O "$state/values" ]] || return 1
  [[ ! -e "$state/restore" && ! -e "$state/restored" ]] || { err "Shared sysctl recovery is pending."; return 1; }
  [[ -f "$file" && ! -L "$file" ]] && cmp -s "$file" "$state/file" || { err "Shared sysctl file was changed; preserve it for manual review."; return 1; }
  while read -r key original applied extra; do
    [[ "$key" == "${expected[$index]:-}" && "$original" =~ ^[0-9]+$ && "$applied" =~ ^[0-9]+$ && -z "$extra" ]] || return 1
    index=$((index+1))
    expected_file+="$key=$applied"$'\n'
    current=$(sysctl -n "$key") || return
    if [[ "$current" == "$applied" ]]; then continue; fi
    if [[ "$current" == "$original" ]]; then changed=yes
    else err "Preserving administrator runtime change to $key; resolve it before starting."; return 1; fi
  done < "$state/values"
  [[ "$index" == "${#expected[@]}" && $(cat "$state/file") == "${expected_file%$'\n'}" ]] || return 1
  [[ "$changed" != yes ]] || sysctl -p "$file" >/dev/null
}

profile_shared_sysctl() (
  local skip="${1:-}" file id forward=no conntrack=no
  shopt -s nullglob
  for file in "$STATE_DIR"/profiles/*/applied.conf; do
    id=${file%/applied.conf}; id=${id##*/}
    [[ "$id" != "$skip" ]] || continue
    read_profile_file "$file" || return
    forward=yes; [[ "$ROLE" != kharej ]] || conntrack=yes
  done
  if [[ "$forward" == no ]]; then restore_sysctl; return; fi
  if [[ ! -d "$STATE_DIR/sysctl/forward" ]]; then tune_forwarding || return
  elif [[ -z "$skip" ]]; then profile_reapply_sysctl forward "$SYSCTL_DIR/99-gre4-forward.conf" || return; fi
  if [[ "$conntrack" == yes ]]; then
    if [[ ! -d "$STATE_DIR/sysctl/conntrack" ]]; then ROLE=kharej; tune_conntrack_if_kharej
    elif [[ -z "$skip" ]]; then profile_reapply_sysctl conntrack "$SYSCTL_DIR/99-gre4-conntrack.conf"; fi
  else restore_sysctl_file conntrack "$SYSCTL_DIR/99-gre4-conntrack.conf"; fi
)

profile_start() (
  local id="${1:-}" state staged
  validate_profile_id "$id" && profile_runtime_lock || return 1
  profile_edit_lock "$id" && profile_migration_start_allowed "$id" || return 1
  state="$STATE_DIR/profiles/$id"
  [[ ! -L "$STATE_DIR" && ! -L "$STATE_DIR/profiles" && ! -L "$state" && ! -L "$PROFILE_DIR" ]] || return 1
  [[ ! -e "$state/cleanup-pending" ]] || { err "Cleanup pending for $id; stop it successfully before starting."; return 1; }
  load_profile "$id" || return
  profile_preflight || return 78
  check_local_public_ip "$LOCAL_PUBLIC_IP" || return
  profile_conflicts "$id" "$ROLE" "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$(profile_subnet "$IRAN_TUN_CIDR")" "$TUN_IF" || return
  check_host_network_conflicts "$(profile_subnet "$IRAN_TUN_CIDR")" "$TUN_IF" || return
  if [[ -f "$state/applied.conf" ]]; then
    cmp -s "$CONF_FILE" "$state/applied.conf" || { err "Applied configuration differs; stop $id before changing it."; return 1; }
    private_config_file "$state/applied.conf" || return
    if ip link show "$TUN_IF" >/dev/null 2>&1; then
      profile_interface_owned || { err "Interface ownership changed: $TUN_IF"; return 1; }
    fi
  else
    if ip link show "$TUN_IF" >/dev/null 2>&1; then err "Interface already exists: $TUN_IF"; return 1; fi
    profile_state_directory "$id" || return
    staged=$(mktemp "$state/.applied.XXXXXX") || return
    if ! cp "$CONF_FILE" "$staged" || ! chmod 600 "$staged" || ! mv -f "$staged" "$state/applied.conf"; then rm -f "$staged"; return 1; fi
  fi
  if ! profile_shared_sysctl || ! profile_setup_gre || ! profile_nat start || ! profile_ufw_reconcile; then
    touch "$state/cleanup-pending"
    err "Start failed for $id; post-stop cleanup must complete before retrying."
    return 1
  fi
  log "Connection started: $id"
)

profile_stop() (
  local id="${1:-}" state interfaces failed=0
  validate_profile_id "$id" && profile_runtime_lock || return 1
  PROFILE_ID="$id"; state="$STATE_DIR/profiles/$id"
  [[ ! -L "$STATE_DIR" && ! -L "$STATE_DIR/profiles" && ! -L "$state" ]] || return 1
  [[ -f "$state/applied.conf" ]] || return 0
  read_profile_file "$state/applied.conf" || return
  touch "$state/cleanup-pending" || return
  interfaces=$(ip -o link show) || { err "Cannot inspect interfaces; keeping recovery records."; return 1; }
  if awk -v name="$TUN_IF" '{split($2,a,/[:@]/); if(a[1]==name) found=1} END {exit !found}' <<< "$interfaces"; then
    if profile_interface_owned; then ip tunnel del "$TUN_IF" || failed=1
    else err "Interface ownership changed; keeping $TUN_IF and recovery records."; failed=1; fi
  fi
  profile_nat stop || failed=1
  profile_ufw_reconcile "$id" stop || failed=1
  if [[ "$failed" == 0 ]]; then profile_shared_sysctl "$id" || failed=1; fi
  if [[ "$failed" != 0 ]]; then err "Cleanup incomplete for $id; recovery records retained."; return 1; fi
  rm -f "$state/applied.conf" "$state/cleanup-pending" || return
  rmdir "$state" || return
  log "Connection stopped: $id"
)

install_apply_script() {
  local staged
  staged=$(mktemp "${APPLY_SCRIPT}.tmp.XXXXXX") || return
  if ! printf '#!/usr/bin/env bash\nset -euo pipefail\n\nSTATE_DIR=%q\nSYSCTL_DIR=%q\nUFW_DIR=%q\nUFW_BEFORE_FILE=%q\nPROFILE_DIR=%q\nLOCK_DIR=%q\nUFW_DEFAULTS_FILE=%q\nMIGRATION_BACKUP_DIR=%q\n' \
    "$STATE_DIR" "$SYSCTL_DIR" "$UFW_DIR" "$UFW_BEFORE_FILE" "$PROFILE_DIR" "$LOCK_DIR" "$UFW_DEFAULTS_FILE" "$MIGRATION_BACKUP_DIR" > "$staged"; then
    rm -f "$staged"; return 1
  fi
  cat >> "$staged" <<'GRE4_RUNTIME' || { rm -f "$staged"; return 1; }
log()  { echo -e "\e[1;32m[+]\e[0m $*"; }
warn() { echo -e "\e[1;33m[!]\e[0m $*"; }
err()  { echo -e "\e[1;31m[-]\e[0m $*" >&2; }

ensure_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Missing command: $1"; return 1; }; }

# iptables helpers (idempotent)
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


ufw_is_active() {
  command -v ufw >/dev/null 2>&1 || return 1
  local status
  status=$(LC_ALL=C ufw status 2>/dev/null) || return 2
  [[ "${status%%$'\n'*}" == "Status: active" ]]
}

ufw_before_rules_test() {
  local file="$1"
  ensure_cmd iptables-restore || return 1
  iptables-restore --test < "$file"
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

GRE4_RUNTIME
  declare -f validate_ipv4 validate_port normalize_ports_list validate_profile_id private_directory private_config_file ipv4_number number_ipv4 cidr_bounds profile_subnet read_profile_file load_profile check_local_public_ip check_host_network_conflicts profile_conflicts profile_runtime_lock profile_edit_lock profile_state_directory profile_interface_owned profile_preflight profile_setup_gre profile_ipt_add profile_ipt_del profile_nat profile_requirements profile_write_ufw_block profile_shared_ssh_ports profile_ufw_reconcile profile_reapply_sysctl profile_shared_sysctl profile_migration_start_allowed legacy_safe_path legacy_owned_file profile_start profile_stop >> "$staged" || { rm -f "$staged"; return 1; }
  cat >> "$staged" <<'GRE4_DISPATCH' || { rm -f "$staged"; return 1; }
case "${1:-start}" in
  start) [[ $# == 2 ]] || { echo "Usage: $0 {start|stop} <connection-id>"; exit 1; }; profile_start "$2" ;;
  stop) [[ $# == 2 ]] || { echo "Usage: $0 {start|stop} <connection-id>"; exit 1; }; profile_stop "$2" ;;
  post-stop)
    [[ $# == 2 ]] || exit 1
    # A preflight-only rejection must not clean an already applied deployment.
    if [[ ${EXIT_CODE:-} == exited && ${EXIT_STATUS:-} == 78 ]]; then exit 0; fi
    profile_stop "$2" ;;
  *) echo "Usage: $0 {start|stop} <connection-id>"; exit 1 ;;
esac
GRE4_DISPATCH
  chmod +x "$staged" || { rm -f "$staged"; return 1; }
  mv -f "$staged" "$APPLY_SCRIPT" || { rm -f "$staged"; return 1; }
  log "Installed: $APPLY_SCRIPT"
}

render_profile_unit() {
  cat <<EOF_UNIT
[Unit]
Description=GRE4 connection %i
Wants=network-online.target
After=network-online.target ssh.service ssh.socket

[Service]
Type=oneshot
ExecStart=$APPLY_SCRIPT start %i
ExecStopPost=$APPLY_SCRIPT post-stop %i
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_UNIT
}

install_profile_unit() {
  local staged
  staged=$(mktemp "${TEMPLATE_FILE}.tmp.XXXXXX") || return
  if ! render_profile_unit > "$staged"; then rm -f "$staged"; return 1; fi
  if ! chmod 644 "$staged" || ! mv -f "$staged" "$TEMPLATE_FILE"; then rm -f "$staged"; return 1; fi
  systemctl daemon-reload
}

profile_normal_mutation_allowed() {
  if [[ -e "$MIGRATION_BACKUP_DIR/upgrade-pending" || -L "$MIGRATION_BACKUP_DIR/upgrade-pending" ]]; then
    err "Upgrade recovery is pending; preserve the backup and review RECOVERY.txt before making changes."
    return 1
  fi
  [[ ${MIGRATING_LEGACY:-0} == 1 ]] && return 0
  if [[ -e "$LEGACY_CONF_FILE" || -e "${LEGACY_UNIT_FILE:-$UNIT_FILE}" || -e "$MIGRATION_BACKUP_DIR/pending" || -L "$MIGRATION_BACKUP_DIR/pending" ]]; then
    err "Legacy migration or recovery is pending. Use Migrate before changing profiles."
    return 1
  fi
}

profile_start_service() {
  validate_profile_id "$1" && profile_normal_mutation_allowed || return 1
  ( load_profile "$1" && profile_preflight ) || return 1
  # Refresh the paired helper/unit so old ExecStopPost cannot bypass preflight protection.
  install_apply_script && install_profile_unit || return
  if ! systemctl start "gre4@$1.service" || ! systemctl is-active --quiet "gre4@$1.service"; then
    err "Connection did not become active: $1"
    return 1
  fi
}

profile_stop_service() {
  local failed=0
  validate_profile_id "$1" || return 1
  systemctl stop "gre4@$1.service" || failed=1
  "$APPLY_SCRIPT" stop "$1" || return
  return "$failed"
}

profile_begin_edit() {
  validate_profile_id "${1:-}" || return 1
  profile_runtime_lock || return
  # The kernel releases the per-profile guard after a killed writer or reboot.
  profile_edit_lock "$1" || return
  flock -u 8; exec 8>&-
}

profile_end_edit() {
  validate_profile_id "${1:-}" || return 1
  flock -u 7 || return
  exec 7>&-
}

profile_update() (
  local id="$1"; shift
  validate_profile_id "$id" || { err "Invalid connection ID."; return 1; }
  acquire_management_lock && profile_normal_mutation_allowed || return
  profile_begin_edit "$id" || return
  trap 'profile_end_edit "$id"' EXIT
  profile_runtime_lock || return
  render_profile "$id" "$@" >/dev/null || return
  check_local_public_ip "$2" || return
  ( ROLE="$1"; profile_preflight ) || return 1
  flock -u 8; exec 8>&-
  profile_stop_service "$id" || return
  profile_runtime_lock || return
  write_profile "$id" "$@" || return
  flock -u 8; exec 8>&-
  profile_end_edit "$id" || return
  trap - EXIT
  profile_start_service "$id"
)

profile_remove() (
  local id="$1"
  validate_profile_id "$id" || return 1
  acquire_management_lock && profile_normal_mutation_allowed || return
  load_profile "$id" || return
  profile_begin_edit "$id" || return
  trap 'profile_end_edit "$id"' EXIT
  profile_stop_service "$id" || return
  systemctl disable "gre4@$id.service" || return
  profile_runtime_lock || return
  rm -f "$PROFILE_DIR/$id.conf" || return
  flock -u 8; exec 8>&-
  profile_end_edit "$id" || return
  trap - EXIT
  log "Removed connection: $id"
)

list_profiles() (
  local file id
  shopt -s nullglob
  printf '%-12s %-8s %-16s %-18s %s\n' ID ROLE PEER TUNNEL PORTS
  for file in "$PROFILE_DIR"/*.conf; do
    id=${file##*/}; id=${id%.conf}
    load_profile "$id" || return
    printf '%-12s %-8s %-16s %-18s %s\n' "$id" "$ROLE" "$PEER_PUBLIC_IP" "$IRAN_TUN_CIDR" "$SERVICE_PORTS"
  done
)

profile_status() (
  local id="$1"
  load_profile "$id" || return
  printf 'Connection: %s\nRole: %s\nPublic endpoints: %s -> %s\nTunnel: %s (%s / %s)\nPorts: %s; UDP: %s\n' \
    "$id" "$ROLE" "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$TUN_IF" "$IRAN_TUN_CIDR" "$KHAREJ_TUN_CIDR" "$SERVICE_PORTS" "$ALLOW_UDP"
  systemctl --no-pager --full status "gre4@$id.service" || true
  ip a show "$TUN_IF" || true
  if [[ -e "$STATE_DIR/profiles/$id/cleanup-pending" ]]; then warn "Cleanup pending; retry Stop before starting."; fi
  warn "Service/interface status is local only. Test peer reachability and real TCP/UDP traffic separately."
)

add_profile_interactive() (
  local role="$1" id local_ip peer ports udp subnet
  acquire_management_lock && profile_normal_mutation_allowed || return
  id=$(prompt_default "Connection ID (lowercase, at most 10 characters)" "iran1")
  validate_profile_id "$id" || { err "Invalid connection ID."; return 1; }
  [[ ! -e "$PROFILE_DIR/$id.conf" ]] || { err "Connection already exists: $id"; return 1; }
  local_ip=$(prompt_default "This server's public IPv4" "")
  peer=$(prompt_default "Other server's public IPv4" "")
  ports=$(prompt_default "Service ports (comma-separated)" "2096")
  udp=$(prompt_default "Forward/allow UDP too? (yes/no)" "no")
  subnet=$(prompt_default "Tunnel /30 network (use the SAME network at both ends)" "$(suggest_profile_subnet)")
  ( ROLE="$role"; profile_preflight ) || return 1
  profile_runtime_lock || return
  write_profile "$id" "$role" "$local_ip" "$peer" "$ports" "$udp" "$subnet" || return
  flock -u 8; exec 8>&-
  install_apply_script && install_profile_unit || return
  if ! systemctl enable "gre4@$id.service" ||
      ! systemctl start "gre4@$id.service" ||
      ! systemctl is-active --quiet "gre4@$id.service"; then
    err "Connection setup failed; configuration retained. Inspect status and retry Stop before Start."
    return 1
  fi
  record_installed_release || return
  load_profile "$id" || return
  printf 'Use this matching configuration at the other end:\nID=%s\nIran tunnel=%s\nKharej tunnel=%s\nPorts=%s\nUDP=%s\n' \
    "$id" "$IRAN_TUN_CIDR" "$KHAREJ_TUN_CIDR" "$SERVICE_PORTS" "$ALLOW_UDP"
  if [[ "$role" == kharej ]]; then
    warn "The destination application must listen on $KHAREJ_TUN_CIDR (without /30) or an appropriate wildcard address. Its configuration is not changed."
  fi
)

manage_profile_menu() {
  local id choice ports udp local_ip peer subnet
  list_profiles || return
  id=$(prompt_default "Connection ID" "")
  load_profile "$id" || return
  while true; do
    echo "1) Settings/status  2) Add ports  3) Remove ports  4) Replace ports"
    echo "5) Change public IPs  6) Toggle UDP  7) Start  8) Stop  9) Restart  10) Remove connection  11) Back"
    read -r -p "Choice: " choice || return
    load_profile "$id" || return
    subnet=$(profile_subnet "$IRAN_TUN_CIDR") || return
    ports="$SERVICE_PORTS"; udp="$ALLOW_UDP"; local_ip="$LOCAL_PUBLIC_IP"; peer="$PEER_PUBLIC_IP"
    case "$choice" in
      1) profile_status "$id" ;;
      2) ports=$(normalize_ports_list "$SERVICE_PORTS,$(prompt_default 'Ports to add' '')") || continue
         profile_update "$id" "$ROLE" "$local_ip" "$peer" "$ports" "$udp" "$subnet" "$TUN_IF" || return ;;
      3) local remove p result=""; local -a current
         remove=$(normalize_ports_list "$(prompt_default 'Ports to remove' '')") || continue
         IFS=, read -r -a current <<< "$SERVICE_PORTS"
         for p in "${current[@]}"; do [[ ",$remove," == *",$p,"* ]] || result+="${result:+,}$p"; done
         [[ -n "$result" ]] || { err "At least one service port must remain."; continue; }
         profile_update "$id" "$ROLE" "$local_ip" "$peer" "$result" "$udp" "$subnet" "$TUN_IF" || return ;;
      4) ports=$(normalize_ports_list "$(prompt_default 'New service ports' "$SERVICE_PORTS")") || continue
         profile_update "$id" "$ROLE" "$local_ip" "$peer" "$ports" "$udp" "$subnet" "$TUN_IF" || return ;;
      5) local_ip=$(prompt_default 'Local public IPv4' "$LOCAL_PUBLIC_IP")
         peer=$(prompt_default 'Peer public IPv4' "$PEER_PUBLIC_IP")
         profile_update "$id" "$ROLE" "$local_ip" "$peer" "$ports" "$udp" "$subnet" "$TUN_IF" || return ;;
      6) udp=$(prompt_default 'UDP (yes/no)' "$ALLOW_UDP")
         profile_update "$id" "$ROLE" "$local_ip" "$peer" "$ports" "$udp" "$subnet" "$TUN_IF" || return ;;
      7) ( acquire_management_lock && profile_start_service "$id" ) || return ;;
      8) ( acquire_management_lock && profile_stop_service "$id" ) || return ;;
      9) ( acquire_management_lock && profile_preflight && profile_stop_service "$id" && profile_start_service "$id" ) || return ;;
      10) if [[ $(prompt_default "Type $id to confirm removal" "") == "$id" ]]; then profile_remove "$id"; return; fi ;;
      11) return ;;
      *) err "Invalid option." ;;
    esac
  done
}

# Canonical v1.0.1 helper generated with the documented installation paths.
LEGACY_HELPER_SHA256="682ae45f5424789d582d393ee691213e01603301b86f4b26110720d67d349e63"

legacy_safe_path() {
  local path="$1"
  [[ "$path" == /* ]] || return 1
  while [[ "$path" != / ]]; do
    [[ ! -L "$path" ]] || return 1
    path=${path%/*}
    [[ -n "$path" ]] || path=/
  done
}

legacy_owned_file() {
  local mode
  legacy_safe_path "$1" && [[ -f "$1" && -O "$1" ]] || return 1
  mode=$(stat -c %a "$1") || return
  (( (8#$mode & 0022) == 0 ))
}

legacy_read_conf() {
  local file="$1" line key value
  local -A seen=()
  legacy_owned_file "$file" || { err "Unsafe legacy configuration: $file"; return 1; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([A-Z_]+)=\"([a-zA-Z0-9.,:/_-]*)\"$ ]] || { err "Unknown legacy configuration format."; return 1; }
    key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
    case "$key" in
      ROLE|LOCAL_PUBLIC_IP|PEER_PUBLIC_IP|SERVICE_PORTS|ALLOW_UDP|TUN_IF|IRAN_TUN_CIDR|KHAREJ_TUN_CIDR) ;;
      *) err "Unknown legacy configuration field: $key"; return 1 ;;
    esac
    [[ ! ${seen[$key]:-} ]] || { err "Duplicate legacy configuration field: $key"; return 1; }
    seen[$key]=1
    printf -v "$key" '%s' "$value"
  done < "$file"
  [[ ${#seen[@]} == 8 && ( "$ROLE" == iran || "$ROLE" == kharej ) && ( "$ALLOW_UDP" == yes || "$ALLOW_UDP" == no ) ]] || return 1
  validate_ipv4 "$LOCAL_PUBLIC_IP" && validate_ipv4 "$PEER_PUBLIC_IP" || return 1
  [[ "$LOCAL_PUBLIC_IP" != "$PEER_PUBLIC_IP" ]] || return 1
  SERVICE_PORTS=$(normalize_ports_list "$SERVICE_PORTS") || return
  [[ "$TUN_IF" == GRE && "$IRAN_TUN_CIDR" == 172.16.1.1/30 && "$KHAREJ_TUN_CIDR" == 172.16.1.2/30 ]] || {
    err "Only the canonical v1.0.1 GRE interface and tunnel addresses can be imported automatically."
    return 1
  }
}

legacy_verify_unit() {
  local unit="$1"
  legacy_owned_file "$unit" || return 1
  # An edited unit can execute a different helper during systemctl stop.
  cmp -s "$unit" <(cat <<EOF
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
  ) || { err "Legacy service unit was edited; review it manually before migration."; return 1; }
}

legacy_verify_helper() {
  local digest
  legacy_owned_file "$APPLY_SCRIPT" && [[ -x "$APPLY_SCRIPT" ]] || return 1
  digest=$(sha256sum "$APPLY_SCRIPT") || return
  [[ ${digest%% *} == "$LEGACY_HELPER_SHA256" ]] || {
    err "Installed helper is not the recognized v1.0.1 helper; automatic migration refused."
    return 1
  }
}

legacy_stop_compatible() (
  legacy_verify_helper || return
  if type -P sshd >/dev/null 2>&1; then
    # Older verified helpers expect lowercase keywords from OpenSSH's dump.
    sshd() {
      local config line
      if [[ $# == 1 && $1 == -T ]]; then
        config=$(command sshd "$@") || return
        while IFS= read -r line || [[ -n "$line" ]]; do
          if [[ "$line" =~ ^([[:space:]]*)([^[:space:]]+)(.*)$ ]]; then
            printf '%s%s%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2],,}" "${BASH_REMATCH[3]}"
          else
            printf '%s\n' "$line"
          fi
        done <<< "$config"
      else
        command sshd "$@"
      fi
    }
    export -f sshd
  fi
  "$APPLY_SCRIPT" stop
)

legacy_verify_effective_unit() {
  local fragment dropins reload
  fragment=$(systemctl show --property=FragmentPath --value gre4.service) || return
  dropins=$(systemctl show --property=DropInPaths --value gre4.service) || return
  reload=$(systemctl show --property=NeedDaemonReload --value gre4.service) || return
  [[ "$fragment" == "$1" && -z "$dropins" && "$reload" == no ]] || {
    err "Legacy unit has overrides or stale systemd configuration; review and reload it before migration."
    return 1
  }
}

legacy_validate_recovery() {
  local name directory persistent key previous applied extra count target expected
  local -a keys=()
  legacy_safe_path "$STATE_DIR" && legacy_safe_path "$SYSCTL_DIR" || return 1
  [[ ! -e "$STATE_DIR" || ( -d "$STATE_DIR" && -O "$STATE_DIR" ) ]] || return 1
  for name in forward conntrack; do
    directory="$STATE_DIR/sysctl/$name"
    persistent="$SYSCTL_DIR/99-gre4-$name.conf"
    if [[ ! -e "$directory" ]]; then
      [[ ! -e "$persistent" && ! -L "$persistent" ]] || {
        err "Legacy sysctl file has no ownership record: $persistent"; return 1;
      }
      continue
    fi
    legacy_safe_path "$directory" && [[ -d "$directory" && -O "$directory" ]] || return 1
    legacy_owned_file "$directory/file" && legacy_owned_file "$directory/values" || return 1
    if [[ "$name" == forward ]]; then keys=(net.ipv4.ip_forward net.ipv4.conf.all.forwarding)
    else keys=(net.netfilter.nf_conntrack_max); fi
    count=0; expected=""
    while read -r key previous applied extra; do
      [[ "$key" == "${keys[$count]:-}" && "$previous" =~ ^[0-9]+$ && "$applied" =~ ^[0-9]+$ && -z "$extra" ]] || return 1
      target="$key=$applied"
      expected+="$target"$'\n'
      count=$((count + 1))
    done < "$directory/values"
    [[ "$count" == "${#keys[@]}" ]] || return 1
    [[ $(cat "$directory/file") == "${expected%$'\n'}" ]] || return 1
    if [[ -e "$persistent" || -L "$persistent" ]]; then
      legacy_owned_file "$persistent" && cmp -s "$directory/file" "$persistent" || {
        err "Preserving an administrator-edited legacy sysctl file: $persistent"; return 1;
      }
    fi
    for target in restore restored; do
      [[ ! -e "$directory/$target" && ! -L "$directory/$target" ]] || legacy_owned_file "$directory/$target" || return 1
    done
  done
}

profile_migration_start_allowed() {
  [[ "$1" == legacy ]] || return 0
  local root="${MIGRATION_BACKUP_DIR:-/var/backups/gre4}" backup stage
  legacy_safe_path "$root" || return 1
  [[ -e "$root/pending" || -L "$root/pending" ]] || return 0
  [[ -d "$root" && -O "$root" && $(stat -c %a "$root") == 700 ]] || return 1
  legacy_owned_file "$root/pending" || return 1
  read -r backup < "$root/pending" || return
  [[ "$backup" == "$root"/migration.* && -d "$backup" && -O "$backup" ]] && legacy_safe_path "$backup" || return 1
  [[ $(stat -c %a "$backup") == 700 ]] || return 1
  legacy_owned_file "$backup/stage" || return 1
  read -r stage < "$backup/stage" || return
  case "$stage" in
    new-installed|complete) return 0 ;;
    *) err "Legacy migration recovery blocks profile start. Retry migration before starting legacy."; return 1 ;;
  esac
}

migration_set_stage() {
  local staged
  staged=$(mktemp "$1/.stage.XXXXXX") || return
  if ! printf '%s\n' "$2" > "$staged" || ! chmod 600 "$staged" || ! mv -f "$staged" "$1/stage"; then
    rm -f "$staged"; return 1
  fi
}

migration_restore_file() {
  local staged
  legacy_owned_file "$1" && legacy_safe_path "$2" || return 1
  staged=$(mktemp "$2.rollback.XXXXXX") || return
  if ! cp -p "$1" "$staged" || ! mv -f "$staged" "$2"; then
    rm -f "$staged"; return 1
  fi
}

migration_restore_legacy() {
  local backup="$1" legacy_conf="$2" legacy_unit="$3" was_active="$4" was_enabled="$5" file
  # The shared helper cannot be rolled back if another profile was introduced.
  for file in "$PROFILE_DIR"/*.conf; do
    [[ ! -e "$file" || "$file" == "$PROFILE_DIR/legacy.conf" ]] || { err "Other profiles block legacy rollback."; return 1; }
  done
  systemctl disable gre4@legacy.service || return
  [[ ! -e "$STATE_DIR/profiles/legacy/applied.conf" && ! -L "$STATE_DIR/profiles/legacy/applied.conf" && ! -e "$STATE_DIR/profiles/legacy/cleanup-pending" && ! -L "$STATE_DIR/profiles/legacy/cleanup-pending" ]] || {
    err "Live profile recovery state blocks legacy restoration. Backup: $backup"; return 1;
  }
  # Publish restoration before replacing any files; retries must not run the old helper as profile cleanup.
  migration_set_stage "$backup" restoring-legacy || return
  if [[ -e "$PROFILE_DIR/legacy.conf" ]]; then
    legacy_owned_file "$PROFILE_DIR/legacy.conf" && cmp -s "$PROFILE_DIR/legacy.conf" "$backup/profile.conf" || {
      err "Imported profile changed; retaining it for manual recovery."; return 1;
    }
    rm -f "$PROFILE_DIR/legacy.conf" || return
  fi
  migration_restore_file "$backup/gre4.conf" "$legacy_conf" || return
  migration_restore_file "$backup/gre4-apply.sh" "$APPLY_SCRIPT" || return
  migration_restore_file "$backup/gre4.service" "$legacy_unit" || return
  if [[ -e "$TEMPLATE_FILE" ]]; then
    legacy_owned_file "$TEMPLATE_FILE" && cmp -s "$TEMPLATE_FILE" "$backup/profile.service" || return 1
    rm -f "$TEMPLATE_FILE" || return
  fi
  systemctl daemon-reload || return
  if [[ "$was_enabled" == yes ]]; then systemctl enable gre4.service || return
  else systemctl disable gre4.service || return; fi
  # Recovery snapshots are evidence, never blindly copied over current runtime state.
  if [[ "$was_active" == yes ]]; then systemctl start gre4.service || return; fi
  migration_set_stage "$backup" rolled-back || return
  return 0
}

migrate_legacy_deployment() (
  MIGRATING_LEGACY=1
  acquire_management_lock || return
  local legacy_conf="${LEGACY_CONF_FILE:-/etc/gre4.conf}" legacy_unit="${LEGACY_UNIT_FILE:-/etc/systemd/system/gre4.service}"
  local backup_root="${MIGRATION_BACKUP_DIR:-/var/backups/gre4}" backup stage was_active=no was_enabled=no file staged
  local role local_ip peer_ip ports udp
  legacy_safe_path "$backup_root" && legacy_safe_path "$PROFILE_DIR" && legacy_safe_path "$TEMPLATE_FILE" || return 1
  if [[ -e "$backup_root" ]]; then
    [[ -d "$backup_root" && -O "$backup_root" ]] || return 1
  fi
  mkdir -p "$backup_root" || return
  chmod 700 "$backup_root" || return
  if [[ -e "$backup_root/pending" || -L "$backup_root/pending" ]]; then
    legacy_owned_file "$backup_root/pending" || return 1
    read -r backup < "$backup_root/pending" || return
    [[ "$backup" == "$backup_root"/migration.* && -d "$backup" && -O "$backup" ]] && legacy_safe_path "$backup" || return 1
    legacy_owned_file "$backup/stage" && legacy_owned_file "$backup/intent" && legacy_owned_file "$backup/targets" || return 1
    read -r stage < "$backup/stage" || return
    read -r was_active was_enabled < "$backup/intent" || return
    [[ ( "$was_active" == yes || "$was_active" == no ) && ( "$was_enabled" == yes || "$was_enabled" == no ) ]] || return 1
    cmp -s "$backup/targets" <(printf '%s\n' "$legacy_conf" "$legacy_unit" "$APPLY_SCRIPT" "$TEMPLATE_FILE" "$PROFILE_DIR" "$STATE_DIR" "$SYSCTL_DIR") || return 1
  else
    legacy_read_conf "$legacy_conf" && legacy_verify_helper && legacy_verify_unit "$legacy_unit" && legacy_validate_recovery || return 1
    for file in "$PROFILE_DIR"/*.conf "$STATE_DIR"/profiles/*; do
      [[ ! -e "$file" && ! -L "$file" ]] || { err "Migrate the singleton before creating profiles."; return 1; }
    done
    [[ ! -e "$TEMPLATE_FILE" && ! -L "$TEMPLATE_FILE" ]] || { err "An existing profile service blocks legacy migration."; return 1; }
    systemctl is-active --quiet gre4.service && was_active=yes
    systemctl is-enabled --quiet gre4.service && was_enabled=yes
    backup=$(mktemp -d "$backup_root/migration.XXXXXX") || return
    chmod 700 "$backup" || return
    cp -p "$legacy_conf" "$backup/gre4.conf" && cp -p "$APPLY_SCRIPT" "$backup/gre4-apply.sh" && cp -p "$legacy_unit" "$backup/gre4.service" || return
    if [[ -d "$STATE_DIR/sysctl" ]]; then cp -a "$STATE_DIR/sysctl" "$backup/sysctl" || return; fi
    printf '%s %s\n' "$was_active" "$was_enabled" > "$backup/intent" || return
    printf '%s\n' "$legacy_conf" "$legacy_unit" "$APPLY_SCRIPT" "$TEMPLATE_FILE" "$PROFILE_DIR" "$STATE_DIR" "$SYSCTL_DIR" > "$backup/targets" || return
    chmod 600 "$backup/intent" "$backup/targets" || return
    migration_set_stage "$backup" prepared || return
    staged=$(mktemp "$backup_root/.pending.XXXXXX") || return
    if ! printf '%s\n' "$backup" > "$staged" || ! chmod 600 "$staged" || ! mv -f "$staged" "$backup_root/pending"; then
      rm -f "$staged"; return 1
    fi
    stage=prepared
  fi
  if [[ "$stage" == complete ]]; then
    [[ -f "$PROFILE_DIR/legacy.conf" && -f "$TEMPLATE_FILE" && ! -e "$legacy_conf" && ! -e "$legacy_unit" ]] || {
      err "Completed migration journal disagrees with installation; review $backup"; return 1;
    }
    for file in "$backup/profile.helper" "$backup/profile.service" "$backup/profile.conf" "$APPLY_SCRIPT" "$TEMPLATE_FILE" "$PROFILE_DIR/legacy.conf"; do
      legacy_owned_file "$file" || return 1
    done
    cmp -s "$APPLY_SCRIPT" "$backup/profile.helper" &&
      cmp -s "$TEMPLATE_FILE" "$backup/profile.service" &&
      cmp -s "$PROFILE_DIR/legacy.conf" "$backup/profile.conf" &&
      upgrade_verify_effective_unit gre4@legacy.service || {
      err "Completed migration artifacts changed; preserve the pending journal and backup $backup"; return 1;
    }
    # This completed journal may belong to an older release; normal upgrade
    # recognition decides its version after the verified journal is cleared.
    rm -f "$backup_root/pending" || return
    log "Legacy migration was already completed. Backup retained: $backup"
    return 0
  fi
  if [[ "$stage" == rolled-back ]]; then
    legacy_verify_helper && legacy_verify_unit "$legacy_unit" && legacy_read_conf "$legacy_conf" || return 1
    rm -f "$backup_root/pending" || return
    warn "Legacy rollback was already completed. Review it before retrying migration. Backup: $backup"
    return 1
  fi
  if [[ "$stage" == recovery-needed || "$stage" == rollback-needed || "$stage" == restoring-legacy ]]; then
    systemctl disable gre4@legacy.service || return
    if [[ "$stage" != restoring-legacy ]]; then
      # Older interrupted rollbacks may already contain the singleton helper; never guess its ownership.
      legacy_owned_file "$backup/profile.helper" && legacy_owned_file "$APPLY_SCRIPT" && cmp -s "$APPLY_SCRIPT" "$backup/profile.helper" || {
        err "Cannot verify installed profile helper; retaining recovery state for manual review. Backup: $backup"; return 1;
      }
      profile_stop_service legacy || { err "New-profile cleanup is still incomplete. Recovery backup: $backup"; return 1; }
      migration_set_stage "$backup" rollback-needed || return
    fi
    migration_restore_legacy "$backup" "$legacy_conf" "$legacy_unit" "$was_active" "$was_enabled" || {
      err "Legacy rollback requires recovery. Backup: $backup"; return 1;
    }
    rm -f "$backup_root/pending" || return
    warn "Legacy installation restored. Review it before retrying migration. Backup: $backup"
    return 1
  fi
  [[ "$stage" == prepared || "$stage" == legacy-clean || "$stage" == new-installed ]] || { err "Unknown migration recovery stage: $stage"; return 1; }
  legacy_read_conf "$backup/gre4.conf" || return
  role=$ROLE; local_ip=$LOCAL_PUBLIC_IP; peer_ip=$PEER_PUBLIC_IP; ports=$SERVICE_PORTS; udp=$ALLOW_UDP
  if [[ "$stage" == prepared ]]; then
    legacy_verify_helper && legacy_verify_unit "$legacy_unit" && legacy_verify_effective_unit "$legacy_unit" || return 1
    cmp -s "$legacy_conf" "$backup/gre4.conf" && cmp -s "$APPLY_SCRIPT" "$backup/gre4-apply.sh" && cmp -s "$legacy_unit" "$backup/gre4.service" || {
      err "Legacy installation changed during migration; review backup $backup"; return 1;
    }
    profile_preflight || return 1
    if ! systemctl stop gre4.service || ! legacy_stop_compatible; then
      err "Legacy cleanup failed; original installation retained. Retry migration after recovery. Backup: $backup"
      return 1
    fi
    for file in "$STATE_DIR/sysctl/forward" "$STATE_DIR/sysctl/conntrack" "$SYSCTL_DIR/99-gre4-forward.conf" "$SYSCTL_DIR/99-gre4-conntrack.conf"; do
      [[ ! -e "$file" && ! -L "$file" ]] || { err "Legacy recovery remains at $file; retaining backup $backup"; return 1; }
    done
    systemctl disable gre4.service || return
    migration_set_stage "$backup" legacy-clean || return
    stage=legacy-clean
  fi
  if [[ "$stage" == legacy-clean ]]; then
    if [[ -e "$PROFILE_DIR/legacy.conf" || -L "$PROFILE_DIR/legacy.conf" ]]; then
      legacy_owned_file "$PROFILE_DIR/legacy.conf" && read_profile_file "$PROFILE_DIR/legacy.conf" || return 1
      [[ "$ROLE" == "$role" && "$LOCAL_PUBLIC_IP" == "$local_ip" && "$PEER_PUBLIC_IP" == "$peer_ip" && "$SERVICE_PORTS" == "$ports" && "$ALLOW_UDP" == "$udp" && "$TUN_IF" == GRE && "$IRAN_TUN_CIDR" == 172.16.1.1/30 && "$KHAREJ_TUN_CIDR" == 172.16.1.2/30 ]] || {
        err "A changed legacy profile blocks migration retry. Backup: $backup"; return 1;
      }
    fi
    if ! write_profile legacy "$role" "$local_ip" "$peer_ip" "$ports" "$udp" 172.16.1.0/30 GRE; then
      err "Cannot create imported profile; legacy service remains stopped. Retry migration. Backup: $backup"
      return 1
    fi
    cp -p "$PROFILE_DIR/legacy.conf" "$backup/profile.conf" || return
    # Journal the cutover before replacing the helper so interruption is recoverable.
    migration_set_stage "$backup" new-installed || return
    if ! install_apply_script || ! install_profile_unit; then
      err "Profile installation interrupted; retry migration. Backup: $backup"
      return 1
    fi
    cp -p "$TEMPLATE_FILE" "$backup/profile.service" || return
  else
    # Installation can have been interrupted after journaling the cutover.
    cmp -s "$PROFILE_DIR/legacy.conf" "$backup/profile.conf" || { err "Imported profile changed; review $backup"; return 1; }
    install_apply_script && install_profile_unit || return
    cp -p "$TEMPLATE_FILE" "$backup/profile.service" || return
  fi
  cp -p "$APPLY_SCRIPT" "$backup/profile.helper" || return
  if [[ "$was_enabled" == yes ]]; then systemctl enable gre4@legacy.service || return
  else systemctl disable gre4@legacy.service || return; fi
  if [[ "$was_active" == yes ]] && ! profile_start_service legacy; then
    migration_set_stage "$backup" recovery-needed || return
    systemctl disable gre4@legacy.service || return
    if ! profile_stop_service legacy; then
      err "Imported profile cleanup failed; old service remains disabled. Retry migration for recovery. Backup: $backup"
      return 1
    fi
    migration_set_stage "$backup" rollback-needed || return
    if migration_restore_legacy "$backup" "$legacy_conf" "$legacy_unit" "$was_active" "$was_enabled"; then
      rm -f "$backup_root/pending" || return
      err "Imported profile failed; legacy installation restored. Backup: $backup"
    else
      err "Imported profile failed and rollback needs recovery. Backup: $backup"
    fi
    return 1
  fi
  rm -f "$legacy_conf" "$legacy_unit" || return
  systemctl daemon-reload || return
  record_installed_release || return
  migration_set_stage "$backup" complete || return
  rm -f "$backup_root/pending" || return
  log "Legacy installation imported as profile legacy. Backup retained: $backup"
)

release_tag_valid() {
  [[ "${1:-}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

release_verified_handoff() {
  local tag="${1:-}" expected="${2:-}" script="${3:-}" actual
  if ! release_tag_valid "$tag" || [[ ! "$expected" =~ ^[0-9a-f]{64}$ || ! -f "$script" ]]; then
    err "Invalid verified-release handoff. Run the documented installation command again."
    return 1
  fi
  actual=$(sha256sum -- "$script") || return
  [[ "${actual%% *}" == "$expected" ]] || {
    err "Release payload changed after verification; refusing to continue."
    return 1
  }
  GRE4_RELEASE_TAG="$tag"
  GRE4_RELEASE_SHA="$expected"
}

release_bootstrap() (
  local work resolved tag checksum expected
  local origin=https://github.com/vahid162/gre-4/releases
  local -a fetch=(curl --fail --silent --show-error --location --max-redirs 5
    --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 120
    --retry 2 --retry-delay 1 --retry-max-time 60)
  ensure_cmd curl || return
  ensure_cmd sha256sum || return
  work=$(mktemp -d -- "${TMPDIR:-/tmp}/gre4-release.XXXXXXXX") || return
  trap 'rm -rf -- "$work"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  chmod 700 "$work" || return
  resolved=$("${fetch[@]}" --output /dev/null --write-out '%{url_effective}' "$origin/latest") || return
  tag=${resolved#"$origin/tag/"}
  if [[ "$resolved" != "$origin/tag/$tag" ]] || ! release_tag_valid "$tag"; then
    err "Could not resolve a stable GRE4 release; installation was not changed."
    return 1
  fi
  "${fetch[@]}" --output "$work/gre4.sh" "$origin/download/$tag/gre4.sh" || return
  "${fetch[@]}" --output "$work/SHA256SUMS" "$origin/download/$tag/SHA256SUMS" || return
  IFS= read -r checksum < "$work/SHA256SUMS" || {
    err "Invalid release checksum manifest; installation was not changed."
    return 1
  }
  [[ "$checksum" =~ ^([0-9a-f]{64})\ \ gre4\.sh$ ]] || {
    err "Invalid release checksum manifest; installation was not changed."
    return 1
  }
  expected=${BASH_REMATCH[1]}
  # Compare bytes too: read ignores NUL bytes and only consumes the first line.
  if ! cmp -s "$work/SHA256SUMS" <(printf '%s  gre4.sh\n' "$expected") ||
      ! (cd "$work" && sha256sum --check --status SHA256SUMS); then
      err "Release checksum verification failed; installation was not changed."
    return 1
  fi
  log "Verified latest stable release: $tag"
  bash "$work/gre4.sh" --gre4-release "$tag" "$expected" "$@"
)

# Unmarked installations are recognized by the canonical helper emitted by v1.1.1.
UPGRADE_V111_HELPER_SHA256="1bde86457fce770ff00c9e2c339fae9dae152ac5bd72f1385a31f76fa99eb86d"
# Bash 5.1 serializes declare -f redirections and literal newlines differently.
UPGRADE_V111_BASH51_HELPER_SHA256="d4b886236ae42f2b0a2e8f7a7ffd83f47137af3ef95ee2c49933098d2e7a28a8"
RELEASE_STAMP_FILE="/var/lib/gre4-release"

upgrade_safe_directory() {
  local path="$1" mode
  legacy_safe_path "$path" || return 1
  [[ ! -e "$path" ]] && return 0
  [[ -d "$path" && -O "$path" ]] || return 1
  mode=$(stat -c %a "$path") || return
  (( (8#$mode & 0022) == 0 ))
}

record_installed_release() {
  [[ -n ${GRE4_RELEASE_TAG:-} ]] || return 0
  local staged helper unit parent=${RELEASE_STAMP_FILE%/*}
  release_tag_valid "$GRE4_RELEASE_TAG" && [[ ${GRE4_RELEASE_SHA:-} =~ ^[0-9a-f]{64}$ ]] || return 1
  upgrade_safe_directory "$parent" && legacy_safe_path "$RELEASE_STAMP_FILE" || return 1
  [[ ! -e "$RELEASE_STAMP_FILE" ]] || private_config_file "$RELEASE_STAMP_FILE" || return 1
  legacy_owned_file "$APPLY_SCRIPT" && legacy_owned_file "$TEMPLATE_FILE" || return 1
  helper=$(sha256sum "$APPLY_SCRIPT") && unit=$(sha256sum "$TEMPLATE_FILE") || return
  staged=$(mktemp "$parent/.gre4-release.XXXXXX") || return
  if ! printf '%s %s %s %s\n' "$GRE4_RELEASE_TAG" "${helper%% *}" "${unit%% *}" "$GRE4_RELEASE_SHA" > "$staged" ||
      ! chmod 600 "$staged" || ! mv -f "$staged" "$RELEASE_STAMP_FILE"; then
    rm -f "$staged"; return 1
  fi
}

upgrade_verify_effective_unit() {
  local unit="$1" fragment dropins reload
  fragment=$(systemctl show --property=FragmentPath --value "$unit") || return
  dropins=$(systemctl show --property=DropInPaths --value "$unit") || return
  reload=$(systemctl show --property=NeedDaemonReload --value "$unit") || return
  [[ "$fragment" == "$TEMPLATE_FILE" && -z "$dropins" && "$reload" == no ]] || {
    err "Unit $unit has overrides or stale systemd configuration; review it before upgrading."; return 1;
  }
}

upgrade_verify_listed_unit() {
  local unit="$1" id
  [[ "$unit" != 'gre4@.service' ]] || return 0
  [[ "$unit" == gre4@*.service ]] || return 1
  id=${unit#gre4@}; id=${id%.service}
  validate_profile_id "$id" || return 1
  [[ ! -f "$PROFILE_DIR/$id.conf" ]] || return 0
  # systemd may cache a stopped template instance after normal profile removal.
  # An active/enabled/customized orphan still requires review before any mutation.
  if [[ ! -e "$PROFILE_DIR/$id.conf" && ! -L "$PROFILE_DIR/$id.conf" &&
        ! -e "$STATE_DIR/profiles/$id" && ! -L "$STATE_DIR/profiles/$id" ]] &&
      upgrade_verify_effective_unit "$unit" &&
      [[ $(systemctl show --property=ActiveState --value "$unit") == inactive &&
         $(systemctl show --property=UnitFileState --value "$unit") == disabled ]]; then
    return 0
  fi
  err "Orphan GRE4 service requires review: $unit"
  return 1
}

upgrade_verify_health() (
  local id="$1" address addresses
  systemctl is-active --quiet "gre4@$id.service" && load_profile "$id" || return 1
  private_config_file "$STATE_DIR/profiles/$id/applied.conf" &&
    cmp -s "$CONF_FILE" "$STATE_DIR/profiles/$id/applied.conf" || return 1
  [[ ! -e "$STATE_DIR/profiles/$id/cleanup-pending" && ! -L "$STATE_DIR/profiles/$id/cleanup-pending" ]] || return 1
  profile_interface_owned || return
  if [[ "$ROLE" == iran ]]; then address="$IRAN_TUN_CIDR"; else address="$KHAREJ_TUN_CIDR"; fi
  addresses=$(ip -o -4 addr show dev "$TUN_IF") || return
  awk -v wanted="$address" '$3=="inet" && $4==wanted {found=1} END {exit !found}' <<< "$addresses"
)

upgrade_verify_profiles_unchanged() {
  local backup="$1" file id active enabled extra count=0
  while read -r id active enabled extra; do
    validate_profile_id "$id" && [[ -z "$extra" ]] || return 1
    private_config_file "$PROFILE_DIR/$id.conf" && cmp -s "$PROFILE_DIR/$id.conf" "$backup/profiles/$id.conf" || {
      err "Profile $id changed during the upgrade. Backup: $backup"; return 1;
    }
    count=$((count+1))
  done < "$backup/intent"
  for file in "$PROFILE_DIR"/*.conf; do
    [[ -e "$file" || -L "$file" ]] || continue
    count=$((count-1))
  done
  [[ "$count" == 0 ]]
}

upgrade_release_runtime_lock() {
  [[ ${UPGRADE_RUNTIME_LOCKED:-0} == 1 ]] || return 0
  flock -u 8 || return
  exec 8>&-
  UPGRADE_RUNTIME_LOCKED=0
}

upgrade_cleanup_profiles() {
  local backup="$1" id active enabled failed=0
  while read -r id active enabled; do
    # The matching installed helper owns cleanup; snapshots are never runtime input.
    profile_stop_service "$id" || failed=1
    [[ ! -e "$STATE_DIR/profiles/$id/applied.conf" && ! -L "$STATE_DIR/profiles/$id/applied.conf" &&
       ! -e "$STATE_DIR/profiles/$id/cleanup-pending" && ! -L "$STATE_DIR/profiles/$id/cleanup-pending" ]] || failed=1
  done < "$backup/intent"
  [[ "$failed" == 0 ]]
}

upgrade_unmask_profiles() {
  local backup="$1" id active enabled
  while read -r id active enabled; do
    systemctl unmask "gre4@$id.service" || return
  done < "$backup/intent"
}

upgrade_start_profiles() {
  local backup="$1" id active enabled
  while read -r id active enabled; do
    if [[ "$active" == active ]]; then
      systemctl start "gre4@$id.service" && upgrade_verify_health "$id" || return 1
    else
      # An inactive but enabled service must remain inactive during this invocation.
      if systemctl is-active --quiet "gre4@$id.service"; then return 1; fi
    fi
    [[ $(systemctl show --property=UnitFileState --value "gre4@$id.service") == "$enabled" ]] || return 1
  done < "$backup/intent"
}

upgrade_prepare_artifacts() (
  local backup="$1" installed_helper="$APPLY_SCRIPT"
  APPLY_SCRIPT="$backup/new-helper"
  install_apply_script >/dev/null || return
  APPLY_SCRIPT="$installed_helper"
  TEMPLATE_FILE="$backup/new-unit"
  render_profile_unit > "$TEMPLATE_FILE" && chmod 644 "$TEMPLATE_FILE" || return
  APPLY_SCRIPT="$backup/new-helper"
  RELEASE_STAMP_FILE="$backup/new-release"
  record_installed_release
)

upgrade_apply() {
  local backup="$1" id active enabled
  upgrade_verify_profiles_unchanged "$backup" &&
    cmp -s "$APPLY_SCRIPT" "$backup/gre4-apply.sh" && cmp -s "$TEMPLATE_FILE" "$backup/gre4@.service" || return 1
  # Persistent per-instance masks also keep an interrupted cutover stopped after reboot.
  while read -r id active enabled; do
    systemctl mask "gre4@$id.service" || return
  done < "$backup/intent"
  upgrade_release_runtime_lock || return
  migration_set_stage "$backup" stopping || return
  upgrade_cleanup_profiles "$backup" || return
  migration_set_stage "$backup" old-clean || return
  migration_restore_file "$backup/new-helper" "$APPLY_SCRIPT" || return
  migration_restore_file "$backup/new-unit" "$TEMPLATE_FILE" || return
  systemctl daemon-reload || return
  migration_set_stage "$backup" new-installed || return
  upgrade_verify_profiles_unchanged "$backup" || return
  upgrade_unmask_profiles "$backup" || return
  upgrade_start_profiles "$backup" || return
  cmp -s "$APPLY_SCRIPT" "$backup/new-helper" && cmp -s "$TEMPLATE_FILE" "$backup/new-unit" || return 1
  migration_restore_file "$backup/new-release" "$RELEASE_STAMP_FILE" || return
  migration_set_stage "$backup" complete || return
  rm -f "$MIGRATION_BACKUP_DIR/upgrade-pending" || return
  log "Installed $GRE4_RELEASE_TAG; configuration and service intent preserved. Backup: $backup"
}

upgrade_rollback() {
  local backup="$1" id active enabled
  upgrade_verify_profiles_unchanged "$backup" || return
  legacy_owned_file "$APPLY_SCRIPT" && legacy_owned_file "$TEMPLATE_FILE" || return 1
  { cmp -s "$APPLY_SCRIPT" "$backup/gre4-apply.sh" ||
      { legacy_owned_file "$backup/new-helper" && cmp -s "$APPLY_SCRIPT" "$backup/new-helper"; }; } || return 1
  { cmp -s "$TEMPLATE_FILE" "$backup/gre4@.service" ||
      { legacy_owned_file "$backup/new-unit" && cmp -s "$TEMPLATE_FILE" "$backup/new-unit"; }; } || return 1
  while read -r id active enabled; do
    systemctl mask "gre4@$id.service" || return
  done < "$backup/intent"
  if [[ -e "$RELEASE_STAMP_FILE" || -L "$RELEASE_STAMP_FILE" ]]; then
    private_config_file "$RELEASE_STAMP_FILE" || return
    { { [[ -f "$backup/release" ]] && cmp -s "$RELEASE_STAMP_FILE" "$backup/release"; } ||
      { [[ -f "$backup/new-release" ]] && cmp -s "$RELEASE_STAMP_FILE" "$backup/new-release"; }; } || return 1
  else
    [[ ! -e "$backup/release" ]] || return 1
  fi
  upgrade_release_runtime_lock || return
  migration_set_stage "$backup" rollback-cleanup || return
  upgrade_cleanup_profiles "$backup" || return
  migration_restore_file "$backup/gre4-apply.sh" "$APPLY_SCRIPT" &&
    migration_restore_file "$backup/gre4@.service" "$TEMPLATE_FILE" || return 1
  if [[ -f "$backup/release" ]]; then
    migration_restore_file "$backup/release" "$RELEASE_STAMP_FILE" || return
  else
    [[ ! -e "$RELEASE_STAMP_FILE" ]] || private_config_file "$RELEASE_STAMP_FILE" || return 1
    rm -f "$RELEASE_STAMP_FILE" || return
  fi
  systemctl daemon-reload || return
  upgrade_unmask_profiles "$backup" && upgrade_start_profiles "$backup" || return 1
  migration_set_stage "$backup" rolled-back || return
  rm -f "$MIGRATION_BACKUP_DIR/upgrade-pending" || return
  err "Upgrade failed; the previous installation was restored. Review before retrying. Backup: $backup"
}

automatic_upgrade() (
  GRE4_RELEASE_TAG="$1"; GRE4_RELEASE_SHA="$2"
  local file id active enabled digest unit_digest installed_tag helper_hash unit_hash manager_hash extra backup staged unit units
  local backup_root="$MIGRATION_BACKUP_DIR" count=0 UPGRADE_RUNTIME_LOCKED=0 state_entries
  manager_hash=
  release_tag_valid "$GRE4_RELEASE_TAG" && [[ "$GRE4_RELEASE_SHA" =~ ^[0-9a-f]{64}$ ]] || return 1
  if [[ -e "$backup_root/upgrade-pending" || -L "$backup_root/upgrade-pending" ]]; then
    err "An interrupted upgrade needs review. Preserve $backup_root/upgrade-pending and its backup; see RECOVERY.txt there."
    return 1
  fi
  if [[ -e "$LEGACY_CONF_FILE" || -L "$LEGACY_CONF_FILE" || -e "${LEGACY_UNIT_FILE:-$UNIT_FILE}" ||
        -L "${LEGACY_UNIT_FILE:-$UNIT_FILE}" || -e "$backup_root/pending" || -L "$backup_root/pending" ]]; then
    migrate_legacy_deployment || return
    automatic_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
    return
  fi
  acquire_management_lock && profile_runtime_lock || return
  UPGRADE_RUNTIME_LOCKED=1
  for file in "$PROFILE_DIR" "$STATE_DIR" "$LOCK_DIR" "$backup_root" "${APPLY_SCRIPT%/*}" "${TEMPLATE_FILE%/*}" "${RELEASE_STAMP_FILE%/*}"; do
    upgrade_safe_directory "$file" || { err "Unsafe installation directory: $file"; return 1; }
  done
  for file in "$APPLY_SCRIPT" "$TEMPLATE_FILE" "$RELEASE_STAMP_FILE"; do
    legacy_safe_path "$file" || return 1
  done
  shopt -s nullglob
  for file in "$PROFILE_DIR"/*.conf; do count=$((count+1)); done
  units=$(systemctl list-units --all --plain --no-legend 'gre4@*.service') || return
  while read -r unit extra; do
    [[ -n "$unit" ]] || continue
    upgrade_verify_listed_unit "$unit" || return
  done <<< "$units"
  # systemctl treats a pattern with no matching unit files as an error.
  units=$(systemctl list-unit-files --no-legend) || return
  while read -r unit extra; do
    [[ "$unit" == gre4@*.service ]] || continue
    upgrade_verify_listed_unit "$unit" || return
  done <<< "$units"
  if [[ "$count" == 0 && ! -e "$APPLY_SCRIPT" && ! -e "$TEMPLATE_FILE" && ! -e "$RELEASE_STAMP_FILE" ]]; then
    # Any recovery records make this an unknown installation rather than a fresh host.
    if [[ -d "$STATE_DIR" ]]; then
      state_entries=$(find "$STATE_DIR" -mindepth 1 -print -quit) || return
      [[ -z "$state_entries" ]] || { err "Unrecognized GRE4 recovery state; review it before installation."; return 1; }
    fi
    return 0
  fi
  legacy_owned_file "$APPLY_SCRIPT" && [[ -x "$APPLY_SCRIPT" ]] && legacy_owned_file "$TEMPLATE_FILE" || {
    err "Incomplete or unsafe GRE4 installation; automatic overwrite refused."; return 1;
  }
  digest=$(sha256sum "$APPLY_SCRIPT") || return
  digest=${digest%% *}
  unit_digest=$(sha256sum "$TEMPLATE_FILE") || return
  unit_digest=${unit_digest%% *}
  if [[ -e "$RELEASE_STAMP_FILE" ]]; then
    private_config_file "$RELEASE_STAMP_FILE" || return
    read -r installed_tag helper_hash unit_hash manager_hash extra < "$RELEASE_STAMP_FILE" || return
    release_tag_valid "$installed_tag" && [[ "$helper_hash" =~ ^[0-9a-f]{64}$ && "$unit_hash" =~ ^[0-9a-f]{64}$ &&
      "$manager_hash" =~ ^[0-9a-f]{64}$ && -z "$extra" ]] || return 1
    [[ $(wc -l < "$RELEASE_STAMP_FILE") == 1 && "$digest" == "$helper_hash" && "$unit_digest" == "$unit_hash" ]] || {
      err "Installed GRE4 files differ from their release record; automatic upgrade refused."; return 1;
    }
    [[ "$installed_tag" == "$GRE4_RELEASE_TAG" || $(printf '%s\n' "$installed_tag" "$GRE4_RELEASE_TAG" | sort -V | tail -1) == "$GRE4_RELEASE_TAG" ]] || {
      err "Installed release is newer than the selected release; automatic downgrade refused."; return 1;
    }
  else
    case "$digest" in
      "$UPGRADE_V111_HELPER_SHA256"|"$UPGRADE_V111_BASH51_HELPER_SHA256") ;;
      *) err "Installed helper is unknown; automatic upgrade refused."; return 1 ;;
    esac
    # The unmarked release has exactly this template; no edited commands are adopted.
    cmp -s "$TEMPLATE_FILE" <(cat <<EOF_UNIT
[Unit]
Description=GRE4 connection %i
Wants=network-online.target
After=network-online.target ssh.service ssh.socket

[Service]
Type=oneshot
ExecStart=$APPLY_SCRIPT start %i
ExecStopPost=$APPLY_SCRIPT post-stop %i
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_UNIT
    ) || { err "Unrecognized GRE4 service template; automatic upgrade refused."; return 1; }
    installed_tag=v1.1.1
  fi
  if [[ -e "$STATE_DIR" ]]; then
    state_entries=$(find "$STATE_DIR" -type l -print -quit) || return
    [[ -z "$state_entries" ]] || { err "Symlink in GRE4 runtime recovery state; automatic upgrade refused."; return 1; }
  fi
  for file in "$STATE_DIR"/profiles/*; do
    [[ -d "$file" && ! -L "$file" && -O "$file" ]] || return 1
    id=${file##*/}
    validate_profile_id "$id" && [[ -f "$PROFILE_DIR/$id.conf" ]] || { err "Orphan GRE4 runtime record: $file"; return 1; }
  done
  # systemd cannot load runtime properties for an uninstantiated template.
  if [[ "$count" == 0 ]]; then upgrade_verify_effective_unit 'gre4@upgrade.service' || return; fi
  for file in "$PROFILE_DIR"/*.conf; do
    id=${file##*/}; id=${id%.conf}
    load_profile "$id" && upgrade_verify_effective_unit "gre4@$id.service" || return 1
    [[ ! -e "$STATE_DIR/profiles/$id/cleanup-pending" && ! -L "$STATE_DIR/profiles/$id/cleanup-pending" ]] || {
      err "Connection $id has pending cleanup; recover it before upgrading."; return 1;
    }
    active=$(systemctl show --property=ActiveState --value "gre4@$id.service") || return
    enabled=$(systemctl show --property=UnitFileState --value "gre4@$id.service") || return
    [[ ( "$active" == active || "$active" == inactive ) && ( "$enabled" == enabled || "$enabled" == disabled ) ]] || {
      err "Connection $id is failed, transitional, masked or customized; review it before upgrading."; return 1;
    }
    if [[ "$active" == active ]]; then upgrade_verify_health "$id" || { err "Connection $id is not healthy before upgrade."; return 1; }
    else [[ ! -e "$STATE_DIR/profiles/$id/applied.conf" && ! -L "$STATE_DIR/profiles/$id/applied.conf" ]] || {
      err "Inactive connection $id retains applied state; recover it before upgrading."; return 1;
    }; fi
  done
  if [[ "$installed_tag" == "$GRE4_RELEASE_TAG" ]]; then
    [[ "$manager_hash" == "$GRE4_RELEASE_SHA" ]] || { err "Release tag has different content; upgrade refused."; return 1; }
    log "Already installed: $GRE4_RELEASE_TAG. Opening the menu without restarting connections."
    return 0
  fi
  # Every role-specific prerequisite is checked before any existing service is stopped.
  for file in "$PROFILE_DIR"/*.conf; do
    id=${file##*/}; id=${id%.conf}
    load_profile "$id" && profile_preflight && check_local_public_ip "$LOCAL_PUBLIC_IP" &&
      render_profile "$id" "$ROLE" "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$SERVICE_PORTS" "$ALLOW_UDP" "$(profile_subnet "$IRAN_TUN_CIDR")" "$TUN_IF" >/dev/null || return 1
  done
  private_directory "$backup_root" || return
  backup=$(mktemp -d "$backup_root/upgrade.XXXXXX") || return
  chmod 700 "$backup" || return
  mkdir "$backup/profiles" || return
  cp -p "$APPLY_SCRIPT" "$backup/gre4-apply.sh" && cp -p "$TEMPLATE_FILE" "$backup/gre4@.service" || return
  [[ ! -e "$RELEASE_STAMP_FILE" ]] || cp -p "$RELEASE_STAMP_FILE" "$backup/release" || return
  [[ ! -d "$STATE_DIR" ]] || cp -a "$STATE_DIR" "$backup/runtime-evidence" || return
  : > "$backup/intent" || return
  for file in "$PROFILE_DIR"/*.conf; do
    id=${file##*/}; id=${id%.conf}
    cp -p "$file" "$backup/profiles/$id.conf" || return
    active=$(systemctl show --property=ActiveState --value "gre4@$id.service") || return
    enabled=$(systemctl show --property=UnitFileState --value "gre4@$id.service") || return
    [[ ( "$active" == active || "$active" == inactive ) && ( "$enabled" == enabled || "$enabled" == disabled ) ]] || return 1
    printf '%s %s %s\n' "$id" "$active" "$enabled" >> "$backup/intent" || return
  done
  chmod 600 "$backup/intent" || return
  cat > "$backup/RECOVERY.txt" <<EOF_RECOVERY
GRE4 upgrade recovery evidence. Do not copy runtime-evidence over live state.
Original profiles: $backup/profiles
Original helper: $backup/gre4-apply.sh
Original template: $backup/gre4@.service
Installed helper target: $APPLY_SCRIPT
Installed template target: $TEMPLATE_FILE
Installed release record: $RELEASE_STAMP_FILE
Original service intent: $backup/intent
Original release record: $backup/release (absent for an unmarked installation)
Journal: $backup/stage
Persistent per-instance masks may be present after interruption.
Before restoring files, verify the installed helper/template against this backup,
stop and clean every listed instance using its matching installed helper, and
confirm all applied.conf / cleanup-pending records were removed successfully.
If ownership changed or cleanup fails, preserve all files and recover manually.
Only after clean runtime: restore the old helper/template (and release record if
present), daemon-reload, unmask each listed gre4@ID.service, and start only entries
recorded active. Confirm the enabled/disabled intent and local tunnel health.
Remove $backup_root/upgrade-pending only after verified recovery. A failed cleanup
or unverified interrupted replacement requires manual review, not a blind retry.
EOF_RECOVERY
  chmod 600 "$backup/RECOVERY.txt" || return
  upgrade_prepare_artifacts "$backup" || {
    err "Cannot prepare upgrade artifacts; existing connections were not changed. Backup: $backup"; return 1;
  }
  migration_set_stage "$backup" prepared || return
  staged=$(mktemp "$backup_root/.upgrade-pending.XXXXXX") || return
  if ! printf '%s\n' "$backup" > "$staged" || ! chmod 600 "$staged" || ! mv -f "$staged" "$backup_root/upgrade-pending"; then
    rm -f "$staged"; return 1
  fi
  if upgrade_apply "$backup"; then return 0; fi
  if ! upgrade_rollback "$backup"; then
    err "Upgrade and safe rollback are incomplete. Connections may remain masked. Preserve $backup and read $backup/RECOVERY.txt."
  fi
  return 1
)

main_menu() {
  echo "1) Add connection on Iran (gateway)"
  echo "2) Add Iran peer on Kharej (outside server)"
  echo "3) Manage a connection"
  echo "4) List connections"
  echo "5) Connection status"
  echo "6) Migrate a v1.0.1 installation"
}

main() {
  need_root
  if [[ ${1:-} != --gre4-release ]]; then
    release_bootstrap "$@" || return
    return 0
  fi
  [[ $# == 3 ]] || { err "Invalid release invocation. Run the documented installation command."; return 1; }
  release_verified_handoff "$2" "$3" "${BASH_SOURCE[0]}" || return
  ensure_cmd ip || return
  ensure_cmd sysctl || return
  ensure_cmd flock || return
  automatic_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA" || return
  main_menu
  local choice id
  read -r -p "Choice (1-6): " choice || return
  case "$choice" in
    1) add_profile_interactive iran ;;
    2) add_profile_interactive kharej ;;
    3) manage_profile_menu ;;
    4) list_profiles ;;
    5) list_profiles; id=$(prompt_default 'Connection ID' ''); profile_status "$id" ;;
    6) migrate_legacy_deployment ;;
    *) err "Invalid option."; return 1 ;;
  esac
}

main "$@"
