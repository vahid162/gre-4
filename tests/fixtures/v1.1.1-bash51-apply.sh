#!/usr/bin/env bash
set -euo pipefail

STATE_DIR=/var/lib/gre4
SYSCTL_DIR=/etc/sysctl.d
UFW_DIR=/etc/ufw
UFW_BEFORE_FILE=/etc/ufw/before.rules
PROFILE_DIR=/etc/gre4/profiles
LOCK_DIR=/run/lock/gre4
UFW_DEFAULTS_FILE=/etc/default/ufw
MIGRATION_BACKUP_DIR=/var/backups/gre4
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

validate_ipv4 () 
{ 
    local ip="$1";
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1;
    IFS='.' read -r -a o <<< "$ip";
    for x in "${o[@]}";
    do
        (( 10#$x >= 0 && 10#$x <= 255 )) || return 1;
    done;
    return 0
}
validate_port () 
{ 
    local p="$1";
    [[ "$p" =~ ^[0-9]{1,5}$ ]] || return 1;
    (( 10#$p >= 1 && 10#$p <= 65535 )) || return 1;
    return 0
}
normalize_ports_list () 
{ 
    local raw="$1";
    local cleaned token;
    cleaned=$(echo "$raw" | tr ' ' ',' | tr -s ',');
    cleaned="${cleaned#,}";
    cleaned="${cleaned%,}";
    [[ -n "$cleaned" ]] || return 1;
    local -A seen=();
    local out=();
    IFS=',' read -r -a tokens <<< "$cleaned";
    for token in "${tokens[@]}";
    do
        [[ -n "$token" ]] || continue;
        validate_port "$token" || return 1;
        token=$((10#$token));
        if [[ -z "${seen[$token]:-}" ]]; then
            out+=("$token");
            seen[$token]=1;
        fi;
    done;
    [[ ${#out[@]} -gt 0 ]] || return 1;
    ( IFS=',';
    echo "${out[*]}" )
}
validate_profile_id () 
{ 
    [[ ${1:-} =~ ^[a-z][a-z0-9_-]{0,9}$ ]]
}
private_directory () 
{ 
    local path="$1";
    [[ ! -L "$path" ]] || { 
        err "Unsafe directory: $path";
        return 1
    };
    mkdir -p "$path" || return;
    [[ -d "$path" && -O "$path" ]] || return 1;
    chmod 700 "$path"
}
private_config_file () 
{ 
    local mode;
    [[ -f "$1" && ! -L "$1" && -O "$1" ]] || { 
        err "Unsafe configuration: $1";
        return 1
    };
    mode=$(stat -c '%a' "$1") || return;
    (( (8#$mode & 077) == 0 )) || { 
        err "Configuration must be private: $1";
        return 1
    }
}
ipv4_number () 
{ 
    local a b c d;
    validate_ipv4 "$1" || return 1;
    IFS=. read -r a b c d <<< "$1";
    printf '%s\n' "$(( (10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d ))"
}
number_ipv4 () 
{ 
    local n="$1";
    printf '%s.%s.%s.%s\n' "$(( (n >> 24) & 255 ))" "$(( (n >> 16) & 255 ))" "$(( (n >> 8) & 255 ))" "$(( n & 255 ))"
}
cidr_bounds () 
{ 
    local address=${1%/*} prefix=${1#*/} n mask;
    [[ "$1" == */* && "$prefix" =~ ^[0-9]{1,2}$ ]] || return 1;
    prefix=$((10#$prefix));
    (( prefix <= 32 )) || return 1;
    n=$(ipv4_number "$address") || return;
    mask=$(( (0xffffffff << (32-prefix)) & 0xffffffff ));
    printf '%s %s\n' "$((n & mask))" "$(( (n & mask) | (0xffffffff ^ mask) ))"
}
profile_subnet () 
{ 
    local base last;
    [[ "$1" == */30 ]] || return 1;
    read -r base last < <(cidr_bounds "$1");
    [[ -n "$base" ]] || return 1;
    printf '%s/30\n' "$(number_ipv4 "$base")"
}
read_profile_file () 
{ 
    local file="$1" key value line required;
    local -A seen=();
    private_config_file "$file" || return;
    unset ROLE LOCAL_PUBLIC_IP PEER_PUBLIC_IP SERVICE_PORTS ALLOW_UDP TUN_IF IRAN_TUN_CIDR KHAREJ_TUN_CIDR;
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue;
        [[ "$line" == *=* ]] || { 
            err "Invalid configuration line in $file";
            return 1
        };
        key=${line%%=*};
        value=${line#*=};
        case "$key" in 
            ROLE | LOCAL_PUBLIC_IP | PEER_PUBLIC_IP | SERVICE_PORTS | ALLOW_UDP | TUN_IF | IRAN_TUN_CIDR | KHAREJ_TUN_CIDR)

            ;;
            *)
                err "Unknown configuration key: $key";
                return 1
            ;;
        esac;
        [[ ! -n ${seen[$key]:-} ]] || { 
            err "Duplicate configuration key: $key";
            return 1
        };
        if [[ "$value" == \"*\" ]]; then
            value=${value:1:${#value}-2};
        fi;
        [[ "$value" =~ ^[a-zA-Z0-9_.,/-]+$ ]] || { 
            err "Invalid value for $key";
            return 1
        };
        printf -v "$key" '%s' "$value";
        seen[$key]=1;
    done < "$file";
    for required in ROLE LOCAL_PUBLIC_IP PEER_PUBLIC_IP SERVICE_PORTS ALLOW_UDP TUN_IF IRAN_TUN_CIDR KHAREJ_TUN_CIDR;
    do
        [[ -n ${seen[$required]:-} ]] || { 
            err "Missing $required in $file";
            return 1
        };
    done;
    [[ "$ROLE" == iran || "$ROLE" == kharej ]] || return 1;
    validate_ipv4 "$LOCAL_PUBLIC_IP" && validate_ipv4 "$PEER_PUBLIC_IP" || return 1;
    LOCAL_PUBLIC_IP=$(number_ipv4 "$(ipv4_number "$LOCAL_PUBLIC_IP")");
    PEER_PUBLIC_IP=$(number_ipv4 "$(ipv4_number "$PEER_PUBLIC_IP")");
    [[ "$LOCAL_PUBLIC_IP" != "$PEER_PUBLIC_IP" ]] || return 1;
    SERVICE_PORTS=$(normalize_ports_list "$SERVICE_PORTS") || return;
    [[ "$ALLOW_UDP" == yes || "$ALLOW_UDP" == no ]] || return 1;
    [[ "$TUN_IF" =~ ^[a-zA-Z0-9_-]{1,15}$ ]] || return 1;
    local base last iran kharej;
    [[ "$IRAN_TUN_CIDR" == */30 && "$KHAREJ_TUN_CIDR" == */30 ]] || return 1;
    read -r base last < <(cidr_bounds "$IRAN_TUN_CIDR");
    [[ -n "$base" ]] || return 1;
    iran=$(ipv4_number "${IRAN_TUN_CIDR%/*}") || return;
    kharej=$(ipv4_number "${KHAREJ_TUN_CIDR%/*}") || return;
    (( iran == base+1 && kharej == base+2 )) || { 
        err "Tunnel addresses must be the first two hosts of one /30.";
        return 1
    }
}
load_profile () 
{ 
    validate_profile_id "$1" || { 
        err "Invalid connection ID.";
        return 1
    };
    PROFILE_ID="$1";
    CONF_FILE="$PROFILE_DIR/$PROFILE_ID.conf";
    read_profile_file "$CONF_FILE" || return;
    [[ "$TUN_IF" == "g4-$PROFILE_ID" || ( "$PROFILE_ID" == legacy && "$TUN_IF" == GRE ) ]] || { 
        err "Unexpected tunnel interface for $PROFILE_ID";
        return 1
    }
}
check_local_public_ip () 
{ 
    local wanted="$1" addresses;
    validate_ipv4 "$wanted" || return 1;
    wanted=$(number_ipv4 "$(ipv4_number "$wanted")");
    addresses=$(ip -o -4 addr show) || return;
    if ! awk -v wanted="$wanted" '$3=="inet" {split($4,a,"/"); if(a[1]==wanted) found=1} END {exit !found}' <<< "$addresses"; then
        err "Local public IP is not assigned on this host: $wanted";
        return 1;
    fi
}
check_host_network_conflicts () 
{ 
    local subnet="$1" own_interface="${2:-}" base last address dev lo hi routes addresses;
    read -r base last < <(cidr_bounds "$subnet");
    addresses=$(ip -o -4 addr show) || return;
    routes=$(ip -4 route show table all) || return;
    while read -r address dev; do
        [[ -n "$address" && "$dev" != "$own_interface" ]] || continue;
        read -r lo hi < <(cidr_bounds "$address");
        [[ -n "$lo" ]] || continue;
        if (( base <= hi && lo <= last )); then
            err "Tunnel subnet overlaps host network $address on $dev";
            return 1;
        fi;
    done < <(awk '$3=="inet" {print $4, $2}' <<< "$addresses"; awk '
    $1!="default" { address=$1; if($1=="local" || $1=="broadcast" || $1=="unreachable" || $1=="blackhole" || $1=="prohibit" || $1=="throw") address=$2;
      if(address !~ /^[0-9]+\./) next; if(address !~ /\//) address=address "/32";
      dev=""; for(i=1;i<NF;i++) if($i=="dev") dev=$(i+1); print address,dev }
  ' <<< "$routes")
}
profile_conflicts () 
{ 
    ( local id="$1" role="$2" local_ip="$3" peer="$4" subnet="$5" iface="$6" base last lo hi file other;
    read -r base last < <(cidr_bounds "$subnet");
    shopt -s nullglob;
    for file in "$PROFILE_DIR"/*.conf "$STATE_DIR"/profiles/*/applied.conf;
    do
        other=${file##*/};
        other=${other%.conf};
        if [[ "$other" == applied ]]; then
            other=${file%/applied.conf};
            other=${other##*/};
        fi;
        [[ "$other" != "$id" ]] || continue;
        read_profile_file "$file" || return;
        [[ "$ROLE" == "$role" && "$LOCAL_PUBLIC_IP" == "$local_ip" ]] || { 
            err "All connections on this host must use the same role and local public IP.";
            return 1
        };
        [[ "$PEER_PUBLIC_IP" != "$peer" ]] || { 
            err "Peer already has a connection: $other";
            return 1
        };
        [[ "$TUN_IF" != "$iface" ]] || { 
            err "Interface already belongs to $other";
            return 1
        };
        read -r lo hi < <(cidr_bounds "$IRAN_TUN_CIDR");
        if (( base <= hi && lo <= last )); then
            err "Tunnel subnet overlaps connection $other";
            return 1;
        fi;
    done )
}
profile_runtime_lock () 
{ 
    private_directory "$LOCK_DIR" || return;
    [[ ! -L "$LOCK_DIR/gre4-runtime.lock" ]] || return 1;
    [[ ! -e "$LOCK_DIR/gre4-runtime.lock" || -O "$LOCK_DIR/gre4-runtime.lock" ]] || return 1;
    exec 8> "$LOCK_DIR/gre4-runtime.lock" || return;
    flock -w 30 8 || { 
        err "Timed out waiting for another GRE4 runtime operation.";
        return 1
    }
}
profile_edit_lock () 
{ 
    local id="${1:-}" file;
    validate_profile_id "$id" || return 1;
    file="$LOCK_DIR/gre4-edit-$id.lock";
    [[ ! -L "$file" && ( ! -e "$file" || -O "$file" ) ]] || return 1;
    exec 7> "$file" || return;
    flock -n 7 || { 
        err "Configuration edit in progress for $id";
        return 1
    }
}
profile_state_directory () 
{ 
    private_directory "$STATE_DIR" && private_directory "$STATE_DIR/profiles" && private_directory "$STATE_DIR/profiles/$1"
}
profile_interface_owned () 
{ 
    local details;
    details=$(ip -d -o link show dev "$TUN_IF") || return;
    [[ " $details " == *" alias gre4:$PROFILE_ID "* ]]
}
profile_preflight () 
{ 
    local command status value;
    for command in ip sysctl flock;
    do
        ensure_cmd "$command" || return 1;
    done;
    if [[ "$ROLE" == iran ]]; then
        ensure_cmd iptables || return 1;
    fi;
    if command -v ufw > /dev/null 2>&1; then
        status=$(LC_ALL=C ufw status 2>/dev/null) || { 
            err "Cannot inspect UFW before starting.";
            return 1
        };
        if [[ "${status%%
*}" == "Status: active" ]]; then
            ensure_cmd iptables-restore || return 1;
        fi;
    fi;
    [[ "$ROLE" == kharej ]] || return 0;
    if value=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null); then
        [[ "$value" =~ ^[0-9]+$ ]] && return 0;
    fi;
    if ! command -v modprobe > /dev/null 2>&1 || ! modprobe nf_conntrack; then
        err "Cannot prepare nf_conntrack. Check kmod, kernel support and module permissions before retrying.";
        return 1;
    fi;
    if ! value=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null) || [[ ! "$value" =~ ^[0-9]+$ ]]; then
        err "nf_conntrack_max is unavailable after module preparation; this kernel or environment may restrict conntrack.";
        return 1;
    fi
}
profile_setup_gre () 
{ 
    local created_index details;
    if ip link show "$TUN_IF" > /dev/null 2>&1; then
        profile_interface_owned || { 
            err "Refusing interface not owned by $PROFILE_ID: $TUN_IF";
            return 1
        };
        ip tunnel del "$TUN_IF" || return;
    fi;
    ip link add name "$TUN_IF" alias "gre4:$PROFILE_ID" type gre remote "$PEER_PUBLIC_IP" local "$LOCAL_PUBLIC_IP" || return;
    details=$(ip -d -o link show dev "$TUN_IF") || return;
    created_index=${details%%:*};
    if ! ip link set dev "$TUN_IF" alias "gre4:$PROFILE_ID" || ! profile_interface_owned; then
        err "Cannot establish interface ownership: $TUN_IF";
        if details=$(ip -d -o link show dev "$TUN_IF") && [[ ${details%%:*} == "$created_index" ]] && { 
            [[ " $details " != *" alias "* ]] || [[ " $details " == *" alias gre4:$PROFILE_ID "* ]]
        }; then
            ip tunnel del "$TUN_IF" || return;
        else
            err "Interface changed during creation; preserving $TUN_IF for manual recovery.";
        fi;
        return 1;
    fi;
    if [[ "$ROLE" == iran ]]; then
        ip addr add "$IRAN_TUN_CIDR" dev "$TUN_IF" || return;
    else
        ip addr add "$KHAREJ_TUN_CIDR" dev "$TUN_IF" || return;
    fi;
    ip link set "$TUN_IF" mtu 1420 || return;
    ip link set "$TUN_IF" up
}
profile_ipt_add () 
{ 
    local table="$1" chain="$2" rc;
    shift 2;
    if iptables -t "$table" -C "$chain" "$@" -m comment --comment "gre4:$PROFILE_ID" 2> /dev/null; then
        return 0;
    else
        rc=$?;
    fi;
    [[ "$rc" == 1 ]] || return "$rc";
    if iptables -t "$table" -C "$chain" "$@" 2> /dev/null; then
        warn "Matching administrator rule retained: $table $chain $*";
        return 0;
    else
        rc=$?;
    fi;
    [[ "$rc" == 1 ]] || return "$rc";
    iptables -t "$table" -A "$chain" "$@" -m comment --comment "gre4:$PROFILE_ID"
}
profile_ipt_del () 
{ 
    local table="$1" chain="$2" rc;
    shift 2;
    while true; do
        if iptables -t "$table" -C "$chain" "$@" -m comment --comment "gre4:$PROFILE_ID" 2> /dev/null; then
            iptables -t "$table" -D "$chain" "$@" -m comment --comment "gre4:$PROFILE_ID" || return;
        else
            rc=$?;
            [[ "$rc" == 1 ]] && return 0;
            return "$rc";
        fi;
    done
}
profile_nat () 
{ 
    [[ "$ROLE" == iran ]] || return 0;
    local action="$1" p proto target=${KHAREJ_TUN_CIDR%/*} failed=0 operation=profile_ipt_add;
    [[ "$action" != stop ]] || operation=profile_ipt_del;
    local -a ports protocols=(tcp);
    [[ "$ALLOW_UDP" != yes && "$action" != stop ]] || protocols+=(udp);
    IFS=, read -r -a ports <<< "$SERVICE_PORTS";
    for p in "${ports[@]}";
    do
        for proto in "${protocols[@]}";
        do
            "$operation" nat PREROUTING -d "$LOCAL_PUBLIC_IP/32" -p "$proto" --dport "$p" -j DNAT --to-destination "$target:$p" || failed=1;
            "$operation" filter FORWARD -o "$TUN_IF" -p "$proto" -d "$target/32" --dport "$p" -j ACCEPT || failed=1;
        done;
    done;
    "$operation" nat POSTROUTING -o "$TUN_IF" -d "$target/32" -j MASQUERADE || failed=1;
    "$operation" filter FORWARD -i "$TUN_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || failed=1;
    return "$failed"
}
profile_requirements () 
{ 
    ( local skip="${1:-}" file id p proto target;
    local -a ports protocols;
    shopt -s nullglob;
    for file in "$STATE_DIR"/profiles/*/applied.conf;
    do
        id=${file%/applied.conf};
        id=${id##*/};
        [[ "$id" != "$skip" ]] || continue;
        validate_profile_id "$id" && read_profile_file "$file" || return;
        printf 'gre -A ufw-before-input -p 47 -s %s -d %s -m comment --comment gre4:%s -j ACCEPT\n' "$PEER_PUBLIC_IP" "$LOCAL_PUBLIC_IP" "$id";
        printf 'gre -A ufw-before-output -p 47 -s %s -d %s -m comment --comment gre4:%s -j ACCEPT\n' "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$id";
        IFS=, read -r -a ports <<< "$SERVICE_PORTS";
        protocols=(tcp);
        [[ "$ALLOW_UDP" != yes ]] || protocols+=(udp);
        if [[ "$ROLE" == kharej ]]; then
            for p in "${ports[@]}";
            do
                for proto in "${protocols[@]}";
                do
                    printf 'port %s %s\n' "$p" "$proto";
                done;
            done;
        else
            target=${KHAREJ_TUN_CIDR%/*};
            printf 'gre -A ufw-before-forward -i %s -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment gre4:%s -j ACCEPT\n' "$TUN_IF" "$id";
            for p in "${ports[@]}";
            do
                for proto in "${protocols[@]}";
                do
                    printf 'gre -A ufw-before-forward -o %s -p %s -d %s/32 --dport %s -m comment --comment gre4:%s -j ACCEPT\n' "$TUN_IF" "$proto" "$target" "$p" "$id";
                done;
            done;
        fi;
    done )
}
profile_write_ufw_block () 
{ 
    local requirements="$1" before="$UFW_BEFORE_FILE" clean staged;
    [[ -f "$before" && ! -L "$before" ]] || { 
        err "Missing or unsafe UFW before.rules";
        return 1
    };
    [[ -f "$requirements" && -r "$requirements" && ! -L "$requirements" ]] || { 
        err "Cannot read UFW requirements.";
        return 1
    };
    clean=$(mktemp "${before}.clean.XXXXXX") || return;
    staged=$(mktemp "${before}.tmp.XXXXXX") || { 
        rm -f "$clean";
        return 1
    };
    if ! awk '
    $0=="# gre4 profiles BEGIN" {if(skip) exit 1; skip=1; next}
    $0=="# gre4 profiles END" {if(!skip) exit 1; skip=0; next}
    !skip {print}
    END {if(skip) exit 1}
  ' "$before" > "$clean"; then
        err "Unbalanced GRE block in $before; keeping original file.";
        rm -f "$clean" "$staged";
        return 1;
    fi;
    if ! awk -v rules="$requirements" '
    {if($0=="*filter") filter=1
     if(filter && $0=="COMMIT" && !inserted) {
       any=0; while((getline line < rules)>0) if(substr(line,1,4)=="gre ") {if(!any++) print "# gre4 profiles BEGIN"; print substr(line,5)}
       close(rules); if(any) print "# gre4 profiles END"; inserted=1
     }
     print; if(filter && $0=="COMMIT") filter=0}
    END {if(!inserted) exit 1}
  ' "$clean" > "$staged"; then
        err "Cannot find a complete filter table in $before; keeping original file.";
        rm -f "$clean" "$staged";
        return 1;
    fi;
    if ! ufw_before_rules_test "$staged" || ! chmod --reference="$before" "$staged" || ! mv -f "$staged" "$before"; then
        err "Invalid or unwritable UFW rules; keeping original file.";
        rm -f "$clean" "$staged";
        return 1;
    fi;
    rm -f "$clean"
}
profile_shared_ssh_ports () 
{ 
    local config key value port found=0;
    if ! command -v sshd > /dev/null 2>&1; then
        return 0;
    fi;
    config=$(sshd -T) || { 
        err "Cannot inspect SSH; keeping shared UFW rules.";
        return 1
    };
    while read -r key value _; do
        case "${key,,}" in 
            port)
                port=$value
            ;;
            listenaddress)
                port=${value##*:}
            ;;
            *)
                continue
            ;;
        esac;
        validate_port "$port" || return 1;
        printf '%s\n' "$((10#$port))";
        found=1;
    done <<< "$config";
    [[ "$found" == 1 ]] || { 
        err "Cannot detect SSH ports; keeping shared UFW rules.";
        return 1
    }
}
profile_ufw_reconcile () 
{ 
    local skip="${1:-}" action="${2:-start}" requirements status state=0 p proto family destination n key file encoded id;
    requirements=$(mktemp) || return;
    if ! profile_requirements "$skip" > "$requirements"; then
        rm -f "$requirements";
        return 1;
    fi;
    ufw_is_active || state=$?;
    if [[ "$state" == 1 ]]; then
        if [[ "$action" == stop ]]; then
            id="$skip";
            encoded=$(printf 'gre4:%s' "$id" | od -An -tx1 | tr -d ' \n');
            for file in "$UFW_DIR/user.rules" "$UFW_DIR/user6.rules" "$UFW_BEFORE_FILE";
            do
                [[ -e "$file" ]] || continue;
                [[ -r "$file" ]] || { 
                    rm -f "$requirements";
                    return 1
                };
                if grep -Eq "gre4:$id([[:space:]\"']|$)|$encoded([^[:xdigit:]]|$)" "$file"; then
                    err "Inactive UFW retains rules for $id; keep recovery records and retry cleanup with UFW active.";
                    rm -f "$requirements";
                    return 1;
                fi;
            done;
            local -a removed_ports removed_protocols=(tcp);
            IFS=, read -r -a removed_ports <<< "$SERVICE_PORTS";
            [[ "$ALLOW_UDP" != yes ]] || removed_protocols+=(udp);
            for p in "${removed_ports[@]}";
            do
                for proto in "${removed_protocols[@]}";
                do
                    if grep -Fxq "port $p $proto" "$requirements"; then
                        continue;
                    fi;
                    for file in "$UFW_DIR/user.rules" "$UFW_DIR/user6.rules";
                    do
                        [[ -e "$file" ]] || continue;
                        if awk -v port="$p" -v proto="$proto" '
            /^### tuple ###/ {tuple=$0}
            /gre4-shared|677265342d736861726564/ {
              if(tuple ~ ("^### tuple ### allow " proto " " port "([[:space:]]|$)")) found=1
              if($0 ~ ("-p " proto "([[:space:]]|$)") && $0 ~ ("--dport " port "([[:space:]]|$)")) found=1
            }
            END {exit !found}
          ' "$file"; then
                            err "Inactive UFW may retain obsolete shared port rules; keep recovery records.";
                            rm -f "$requirements";
                            return 1;
                        fi;
                    done;
                done;
            done;
        fi;
        rm -f "$requirements";
        return 0;
    fi;
    [[ "$state" == 0 ]] || { 
        rm -f "$requirements";
        err "Cannot read UFW status.";
        return 1
    };
    local -A desired_allowances=() ssh=();
    local -a families=(4) obsolete=();
    if ufw_ipv6_enabled "$UFW_DEFAULTS_FILE" "$UFW_DIR/ufw.conf"; then
        families+=(6);
    fi;
    while read -r key p proto; do
        [[ "$key" == port ]] || continue;
        for family in "${families[@]}";
        do
            desired_allowances["$family:$proto:$p"]=1;
        done;
    done < "$requirements";
    status=$(LC_ALL=C ufw status numbered) || { 
        rm -f "$requirements";
        return 1
    };
    for key in "${!desired_allowances[@]}";
    do
        IFS=: read -r family proto p <<< "$key";
        if ufw_has_public_allow "$status" "$p" "$proto" "$family"; then
            continue;
        fi;
        destination=0.0.0.0/0;
        [[ "$family" != 6 ]] || destination=::/0;
        if ! ufw allow proto "$proto" from any to "$destination" port "$p" comment gre4-shared > /dev/null; then
            rm -f "$requirements";
            return 1;
        fi;
    done;
    status=$(LC_ALL=C ufw status numbered) || { 
        rm -f "$requirements";
        return 1
    };
    if ! profile_write_ufw_block "$requirements"; then
        rm -f "$requirements";
        return 1;
    fi;
    local ssh_list candidate;
    while read -r n p proto family; do
        [[ -n "$n" ]] || continue;
        [[ -n ${desired_allowances["$family:$proto:$p"]:-} ]] && continue;
        obsolete+=("$n:$p:$proto");
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
  ' <<< "$status" | sort -rn);
    if [[ ${#obsolete[@]} -gt 0 ]]; then
        ssh_list=$(profile_shared_ssh_ports) || { 
            rm -f "$requirements";
            return 1
        };
        while read -r p; do
            [[ -z "$p" ]] || ssh[$p]=1;
        done <<< "$ssh_list";
    fi;
    for candidate in "${obsolete[@]}";
    do
        IFS=: read -r n p proto <<< "$candidate";
        [[ "$proto" == tcp && -n ${ssh[$p]:-} ]] && continue;
        if ! ufw --force delete "$n" > /dev/null; then
            rm -f "$requirements";
            return 1;
        fi;
    done;
    rm -f "$requirements";
    ufw reload > /dev/null
}
profile_reapply_sysctl () 
{ 
    local name="$1" file="$2" state="$STATE_DIR/sysctl/$1" key original applied extra current changed=no index=0 expected_file="";
    local -a expected;
    case "$name" in 
        forward)
            expected=(net.ipv4.ip_forward net.ipv4.conf.all.forwarding)
        ;;
        conntrack)
            expected=(net.netfilter.nf_conntrack_max)
        ;;
        *)
            return 1
        ;;
    esac;
    [[ -d "$STATE_DIR/sysctl" && ! -L "$STATE_DIR/sysctl" && -O "$STATE_DIR/sysctl" ]] || return 1;
    [[ -d "$state" && ! -L "$state" && -f "$state/file" && ! -L "$state/file" && -f "$state/values" && ! -L "$state/values" ]] || return 1;
    [[ -O "$state" && -O "$state/file" && -O "$state/values" ]] || return 1;
    [[ ! -e "$state/restore" && ! -e "$state/restored" ]] || { 
        err "Shared sysctl recovery is pending.";
        return 1
    };
    [[ -f "$file" && ! -L "$file" ]] && cmp -s "$file" "$state/file" || { 
        err "Shared sysctl file was changed; preserve it for manual review.";
        return 1
    };
    while read -r key original applied extra; do
        [[ "$key" == "${expected[$index]:-}" && "$original" =~ ^[0-9]+$ && "$applied" =~ ^[0-9]+$ && -z "$extra" ]] || return 1;
        index=$((index+1));
        expected_file+="$key=$applied"'
';
        current=$(sysctl -n "$key") || return;
        if [[ "$current" == "$applied" ]]; then
            continue;
        fi;
        if [[ "$current" == "$original" ]]; then
            changed=yes;
        else
            err "Preserving administrator runtime change to $key; resolve it before starting.";
            return 1;
        fi;
    done < "$state/values";
    [[ "$index" == "${#expected[@]}" && $(cat "$state/file") == "${expected_file%
}" ]] || return 1;
    [[ "$changed" != yes ]] || sysctl -p "$file" > /dev/null
}
profile_shared_sysctl () 
{ 
    ( local skip="${1:-}" file id forward=no conntrack=no;
    shopt -s nullglob;
    for file in "$STATE_DIR"/profiles/*/applied.conf;
    do
        id=${file%/applied.conf};
        id=${id##*/};
        [[ "$id" != "$skip" ]] || continue;
        read_profile_file "$file" || return;
        forward=yes;
        [[ "$ROLE" != kharej ]] || conntrack=yes;
    done;
    if [[ "$forward" == no ]]; then
        restore_sysctl;
        return;
    fi;
    if [[ ! -d "$STATE_DIR/sysctl/forward" ]]; then
        tune_forwarding || return;
    else
        if [[ -z "$skip" ]]; then
            profile_reapply_sysctl forward "$SYSCTL_DIR/99-gre4-forward.conf" || return;
        fi;
    fi;
    if [[ "$conntrack" == yes ]]; then
        if [[ ! -d "$STATE_DIR/sysctl/conntrack" ]]; then
            ROLE=kharej;
            tune_conntrack_if_kharej;
        else
            if [[ -z "$skip" ]]; then
                profile_reapply_sysctl conntrack "$SYSCTL_DIR/99-gre4-conntrack.conf";
            fi;
        fi;
    else
        restore_sysctl_file conntrack "$SYSCTL_DIR/99-gre4-conntrack.conf";
    fi )
}
profile_migration_start_allowed () 
{ 
    [[ "$1" == legacy ]] || return 0;
    local root="${MIGRATION_BACKUP_DIR:-/var/backups/gre4}" backup stage;
    legacy_safe_path "$root" || return 1;
    [[ -e "$root/pending" || -L "$root/pending" ]] || return 0;
    [[ -d "$root" && -O "$root" && $(stat -c %a "$root") == 700 ]] || return 1;
    legacy_owned_file "$root/pending" || return 1;
    read -r backup < "$root/pending" || return;
    [[ "$backup" == "$root"/migration.* && -d "$backup" && -O "$backup" ]] && legacy_safe_path "$backup" || return 1;
    [[ $(stat -c %a "$backup") == 700 ]] || return 1;
    legacy_owned_file "$backup/stage" || return 1;
    read -r stage < "$backup/stage" || return;
    case "$stage" in 
        new-installed | complete)
            return 0
        ;;
        *)
            err "Legacy migration recovery blocks profile start. Retry migration before starting legacy.";
            return 1
        ;;
    esac
}
legacy_safe_path () 
{ 
    local path="$1";
    [[ "$path" == /* ]] || return 1;
    while [[ "$path" != / ]]; do
        [[ ! -L "$path" ]] || return 1;
        path=${path%/*};
        [[ -n "$path" ]] || path=/;
    done
}
legacy_owned_file () 
{ 
    local mode;
    legacy_safe_path "$1" && [[ -f "$1" && -O "$1" ]] || return 1;
    mode=$(stat -c %a "$1") || return;
    (( (8#$mode & 0022) == 0 ))
}
profile_start () 
{ 
    ( local id="${1:-}" state staged;
    validate_profile_id "$id" && profile_runtime_lock || return 1;
    profile_edit_lock "$id" && profile_migration_start_allowed "$id" || return 1;
    state="$STATE_DIR/profiles/$id";
    [[ ! -L "$STATE_DIR" && ! -L "$STATE_DIR/profiles" && ! -L "$state" && ! -L "$PROFILE_DIR" ]] || return 1;
    [[ ! -e "$state/cleanup-pending" ]] || { 
        err "Cleanup pending for $id; stop it successfully before starting.";
        return 1
    };
    load_profile "$id" || return;
    profile_preflight || return 78;
    check_local_public_ip "$LOCAL_PUBLIC_IP" || return;
    profile_conflicts "$id" "$ROLE" "$LOCAL_PUBLIC_IP" "$PEER_PUBLIC_IP" "$(profile_subnet "$IRAN_TUN_CIDR")" "$TUN_IF" || return;
    check_host_network_conflicts "$(profile_subnet "$IRAN_TUN_CIDR")" "$TUN_IF" || return;
    if [[ -f "$state/applied.conf" ]]; then
        cmp -s "$CONF_FILE" "$state/applied.conf" || { 
            err "Applied configuration differs; stop $id before changing it.";
            return 1
        };
        private_config_file "$state/applied.conf" || return;
        if ip link show "$TUN_IF" > /dev/null 2>&1; then
            profile_interface_owned || { 
                err "Interface ownership changed: $TUN_IF";
                return 1
            };
        fi;
    else
        if ip link show "$TUN_IF" > /dev/null 2>&1; then
            err "Interface already exists: $TUN_IF";
            return 1;
        fi;
        profile_state_directory "$id" || return;
        staged=$(mktemp "$state/.applied.XXXXXX") || return;
        if ! cp "$CONF_FILE" "$staged" || ! chmod 600 "$staged" || ! mv -f "$staged" "$state/applied.conf"; then
            rm -f "$staged";
            return 1;
        fi;
    fi;
    if ! profile_shared_sysctl || ! profile_setup_gre || ! profile_nat start || ! profile_ufw_reconcile; then
        touch "$state/cleanup-pending";
        err "Start failed for $id; post-stop cleanup must complete before retrying.";
        return 1;
    fi;
    log "Connection started: $id" )
}
profile_stop () 
{ 
    ( local id="${1:-}" state interfaces failed=0;
    validate_profile_id "$id" && profile_runtime_lock || return 1;
    PROFILE_ID="$id";
    state="$STATE_DIR/profiles/$id";
    [[ ! -L "$STATE_DIR" && ! -L "$STATE_DIR/profiles" && ! -L "$state" ]] || return 1;
    [[ -f "$state/applied.conf" ]] || return 0;
    read_profile_file "$state/applied.conf" || return;
    touch "$state/cleanup-pending" || return;
    interfaces=$(ip -o link show) || { 
        err "Cannot inspect interfaces; keeping recovery records.";
        return 1
    };
    if awk -v name="$TUN_IF" '{split($2,a,/[:@]/); if(a[1]==name) found=1} END {exit !found}' <<< "$interfaces"; then
        if profile_interface_owned; then
            ip tunnel del "$TUN_IF" || failed=1;
        else
            err "Interface ownership changed; keeping $TUN_IF and recovery records.";
            failed=1;
        fi;
    fi;
    profile_nat stop || failed=1;
    profile_ufw_reconcile "$id" stop || failed=1;
    if [[ "$failed" == 0 ]]; then
        profile_shared_sysctl "$id" || failed=1;
    fi;
    if [[ "$failed" != 0 ]]; then
        err "Cleanup incomplete for $id; recovery records retained.";
        return 1;
    fi;
    rm -f "$state/applied.conf" "$state/cleanup-pending" || return;
    rmdir "$state" || return;
    log "Connection stopped: $id" )
}
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
