#!/usr/bin/env bash
set -euo pipefail

CONF_FILE=/etc/gre4.conf
STATE_DIR=/var/lib/gre4
SYSCTL_DIR=/etc/sysctl.d
UFW_DIR=/etc/ufw
UFW_BEFORE_FILE=/etc/ufw/before.rules
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
