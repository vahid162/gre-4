"""Regression checks with temporary files and substitutes, never host networking."""
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "gre4.sh").read_text()
assert SOURCE.splitlines()[-1] == 'main "$@"'
FUNCTIONS = SOURCE.rsplit('\nmain "$@"', 1)[0]
UFW_STUBS = r'''
commands=()
ip() { return 1; }
iptables() { return 1; }
ufw_is_active() { return 0; }
ufw_remove_gre_proto47_block() { :; }
ufw_allow_gre_proto47() { :; }
ufw_before_rules_test() { :; }
ufw_ipv6_enabled() { return 1; }
sshd() { echo 'port 2222'; }
ufw() {
  if [[ $1 == status ]]; then
    printf '%s\n' "$fixture"
  else
    commands+=("$*")
    if [[ $1 == --force && $2 == delete ]]; then
      fixture=$(awk -v number="$3" '
        { current=$0; sub(/^\[[[:space:]]*/, "", current); sub(/\].*$/, "", current); if (current!=number) print }
      ' <<< "$fixture")
    fi
  fi
}
ROLE=kharej SERVICE_PORTS=443 ALLOW_UDP=no
'''


class Gre4Tests(unittest.TestCase):
    def test_generated_apply_loads_quoted_config_path(self):
        with tempfile.TemporaryDirectory(prefix="gre4-generate-") as scratch:
            config = Path(scratch) / 'config with spaces'
            config.write_text('ROLE=iran\nSERVICE_PORTS=443\n')
            apply = Path(scratch) / 'apply.sh'
            subprocess.run(
                ['bash', '-s', '--', str(apply), str(config)],
                input=FUNCTIONS + '\nAPPLY_SCRIPT=$1\nCONF_FILE=$2\ninstall_apply_script\n',
                text=True, capture_output=True, check=True, timeout=5,
            )
            result = subprocess.run(
                ['bash', str(apply), '__gre4_test_invalid_action__'],
                text=True, capture_output=True, timeout=5,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn('Usage:', result.stdout)
            self.assertNotIn('Missing', result.stdout + result.stderr)

    def test_failed_apply_installation_preserves_previous_script(self):
        with tempfile.TemporaryDirectory(prefix="gre4-generate-") as scratch:
            result = subprocess.run(
                ['bash', '-s', '--', scratch],
                input=FUNCTIONS + r'''
APPLY_SCRIPT=$1/apply.sh
printf 'previous helper\n' > "$APPLY_SCRIPT"
chmod() { return 1; }
if install_apply_script; then exit 1; fi
[[ $(cat "$APPLY_SCRIPT") == 'previous helper' ]]
''', text=True, capture_output=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def run_shell(self, body, expected=0):
        with tempfile.TemporaryDirectory(prefix="gre4-test-") as scratch:
            generated = Path(scratch) / "apply.sh"
            result = subprocess.run(
                ["bash", "-s", "--", str(generated)],
                input=FUNCTIONS + '\nAPPLY_SCRIPT=$1\ninstall_apply_script\n',
                text=True, capture_output=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            apply = generated.read_text()
            apply_functions = apply[apply.index("log()"):apply.index('case "${1:-start}" in')]
            result = subprocess.run(
                ["bash", "-s", "--", scratch],
                input=(FUNCTIONS + '\n' + apply_functions
                       + '\nCONF_FILE=$1/config\nAPPLY_SCRIPT=$1/installed-apply.sh\nUNIT_FILE=$1/unit\n'
                       + 'STATE_DIR=$1/state\nSYSCTL_DIR=$1/sysctl\nUFW_DIR=$1/ufw\nUFW_BEFORE_FILE=$UFW_DIR/before.rules\nmkdir -p "$SYSCTL_DIR" "$UFW_DIR"\n'
                       + "printf '#!/usr/bin/env bash\\nexit 0\\n' > \"$APPLY_SCRIPT\"\n"
                       + 'chmod +x "$APPLY_SCRIPT"\necho old-unit > "$UNIT_FILE"\n'
                       + "install_apply_script() { printf '#!/usr/bin/env bash\\n# refreshed cleanup\\nexit 0\\n' > \"$APPLY_SCRIPT\"; chmod +x \"$APPLY_SCRIPT\"; }\n"
                       + body),
                text=True, capture_output=True, timeout=5,
            )
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            return result.stdout

    def test_removing_port_cleans_previous_nat_and_forward_rules(self):
        self.run_shell(r'''
declare -A rules=()
for p in 80 443; do
  rules["nat PREROUTING -p tcp --dport $p -j DNAT --to-destination 172.16.1.2:$p -m comment --comment gre4-managed"]=1
  rules["filter FORWARD -o GRE -p tcp -d 172.16.1.2/32 --dport $p -j ACCEPT -m comment --comment gre4-managed"]=1
done
iptables() {
  local table=$2 op=$3 chain=$4 key
  shift 4
  key="$table $chain $*"
  case $op in
    -C) [[ ${rules[$key]:-} == 1 ]] ;;
    -D) unset 'rules[$key]' ;;
    *) return 99 ;;
  esac
}
ip() { return 1; }
ufw_is_active() { return 1; }
systemctl() {
  source "$CONF_FILE"
  case $1 in
    stop) stop_all ;;
    start|restart)
      [[ $1 != restart ]] || stop_all
      rules["nat PREROUTING -p tcp --dport 443 -j DNAT --to-destination 172.16.1.2:443 -m comment --comment gre4-managed"]=1
      rules["filter FORWARD -o GRE -p tcp -d 172.16.1.2/32 --dport 443 -j ACCEPT -m comment --comment gre4-managed"]=1
      ;;
    daemon-reload) : ;;
    *) return 99 ;;
  esac
}
write_conf iran 192.0.2.1 198.51.100.1 80,443 no
manage_ports_remove <<<80
[[ ! ${rules["nat PREROUTING -p tcp --dport 80 -j DNAT --to-destination 172.16.1.2:80 -m comment --comment gre4-managed"]:-} ]]
[[ ! ${rules["filter FORWARD -o GRE -p tcp -d 172.16.1.2/32 --dport 80 -j ACCEPT -m comment --comment gre4-managed"]:-} ]]
[[ ${rules["nat PREROUTING -p tcp --dport 443 -j DNAT --to-destination 172.16.1.2:443 -m comment --comment gre4-managed"]:-} == 1 ]]
''')

    def test_cleanup_preserves_only_existing_managed_ssh_allows(self):
        self.run_shell(UFW_STUBS + r'''
fixture='[ 1] 2222/tcp on eth0 ALLOW IN 203.0.113.10 # gre4-managed
[ 2] 443/tcp ALLOW IN Anywhere # gre4-managed
[ 3] 2222/udp ALLOW IN Anywhere # gre4-managed
[ 4] 2222/tcp (v6) ALLOW IN 2001:db8::1 # gre4-managed
[ 5] 2222/tcp DENY IN Anywhere # gre4-managed
[ 6] 2222/tcp ALLOW OUT Anywhere # gre4-managed
[ 7] 22/tcp ALLOW IN 203.0.113.10
[ 8] 192.0.2.2 2222/tcp ALLOW IN 203.0.113.10 # gre4-managed
[ 9] 2001:db8::2 2222/tcp ALLOW IN 2001:db8::1 # gre4-managed
[10] 443/tcp ALLOW IN 203.0.113.10 2222/tcp # gre4-managed'
stop_all
[[ ${commands[*]} == '--force delete 10 --force delete 6 --force delete 5 --force delete 3 --force delete 2 reload' ]]
''')

    def test_cleanup_never_opens_unmanaged_ssh(self):
        self.run_shell(UFW_STUBS + r'''
fixture='[ 1] 2222/tcp ALLOW IN 203.0.113.10
[ 2] 443/tcp ALLOW IN Anywhere # gre4-managed'
ROLE=iran
stop_all
[[ ${commands[*]} == '--force delete 2 reload' ]]
''')

    def test_cleanup_keeps_rules_when_ssh_detection_fails(self):
        self.run_shell(UFW_STUBS + r'''
fixture='[ 1] 2222/tcp ALLOW IN Anywhere # gre4-managed'
sshd() { return 1; }
if stop_all; then exit 1; fi
[[ ${commands[*]} == reload ]]
''')

    def test_start_preserves_previous_managed_ssh_allowance(self):
        self.run_shell(UFW_STUBS + r'''
fixture='[ 1] 2222/tcp on eth0 ALLOW IN 203.0.113.10 # gre4-managed
[ 2] 443/tcp ALLOW IN Anywhere # gre4-managed'
setup_kharej_ufw
[[ ${commands[*]} == '--force delete 2 allow proto tcp from any to 0.0.0.0/0 port 443 comment gre4-managed reload' ]]
''')

    def test_unreliable_ssh_detection_never_deletes_rules(self):
        for config in ("", "port invalid", "port 65536"):
            with self.subTest(config=config):
                self.run_shell(UFW_STUBS + f"sshd() {{ echo '{config}'; }}\n" + r'''
fixture='[ 1] 2222/tcp ALLOW IN Anywhere # gre4-managed'
if stop_all; then exit 1; fi
[[ ${commands[*]} == reload ]]
''')

    def test_failed_ufw_deletion_stops_numbered_cleanup(self):
        self.run_shell(UFW_STUBS + r'''
fixture='[ 1] 80/tcp ALLOW IN Anywhere # gre4-managed
[ 2] 443/tcp ALLOW IN Anywhere # gre4-managed'
ufw() {
  if [[ $1 == status ]]; then printf '%s\n' "$fixture"; return; fi
  commands+=("$*")
  return 1
}
if ufw_delete_managed_rules preserve-ssh; then exit 1; fi
[[ ${commands[*]} == '--force delete 2' ]]
''')

    def test_first_ufw_setup_needs_no_ssh_detection(self):
        self.run_shell(UFW_STUBS + r'''
fixture='Status: active'
sshd() { return 1; }
setup_kharej_ufw
[[ ${commands[*]} == 'allow proto tcp from any to 0.0.0.0/0 port 443 comment gre4-managed reload' ]]
''')

    def test_repeated_setup_stops_old_deployment_and_applies_new_config(self):
        for choice, role in ((1, "iran"), (2, "kharej")):
            with self.subTest(role=role):
                self.run_shell(r'''
need_root() { :; }
ensure_cmd() { :; }
write_conf iran 192.0.2.1 198.51.100.1 80,443 no
echo old-unit > "$UNIT_FILE"
active=yes live=old stopped_ports=''
systemctl() {
  case $1 in
    stop)
      source "$CONF_FILE"
      stopped_ports=$SERVICE_PORTS
      active=no
      ;;
    daemon-reload) : ;;
    enable)
      if [[ $active == no ]]; then
        source "$CONF_FILE"
        live="$ROLE:$LOCAL_PUBLIC_IP:$PEER_PUBLIC_IP:$SERVICE_PORTS:$ALLOW_UDP"
        active=yes
      fi
      ;;
    *) return 99 ;;
  esac
}
''' + f"main <<<'{choice}\n192.0.2.2\n198.51.100.2\n2096\nyes'\n" + f'''
[[ $stopped_ports == 80,443 ]]
[[ $live == {role}:192.0.2.2:198.51.100.2:2096:yes ]]
[[ $active == yes ]]
''')

    def test_reload_failure_fails_start_without_success_messages(self):
        output = self.run_shell(UFW_STUBS + r'''
fixture='Status: active'
tune_forwarding() { :; }
tune_conntrack_if_kharej() { :; }
setup_gre() { :; }
setup_iran_nat() { :; }
ufw() {
  if [[ $1 == status ]]; then printf '%s\n' "$fixture"; return; fi
  [[ $1 != reload ]]
}
start_all
''', expected=1)
        self.assertNotIn("UFW updated", output)
        self.assertNotIn("Start done", output)

    def test_successful_reload_allows_start_success(self):
        output = self.run_shell(UFW_STUBS + r'''
fixture='Status: active'
tune_forwarding() { :; }
tune_conntrack_if_kharej() { :; }
setup_gre() { :; }
setup_iran_nat() { :; }
start_all
''')
        self.assertIn("UFW updated", output)
        self.assertIn("Start done", output)

    def test_setup_stop_failure_keeps_previous_files(self):
        self.run_shell(r'''
write_conf iran 192.0.2.1 198.51.100.1 80,443 no
echo old-unit > "$UNIT_FILE"
before=$(cat "$CONF_FILE")
systemctl() { return 1; }
if setup_deployment kharej 192.0.2.2 198.51.100.2 2096 yes; then exit 1; fi
[[ $(cat "$CONF_FILE") == "$before" ]]
[[ -x $APPLY_SCRIPT ]]
[[ $(cat "$UNIT_FILE") == old-unit ]]
''')

    def test_ufw_snapshot_failure_deletes_nothing(self):
        self.run_shell(UFW_STUBS + r'''
ufw() { [[ $1 != status ]] && commands+=("$*"); return 1; }
if ufw_delete_managed_rules preserve-ssh; then exit 1; fi
[[ ${#commands[@]} == 0 ]]
''')

    def test_existing_service_rules_can_be_cleaned_without_openssh(self):
        self.run_shell(UFW_STUBS + r'''
fixture='[ 1] 443/tcp ALLOW IN Anywhere # gre4-managed'
command() {
  if [[ $1 == -v && $2 == sshd ]]; then return 1; fi
  builtin command "$@"
}
setup_kharej_ufw
[[ ${commands[*]} == '--force delete 1 allow proto tcp from any to 0.0.0.0/0 port 443 comment gre4-managed reload' ]]
''')

    def test_firewall_stop_failure_is_reported(self):
        output = self.run_shell(UFW_STUBS + r'''
fixture='Status: active'
ufw() {
  if [[ $1 == status ]]; then printf '%s\n' "$fixture"; return; fi
  [[ $1 != reload ]]
}
stop_all
''', expected=1)
        self.assertNotIn("Stop done", output)

    def test_uninstall_failure_preserves_cleanup_files(self):
        self.run_shell(r'''
write_conf iran 192.0.2.1 198.51.100.1 80,443 no
printf '#!/usr/bin/env bash\nexit 1\n' > "$APPLY_SCRIPT"
chmod +x "$APPLY_SCRIPT"
install_apply_script() { :; }
echo old-unit > "$UNIT_FILE"
systemctl() { :; }
ip() { return 1; }
if remove_everything; then exit 1; fi
[[ -f $CONF_FILE && -x $APPLY_SCRIPT && -f $UNIT_FILE ]]
''')

    def test_failed_activation_has_post_stop_cleanup(self):
        self.run_shell(r'''
systemctl() { :; }
install_systemd_unit
grep -Fxq "ExecStopPost=$APPLY_SCRIPT stop" "$UNIT_FILE"
! grep -q '^ExecStop=' "$UNIT_FILE"
''')

    def test_existing_public_rules_are_preserved_per_address_family(self):
        v4 = '[ 1] 443/tcp ALLOW IN Anywhere # administrator-web'
        v6 = '[ 2] 443/tcp (v6) ALLOW IN Anywhere (v6) # administrator-web'
        add4 = 'allow proto tcp from any to 0.0.0.0/0 port 443 comment gre4-managed'
        add6 = 'allow proto tcp from any to ::/0 port 443 comment gre4-managed'
        cases = [(v4, add6), (v6, add4), (v4 + '\n' + v6, ''),
                 ('Status: active', add4 + ' ' + add6)]
        for fixture, additions in cases:
            with self.subTest(fixture=fixture):
                self.run_shell(UFW_STUBS + '\nfixture=' + shlex.quote(fixture) + '\n'
                               + 'original=$fixture\nufw_ipv6_enabled() { return 0; }\n'
                               + 'setup_kharej_ufw\n'
                               + '[[ $fixture == "$original" ]]\n'
                               + '[[ ${commands[*]} == ' + shlex.quote((additions + ' reload').strip()) + ' ]]\n')

    def test_only_unrestricted_inbound_allows_suppress_additions(self):
        cases = [
            ('443/tcp ALLOW IN Anywhere # human-comment', True),
            ('443/tcp ALLOW IN Anywhere (log-all) # human-comment', True),
            ('443/tcp ALLOW IN 203.0.113.10 # human-comment', False),
            ('443/tcp on eth0 ALLOW IN Anywhere # human-comment', False),
            ('192.0.2.1 443/tcp ALLOW IN Anywhere # human-comment', False),
            ('443/tcp ALLOW IN Anywhere 1234 # human-comment', False),
            ('443/tcp DENY IN Anywhere # human-comment', False),
            ('443/tcp ALLOW OUT Anywhere # human-comment', False),
            ('443/udp ALLOW IN Anywhere # human-comment', False),
        ]
        for rule, allowed in cases:
            with self.subTest(rule=rule):
                self.run_shell('status=' + shlex.quote('[ 1] ' + rule) + '\n'
                               + 'if ufw_has_public_allow "$status" 443 tcp 4; then found=yes; else found=no; fi\n'
                               + f'[[ $found == {"yes" if allowed else "no"} ]]\n')

    @unittest.skipUnless(Path('/proc/sys/net/ipv6').is_dir(), 'Kernel IPv6 unavailable')
    def test_ufw_ipv6_configuration_precedence(self):
        self.run_shell(r'''
echo 'IPV6=yes' > "$1/defaults"
echo 'ENABLED=yes' > "$1/ufw.conf"
ufw_ipv6_enabled "$1/defaults" "$1/ufw.conf"
echo 'IPV6="no"' > "$1/ufw.conf"
if ufw_ipv6_enabled "$1/defaults" "$1/ufw.conf"; then exit 1; fi
echo 'IPV6="yes"' > "$1/ufw.conf"
ufw_ipv6_enabled "$1/defaults" "$1/ufw.conf"
echo 'IPV6=no' > "$1/defaults"
echo "IPV6='yes'" > "$1/ufw.conf"
if ufw_ipv6_enabled "$1/defaults" "$1/ufw.conf"; then exit 1; fi
echo 'IPV6=yes' > "$1/defaults"
echo "IPV6='no'" > "$1/ufw.conf"
ufw_ipv6_enabled "$1/defaults" "$1/ufw.conf"
echo 'IPV6= no' > "$1/ufw.conf"
ufw_ipv6_enabled "$1/defaults" "$1/ufw.conf"
''')

    def test_inactive_service_cleanup_failure_preserves_old_config(self):
        self.run_shell(r'''
write_conf iran 192.0.2.1 198.51.100.1 80,443 no
before=$(cat "$CONF_FILE")
printf '#!/usr/bin/env bash\nexit 1\n' > "$APPLY_SCRIPT"
chmod +x "$APPLY_SCRIPT"
install_apply_script() { :; }
systemctl() { :; }
if update_conf iran 192.0.2.1 198.51.100.1 443 no; then exit 1; fi
[[ $(cat "$CONF_FILE") == "$before" ]]
''')

    def test_iptables_cleanup_failures_are_bounded_and_propagated(self):
        self.run_shell(r'''
calls=0
iptables() { calls=$((calls+1)); [[ $3 == -C ]]; }
if ipt_del_all nat PREROUTING -p tcp --dport 443; then exit 1; fi
[[ $calls == 2 ]]
iptables() { return 4; }
if ipt_del_all nat PREROUTING -p tcp --dport 443; then exit 1; fi
''')

    def test_disabling_udp_removes_previous_udp_rules(self):
        self.run_shell(r'''
declare -A rules=()
for proto in tcp udp; do
  rules["nat PREROUTING -p $proto --dport 443 -j DNAT --to-destination 172.16.1.2:443 -m comment --comment gre4-managed"]=1
  rules["filter FORWARD -o GRE -p $proto -d 172.16.1.2/32 --dport 443 -j ACCEPT -m comment --comment gre4-managed"]=1
done
iptables() {
  local table=$2 op=$3 chain=$4 key
  shift 4
  key="$table $chain $*"
  case $op in
    -C) [[ ${rules[$key]:-} == 1 ]] ;;
    -D) unset 'rules[$key]' ;;
    *) return 99 ;;
  esac
}
ip() { return 1; }
ufw_is_active() { return 1; }
systemctl() {
  source "$CONF_FILE"
  case $1 in
    stop) stop_all ;;
    start)
      [[ $ALLOW_UDP == no ]]
      rules['nat PREROUTING -p tcp --dport 443 -j DNAT --to-destination 172.16.1.2:443 -m comment --comment gre4-managed']=1
      ;;
    *) return 99 ;;
  esac
}
write_conf iran 192.0.2.1 198.51.100.1 443 yes
manage_toggle_udp <<<no
[[ ! ${rules['nat PREROUTING -p udp --dport 443 -j DNAT --to-destination 172.16.1.2:443 -m comment --comment gre4-managed']:-} ]]
[[ ! ${rules['filter FORWARD -o GRE -p udp -d 172.16.1.2/32 --dport 443 -j ACCEPT -m comment --comment gre4-managed']:-} ]]
[[ ${rules['nat PREROUTING -p tcp --dport 443 -j DNAT --to-destination 172.16.1.2:443 -m comment --comment gre4-managed']:-} == 1 ]]
''')

    def test_upgrade_uses_new_cleanup_before_replacing_config(self):
        self.run_shell(r'''
write_conf iran 192.0.2.1 198.51.100.1 80,443 no
before=$(cat "$CONF_FILE")
install_apply_script() {
  printf '#!/usr/bin/env bash\nexit 1\n' > "$APPLY_SCRIPT"
  chmod +x "$APPLY_SCRIPT"
}
systemctl() { :; }
if setup_deployment iran 192.0.2.2 198.51.100.2 443 no; then exit 1; fi
[[ $(cat "$CONF_FILE") == "$before" ]]
[[ -f $UNIT_FILE && -x $APPLY_SCRIPT ]]
''')

    def test_ufw_status_query_error_is_not_treated_as_inactive(self):
        output = self.run_shell(r'''
ip() { return 1; }
iptables() { return 1; }
ufw() { return 1; }
TUN_IF=GRE ROLE=kharej SERVICE_PORTS=443
stop_all
''', expected=1)
        self.assertNotIn('Stop done', output)

    def test_failed_stop_preserves_configuration(self):
        self.run_shell(r'''
write_conf iran 192.0.2.1 198.51.100.1 80,443 no
before=$(cat "$CONF_FILE")
systemctl() { return 1; }
if manage_replace_ports <<<443; then exit 1; fi
[[ $(cat "$CONF_FILE") == "$before" ]]
''')

    def test_failed_config_replacement_preserves_original(self):
        for failure in ('write', 'chmod', 'rename'):
            with self.subTest(failure=failure):
                self.run_shell(r'''
write_conf iran 192.0.2.1 198.51.100.1 443 no
before=$(cat "$CONF_FILE")
''' + {
                    'write': "cat() { printf 'ROLE=broken'; return 1; }\n",
                    'chmod': 'chmod() { return 1; }\n',
                    'rename': 'mv() { return 1; }\n',
                }[failure] + r'''
if write_conf kharej 192.0.2.2 198.51.100.2 80 yes; then exit 1; fi
[[ $(command cat "$CONF_FILE") == "$before" ]]
[[ $(stat -c %a "$CONF_FILE") == 600 ]]
! compgen -G "${CONF_FILE}.tmp.*"
''')

    def test_cleanup_preserves_ports_from_listenaddress(self):
        for address in ('0.0.0.0:2222', '[::]:2222', '[2001:db8::1]:2222'):
            with self.subTest(address=address):
                self.run_shell(UFW_STUBS + '\nsshd() { printf \'%s\\n\' \'port 22\' '
                               + shlex.quote('listenaddress ' + address) + '; }\n' + r'''
fixture='[ 1] 2222/tcp on eth0 ALLOW IN 203.0.113.10 # gre4-managed
[ 2] 443/tcp ALLOW IN Anywhere # gre4-managed
[ 3] 2222/tcp (v6) ALLOW IN 2001:db8::1 # gre4-managed'
ufw_delete_managed_rules preserve-ssh
[[ ${commands[*]} == '--force delete 2' ]]
''')

    def test_invalid_listener_port_keeps_all_managed_rules(self):
        self.run_shell(UFW_STUBS + r'''
sshd() { printf '%s\n' 'port 22' 'listenaddress [::]:invalid'; }
fixture='[ 1] 2222/tcp ALLOW IN Anywhere # gre4-managed'
if ufw_delete_managed_rules preserve-ssh; then exit 1; fi
[[ ${#commands[@]} == 0 ]]
''')

    def test_inactive_ufw_retains_recovery_files_for_owned_rules(self):
        for filename, marker in (
            ('user.rules', '# gre4-managed'),
            ('user6.rules', '# tuple ### comment=677265342d6d616e61676564'),
            ('before.rules', '# gre4.sh BEGIN\n# gre4.sh END'),
        ):
            with self.subTest(filename=filename):
                self.run_shell(r'''
ip() { return 1; }
iptables() { return 1; }
ufw_is_active() { return 1; }
ufw() { echo 'Inactive firewall must not be enabled or reloaded' >&2; return 99; }
systemctl() { source "$CONF_FILE"; [[ $1 == stop ]] && stop_all; }
write_conf kharej 192.0.2.1 198.51.100.1 443 no
before=$(cat "$CONF_FILE")
''' + 'printf \'%s\\n\' ' + shlex.quote(marker)
                               + ' > "$UFW_DIR/' + filename + '"\n' + r'''
if update_conf kharej 192.0.2.1 198.51.100.1 80 no; then exit 1; fi
[[ $(cat "$CONF_FILE") == "$before" ]]
if remove_everything; then exit 1; fi
[[ -f $CONF_FILE && -x $APPLY_SCRIPT && -f $UNIT_FILE ]]
''')

    def test_inactive_ufw_without_owned_rules_can_be_cleaned(self):
        self.run_shell(r'''
ip() { return 1; }
iptables() { return 1; }
ufw_is_active() { return 1; }
printf '# administrator-only rules\n' > "$UFW_DIR/user.rules"
ROLE=iran SERVICE_PORTS=443
stop_all
''')

    def test_iptables_cleanup_preserves_unowned_matching_rules(self):
        self.run_shell(r'''
declare -A rules=()
rule='nat POSTROUTING -o GRE -d 172.16.1.2/32 -j MASQUERADE'
tag=' -m comment --comment gre4-managed'
rules["$rule"]=administrator
iptables() {
  local table=$2 op=$3 chain=$4 key
  shift 4
  key="$table $chain $*"
  case $op in
    -C) [[ -n ${rules[$key]:-} ]] ;;
    -A) rules["$key"]=gre4 ;;
    -D) unset 'rules[$key]' ;;
    *) return 99 ;;
  esac
}
ipt_add nat POSTROUTING -o GRE -d 172.16.1.2/32 -j MASQUERADE
[[ ${rules[$rule]} == administrator && ! ${rules["$rule$tag"]:-} ]]
ipt_del_all nat POSTROUTING -o GRE -d 172.16.1.2/32 -j MASQUERADE
[[ ${rules[$rule]} == administrator ]]
rules["$rule$tag"]=gre4
ip() { return 1; }
ufw_is_active() { return 1; }
ROLE=iran SERVICE_PORTS=443
stop_all
[[ ${rules[$rule]} == administrator && ! ${rules["$rule$tag"]:-} ]]
''')

    def test_new_iptables_rules_are_owned_and_idempotent(self):
        self.run_shell(r'''
declare -A rules=()
adds=0
iptables() {
  local table=$2 op=$3 chain=$4 key
  shift 4
  key="$table $chain $*"
  case $op in
    -C) [[ -n ${rules[$key]:-} ]] ;;
    -A) rules["$key"]=1; adds=$((adds+1)) ;;
    *) return 99 ;;
  esac
}
ipt_add nat PREROUTING -p tcp --dport 443 -j DNAT --to-destination 172.16.1.2:443
ipt_add nat PREROUTING -p tcp --dport 443 -j DNAT --to-destination 172.16.1.2:443
[[ $adds == 1 && ${#rules[@]} == 1 ]]
[[ ${rules['nat PREROUTING -p tcp --dport 443 -j DNAT --to-destination 172.16.1.2:443 -m comment --comment gre4-managed']:-} == 1 ]]
iptables() { return 4; }
if ipt_add nat PREROUTING -p tcp --dport 80; then exit 1; fi
''')


if __name__ == "__main__":
    unittest.main()
