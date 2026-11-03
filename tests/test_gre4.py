"""Regression checks with temporary files and substitutes, never host networking."""
from pathlib import Path
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
sshd() { echo 'port 2222'; }
ufw() {
  if [[ $1 == status ]]; then
    printf '%s\n' "$fixture"
  else
    commands+=("$*")
  fi
}
ROLE=kharej SERVICE_PORTS=443 ALLOW_UDP=no
'''


class Gre4Tests(unittest.TestCase):
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
                       + '\nCONF_FILE=$1/config\nAPPLY_SCRIPT=$1/apply.sh\nUNIT_FILE=$1/unit\n'
                       + body),
                text=True, capture_output=True, timeout=5,
            )
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            return result.stdout

    def test_removing_port_cleans_previous_nat_and_forward_rules(self):
        self.run_shell(r'''
declare -A rules=()
for p in 80 443; do
  rules["nat PREROUTING -p tcp --dport $p -j DNAT --to-destination 172.16.1.2:$p"]=1
  rules["filter FORWARD -o GRE -p tcp -d 172.16.1.2/32 --dport $p -j ACCEPT"]=1
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
      rules["nat PREROUTING -p tcp --dport 443 -j DNAT --to-destination 172.16.1.2:443"]=1
      rules["filter FORWARD -o GRE -p tcp -d 172.16.1.2/32 --dport 443 -j ACCEPT"]=1
      ;;
    daemon-reload) : ;;
    *) return 99 ;;
  esac
}
write_conf iran 192.0.2.1 198.51.100.1 80,443 no
manage_ports_remove <<<80
[[ ! ${rules["nat PREROUTING -p tcp --dport 80 -j DNAT --to-destination 172.16.1.2:80"]:-} ]]
[[ ! ${rules["filter FORWARD -o GRE -p tcp -d 172.16.1.2/32 --dport 80 -j ACCEPT"]:-} ]]
[[ ${rules["nat PREROUTING -p tcp --dport 443 -j DNAT --to-destination 172.16.1.2:443"]:-} == 1 ]]
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
stop_all
[[ ${commands[*]} == reload ]]
''')

    def test_start_preserves_previous_managed_ssh_allowance(self):
        self.run_shell(UFW_STUBS + r'''
fixture='[ 1] 2222/tcp on eth0 ALLOW IN 203.0.113.10 # gre4-managed
[ 2] 443/tcp ALLOW IN Anywhere # gre4-managed'
setup_kharej_ufw
[[ ${commands[*]} == '--force delete 2 allow 443/tcp comment gre4-managed reload' ]]
''')

    def test_unreliable_ssh_detection_never_deletes_rules(self):
        for config in ("", "port invalid", "port 65536"):
            with self.subTest(config=config):
                self.run_shell(UFW_STUBS + f"sshd() {{ echo '{config}'; }}\n" + r'''
fixture='[ 1] 2222/tcp ALLOW IN Anywhere # gre4-managed'
stop_all
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
[[ ${commands[*]} == 'allow 443/tcp comment gre4-managed reload' ]]
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
old_apply=$(cat "$APPLY_SCRIPT")
systemctl() { return 1; }
if setup_deployment kharej 192.0.2.2 198.51.100.2 2096 yes; then exit 1; fi
[[ $(cat "$CONF_FILE") == "$before" ]]
[[ $(cat "$APPLY_SCRIPT") == "$old_apply" ]]
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
[[ ${commands[*]} == '--force delete 1 allow 443/tcp comment gre4-managed reload' ]]
''')

    def test_failed_stop_preserves_configuration(self):
        self.run_shell(r'''
write_conf iran 192.0.2.1 198.51.100.1 80,443 no
before=$(cat "$CONF_FILE")
systemctl() { return 1; }
if manage_replace_ports <<<443; then exit 1; fi
[[ $(cat "$CONF_FILE") == "$before" ]]
''')


if __name__ == "__main__":
    unittest.main()
