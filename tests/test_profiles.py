"""Profile configuration and generated-helper checks never touch host networking."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from shell_source import FUNCTIONS
from profile_fixture import ProfileRuntimeCase


class ProfileConfigTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="gre4-profiles-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def run_shell(self, body, expected=0):
        result = subprocess.run(
            ["bash", "-s", "--", str(self.root)],
            input=(FUNCTIONS + r'''
PROFILE_DIR=$1/profiles
STATE_DIR=$1/state
LOCK_DIR=$1/locks
TEMPLATE_FILE=$1/gre4@.service
APPLY_SCRIPT=$1/apply.sh
# Profile tests provide an empty, successful host-network inventory.
ip() { :; }
''' + body),
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def test_profile_ids_are_short_safe_names(self):
        self.run_shell(r'''
for value in iran1 node_2 a-b a123456789; do
  validate_profile_id "$value" || exit 71
done
for value in '' Iran1 ../iran1 '-iran1' 'two words' a1234567890 'iran/one'; do
  if validate_profile_id "$value"; then exit 72; fi
done
''')

    def test_distinct_profiles_persist_private_independent_addresses(self):
        self.run_shell(r'''
write_profile iran1 kharej 192.0.2.10 198.51.100.1 443,2096 no 172.16.1.0/30
write_profile iran2 kharej 192.0.2.10 198.51.100.2 443 yes 172.16.1.4/30
load_profile iran1
[[ $TUN_IF == g4-iran1 && $IRAN_TUN_CIDR == 172.16.1.1/30 && $KHAREJ_TUN_CIDR == 172.16.1.2/30 ]]
[[ $SERVICE_PORTS == 443,2096 && $ALLOW_UDP == no ]]
load_profile iran2
[[ $TUN_IF == g4-iran2 && $IRAN_TUN_CIDR == 172.16.1.5/30 && $KHAREJ_TUN_CIDR == 172.16.1.6/30 ]]
[[ $SERVICE_PORTS == 443 && $ALLOW_UDP == yes ]]
[[ $(stat -c %a "$PROFILE_DIR") == 700 ]]
[[ $(stat -c %a "$PROFILE_DIR/iran1.conf") == 600 ]]
[[ $(stat -c %a "$PROFILE_DIR/iran2.conf") == 600 ]]
''')

    def test_duplicate_peer_and_overlapping_subnet_are_rejected(self):
        self.run_shell(r'''
write_profile iran1 kharej 192.0.2.10 198.51.100.1 443 no 172.16.1.0/30
if write_profile iran2 kharej 192.0.2.10 198.51.100.1 443 no 172.16.1.4/30; then exit 71; fi
if write_profile iran3 kharej 192.0.2.10 198.51.100.3 443 no 172.16.1.0/30; then exit 72; fi
[[ ! -e $PROFILE_DIR/iran2.conf && ! -e $PROFILE_DIR/iran3.conf ]]
load_profile iran1
[[ $PEER_PUBLIC_IP == 198.51.100.1 && $IRAN_TUN_CIDR == 172.16.1.1/30 ]]
''')

    def test_profile_parser_rejects_shell_code_without_executing_it(self):
        self.run_shell(r'''
write_profile iran1 iran 192.0.2.1 198.51.100.1 443 no 172.16.1.0/30
printf 'LOCAL_PUBLIC_IP=$(touch %s)\n' "$1/executed" >> "$PROFILE_DIR/iran1.conf"
if load_profile iran1; then exit 71; fi
[[ ! -e $1/executed ]]
''')

    def test_profile_file_and_directory_symlinks_are_refused(self):
        self.run_shell(r'''
write_profile iran1 iran 192.0.2.1 198.51.100.1 443 no 172.16.1.0/30
cp "$PROFILE_DIR/iran1.conf" "$1/original"
rm "$PROFILE_DIR/iran1.conf"
ln -s "$1/original" "$PROFILE_DIR/iran1.conf"
if load_profile iran1; then exit 71; fi
if write_profile iran1 iran 192.0.2.1 198.51.100.1 443 no 172.16.1.0/30; then exit 72; fi
rm "$PROFILE_DIR/iran1.conf"
rmdir "$PROFILE_DIR"
mkdir "$1/elsewhere"
ln -s "$1/elsewhere" "$PROFILE_DIR"
if write_profile iran2 iran 192.0.2.2 198.51.100.1 443 no 172.16.1.4/30; then exit 73; fi
[[ ! -e $1/elsewhere/iran2.conf ]]
''')

    def test_failed_replacement_preserves_previous_configuration(self):
        self.run_shell(r'''
write_profile iran1 iran 192.0.2.1 198.51.100.1 443 no 172.16.1.0/30
cp "$PROFILE_DIR/iran1.conf" "$1/original"
chmod() { return 1; }
if write_profile iran1 iran 192.0.2.1 198.51.100.1 8443 no 172.16.1.0/30; then exit 71; fi
cmp -s "$PROFILE_DIR/iran1.conf" "$1/original"
''')

    def test_invalid_profile_values_are_rejected_before_creating_files(self):
        self.run_shell(r'''
for fields in \
  'iran 192.0.2.1 198.51.100.1 0 no 172.16.1.0/30' \
  'iran 192.0.2.1 198.51.100.1 65536 no 172.16.1.0/30' \
  'iran 192.0.2.1 198.51.100.1 443 maybe 172.16.1.0/30' \
  'unknown 192.0.2.1 198.51.100.1 443 no 172.16.1.0/30' \
  'iran 192.0.2.1 198.51.100.1 443 no 172.16.1.1/30' \
  'iran 192.0.2.1 198.51.100.1 443 no 172.16.1.0/31' \
  'iran 192.0.2.999 198.51.100.1 443 no 172.16.1.0/30'; do
  read -r -a args <<< "$fields"
  if write_profile iran1 "${args[@]}"; then exit 71; fi
done
[[ ! -e $PROFILE_DIR/iran1.conf ]]
''')

    def test_decimal_ports_and_endpoint_aliases_are_normalized(self):
        self.run_shell(r'''
[[ $(normalize_ports_list '0080,80,00443') == 80,443 ]]
validate_port 08
if validate_port 00000; then exit 71; fi
write_profile iran1 kharej 192.000.002.010 198.051.100.001 0080,80,00443 no 172.16.1.0/30
load_profile iran1
[[ $LOCAL_PUBLIC_IP == 192.0.2.10 && $PEER_PUBLIC_IP == 198.51.100.1 && $SERVICE_PORTS == 80,443 ]]
if write_profile iran2 kharej 192.0.2.10 198.51.100.001 443 no 172.16.1.4/30; then exit 72; fi
''')

    def test_host_route_and_address_conflicts_are_rejected(self):
        self.run_shell(r'''
ip() {
  if [[ $* == '-4 route show table all' ]]; then
    printf '%s\n' 'default via 192.0.2.254 dev eth0' '172.16.0.0/16 dev vpn0'
  fi
}
if write_profile iran1 iran 192.0.2.1 198.51.100.1 443 no 172.16.1.0/30; then exit 71; fi
ip() {
  if [[ $* == '-o -4 addr show' ]]; then
    printf '%s\n' '2: vpn0 inet 172.16.1.6/30 scope global vpn0'
  fi
}
if write_profile iran2 iran 192.0.2.1 198.51.100.1 443 no 172.16.1.4/30; then exit 72; fi
[[ ! -e $PROFILE_DIR/iran1.conf && ! -e $PROFILE_DIR/iran2.conf ]]
''')

    def test_invalid_update_id_cannot_delete_a_preexisting_state_file(self):
        self.run_shell(r'''
mkdir -p "$STATE_DIR"
echo administrator-record > "$STATE_DIR/escaped"
if profile_update ../escaped iran 192.0.2.1 198.51.100.1 443 no 172.16.1.0/30; then exit 71; fi
[[ $(cat "$STATE_DIR/escaped") == administrator-record ]]
''')

    def test_runtime_lock_refuses_a_symlinked_directory(self):
        self.run_shell(r'''
mkdir "$1/administrator-locks"
chmod 755 "$1/administrator-locks"
ln -s "$1/administrator-locks" "$LOCK_DIR"
if profile_runtime_lock; then exit 71; fi
[[ $(stat -c %a "$1/administrator-locks") == 755 ]]
[[ ! -e $1/administrator-locks/gre4-runtime.lock ]]
''')

    def test_runtime_lock_preserves_shared_parent_permissions(self):
        self.run_shell(r'''
mkdir "$1/shared-locks"
chmod 1777 "$1/shared-locks"
LOCK_DIR=$1/shared-locks/gre4
profile_runtime_lock
[[ $(stat -c %a "$1/shared-locks") == 1777 ]]
[[ $(stat -c %a "$LOCK_DIR") == 700 ]]
flock -u 8
exec 8>&-
''')

    def test_runtime_lock_refuses_a_symlinked_lock_file(self):
        self.run_shell(r'''
mkdir "$LOCK_DIR"
chmod 700 "$LOCK_DIR"
echo administrator-record > "$1/original"
ln -s "$1/original" "$LOCK_DIR/gre4-runtime.lock"
if profile_runtime_lock; then exit 71; fi
[[ $(cat "$1/original") == administrator-record ]]
''')

class ProfileRuntimeTests(ProfileRuntimeCase):
    def test_removing_another_profile_does_not_renumber_saved_addresses(self):
        self.config('iran1', role='kharej', number=1)
        self.config('iran2', role='kharej', number=2)
        self.config('iran3', role='kharej', number=3)
        before = (self.profiles / 'iran3.conf').read_bytes()
        self.shell('profile_remove iran2\n')
        self.assertFalse((self.profiles / 'iran2.conf').exists())
        self.assertEqual((self.profiles / 'iran3.conf').read_bytes(), before)
        self.shell('load_profile iran3\n[[ $IRAN_TUN_CIDR == 172.16.1.9/30 && $KHAREJ_TUN_CIDR == 172.16.1.10/30 ]]\n')

    def test_stopping_one_peer_preserves_sibling_and_shared_sysctls(self):
        self.config('iran1', role='kharej', number=1)
        self.config('iran2', role='kharej', number=2)
        self.invoke('start', 'iran1')
        self.invoke('start', 'iran2')
        before = self.data()['interfaces']['g4-iran2']
        self.invoke('stop', 'iran1')
        state = self.data()
        self.assertNotIn('g4-iran1', state['interfaces'])
        self.assertEqual(state['interfaces']['g4-iran2'], before)
        self.assertEqual(state['sysctl']['net.ipv4.ip_forward'], '1')
        self.assertTrue((self.state_dir / 'profiles/iran2/applied.conf').exists())
        self.invoke('stop', 'iran2')
        state = self.data()
        self.assertEqual(state['interfaces'], {})
        self.assertEqual(state['sysctl']['net.ipv4.ip_forward'], '0')
        self.assertEqual(state['sysctl']['net.netfilter.nf_conntrack_max'], '32768')

    def test_nat_uses_profile_destination_and_cleanup_survives_missing_config(self):
        self.config('iran2', number=2, ports='443,2096', udp='yes')
        self.invoke('start', 'iran2')
        rules = [' '.join(rule) for rule in self.data()['iptables']]
        self.assertTrue(any('DNAT --to-destination 172.16.1.6:443' in rule and 'gre4:iran2' in rule for rule in rules))
        self.assertTrue(any('-p udp' in rule and '172.16.1.6:2096' in rule for rule in rules))
        self.assertFalse(any('172.16.1.2' in rule for rule in rules))
        (self.profiles / 'iran2.conf').unlink()
        self.invoke('stop', 'iran2')
        self.assertEqual(self.data()['iptables'], [])
        self.assertEqual(self.data()['interfaces'], {})

    def test_cleanup_uses_applied_snapshot_after_configuration_edit(self):
        self.config('iran2', number=2, ports='443', udp='yes')
        self.invoke('start', 'iran2')
        path = self.profiles / 'iran2.conf'
        path.write_text(path.read_text().replace('443', '8443'))
        self.invoke('stop', 'iran2')
        self.assertEqual(self.data()['iptables'], [])
        self.assertEqual(self.data()['interfaces'], {})
        self.assertIn('8443', path.read_text())

    def test_unowned_interface_collision_is_preserved(self):
        self.config('iran1', number=1)
        unrelated = {'local': '192.0.2.9', 'remote': '198.51.100.9',
                     'alias': 'administrator', 'addresses': ['10.0.0.1/30'], 'up': True}
        self.update(interfaces={'g4-iran1': unrelated})
        result = self.invoke('start', 'iran1', success=False)
        self.assertRegex((result.stdout + result.stderr).lower(), 'interface|owned')
        self.assertEqual(self.data()['interfaces']['g4-iran1'], unrelated)
        self.assertFalse(any(command.startswith('ip tunnel del') for command in self.data()['commands']))

    def test_failed_cleanup_retains_snapshot_and_blocks_reapplication(self):
        self.config('iran1', number=1)
        self.invoke('start', 'iran1')
        self.update(failures=['ip tunnel del g4-iran1'])
        self.invoke('stop', 'iran1', success=False)
        snapshot = self.state_dir / 'profiles/iran1/applied.conf'
        self.assertTrue(snapshot.exists())
        self.assertTrue((snapshot.parent / 'cleanup-pending').exists())
        self.invoke('start', 'iran1', success=False)
        self.update(failures=[])
        self.invoke('stop', 'iran1')
        self.assertFalse(snapshot.exists())
        self.assertEqual(self.data()['interfaces'], {})

    def test_cleanup_refuses_a_symlinked_profile_state_directory(self):
        self.config('iran1')
        self.invoke('start', 'iran1')
        state = self.state_dir / 'profiles/iran1'
        elsewhere = self.root / 'administrator-state'
        state.rename(elsewhere)
        state.symlink_to(elsewhere, target_is_directory=True)
        before = self.data()['interfaces']
        self.invoke('stop', 'iran1', success=False)
        self.assertEqual(self.data()['interfaces'], before)
        self.assertTrue((elsewhere / 'applied.conf').exists())
        self.assertFalse((elsewhere / 'cleanup-pending').exists())

    def test_administrator_sysctl_change_survives_last_peer_cleanup(self):
        self.config('iran1', role='kharej', number=1)
        self.config('iran2', role='kharej', number=2)
        self.invoke('start', 'iran1')
        self.invoke('start', 'iran2')
        values = self.data()['sysctl']
        values['net.netfilter.nf_conntrack_max'] = '99999'
        self.update(sysctl=values)
        self.invoke('stop', 'iran1')
        self.invoke('stop', 'iran2')
        self.assertEqual(self.data()['sysctl']['net.netfilter.nf_conntrack_max'], '99999')

    def test_failed_second_start_cleans_only_its_own_partial_state(self):
        self.config('iran1', role='kharej', number=1)
        self.config('iran2', role='kharej', number=2)
        self.invoke('start', 'iran1')
        sibling = self.data()['interfaces']['g4-iran1']
        self.update(failures=['ip link add name g4-iran2'])
        self.invoke('start', 'iran2', success=False)
        # systemd ExecStopPost invokes stop even when the start command fails.
        self.invoke('stop', 'iran2')
        state = self.data()
        self.assertEqual(state['interfaces'], {'g4-iran1': sibling})
        self.assertEqual(state['sysctl']['net.ipv4.ip_forward'], '1')
        self.assertTrue((self.state_dir / 'profiles/iran1/applied.conf').exists())
        self.assertFalse((self.state_dir / 'profiles/iran2/applied.conf').exists())
        self.update(failures=[])
        self.invoke('stop', 'iran1')

    def test_shared_ufw_ports_and_gre_peers_survive_one_peer_stop(self):
        original = ['8443/tcp ALLOW IN 203.0.113.7',
                    '2222/tcp on eth0 ALLOW IN 203.0.113.10 # gre4-shared']
        self.update(ufw_active=True, ufw_rules=original)
        self.config('iran1', role='kharej', number=1, ports='443,2096', udp='yes')
        self.config('iran2', role='kharej', number=2, ports='443', udp='no')
        self.invoke('start', 'iran1')
        self.invoke('start', 'iran2')
        self.invoke('stop', 'iran1')
        state = self.data()
        for rule in original:
            self.assertIn(rule, state['ufw_rules'])
        managed = [rule for rule in state['ufw_rules'] if '# gre4-shared' in rule and not rule.startswith('2222/')]
        self.assertEqual(len(managed), 1, managed)
        self.assertTrue(managed[0].startswith('443/tcp'), managed)
        rules = self.before.read_text()
        self.assertIn('198.51.100.2', rules)
        self.assertNotIn('198.51.100.1 ', rules)
        self.invoke('stop', 'iran2')
        self.assertEqual(self.data()['ufw_rules'], original)
        self.assertNotIn('# gre4 profiles BEGIN', self.before.read_text())

    def test_invalid_openssh_configuration_preserves_ufw_rules_and_recovery(self):
        self.update(ufw_active=True, ufw_rules=[])
        self.config('iran1', role='kharej', number=1, ports='443')
        self.invoke('start', 'iran1')
        before = self.data()['ufw_rules']
        self.update(sshd='listenaddress [::]:invalid\n')
        self.invoke('stop', 'iran1', success=False)
        self.assertEqual(self.data()['ufw_rules'], before)
        self.assertTrue((self.state_dir / 'profiles/iran1/applied.conf').exists())
        self.update(sshd='port 2222\n')
        self.invoke('stop', 'iran1')

    def test_listenaddress_ssh_rule_keeps_original_source_restriction(self):
        original = '7443/tcp on eth0 ALLOW IN 203.0.113.10 # gre4-shared'
        self.update(ufw_active=True, ufw_rules=[original],
                    sshd='port 2222\nlistenaddress 0.0.0.0:7443\nlistenaddress [::]:7443\n')
        self.config('iran1', role='kharej', number=1)
        self.invoke('start', 'iran1')
        self.invoke('stop', 'iran1')
        self.assertEqual(self.data()['ufw_rules'], [original])
        self.assertFalse(any(command.startswith('ufw allow') and 'port 7443 ' in command
                             for command in self.data()['commands']))

    def test_reload_failure_retains_cleanup_snapshot_and_can_be_retried(self):
        self.update(ufw_active=True)
        self.config('iran1', role='kharej', number=1)
        self.invoke('start', 'iran1')
        self.update(failures=['ufw reload'])
        self.invoke('stop', 'iran1', success=False)
        snapshot = self.state_dir / 'profiles/iran1/applied.conf'
        self.assertTrue(snapshot.exists())
        self.assertEqual(self.data()['sysctl']['net.ipv4.ip_forward'], '1')
        self.update(failures=[])
        self.invoke('stop', 'iran1')
        self.assertFalse(snapshot.exists())
        self.assertEqual(self.data()['sysctl']['net.ipv4.ip_forward'], '0')

    def test_repeated_start_does_not_duplicate_owned_rules(self):
        self.config('iran1', ports='443,2096', udp='yes')
        self.invoke('start', 'iran1')
        before = self.data()
        self.invoke('start', 'iran1')
        after = self.data()
        self.assertEqual(after['iptables'], before['iptables'])
        self.assertEqual(after['interfaces'], before['interfaces'])
        self.invoke('stop', 'iran1')

    def test_parallel_peer_lifecycle_keeps_shared_recovery_consistent(self):
        self.config('iran1', role='kharej', number=1)
        self.config('iran2', role='kharej', number=2)
        for action in ('start', 'stop'):
            processes = [subprocess.Popen(['bash', str(self.helper), action, name],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         text=True, env=self.env)
                         for name in ('iran1', 'iran2')]
            for process in processes:
                stdout, stderr = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, stdout + stderr)
            if action == 'start':
                self.assertEqual(set(self.data()['interfaces']), {'g4-iran1', 'g4-iran2'})
        state = self.data()
        self.assertEqual(state['interfaces'], {})
        self.assertEqual(state['sysctl']['net.ipv4.ip_forward'], '0')
        self.assertEqual(state['sysctl']['net.netfilter.nf_conntrack_max'], '32768')

    def test_applied_profile_recovers_after_kernel_state_is_lost(self):
        self.config('iran1', role='kharej', number=1)
        self.invoke('start', 'iran1')
        values = self.data()['sysctl']
        values.update({'net.ipv4.ip_forward': '0', 'net.ipv4.conf.all.forwarding': '0',
                       'net.netfilter.nf_conntrack_max': '32768'})
        self.update(interfaces={}, iptables=[], sysctl=values)
        self.invoke('start', 'iran1')
        state = self.data()
        self.assertIn('g4-iran1', state['interfaces'])
        self.assertEqual(state['sysctl']['net.ipv4.ip_forward'], '1')
        self.assertNotEqual(state['sysctl']['net.netfilter.nf_conntrack_max'], '32768')
        self.invoke('stop', 'iran1')
        self.assertEqual(self.data()['sysctl']['net.netfilter.nf_conntrack_max'], '32768')

    def test_resumed_start_rejects_a_new_administrator_route_conflict(self):
        self.config('iran1', role='kharej')
        self.invoke('start', 'iran1')
        self.update(interfaces={}, route_inventory='172.16.1.0/24 dev administrator-vpn\n', commands=[])
        self.invoke('start', 'iran1', success=False)
        self.assertEqual(self.data()['interfaces'], {})
        self.assertTrue((self.state_dir / 'profiles/iran1/applied.conf').exists())
        self.assertFalse(any(' add ' in command for command in self.data()['commands']))
        self.invoke('stop', 'iran1')

    def test_rejected_edits_preserve_running_profiles_and_recovery(self):
        self.config('iran1', role='kharej', number=1)
        self.config('iran2', role='kharej', number=2)
        self.invoke('start', 'iran1')
        self.invoke('start', 'iran2')
        before = self.data()
        config = (self.profiles / 'iran1.conf').read_bytes()
        snapshot = (self.state_dir / 'profiles/iran1/applied.conf').read_bytes()
        candidates = [
            '192.0.2.10 198.51.100.1 443 maybe 172.16.1.0/30',
            'invalid 198.51.100.1 443 no 172.16.1.0/30',
            '192.0.2.10 198.51.100.2 443 no 172.16.1.0/30',
            '192.0.2.10 198.51.100.1 443 no 172.16.1.4/30',
        ]
        for fields in candidates:
            with self.subTest(candidate=fields):
                self.shell(f'profile_update iran1 kharej {fields}\n', expected=1)
                after = self.data()
                for key in ('interfaces', 'iptables', 'ufw_rules', 'sysctl'):
                    self.assertEqual(after[key], before[key])
                self.assertEqual((self.profiles / 'iran1.conf').read_bytes(), config)
                self.assertEqual((self.state_dir / 'profiles/iran1/applied.conf').read_bytes(), snapshot)
        self.invoke('stop', 'iran1')
        self.invoke('stop', 'iran2')

    def test_failed_interface_alias_creation_is_cleanable_without_affecting_sibling(self):
        self.config('iran1', role='kharej', number=1)
        self.config('iran2', role='kharej', number=2)
        self.invoke('start', 'iran1')
        sibling = self.data()['interfaces']['g4-iran1']
        self.update(fail_alias=True)
        self.invoke('start', 'iran2', success=False)
        self.update(fail_alias=False)
        self.invoke('stop', 'iran2')
        self.assertEqual(self.data()['interfaces'], {'g4-iran1': sibling})
        self.assertFalse((self.state_dir / 'profiles/iran2/applied.conf').exists())
        self.invoke('start', 'iran2')
        self.assertEqual(self.data()['interfaces']['g4-iran2']['alias'], 'gre4:iran2')
        self.invoke('stop', 'iran2')
        self.invoke('stop', 'iran1')

    def test_interface_inspection_failure_retains_cleanup_ownership(self):
        self.config('iran1')
        self.invoke('start', 'iran1')
        interface = self.data()['interfaces']['g4-iran1']
        self.update(failures=['ip link show', 'ip -o link show'])
        self.invoke('stop', 'iran1', success=False)
        self.assertEqual(self.data()['interfaces']['g4-iran1'], interface)
        self.assertTrue((self.state_dir / 'profiles/iran1/applied.conf').exists())
        self.assertTrue((self.state_dir / 'profiles/iran1/cleanup-pending').exists())
        self.assertEqual(self.data()['sysctl']['net.ipv4.ip_forward'], '1')
        self.update(failures=[])
        self.invoke('stop', 'iran1')
        self.assertEqual(self.data()['interfaces'], {})
        self.assertFalse((self.state_dir / 'profiles/iran1/applied.conf').exists())

    def test_new_ipv4_allowance_does_not_shift_cleanup_onto_ipv6_ssh(self):
        (self.root / 'ufw-defaults').write_text('IPV6=yes\n')
        original = ['22/tcp ALLOW IN Anywhere # administrator',
                    '2222/tcp ALLOW IN Anywhere # gre4-shared',
                    '22/tcp (v6) ALLOW IN Anywhere (v6) # administrator',
                    '2222/tcp (v6) ALLOW IN Anywhere (v6) # gre4-shared']
        self.update(ufw_active=True, ufw_rules=original, sshd='port 22\n')
        self.config('iran1', role='kharej', ports='443')
        self.invoke('start', 'iran1')
        rules = self.data()['ufw_rules']
        for rule in (original[0], original[2]):
            self.assertIn(rule, rules)
        self.assertFalse(any(rule.startswith('2222/') for rule in rules))
        for suffix in ('', ' (v6)'):
            self.assertIn(f'443/tcp{suffix} ALLOW IN Anywhere{suffix} # gre4-shared', rules)
        self.invoke('stop', 'iran1')
        self.assertEqual(self.data()['ufw_rules'], [original[0], original[2]])

    def test_failed_ufw_number_refresh_never_deletes_using_old_indices(self):
        self.config('iran1', role='kharej', ports='443')
        self.invoke('start', 'iran1')
        old = '8443/tcp ALLOW IN Anywhere # gre4-shared'
        self.update(ufw_active=True, ufw_rules=[old], commands=[])
        self.runtime_shell(r'''
ufw() {
  if [[ $* == 'status numbered' ]]; then
    if [[ -e $STATE_DIR/status-read ]]; then return 1; fi
    touch "$STATE_DIR/status-read"
  fi
  command ufw "$@"
}
profile_ufw_reconcile
''', expected=1)
        self.assertIn(old, self.data()['ufw_rules'])
        self.assertFalse(any(command.startswith('ufw --force delete') for command in self.data()['commands']))
        self.invoke('stop', 'iran1')

    def test_inactive_ufw_retains_only_another_peers_shared_port(self):
        self.config('iran1', role='kharej', number=1, ports='443')
        self.config('iran2', role='kharej', number=2, ports='8443')
        self.invoke('start', 'iran1')
        self.invoke('start', 'iran2')
        (self.ufw_dir / 'user.rules').write_text(
            '*filter\n### tuple ### allow tcp 8443 0.0.0.0/0 any 0.0.0.0/0 in '
            'comment=677265342d736861726564\n'
            '-A ufw-user-input -p tcp --dport 8443 -j ACCEPT\nCOMMIT\n')
        self.invoke('stop', 'iran1')
        self.assertTrue((self.state_dir / 'profiles/iran2/applied.conf').exists())
        self.assertIn('g4-iran2', self.data()['interfaces'])

    def test_missing_local_public_ip_is_rejected_before_runtime_changes(self):
        self.config('iran1')
        self.update(address_inventory='')
        result = self.invoke('start', 'iran1', success=False)
        self.assertIn('Local public IP', result.stdout + result.stderr)
        self.assertEqual(self.data()['interfaces'], {})
        self.assertEqual(self.data()['sysctl']['net.ipv4.ip_forward'], '0')
        self.assertFalse((self.state_dir / 'profiles/iran1/applied.conf').exists())

    def test_start_service_repairs_an_interrupted_helper_installation(self):
        self.config('iran1')
        self.helper.unlink()
        self.shell('profile_start_service iran1\n')
        self.assertTrue(self.helper.exists())
        self.assertTrue((self.root / 'gre4@.service').exists())
        self.assertIn('g4-iran1', self.data()['interfaces'])
        self.invoke('stop', 'iran1')

    def test_pending_migration_blocks_normal_changes_but_allows_cleanup(self):
        self.config('iran1')
        self.invoke('start', 'iran1')
        before = (self.profiles / 'iran1.conf').read_bytes()
        backups = self.root / 'backups'
        backups.mkdir()
        (backups / 'pending').write_text('migration-in-progress\n')
        self.shell(r'''
if profile_start_service iran1; then exit 71; fi
if profile_update iran1 iran 198.51.100.1 192.0.2.10 8443 no 172.16.1.0/30; then exit 72; fi
if profile_remove iran1; then exit 73; fi
profile_stop_service iran1
''')
        self.assertEqual((self.profiles / 'iran1.conf').read_bytes(), before)
        self.assertEqual(self.data()['interfaces'], {})


if __name__ == "__main__":
    unittest.main()
