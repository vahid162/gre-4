"""Regression behavior exercised through the shipped profile/helper paths."""
from pathlib import Path
import shlex
import subprocess
import unittest

from shell_source import SOURCE, FUNCTIONS
from profile_fixture import ProfileRuntimeCase


class Gre4Tests(ProfileRuntimeCase):
    def running(self, role='iran', ports='443', udp='no'):
        self.config('iran1', role=role, ports=ports, udp=udp)
        return self.invoke('start', 'iran1')

    def replace(self, ports='443', udp='no', expected=0):
        return self.shell(f'profile_update iran1 iran 198.51.100.1 192.0.2.10 {ports} {udp} 172.16.1.0/30\n', expected)

    def test_generated_apply_loads_quoted_config_path(self):
        self.assertIn(' ', str(self.root))
        self.running()
        self.assertIn('g4-iran1', self.data()['interfaces'])
        self.invoke('stop', 'iran1')

    def test_failed_apply_installation_preserves_previous_script(self):
        self.shell(r'''
cp "$APPLY_SCRIPT" "$1/before"
chmod() { return 1; }
if install_apply_script; then exit 71; fi
cmp -s "$APPLY_SCRIPT" "$1/before"
''')

    def test_removing_port_cleans_previous_nat_and_forward_rules(self):
        self.running(ports='80,443')
        self.replace(ports='443')
        rules = [' '.join(rule) for rule in self.data()['iptables']]
        self.assertFalse(any('--dport 80 ' in rule for rule in rules))
        self.assertTrue(any('--dport 443 ' in rule and 'DNAT' in rule for rule in rules))
        self.invoke('stop', 'iran1')

    def test_cleanup_preserves_ssh_and_administrator_modified_rule_shapes(self):
        self.update(ufw_active=True)
        self.running(role='kharej')
        rules = [
            '2222/tcp on eth0 ALLOW IN 203.0.113.10 # gre4-shared',
            '443/tcp ALLOW IN Anywhere # gre4-shared',
            '2222/udp ALLOW IN Anywhere # gre4-shared',
            '2222/tcp (v6) ALLOW IN 2001:db8::1 # gre4-shared',
            '2222/tcp DENY IN Anywhere # gre4-shared',
            '2222/tcp ALLOW OUT Anywhere # gre4-shared',
            '22/tcp ALLOW IN 203.0.113.10',
            '192.0.2.2 2222/tcp ALLOW IN 203.0.113.10 # gre4-shared',
            '2001:db8::2 2222/tcp ALLOW IN 2001:db8::1 # gre4-shared',
            '443/tcp ALLOW IN 203.0.113.10 2222/tcp # gre4-shared',
        ]
        self.update(ufw_rules=rules)
        self.invoke('stop', 'iran1')
        # GRE4 only owns exact public ALLOW shapes it creates. Restricted,
        # DENY, and outbound edits remain administrator-owned even with a tag.
        self.assertEqual(self.data()['ufw_rules'], [rules[i] for i in (0, 3, 4, 5, 6, 7, 8, 9)])

    def test_cleanup_never_opens_unmanaged_ssh(self):
        original = '2222/tcp ALLOW IN 203.0.113.10'
        self.update(ufw_active=True, ufw_rules=[original])
        self.running(role='kharej')
        self.invoke('stop', 'iran1')
        self.assertEqual(self.data()['ufw_rules'], [original])
        self.assertFalse(any(command.startswith('ufw allow') and 'port 2222 ' in command
                             for command in self.data()['commands']))

    def test_cleanup_keeps_rules_when_ssh_detection_fails(self):
        self.update(ufw_active=True)
        self.running(role='kharej')
        rules = self.data()['ufw_rules']
        self.update(failures=['sshd -T'])
        self.invoke('stop', 'iran1', success=False)
        self.assertEqual(self.data()['ufw_rules'], rules)
        self.assertTrue((self.state_dir / 'profiles/iran1/applied.conf').exists())

    def test_start_preserves_previous_managed_ssh_allowance(self):
        original = '2222/tcp on eth0 ALLOW IN 203.0.113.10 # gre4-shared'
        self.update(ufw_active=True, ufw_rules=[original])
        self.running(role='kharej')
        self.assertIn(original, self.data()['ufw_rules'])
        self.invoke('stop', 'iran1')
        self.assertEqual(self.data()['ufw_rules'], [original])

    def test_unreliable_ssh_detection_never_deletes_rules(self):
        self.update(ufw_active=True)
        self.running(role='kharej')
        before = self.data()['ufw_rules']
        for config in ('port invalid\n', 'port 0\n', 'port 65536\n', ''):
            with self.subTest(config=config):
                self.update(sshd=config)
                self.invoke('stop', 'iran1', success=False)
                self.assertEqual(self.data()['ufw_rules'], before)

    def test_failed_ufw_deletion_stops_numbered_cleanup(self):
        self.update(ufw_active=True)
        self.running(role='kharej', ports='443,2096')
        before = self.data()['ufw_rules']
        self.update(failures=['ufw --force delete'], commands=[])
        self.invoke('stop', 'iran1', success=False)
        self.assertEqual(self.data()['ufw_rules'], before)
        self.assertEqual(sum(command.startswith('ufw --force delete') for command in self.data()['commands']), 1)

    def test_first_ufw_setup_needs_no_ssh_detection(self):
        self.update(ufw_active=True, failures=['sshd -T'])
        self.running(role='kharej')
        self.assertTrue(any(rule.startswith('443/tcp') for rule in self.data()['ufw_rules']))

    def test_repeated_setup_stops_old_deployment_and_applies_new_config(self):
        self.running(ports='80,443')
        self.replace(ports='2096')
        rules = [' '.join(rule) for rule in self.data()['iptables']]
        self.assertFalse(any('--dport 80 ' in rule or '--dport 443 ' in rule for rule in rules))
        self.assertTrue(any('--dport 2096 ' in rule for rule in rules))
        commands = self.data()['commands']
        self.assertLess(commands.index('ip tunnel del g4-iran1'),
                        max(i for i, command in enumerate(commands) if command.startswith('ip link add name g4-iran1')))

    def test_reload_failure_fails_start_without_success_messages(self):
        self.update(ufw_active=True, failures=['ufw reload'])
        self.config('iran1', role='kharej')
        result = self.invoke('start', 'iran1', success=False)
        self.assertNotIn('Connection started', result.stdout)
        self.assertTrue((self.state_dir / 'profiles/iran1/cleanup-pending').exists())

    def test_successful_reload_allows_start_success(self):
        self.update(ufw_active=True)
        result = self.running(role='kharej')
        self.assertIn('Connection started: iran1', result.stdout)

    def test_setup_stop_failure_keeps_previous_files(self):
        self.running()
        before = (self.profiles / 'iran1.conf').read_bytes()
        self.update(failures=['ip tunnel del g4-iran1'])
        self.replace(ports='8443', expected=1)
        self.assertEqual((self.profiles / 'iran1.conf').read_bytes(), before)
        self.assertTrue(self.helper.exists())
        self.assertTrue((self.state_dir / 'profiles/iran1/applied.conf').exists())

    def test_ufw_snapshot_failure_deletes_nothing(self):
        self.update(ufw_active=True)
        self.running(role='kharej')
        before = self.data()['ufw_rules']
        self.update(failures=['ufw status'], commands=[])
        self.invoke('stop', 'iran1', success=False)
        self.assertEqual(self.data()['ufw_rules'], before)
        self.assertFalse(any(command.startswith('ufw --force delete') for command in self.data()['commands']))

    def test_existing_service_rules_can_be_cleaned_without_openssh(self):
        (self.bin / 'sshd').unlink()
        self.env['PATH'] = f'{self.bin}:/usr/bin:/bin'
        self.update(ufw_active=True)
        self.running(role='kharej')
        self.invoke('stop', 'iran1')
        self.assertEqual(self.data()['ufw_rules'], [])

    def test_firewall_stop_failure_is_reported(self):
        self.update(ufw_active=True)
        self.running(role='kharej')
        self.update(failures=['ufw --force delete'])
        result = self.invoke('stop', 'iran1', success=False)
        self.assertIn('Cleanup incomplete', result.stdout + result.stderr)

    def test_uninstall_failure_preserves_cleanup_files(self):
        self.running()
        before = (self.profiles / 'iran1.conf').read_bytes()
        self.update(failures=['ip tunnel del g4-iran1'])
        self.shell('if profile_remove iran1; then exit 71; fi\n')
        self.assertEqual((self.profiles / 'iran1.conf').read_bytes(), before)
        self.assertTrue(self.helper.exists())
        self.assertTrue((self.state_dir / 'profiles/iran1/applied.conf').exists())

    def test_failed_activation_has_post_stop_cleanup(self):
        self.shell(r'''
install_profile_unit
grep -Fxq "ExecStopPost=$APPLY_SCRIPT post-stop %i" "$TEMPLATE_FILE"
grep -Fxq "ExecStart=$APPLY_SCRIPT start %i" "$TEMPLATE_FILE"
grep -Fxq 'After=network-online.target ssh.service ssh.socket' "$TEMPLATE_FILE"
! grep -Eq '^(Wants|Requires)=.*ssh\.(service|socket)' "$TEMPLATE_FILE"
! grep -q '^ExecStop=' "$TEMPLATE_FILE"
''')

    @unittest.skipUnless(Path('/proc/sys/net/ipv6').is_dir(), 'Kernel IPv6 unavailable')
    def test_existing_public_rules_are_preserved_per_address_family(self):
        (self.root / 'ufw-defaults').write_text('IPV6=yes\n')
        v4 = '443/tcp ALLOW IN Anywhere # administrator-web'
        v6 = '443/tcp (v6) ALLOW IN Anywhere (v6) # administrator-web'
        for originals, expected in (([v4], '(v6)'), ([v6], '443/tcp ALLOW'), ([v4, v6], None)):
            with self.subTest(originals=originals):
                self.update(ufw_active=True, ufw_rules=originals)
                self.config('iran1', role='kharej')
                self.invoke('start', 'iran1')
                rules = self.data()['ufw_rules']
                for original in originals:
                    self.assertIn(original, rules)
                additions = [rule for rule in rules if rule not in originals]
                self.assertEqual(len(additions), 0 if expected is None else 1)
                if expected:
                    self.assertIn(expected, additions[0])
                self.invoke('stop', 'iran1')
                self.assertEqual(self.data()['ufw_rules'], originals)

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
                self.runtime_shell('status=' + shlex.quote('[ 1] ' + rule) + '\n'
                                   + 'if ufw_has_public_allow "$status" 443 tcp 4; then found=yes; else found=no; fi\n'
                                   + f'[[ $found == {"yes" if allowed else "no"} ]]\n')

    @unittest.skipUnless(Path('/proc/sys/net/ipv6').is_dir(), 'Kernel IPv6 unavailable')
    def test_ufw_ipv6_configuration_precedence(self):
        self.runtime_shell(r'''
echo 'IPV6=yes' > "$1/defaults"
echo 'ENABLED=yes' > "$1/ufw.conf"
ufw_ipv6_enabled "$1/defaults" "$1/ufw.conf"
echo 'IPV6="no"' > "$1/ufw.conf"
if ufw_ipv6_enabled "$1/defaults" "$1/ufw.conf"; then exit 71; fi
echo 'IPV6="yes"' > "$1/ufw.conf"
ufw_ipv6_enabled "$1/defaults" "$1/ufw.conf"
echo 'IPV6=no' > "$1/defaults"
echo "IPV6='yes'" > "$1/ufw.conf"
if ufw_ipv6_enabled "$1/defaults" "$1/ufw.conf"; then exit 72; fi
echo 'IPV6=yes' > "$1/defaults"
echo "IPV6='no'" > "$1/ufw.conf"
ufw_ipv6_enabled "$1/defaults" "$1/ufw.conf"
echo 'IPV6= no' > "$1/ufw.conf"
ufw_ipv6_enabled "$1/defaults" "$1/ufw.conf"
''')

    def test_inactive_service_cleanup_failure_preserves_old_config(self):
        self.running(ports='80,443')
        self.update(failures=['ip tunnel del g4-iran1'])
        before = (self.profiles / 'iran1.conf').read_bytes()
        self.replace(ports='443', expected=1)
        self.assertEqual((self.profiles / 'iran1.conf').read_bytes(), before)

    def test_iptables_cleanup_failures_are_bounded_and_propagated(self):
        self.running(ports='80,443')
        self.update(failures=['iptables -t nat -D'], commands=[])
        self.invoke('stop', 'iran1', success=False)
        deletions = [command for command in self.data()['commands'] if command.startswith('iptables -t nat -D')]
        self.assertLessEqual(len(deletions), 5)
        self.assertGreater(len(deletions), 0)
        self.assertTrue((self.state_dir / 'profiles/iran1/applied.conf').exists())

    def test_disabling_udp_removes_previous_udp_rules(self):
        self.running(udp='yes')
        self.replace(udp='no')
        rules = [' '.join(rule) for rule in self.data()['iptables']]
        self.assertFalse(any('-p udp ' in rule for rule in rules))
        self.assertTrue(any('-p tcp ' in rule for rule in rules))

    def test_upgrade_uses_new_cleanup_before_replacing_config(self):
        self.running(ports='80,443')
        self.update(failures=['iptables -t nat -D'])
        before = (self.profiles / 'iran1.conf').read_bytes()
        self.replace(ports='2096', expected=1)
        self.assertEqual((self.profiles / 'iran1.conf').read_bytes(), before)
        self.assertTrue(self.helper.exists())

    def test_ufw_status_query_error_is_not_treated_as_inactive(self):
        self.running()
        self.update(failures=['ufw status'])
        output = self.invoke('stop', 'iran1', success=False)
        self.assertNotIn('Connection stopped', output.stdout)
        self.assertTrue((self.state_dir / 'profiles/iran1/applied.conf').exists())

    def test_failed_stop_preserves_configuration(self):
        self.running()
        before = (self.profiles / 'iran1.conf').read_bytes()
        self.update(failures=['systemctl stop'])
        self.replace(ports='8443', expected=1)
        self.assertEqual((self.profiles / 'iran1.conf').read_bytes(), before)

    def test_failed_config_replacement_preserves_original(self):
        self.config('iran1')
        for failure in ('mktemp', 'chmod', 'mv'):
            with self.subTest(failure=failure):
                self.shell('cp "$PROFILE_DIR/iran1.conf" "$1/before"\n'
                           + f'{failure}() {{ return 1; }}\n'
                           + 'if write_profile iran1 iran 198.51.100.1 192.0.2.10 8443 no 172.16.1.0/30; then exit 71; fi\n'
                           + 'cmp -s "$PROFILE_DIR/iran1.conf" "$1/before"\n'
                           + '[[ $(stat -c %a "$PROFILE_DIR/iran1.conf") == 600 ]]\n'
                           + '! compgen -G "$PROFILE_DIR/.iran1.*"\n')

    def test_cleanup_preserves_ports_from_listenaddress(self):
        original = '7443/tcp on eth0 ALLOW IN 203.0.113.10 # gre4-shared'
        self.update(ufw_active=True, ufw_rules=[original], sshd='port 2222\nlistenaddress [::]:7443\n')
        self.running(role='kharej')
        self.invoke('stop', 'iran1')
        self.assertEqual(self.data()['ufw_rules'], [original])

    def test_invalid_listener_port_keeps_all_managed_rules(self):
        self.update(ufw_active=True)
        self.running(role='kharej')
        before = self.data()['ufw_rules']
        self.update(sshd='port 2222\nlistenaddress [::]:invalid\n')
        self.invoke('stop', 'iran1', success=False)
        self.assertEqual(self.data()['ufw_rules'], before)

    def test_inactive_ufw_retains_recovery_files_for_owned_rules(self):
        self.running()
        self.before.write_text(self.before.read_text().replace('COMMIT',
                              '-A ufw-before-input -p 47 -m comment --comment gre4:iran1 -j ACCEPT\nCOMMIT'))
        self.invoke('stop', 'iran1', success=False)
        self.assertTrue((self.state_dir / 'profiles/iran1/applied.conf').exists())
        self.assertTrue((self.profiles / 'iran1.conf').exists())
        self.assertTrue(self.helper.exists())

    def test_inactive_ufw_without_owned_rules_can_be_cleaned(self):
        self.running()
        self.invoke('stop', 'iran1')
        self.assertFalse((self.state_dir / 'profiles/iran1/applied.conf').exists())
        self.assertEqual(self.data()['iptables'], [])

    def test_iptables_cleanup_preserves_unowned_matching_rules(self):
        original = ['nat', 'PREROUTING', '-d', '198.51.100.1/32', '-p', 'tcp', '--dport', '443',
                    '-j', 'DNAT', '--to-destination', '172.16.1.2:443']
        self.update(iptables=[original])
        self.running()
        self.invoke('stop', 'iran1')
        self.assertEqual(self.data()['iptables'], [original])

    def test_new_iptables_rules_are_owned_and_idempotent(self):
        self.runtime_shell(r'''
PROFILE_ID=iran1
profile_ipt_add nat PREROUTING -p tcp --dport 443 -j ACCEPT
profile_ipt_add nat PREROUTING -p tcp --dport 443 -j ACCEPT
''')
        rules = self.data()['iptables']
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0][-4:], ['-m', 'comment', '--comment', 'gre4:iran1'])
        self.runtime_shell(r'''
PROFILE_ID=iran1
iptables() { return 4; }
if profile_ipt_add nat PREROUTING -p tcp --dport 80 -j ACCEPT; then exit 71; fi
''')


if __name__ == '__main__':
    unittest.main()
