"""Prompt-driven Add and real-helper migration with private filesystem substitutes."""
from pathlib import Path
import hashlib
import shlex

from profile_fixture import ProfileRuntimeCase


class AddWorkflowTests(ProfileRuntimeCase):
    def add(self, role, expected=0, prefix=''):
        local, peer = ('198.51.100.1', '192.0.2.10') if role == 'iran' else ('192.0.2.10', '198.51.100.1')
        return self.shell(prefix + f'''add_profile_interactive {role} <<'ANSWERS'
new
{local}
{peer}
443,2096
yes
172.16.1.0/30
ANSWERS
''', expected)

    def sibling(self, role):
        self.shell('install_profile_unit\n')
        if role == 'iran':
            self.shell('write_profile sibling iran 198.51.100.1 192.0.2.20 8443 no 172.16.1.4/30\n')
        else:
            self.config('sibling', role=role, number=2, ports='8443')
        self.shell('systemctl enable --now gre4@sibling.service\n')
        return ((self.profiles / 'sibling.conf').read_bytes(),
                (self.state_dir / 'profiles/sibling/applied.conf').read_bytes(),
                self.data()['interfaces']['g4-sibling'],
                [rule for rule in self.data()['iptables'] if 'gre4:sibling' in rule])

    def assert_sibling(self, before):
        self.assertEqual(before, ((self.profiles / 'sibling.conf').read_bytes(),
                                 (self.state_dir / 'profiles/sibling/applied.conf').read_bytes(),
                                 self.data()['interfaces']['g4-sibling'],
                                 [rule for rule in self.data()['iptables'] if 'gre4:sibling' in rule]))
        self.assertTrue(self.data()['enabled']['gre4@sibling.service'])
        self.assertTrue(self.data()['active']['gre4@sibling.service'])

    def test_add_each_role_enables_and_activates_only_selected_profile(self):
        # Each role gets a separate fixture to avoid mixed-role shared-host policy.
        for role in ('iran', 'kharej'):
            with self.subTest(role=role):
                before = self.sibling(role)
                self.add(role)
                state = self.data()
                self.assertTrue(state['enabled']['gre4@new.service'])
                self.assertTrue(state['active']['gre4@new.service'])
                self.assertEqual(state['interfaces']['g4-new']['alias'], 'gre4:new')
                self.assertTrue(state['interfaces']['g4-new']['up'])
                self.assertEqual((self.state_dir / 'profiles/new/applied.conf').read_bytes(),
                                 (self.profiles / 'new.conf').read_bytes())
                self.assert_sibling(before)
                self.shell('profile_remove new\nprofile_remove sibling\n')

    def test_failed_add_keeps_configuration_and_live_recovery_until_stop_retry(self):
        before = self.sibling('iran')
        self.update(failures=['iptables -t nat -A PREROUTING', 'ip tunnel del g4-new'])
        self.add('iran', expected=1)
        state = self.data()
        self.assertTrue(state['enabled']['gre4@new.service'])
        self.assertFalse(state['active']['gre4@new.service'])
        self.assertIn('g4-new', state['interfaces'])
        self.assertTrue((self.profiles / 'new.conf').is_file())
        self.assertTrue((self.state_dir / 'profiles/new/applied.conf').is_file())
        self.assertTrue((self.state_dir / 'profiles/new/cleanup-pending').is_file())
        self.assertTrue((self.state_dir / 'sysctl/forward/values').is_file())
        self.assert_sibling(before)
        self.update(failures=[])
        self.shell('profile_stop_service new\n')
        self.assertNotIn('g4-new', self.data()['interfaces'])
        self.assertFalse((self.state_dir / 'profiles/new').exists())
        self.assertTrue((self.profiles / 'new.conf').is_file())
        self.assert_sibling(before)

    def test_failed_activation_cannot_be_hidden_by_enable_success(self):
        foreign = {'local': '', 'remote': '', 'alias': 'administrator',
                   'addresses': [], 'up': True}
        # Inject the competing interface after file preflight, before activation.
        self.update(interfaces_on_enable={'g4-new': foreign})
        # Some systemctl versions report a successful enable even when --now
        # logs a failed start. Keep the actual failed service state observable.
        result = self.add('kharej', expected=1, prefix='''systemctl() {
  if [[ $1 == enable && $2 == --now ]]; then
    command systemctl "$@" || return 0
  else
    command systemctl "$@"
  fi
}
''')
        self.assertIn('Connection setup failed', result.stdout + result.stderr)
        self.assertNotIn('Use this matching configuration', result.stdout)
        self.assertEqual(self.data()['interfaces'], {'g4-new': foreign})
        self.assertFalse(self.data()['active']['gre4@new.service'])
        self.assertTrue((self.profiles / 'new.conf').is_file())

    def test_inactive_service_is_not_reported_as_a_successful_add(self):
        result = self.add('kharej', expected=1, prefix='''systemctl() {
  if [[ $1 == start ]]; then return 0; fi
  if [[ $1 == enable ]]; then command systemctl enable "${@: -1}"; return; fi
  command systemctl "$@"
}
''')
        self.assertIn('Connection setup failed', result.stdout + result.stderr)
        self.assertNotIn('Use this matching configuration', result.stdout)
        self.assertEqual(self.data()['interfaces'], {})
        self.assertTrue((self.profiles / 'new.conf').is_file())

    def test_start_service_verifies_active_state_after_successful_command(self):
        self.config('new', role='kharej')
        result = self.shell('''systemctl() {
  if [[ $1 == start ]]; then return 0; fi
  command systemctl "$@"
}
profile_start_service new
''', expected=1)
        self.assertIn('Connection did not become active', result.stdout + result.stderr)
        self.assertEqual(self.data()['interfaces'], {})

    def test_preexisting_foreign_interface_is_rejected_before_profile_publication(self):
        foreign = {'local': '', 'remote': '', 'alias': 'administrator',
                   'addresses': [], 'up': True}
        self.update(interfaces={'g4-new': foreign})
        result = self.add('iran', expected=1)
        self.assertIn('inactive connection still has an interface', result.stdout + result.stderr)
        self.assertFalse((self.profiles / 'new.conf').exists())
        self.assertEqual(self.data()['interfaces'], {'g4-new': foreign})
        self.assertNotIn('systemctl enable gre4@new.service', self.data()['commands'])

    def assert_interrupted_add_resumes(self, point):
        prefix = ('GRE4_RELEASE_TAG=v1.3.1\nGRE4_RELEASE_SHA=' + 'a' * 64 + '\n' +
                  'INTERRUPT_POINT=' + point + r'''
                  eval "$(declare -f install_publish_file | sed '1s/install_publish_file/original_publish/')"
                  install_publish_file() {
                    original_publish "$@" || return
                    if [[ $2 == "$INTERRUPT_POINT" ]]; then kill -KILL "$BASHPID"; fi
                  }
                  ''')
        self.add('iran', expected=137, prefix=prefix)
        before = (self.profiles / 'new.conf').read_bytes()
        helper = self.helper.read_bytes()
        self.assertTrue((self.root / 'backups/install-pending').is_file())
        self.assertFalse((self.root / 'gre4@.service').exists())
        self.assertEqual(self.data()['interfaces'], {})
        self.shell(r'''
need_root() { :; }
release_verified_handoff() { GRE4_RELEASE_TAG=$1; GRE4_RELEASE_SHA=$2; }
main --gre4-release v1.3.1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa <<<'4'
''', timeout=30)
        self.assertEqual((self.profiles / 'new.conf').read_bytes(), before)
        self.assertEqual(self.helper.read_bytes(), helper)
        self.assertFalse((self.root / 'backups/install-pending').exists())
        self.assertTrue((self.root / 'gre4@.service').is_file())
        self.assertFalse(self.data().get('active', {}).get('gre4@new.service', False))
        self.assertFalse(self.data().get('enabled', {}).get('gre4@new.service', False))
        self.assertFalse(any(command.startswith(('systemctl start ', 'systemctl enable '))
                             for command in self.data()['commands']))
        backups = list((self.root / 'backups').glob('install.*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / 'stage').read_text(), 'complete\n')
        self.shell(r'''
need_root() { :; }
release_verified_handoff() { GRE4_RELEASE_TAG=$1; GRE4_RELEASE_SHA=$2; }
main --gre4-release v1.3.1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa <<<'4'
''', timeout=30)
        self.assertEqual(list((self.root / 'backups').glob('install.*')), backups)

    def test_add_interrupted_after_profile_resumes_through_default_entry(self):
        self.assert_interrupted_add_resumes('profile')

    def test_add_interrupted_after_helper_resumes_through_default_entry(self):
        self.assert_interrupted_add_resumes('helper')


class CanonicalMigrationWorkflowTests(ProfileRuntimeCase):
    def setUp(self):
        super().setUp()
        fixture = Path(__file__).with_name('fixtures') / 'v1.0.1-apply.sh'
        canonical = fixture.read_text()
        self.helper.write_text(canonical)
        self.helper.chmod(0o700)
        # Verify production recognition of the exact golden BEFORE remapping it.
        self.shell('legacy_verify_helper\n')
        mapped = canonical
        for old, new in (('/etc/gre4.conf', self.root / 'legacy.conf'),
                         ('/var/lib/gre4', self.state_dir),
                         ('/etc/sysctl.d', self.sysctl_dir),
                         ('/etc/ufw', self.ufw_dir),
                         ('/etc/default/ufw', self.root / 'ufw-defaults')):
            mapped = mapped.replace(old, shlex.quote(str(new)))
        self.helper.write_text(mapped)
        self.mapped_digest = hashlib.sha256(self.helper.read_bytes()).hexdigest()
        self.shell('''cat > "$LEGACY_CONF_FILE" <<'CONF'
ROLE="iran"
LOCAL_PUBLIC_IP="198.51.100.1"
PEER_PUBLIC_IP="192.0.2.10"
SERVICE_PORTS="443,2096"
ALLOW_UDP="yes"
TUN_IF="GRE"
IRAN_TUN_CIDR="172.16.1.1/30"
KHAREJ_TUN_CIDR="172.16.1.2/30"
CONF
chmod 600 "$LEGACY_CONF_FILE"
cat > "$LEGACY_UNIT_FILE" <<UNIT
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
UNIT
chmod 600 "$LEGACY_UNIT_FILE"
umask 022
systemctl enable --now gre4.service
''')
        self.assertIn('GRE', self.data()['interfaces'])
        self.assertTrue(any('gre4-managed' in rule for rule in self.data()['iptables']))

    def migrate(self, expected=0):
        # Path mapping changes the hash; production recognition is tested separately above.
        return self.shell(f'LEGACY_HELPER_SHA256={shlex.quote(self.mapped_digest)}\nmigrate_legacy_deployment\n', expected, timeout=45)

    def test_active_canonical_migration_cleans_old_ownership_before_new_start(self):
        self.migrate()
        state = self.data()
        starts = [event for event in state['service_events']
                  if event['action'] == 'start' and event['unit'] == 'gre4@legacy.service']
        self.assertEqual(len(starts), 1)
        self.assertNotIn('GRE', starts[0]['interfaces'])
        self.assertFalse(any('gre4-managed' in rule for rule in starts[0]['iptables']))
        self.assertEqual(state['interfaces']['GRE']['alias'], 'gre4:legacy')
        self.assertFalse(any('gre4-managed' in rule for rule in state['iptables']))
        self.assertTrue(any('gre4:legacy' in rule for rule in state['iptables']))
        self.assertTrue(state['active']['gre4@legacy.service'])
        self.assertTrue(state['enabled']['gre4@legacy.service'])
        self.assertFalse(state['enabled']['gre4.service'])
        self.assertFalse((self.root / 'legacy.conf').exists())
        self.assertFalse((self.root / 'backups/pending').exists())
        self.assertEqual((self.state_dir / 'profiles/legacy/applied.conf').read_bytes(),
                         (self.profiles / 'legacy.conf').read_bytes())

    def test_canonical_migration_handles_mixed_case_ssh_dump_without_rewriting_old_helper(self):
        self.shell('systemctl stop gre4.service\n')
        self.update(ufw_active=True)
        self.shell('''sed -i 's/ROLE="iran"/ROLE="kharej"/; s/LOCAL_PUBLIC_IP="198.51.100.1"/LOCAL_PUBLIC_IP="192.0.2.10"/; s/PEER_PUBLIC_IP="192.0.2.10"/PEER_PUBLIC_IP="198.51.100.1"/' "$LEGACY_CONF_FILE"
systemctl start gre4.service
''')
        self.assertTrue(any('gre4-managed' in rule for rule in self.data()['ufw_rules']))
        old_helper = self.helper.read_bytes()
        ssh_rule = '7443/tcp on eth0 ALLOW IN 203.0.113.10 # gre4-managed'
        self.update(sshd='Port 2222\nListenAddress [::]:7443\n',
                    ufw_rules=self.data()['ufw_rules'] + [ssh_rule])
        # systemd can complete the stop job despite failed ExecStopPost; the
        # manager must still complete checked explicit legacy cleanup afterward.
        self.shell('''systemctl() {
  if [[ $1 == stop && $2 == gre4.service ]]; then
    command systemctl "$@" || return 0
  else
    command systemctl "$@"
  fi
}
''' + f'LEGACY_HELPER_SHA256={self.mapped_digest}\nmigrate_legacy_deployment\n'
            + 'if declare -F sshd >/dev/null; then exit 71; fi\n', timeout=45)
        state = self.data()
        self.assertTrue(state['active']['gre4@legacy.service'])
        self.assertIn(ssh_rule, state['ufw_rules'])
        self.assertFalse(any('gre4-managed' in rule and rule != ssh_rule for rule in state['ufw_rules']))
        backup = next((self.root / 'backups').glob('migration.*'))
        self.assertEqual((backup / 'gre4-apply.sh').read_bytes(), old_helper)
        self.assertFalse((self.root / 'backups/pending').exists())

    def test_compatible_cleanup_keeps_rules_and_original_files_when_ssh_dump_is_invalid(self):
        self.shell('systemctl stop gre4.service\n')
        self.update(ufw_active=True)
        self.shell('''sed -i 's/ROLE="iran"/ROLE="kharej"/; s/LOCAL_PUBLIC_IP="198.51.100.1"/LOCAL_PUBLIC_IP="192.0.2.10"/; s/PEER_PUBLIC_IP="192.0.2.10"/PEER_PUBLIC_IP="198.51.100.1"/' "$LEGACY_CONF_FILE"
systemctl start gre4.service
''')
        original_rules = self.data()['ufw_rules']
        original_helper = self.helper.read_bytes()
        original_config = (self.root / 'legacy.conf').read_bytes()
        for dump in ('Port invalid\n', 'UnknownDirective 2222\n'):
            with self.subTest(dump=dump):
                self.update(sshd=dump)
                self.shell(f'LEGACY_HELPER_SHA256={self.mapped_digest}\nlegacy_stop_compatible\n', expected=1)
                self.assertEqual(self.data()['ufw_rules'], original_rules)
                self.assertEqual(self.helper.read_bytes(), original_helper)
                self.assertEqual((self.root / 'legacy.conf').read_bytes(), original_config)

    def test_failed_new_activation_retains_live_recovery_then_rolls_back_on_retry(self):
        # Fail after new GRE creation and prevent cleanup, beginning only at cutover.
        self.shell('''original_install=$(declare -f install_apply_script)
eval "${original_install/install_apply_script/install_real_helper}"
install_apply_script() {
  install_real_helper || return
  python3 - "$GRE4_FAKE_STATE" <<'FAIL'
import json, sys
from pathlib import Path
p = Path(sys.argv[1]); state = json.loads(p.read_text())
state['failures'] = ['ip link set GRE mtu', 'ip tunnel del GRE']
# An administrator changes forwarding after old cleanup, before new ownership.
state['sysctl']['net.ipv4.ip_forward'] = '1'
state['sysctl']['net.ipv4.conf.all.forwarding'] = '1'
p.write_text(json.dumps(state))
FAIL
}
''' + f'LEGACY_HELPER_SHA256={self.mapped_digest}\nmigrate_legacy_deployment\n', expected=1, timeout=45)
        state = self.data()
        self.assertFalse(state['enabled']['gre4.service'])
        self.assertFalse(state['active']['gre4.service'])
        self.assertEqual(state['interfaces']['GRE']['alias'], 'gre4:legacy')
        self.assertTrue((self.root / 'backups/pending').is_file())
        self.assertTrue((self.state_dir / 'profiles/legacy/applied.conf').is_file())
        self.assertTrue((self.state_dir / 'profiles/legacy/cleanup-pending').is_file())
        live_values = (self.state_dir / 'sysctl/forward/values').read_bytes()
        self.assertIn(b'net.ipv4.ip_forward 1 1', live_values)
        backup = Path((self.root / 'backups/pending').read_text().strip())
        self.assertNotEqual((backup / 'sysctl/forward/values').read_bytes(), live_values)
        self.update(failures=[])
        self.migrate(expected=1)  # A completed rollback reports failure of migration.
        state = self.data()
        self.assertTrue(state['active']['gre4.service'])
        self.assertTrue(state['enabled']['gre4.service'])
        self.assertFalse(state['enabled']['gre4@legacy.service'])
        self.assertEqual(state['interfaces']['GRE']['alias'], '')
        self.assertFalse((self.state_dir / 'profiles/legacy').exists())
        self.assertFalse((self.profiles / 'legacy.conf').exists())
        self.assertFalse((self.root / 'backups/pending').exists())
        self.assertEqual((self.state_dir / 'sysctl/forward/values').read_bytes(), live_values)
        self.assertEqual(hashlib.sha256(self.helper.read_bytes()).hexdigest(), self.mapped_digest)


class LegacyStopBridgeTests(ProfileRuntimeCase):
    def setUp(self):
        super().setUp()
        self.helper.write_text('''#!/usr/bin/env bash
set -euo pipefail
sshd -T > "${GRE4_FAKE_STATE}.normalized"
sshd -V > "${GRE4_FAKE_STATE}.other"
''')
        self.helper.chmod(0o700)
        self.digest = hashlib.sha256(self.helper.read_bytes()).hexdigest()

    def compatible_stop(self, expected=0, prefix=''):
        return self.shell(prefix + f'LEGACY_HELPER_SHA256={self.digest}\nlegacy_stop_compatible\n'
                          + 'if declare -F sshd >/dev/null; then exit 71; fi\n', expected)

    def test_only_dump_directive_names_are_normalized_and_helper_is_unchanged(self):
        dump = '  Port 2222\nListenAddress [::]:7443\nAuthorizedKeysCommand /bin/check MixedCaseArg\n'
        self.update(sshd=dump)
        self.compatible_stop()
        self.assertEqual(Path(str(self.fake) + '.normalized').read_text(),
                         '  port 2222\nlistenaddress [::]:7443\nauthorizedkeyscommand /bin/check MixedCaseArg\n')
        self.assertEqual(Path(str(self.fake) + '.other').read_text(), dump)
        self.assertEqual(hashlib.sha256(self.helper.read_bytes()).hexdigest(), self.digest)

    def test_dump_failure_is_not_converted_into_success(self):
        self.update(failures=['sshd -T'])
        self.compatible_stop(expected=1)
        self.assertNotIn('sshd -V', self.data()['commands'])

    def test_dump_failure_preserves_exit_code_and_diagnostic(self):
        (self.bin / 'sshd').write_text('#!/usr/bin/env bash\necho "invalid SSH configuration" >&2\nexit 23\n')
        result = self.compatible_stop(expected=23)
        self.assertIn('invalid SSH configuration', result.stderr)
        self.assertNotIn('sshd -V', self.data()['commands'])

    def test_unknown_helper_is_rejected_before_execution(self):
        self.shell('LEGACY_HELPER_SHA256=unknown\nif legacy_stop_compatible; then exit 71; fi\n')
        self.assertFalse(Path(str(self.fake) + '.normalized').exists())

    def test_missing_external_sshd_does_not_introduce_a_function(self):
        self.helper.write_text('''#!/usr/bin/env bash
[[ $(type -t sshd) != function ]]
''')
        self.digest = hashlib.sha256(self.helper.read_bytes()).hexdigest()
        self.compatible_stop(prefix='''type() {
  if [[ $* == '-P sshd' ]]; then return 1; fi
  builtin type "$@"
}
''')
