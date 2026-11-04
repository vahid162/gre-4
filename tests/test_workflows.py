"""Prompt-driven Add and real-helper migration with private filesystem substitutes."""
from pathlib import Path
import hashlib
import shlex

from profile_fixture import ProfileRuntimeCase


class AddWorkflowTests(ProfileRuntimeCase):
    def add(self, role, expected=0):
        local, peer = ('198.51.100.1', '192.0.2.10') if role == 'iran' else ('192.0.2.10', '198.51.100.1')
        return self.shell(f'''add_profile_interactive {role} <<'ANSWERS'
new
{local}
{peer}
443,2096
yes
172.16.1.0/30
ANSWERS
''', expected)

    def sibling(self, role):
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
