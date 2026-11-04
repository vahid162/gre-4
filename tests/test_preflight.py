"""Preflight and ownership regressions use private fake system commands only."""
import subprocess

from profile_fixture import ProfileRuntimeCase


class PreflightTests(ProfileRuntimeCase):
    def missing_conntrack(self, **options):
        values = self.data()['sysctl']
        values.pop('net.netfilter.nf_conntrack_max')
        self.update(sysctl=values, **options)

    def assert_no_runtime_changes(self):
        state = self.data()
        self.assertEqual(state['interfaces'], {})
        self.assertEqual(state['iptables'], [])
        self.assertEqual(state['sysctl']['net.ipv4.ip_forward'], '0')
        self.assertFalse(self.state_dir.exists())

    def test_missing_conntrack_is_loaded_before_forwarding(self):
        self.config('peer', role='kharej')
        self.missing_conntrack()
        self.invoke('start', 'peer')
        commands = self.data()['commands']
        self.assertLess(commands.index('modprobe nf_conntrack'),
                        next(i for i, c in enumerate(commands) if c.startswith('sysctl -p ')))
        self.invoke('stop', 'peer')

    def test_failed_or_ineffective_module_load_leaves_no_runtime_changes(self):
        self.config('peer', role='kharej')
        self.missing_conntrack(failures=['modprobe nf_conntrack'])
        failed = self.invoke('start', 'peer', success=False)
        self.assertIn('nf_conntrack', failed.stdout + failed.stderr)
        self.assertEqual(failed.returncode, 78)
        self.assert_no_runtime_changes()
        self.update(failures=[], modprobe_loads_conntrack=False)
        failed = self.invoke('start', 'peer', success=False)
        self.assertEqual(failed.returncode, 78)
        self.assert_no_runtime_changes()

    def test_existing_key_does_not_require_modprobe(self):
        self.config('peer', role='kharej')
        self.update(failures=['modprobe nf_conntrack'])
        self.invoke('start', 'peer')
        self.assertNotIn('modprobe nf_conntrack', self.data()['commands'])
        self.invoke('stop', 'peer')

    def test_missing_modprobe_is_only_an_error_when_preparation_is_needed(self):
        self.config('peer', role='kharej')
        without_modprobe = '''load_profile peer
command() {
  if [[ $* == '-v modprobe' ]]; then return 1; fi
  builtin command "$@"
}
profile_preflight
'''
        self.runtime_shell(without_modprobe)
        self.missing_conntrack()
        self.runtime_shell(without_modprobe, expected=1)
        self.assert_no_runtime_changes()

    def test_invalid_conntrack_value_is_rejected_before_forwarding(self):
        self.config('peer', role='kharej')
        values = self.data()['sysctl']
        values['net.netfilter.nf_conntrack_max'] = 'not-a-number'
        self.update(sysctl=values, modprobe_loads_conntrack=False)
        result = self.invoke('start', 'peer', success=False)
        self.assertEqual(result.returncode, 78)
        self.assert_no_runtime_changes()

    def test_iran_does_not_require_conntrack_tuning_key(self):
        self.config('peer', role='iran')
        self.missing_conntrack(failures=['modprobe nf_conntrack'])
        self.invoke('start', 'peer')
        self.assertNotIn('modprobe nf_conntrack', self.data()['commands'])
        self.invoke('stop', 'peer')

    def test_rejected_update_does_not_stop_running_connection(self):
        self.config('peer', role='kharej')
        self.invoke('start', 'peer')
        before = self.data()['interfaces']
        old_config = (self.profiles / 'peer.conf').read_bytes()
        self.missing_conntrack(failures=['modprobe nf_conntrack'])
        self.shell('profile_update peer kharej 192.0.2.10 198.51.100.1 8443 no 172.16.1.0/30\n', expected=1)
        self.assertEqual(self.data()['interfaces'], before)
        self.assertEqual((self.profiles / 'peer.conf').read_bytes(), old_config)
        self.assertFalse(self.data().get('service_events', []))

    def test_generated_post_stop_preserves_deployment_after_preflight_rejection(self):
        self.config('peer', role='kharej')
        self.invoke('start', 'peer')
        before = self.data()['interfaces']
        sysctls = self.data()['sysctl']
        self.missing_conntrack(failures=['modprobe nf_conntrack'])
        failed = self.invoke('start', 'peer', success=False)
        self.assertEqual(failed.returncode, 78)
        result = subprocess.run(['bash', str(self.helper), 'post-stop', 'peer'],
                                env=dict(self.env, EXIT_CODE='exited', EXIT_STATUS='78'),
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.data()['interfaces'], before)
        self.assertTrue((self.state_dir / 'profiles/peer/applied.conf').exists())
        # Explicit Stop still means cleanup, even with a stale service environment.
        self.update(sysctl=sysctls, failures=[])
        result = subprocess.run(['bash', str(self.helper), 'stop', 'peer'],
                                env=dict(self.env, EXIT_CODE='exited', EXIT_STATUS='78'),
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.data()['interfaces'], {})

    def test_systemd_post_stop_preserves_applied_state_on_failed_preflight(self):
        self.config('peer', role='kharej')
        self.invoke('start', 'peer')
        before = self.data()['interfaces']
        self.missing_conntrack(failures=['modprobe nf_conntrack'])
        self.shell('systemctl start gre4@peer.service\n', expected=78)
        self.assertEqual(self.data()['interfaces'], before)
        self.assertTrue((self.state_dir / 'profiles/peer/applied.conf').exists())

    def test_start_service_refreshes_old_paired_template_before_start(self):
        self.config('peer', role='kharej')
        template = self.root / 'gre4@.service'
        template.write_text('ExecStopPost=old-helper stop %i\n')
        self.shell('profile_start_service peer\n')
        self.assertIn('post-stop %i', template.read_text())
        self.invoke('stop', 'peer')

    def test_role_and_ufw_command_checks_run_before_changes(self):
        self.config('peer', role='iran')
        self.runtime_shell('''load_profile peer
ensure_cmd() { [[ $1 != iptables ]]; }
profile_preflight
''', expected=1)
        self.assert_no_runtime_changes()
        self.update(ufw_active=True)
        self.runtime_shell('''load_profile peer
ensure_cmd() { [[ $1 != iptables-restore ]]; }
profile_preflight
''', expected=1)
        self.assert_no_runtime_changes()

    def test_missing_ufw_validator_preserves_rules_during_cleanup(self):
        self.config('peer', role='kharej')
        self.update(ufw_active=True)
        self.invoke('start', 'peer')
        rules = self.data()['ufw_rules']
        before = self.before.read_bytes()
        self.runtime_shell('''load_profile peer
command() {
  if [[ $* == '-v iptables-restore' ]]; then return 1; fi
  builtin command "$@"
}
profile_ufw_reconcile peer stop
''', expected=1)
        self.assertEqual(self.data()['ufw_rules'], rules)
        self.assertEqual(self.before.read_bytes(), before)
        self.invoke('stop', 'peer')


class AliasLifecycleTests(ProfileRuntimeCase):
    def test_successful_creation_without_alias_is_followed_by_set_and_verified(self):
        for role in ('iran', 'kharej'):
            with self.subTest(role=role):
                self.config('peer', role=role)
                self.invoke('start', 'peer')
                self.assertEqual(self.data()['interfaces']['g4-peer']['alias'], 'gre4:peer')
                self.assertIn('ip link set dev g4-peer alias gre4:peer', self.data()['commands'])
                self.invoke('stop', 'peer')
                self.assertEqual(self.data()['interfaces'], {})

    def test_alias_set_failure_removes_only_just_created_interface(self):
        self.config('peer', role='kharej')
        self.update(failures=['ip link set dev g4-peer alias'])
        self.invoke('start', 'peer', success=False)
        self.assertEqual(self.data()['interfaces'], {})
        self.update(failures=[])
        self.invoke('stop', 'peer')
        self.assertFalse((self.state_dir / 'profiles/peer').exists())

    def test_failure_after_alias_set_remains_cleanable(self):
        self.config('peer', role='kharej')
        self.update(failures=['ip addr add'])
        self.invoke('start', 'peer', success=False)
        self.assertEqual(self.data()['interfaces']['g4-peer']['alias'], 'gre4:peer')
        self.update(failures=[])
        self.invoke('stop', 'peer')
        self.assertEqual(self.data()['interfaces'], {})

    def test_alias_set_success_without_effect_is_rejected_and_cleaned(self):
        self.config('peer', role='kharej')
        self.update(ignore_alias_set=True)
        self.invoke('start', 'peer', success=False)
        self.assertEqual(self.data()['interfaces'], {})
        self.update(ignore_alias_set=False)
        self.invoke('stop', 'peer')

    def test_foreign_marker_after_creation_is_preserved(self):
        self.config('peer', role='kharej')
        self.update(alias_set_override='administrator')
        self.invoke('start', 'peer', success=False)
        self.assertEqual(self.data()['interfaces']['g4-peer']['alias'], 'administrator')
        self.invoke('stop', 'peer', success=False)
        self.assertEqual(self.data()['interfaces']['g4-peer']['alias'], 'administrator')
