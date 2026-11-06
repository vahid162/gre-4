"""Offline safety/integrity checks for the real-VM acceptance runner."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


DIRECTORY = Path(__file__).parent / 'integration'


def load(name):
    spec = importlib.util.spec_from_file_location(name, DIRECTORY / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load('ubuntu_vm')
guest = load('guest_acceptance')


class UbuntuAcceptanceSafetyTests(unittest.TestCase):
    def test_collision_retries_add_before_starting_a_preflight_rejected_profile(self):
        self.check_collision()

    def test_collision_rejects_changed_link_identity_or_kind(self):
        for inspection in (2, 4):
            for changed in ({'ifindex': 78, 'linkinfo': {'info_kind': 'dummy'}},
                            {'ifindex': 77, 'linkinfo': {'info_kind': 'gre'}}):
                with self.subTest(inspection=inspection, changed=changed):
                    with self.assertRaises(AssertionError) as result:
                        self.check_collision((inspection, changed))
                    snapshots = json.loads(str(result.exception))
                    self.assertEqual(snapshots['before'], [
                        {'ifindex': 77, 'linkinfo': {'info_kind': 'dummy'}}])
                    self.assertEqual(snapshots['after'], [changed])

    def check_collision(self, changed_snapshot=None):
        state = {'interface': None, 'profile': False, 'applied': False, 'inspections': 0, 'settled': False}

        def command(*args, **kwargs):
            if args[:3] == ('ip', 'link', 'add'):
                self.assertIsNone(state['interface'])
                state['interface'] = {'linkinfo': {'info_kind': 'dummy'}, 'ifindex': 77}
                state['settled'] = False
            elif args[:2] == ('udevadm', 'settle'):
                state['settled'] = True
            elif args[:3] == ('ip', 'link', 'delete'):
                state['interface'] = None
            elif args[0] == 'ip':
                self.assertIsNotNone(state['interface'])
                self.assertTrue(state['settled'], 'Settle each dummy before its baseline inspection')
                state['inspections'] += 1
                if changed_snapshot and state['inspections'] == changed_snapshot[0]:
                    state['interface'] = changed_snapshot[1]
            return subprocess.CompletedProcess(args, 0, json.dumps(
                [state['interface']], sort_keys=state['inspections'] % 2 == 0,
                indent=2 if state['inspections'] % 2 else None), '')

        def add(*args, success=True, **kwargs):
            self.assertEqual(success, state['interface'] is None)
            if success:
                state.update(profile=True, applied=True, interface={'kind': 'gre'})
            return subprocess.CompletedProcess([], 0 if success else 1,
                '' if success else 'An inactive connection still has an interface: collision', '')

        def service(profile, action, check=True):
            self.assertTrue(state['profile'], 'Start must not assume failed Add saved a profile')
            if action == 'stop':
                state.update(applied=False, interface=None)
                return subprocess.CompletedProcess([], 0)
            if state['interface'] is not None:
                self.assertFalse(check)
                return subprocess.CompletedProcess([], 1)
            state.update(applied=True, interface={'kind': 'gre'})
            return subprocess.CompletedProcess([], 0)

        def path(value):
            kind = 'profile' if value.startswith('/etc/') else 'applied'
            return Mock(exists=lambda: state[kind])

        with patch.object(guest, 'run', side_effect=command), \
                patch.object(guest, 'menu', side_effect=add) as menu, \
                patch.object(guest, 'unit', side_effect=service) as unit, \
                patch.object(guest, 'Path', side_effect=path), \
                patch.object(guest, 'manager') as manager, \
                patch.object(guest, 'traffic') as traffic:
            guest.collision()
        self.assertEqual([call.kwargs.get('success', True) for call in menu.call_args_list], [False, True])
        self.assertIn((('collision', 'start'), {'check': False}),
                      [(call.args, call.kwargs) for call in unit.call_args_list])
        self.assertEqual(unit.call_args.args, ('collision', 'start'))
        manager.assert_called_once_with('profile_remove collision\n')
        self.assertGreaterEqual(traffic.call_count, 3)

    def test_partial_install_action_refuses_unmarked_machine_before_commands(self):
        with patch.object(guest.os, 'geteuid', return_value=0), \
                patch.object(guest, 'MARKER') as marker, \
                patch.object(guest, 'run') as run, \
                patch('sys.argv', ['guest_acceptance.py', 'repair-partial', '--role', 'iran1']), \
                contextlib.redirect_stderr(io.StringIO()) as error:
            marker.is_file.return_value = False
            with self.assertRaises(SystemExit) as result:
                guest.main()
            self.assertEqual(result.exception.code, 2)
            self.assertIn('Refusing to run outside', error.getvalue())
            run.assert_not_called()

    def test_partial_install_phase_detects_an_unexpected_old_peer_change(self):
        for changed_peer in (None, 'kharej', 'iran2'):
            with self.subTest(changed_peer=changed_peer):
                guests = []
                events = []
                for role in ['kharej', 'iran1', 'iran2']:
                    vm = Mock(role=role)
                    vm.check.side_effect = lambda *args, role=role: events.append((role, args))
                    reads = [0]

                    def ssh(*args, role=role, reads=reads, **kwargs):
                        if args[:2] == ('sudo', 'sha256sum'):
                            reads[0] += 1
                            changed = changed_peer == role and reads[0] > 1
                            return subprocess.CompletedProcess(args, 0, role + ('-changed' if changed else '-old'), '')
                        return subprocess.CompletedProcess(args, 0, '', '')

                    vm.ssh.side_effect = ssh
                    guests.append(vm)
                record = {'passed': []}
                if changed_peer is None:
                    runner.partial_install_acceptance(guests, record)
                    self.assertIn(('iran1', ('repair-partial',)), events)
                    self.assertEqual([role for role, args in events if args == ('clean',)],
                                     ['kharej', 'iran1', 'iran2'])
                    self.assertTrue(any('partial install' in item for item in record['passed']))
                else:
                    with self.assertRaises(AssertionError):
                        runner.partial_install_acceptance(guests, record)
                    self.assertFalse(record['passed'])

    def test_release_command_forwards_operator_arguments_after_verified_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'gre4.sh'
            source.write_text('# candidate payload\n')
            (root / 'VERSION').write_text('1.3.0\n')
            with patch.object(guest, 'ROOT', root), patch.object(guest, 'SOURCE', source):
                command = guest.release_command('--recover', 'upgrade.selected')
        self.assertEqual(command[-2:], ['--recover', 'upgrade.selected'])
        self.assertIn('v1.3.0', command)
        self.assertIn(hashlib.sha256(b'# candidate payload\n').hexdigest(), command)

    def test_canonical_runtime_fixtures_are_exact_and_reach_disposable_guests(self):
        for name, expected in (
                ('v1.1.1-bash51-apply.sh', 'd4b886236ae42f2b0a2e8f7a7ffd83f47137af3ef95ee2c49933098d2e7a28a8'),
                ('v1.1.1-bash52-apply.sh', '1bde86457fce770ff00c9e2c339fae9dae152ac5bd72f1385a31f76fa99eb86d')):
            with self.subTest(name=name):
                path = DIRECTORY.parent / 'fixtures' / name
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)
                self.assertIn(path.resolve(), [item.resolve() for item in runner.GUEST_FILES])

    def test_cutover_chooses_the_other_official_runtime_and_rejects_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = DIRECTORY.parent / 'fixtures'
            for name in guest.CANONICAL_HELPERS:
                (root / name).write_bytes((fixtures / name).read_bytes())
            with patch.object(guest, 'ROOT', root):
                for name, digest in guest.CANONICAL_HELPERS.items():
                    other = guest.opposite_canonical_helper(digest)
                    self.assertNotEqual(hashlib.sha256(other).hexdigest(), digest)
                    self.assertIn(hashlib.sha256(other).hexdigest(), guest.CANONICAL_HELPERS.values())
                with self.assertRaisesRegex(AssertionError, 'not an official canonical'):
                    guest.opposite_canonical_helper('0' * 64)
                (root / name).write_bytes((root / name).read_bytes() + b'\n# changed\n')
                with self.assertRaisesRegex(AssertionError, 'Corrupt canonical'):
                    guest.opposite_canonical_helper(digest)

    def test_cutover_seed_generates_and_validates_candidate_only_in_private_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            helper, record = root / 'installed-helper', root / 'release'
            helper.write_bytes(b'previous fixture')
            record.write_bytes(b'previous record')
            for name in guest.CANONICAL_HELPERS:
                (root / name).write_bytes((DIRECTORY.parent / 'fixtures' / name).read_bytes())
            with patch.object(guest, 'ROOT', root), patch.object(guest, 'HELPER', helper), \
                    patch.object(guest, 'RECORD', record), \
                    patch.object(guest, 'SOURCE', DIRECTORY.parent.parent / 'gre4.sh'):
                # The current generator only writes its private candidate file;
                # neither canonical historical helper is executed by this check.
                selected = guest.seed_opposite_canonical_runtime()
            self.assertEqual(helper.read_bytes(), selected)
            self.assertEqual(helper.stat().st_mode & 0o777, 0o755)
            self.assertFalse(record.exists())
            self.assertIn(hashlib.sha256(selected).hexdigest(), guest.CANONICAL_HELPERS.values())

    def test_snapshot_detects_identical_content_atomic_rewrites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'artifact'
            path.write_bytes(b'unchanged')
            before = guest.filesystem_snapshot([path])
            replacement = root / 'replacement'
            replacement.write_bytes(b'unchanged')
            replacement.replace(path)
            self.assertNotEqual(guest.filesystem_snapshot([path]), before)

    def test_outside_upgrade_and_public_recovery_precede_any_iran_upgrade(self):
        events = []
        guests = []
        for role in ['kharej', 'iran1', 'iran2']:
            vm = Mock(role=role)
            vm.check.side_effect = lambda *args, role=role: events.append((role, 'check', args))
            vm.reboot.side_effect = lambda role=role: events.append((role, 'reboot', ()))

            def ssh(*args, role=role, **kwargs):
                events.append((role, 'ssh', args))
                return subprocess.CompletedProcess(args, 0, role + '-old-canonical-bytes\n', '')

            vm.ssh.side_effect = ssh
            guests.append(vm)
        record = {'passed': []}
        runner.profile_upgrade_acceptance(guests, record)
        expected = [('kharej', 'check', ('upgrade-metadata',)),
                    ('kharej', 'check', ('upgrade-interrupt',)), ('kharej', 'reboot', ()),
                    ('kharej', 'check', ('upgrade-recover',)), ('kharej', 'check', ('upgrade',)),
                    ('iran1', 'check', ('upgrade',))]
        positions = [events.index(item) for item in expected]
        self.assertEqual(positions, sorted(positions))
        for role in ['iran1', 'iran2']:
            peer_checks = [index for index, item in enumerate(events)
                           if item[:2] == (role, 'ssh') and item[2][:2] == ('sudo', 'sha256sum')]
            self.assertEqual(len(peer_checks), 2)
            self.assertLess(peer_checks[0], positions[0])
            self.assertGreater(peer_checks[1], positions[-2])
            self.assertLess(peer_checks[1], positions[-1])
        self.assertNotIn(('iran2', 'check', ('upgrade',)), events)

    def test_checksum_requires_one_exact_filename(self):
        digest = 'a' * 64
        self.assertEqual(runner.image_checksum(digest + ' *noble-server-cloudimg-amd64.img\n',
                                              'noble-server-cloudimg-amd64.img'), digest)
        for manifest in [digest + ' *wrong.img\n', digest + ' *x.img\n' + digest + ' *x.img\n',
                         'not-a-sha256 *x.img\n']:
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                runner.image_checksum(manifest, 'x.img')

    def test_management_network_keeps_boot_name_and_required_dhcp(self):
        for role in ['kharej', 'iran1', 'iran2']:
            wan = runner.network_config(role)['ethernets']['wan0']
            self.assertNotIn('set-name', wan)
            self.assertEqual(wan['match'], {'macaddress': runner.mac_address(role, 1)})
            self.assertTrue(wan['dhcp4'])
            self.assertFalse(wan['dhcp6'])
            self.assertFalse(wan['optional'])

    def test_lab_network_keeps_mac_identity_and_peer_addresses(self):
        for role, addresses in [('kharej', {'lab0': '192.0.2.1/30', 'lab1': '198.51.100.1/30'}),
                                ('iran1', {'lab0': '192.0.2.2/30'}),
                                ('iran2', {'lab0': '198.51.100.2/30'})]:
            ethernets = runner.network_config(role)['ethernets']
            self.assertEqual(set(ethernets), {'wan0', *addresses})
            for index, (name, address) in enumerate(addresses.items(), start=2):
                self.assertEqual(ethernets[name]['addresses'], [address])
                self.assertEqual(ethernets[name]['match'], {'macaddress': runner.mac_address(role, index)})
                self.assertNotIn('set-name', ethernets[name])
                self.assertTrue(ethernets[name]['optional'])

    def test_guest_macs_do_not_collide(self):
        addresses = [runner.mac_address(role, index) for role in ['kharej', 'iran1', 'iran2']
                     for index in [1, 2, 3]]
        self.assertEqual(len(addresses), len(set(addresses)))

    def test_second_peer_routes_to_shared_kharej_endpoint(self):
        peer = runner.network_config('iran2')['ethernets']['lab0']
        self.assertEqual(peer['routes'], [{'to': '192.0.2.1/32', 'via': '198.51.100.1'}])

    def test_guest_refuses_unmarked_machine_before_running_commands(self):
        with patch.object(guest.os, 'geteuid', return_value=0), \
                patch.object(guest, 'MARKER') as marker, \
                patch.object(guest, 'run') as run, \
                patch('sys.argv', ['guest_acceptance.py', 'setup']), \
                contextlib.redirect_stderr(io.StringIO()):
            marker.is_file.return_value = False
            with self.assertRaises(SystemExit) as result:
                guest.main()
            self.assertEqual(result.exception.code, 2)
            run.assert_not_called()


class UbuntuReadinessTests(unittest.TestCase):
    def make_guest(self, responses):
        vm = runner.Guest.__new__(runner.Guest)
        vm.role = 'iran1'
        vm.process = Mock()
        vm.process.poll.return_value = None
        if callable(responses):
            vm.ssh = Mock(side_effect=responses)
        else:
            responses = iter(responses)

            def ssh(*args, check=True, **kwargs):
                result = next(responses)
                if isinstance(result, Exception):
                    raise result
                if check and result.returncode:
                    raise RuntimeError(result.stderr)
                return result

            vm.ssh = Mock(side_effect=ssh)
        return vm

    def result(self, returncode=0, stdout='', stderr=''):
        return subprocess.CompletedProcess(['ssh'], returncode, stdout, stderr)

    def test_readiness_retries_initial_ssh_timeout(self):
        vm = self.make_guest([subprocess.TimeoutExpired('ssh', 10), self.result(),
                              self.result(stdout='new-boot\n'), self.result()])
        with patch.object(runner.time, 'sleep'):
            vm.ready(old_boot='old-boot')
        self.assertEqual(vm.ssh.call_count, 4)
        self.assertEqual(vm.ssh.call_args.args, ('sudo', 'cloud-init', 'status', '--wait'))

    def test_readiness_retries_boot_id_transport_failures(self):
        for failure in [subprocess.TimeoutExpired('ssh', 10),
                        self.result(255, stderr='Connection reset by peer')]:
            with self.subTest(failure=failure):
                vm = self.make_guest([self.result(), failure, self.result(),
                                      self.result(stdout='new-boot\n'), self.result()])
                with patch.object(runner.time, 'sleep'):
                    vm.ready(old_boot='old-boot')
                self.assertEqual(vm.ssh.call_count, 5)

    def test_readiness_retries_cloud_init_transport_failure(self):
        vm = self.make_guest([self.result(), self.result(stdout='new-boot\n'),
                              self.result(255, stderr='Connection timed out during banner exchange'),
                              self.result(stdout='status: done\n')])
        with patch.object(runner.time, 'sleep') as sleep:
            vm.ready(old_boot='old-boot')
        sleep.assert_called_once()
        self.assertEqual(vm.ssh.call_count, 4)
        self.assertEqual(vm.ssh.call_args.args, ('sudo', 'cloud-init', 'status', '--wait'))

    def test_cloud_init_transport_retries_stop_at_readiness_deadline(self):
        now = [0]

        def ssh(*args, **kwargs):
            if args[0] != 'sudo':
                return self.result(stdout='new-boot\n')
            self.assertGreater(kwargs['timeout'], 0)
            self.assertLessEqual(kwargs['timeout'], 180)
            self.assertLessEqual(now[0] + kwargs['timeout'], 1200)
            now[0] += kwargs['timeout']
            return self.result(255, stderr='Connection timed out during banner exchange')

        vm = self.make_guest(ssh)
        with patch.object(runner.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(runner.time, 'sleep', side_effect=lambda seconds: now.__setitem__(0, now[0] + seconds)):
            with self.assertRaisesRegex(TimeoutError, 'iran1 did not finish boot/cloud-init'):
                vm.ready(old_boot='old-boot')
        self.assertEqual(now[0], 1200)

    def test_readiness_waits_for_boot_id_change(self):
        vm = self.make_guest([self.result(), self.result(stdout='old-boot\n'),
                              self.result(), self.result(stdout='new-boot\n'), self.result()])
        with patch.object(runner.time, 'sleep') as sleep:
            vm.ready(old_boot='old-boot')
        sleep.assert_called_once()
        self.assertEqual(vm.ssh.call_count, 5)

    def test_readiness_deadline_bounds_ssh_retries(self):
        now = [0]

        def timeout(*args, **kwargs):
            self.assertGreater(kwargs['timeout'], 0)
            self.assertLessEqual(kwargs['timeout'], 10)
            self.assertLessEqual(now[0] + kwargs['timeout'], 1200)
            now[0] += kwargs['timeout']
            raise subprocess.TimeoutExpired('ssh', kwargs['timeout'])

        vm = self.make_guest(timeout)
        with patch.object(runner.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(runner.time, 'sleep', side_effect=lambda seconds: now.__setitem__(0, now[0] + seconds)):
            with self.assertRaisesRegex(TimeoutError, 'iran1 did not finish boot/cloud-init'):
                vm.ready()
        self.assertEqual(now[0], 1200)

    def test_readiness_preserves_fatal_qemu_and_cloud_init_errors(self):
        vm = self.make_guest([])
        vm.process.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, 'QEMU exited'):
            vm.ready()
        vm.ssh.assert_not_called()
        for failure in [RuntimeError('cloud-init failed'), subprocess.TimeoutExpired('cloud-init', 180)]:
            with self.subTest(failure=failure):
                vm = self.make_guest([self.result(), self.result(stdout='new-boot\n'), failure])
                with self.assertRaises(type(failure)):
                    vm.ready()
                self.assertEqual(vm.ssh.call_count, 3)

    def test_readiness_preserves_fatal_boot_id_errors(self):
        vm = self.make_guest([self.result(), self.result(1, stderr='boot ID unavailable')])
        with self.assertRaisesRegex(RuntimeError, 'boot ID unavailable'):
            vm.ready()
        self.assertEqual(vm.ssh.call_count, 2)

    def test_readiness_rejects_cloud_init_done_with_nonzero_exit(self):
        for code in [1, 2]:
            with self.subTest(code=code):
                vm = self.make_guest([self.result(), self.result(stdout='new-boot\n'),
                                      self.result(code, stdout='status: done\n')])
                with self.assertRaises(RuntimeError):
                    vm.ready()
                self.assertEqual(vm.ssh.call_count, 3)

    def test_ssh_timeout_records_command_and_partial_output(self):
        vm = runner.Guest.__new__(runner.Guest)
        vm.role, vm.key, vm.port = 'iran1', Path('/unused-key'), 2222
        failure = subprocess.TimeoutExpired('ssh', 10, output=b'partial stdout\n', stderr=b'partial stderr\n')
        with tempfile.TemporaryDirectory() as directory:
            vm.output = Path(directory)
            with patch.object(runner.subprocess, 'run', side_effect=failure):
                with self.assertRaises(subprocess.TimeoutExpired):
                    vm.ssh('test', '-f', '/var/lib/gre4-acceptance-vm', timeout=10)
            log = (vm.output / 'iran1-commands.log').read_text()
        for detail in ['test -f /var/lib/gre4-acceptance-vm', 'timed out', '10',
                       'partial stdout', 'partial stderr']:
            self.assertIn(detail, log)


if __name__ == '__main__':
    unittest.main()
