"""Offline safety/integrity checks for the real-VM acceptance runner."""
import contextlib
import importlib.util
import io
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
