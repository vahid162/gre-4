"""Offline safety/integrity checks for the real-VM acceptance runner."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch


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

    def test_management_network_is_required_for_cloud_init(self):
        for role in ['kharej', 'iran1', 'iran2']:
            wan = runner.network_config(role)['ethernets']['wan0']
            self.assertTrue(wan['dhcp4'])
            self.assertFalse(wan['optional'])

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


if __name__ == '__main__':
    unittest.main()
