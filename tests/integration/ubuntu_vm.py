"""Boot three disposable Ubuntu VMs; exercise real GRE, systemd and UFW.

This runner never configures the host's network or uses production credentials.
VM disks, cloud-init seeds and ephemeral SSH keys stay outside artifact paths.
"""
import argparse
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request


RELEASES = {'22.04': 'jammy', '24.04': 'noble', '26.04': 'resolute', '26.10': 'stonking'}
REPO = Path(__file__).resolve().parents[2]
GUEST_FILES = [REPO / 'gre4.sh', Path(__file__).with_name('guest_acceptance.py'),
               Path(__file__).with_name('echo_server.py'), REPO / 'tests/fixtures/v1.0.1-apply.sh']


def command(*args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, check=True, timeout=120, **kwargs)


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def lab_ports():
    # Keep reservations open together so the kernel cannot return the same port twice.
    with ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) for _ in range(4)]
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
        return [sock.getsockname()[1] for sock in sockets]


def image_checksum(manifest, filename):
    matches = re.findall(r'^([a-fA-F0-9]{64})\s+\*?' + re.escape(filename) + r'$', manifest, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError('Expected exactly one checksum for ' + filename)
    return matches[0].lower()


def cloud_image(codename, directory, output):
    base = 'https://cloud-images.ubuntu.com/' + codename + '/current/'
    filename = codename + '-server-cloudimg-amd64.img'
    with urllib.request.urlopen(base + 'SHA256SUMS', timeout=60) as response:
        expected = image_checksum(response.read().decode(), filename)
    target = directory / filename
    digest = hashlib.sha256()
    with urllib.request.urlopen(base + filename, timeout=120) as response, target.open('wb') as image:
        while chunk := response.read(1024 * 1024):
            digest.update(chunk)
            image.write(chunk)
    if digest.hexdigest() != expected:
        raise ValueError('Cloud image checksum mismatch; refusing to boot')
    (output / 'image.json').write_text(json.dumps({'url': base + filename, 'sha256': expected}, indent=2) + '\n')
    return target


def firmware():
    for suffix in ['_4M', '']:
        code = Path('/usr/share/OVMF/OVMF_CODE' + suffix + '.fd')
        variables = Path('/usr/share/OVMF/OVMF_VARS' + suffix + '.fd')
        if code.is_file() and variables.is_file():
            return code, variables
    raise RuntimeError('Install ovmf: a matching OVMF CODE/VARS pair is required')


def mac_address(role, interface):
    number = {'kharej': 10, 'iran1': 11, 'iran2': 12}[role]
    return f'52:54:00:12:{number:02x}:{interface:02x}'


def network_config(role):
    ethernets = {'wan0': {'match': {'macaddress': mac_address(role, 1)},
                          'set-name': 'wan0', 'dhcp4': True, 'dhcp6': False, 'optional': False}}
    first = {'match': {'macaddress': mac_address(role, 2)}, 'set-name': 'lab0', 'optional': True}
    if role == 'kharej':
        first['addresses'] = ['192.0.2.1/30']
        ethernets['lab1'] = {'match': {'macaddress': mac_address(role, 3)}, 'set-name': 'lab1',
                             'addresses': ['198.51.100.1/30'], 'optional': True}
    elif role == 'iran1':
        first['addresses'] = ['192.0.2.2/30']
    else:
        first['addresses'] = ['198.51.100.2/30']
        first['routes'] = [{'to': '192.0.2.1/32', 'via': '198.51.100.1'}]
    ethernets['lab0'] = first
    return {'version': 2, 'ethernets': ethernets}


class Guest:
    def __init__(self, role, work, output, image, key, public_key, links):
        self.role, self.key, self.output = role, key, output
        self.directory = work / role
        self.directory.mkdir()
        self.port = free_port()
        self.process = None
        self.accelerator = 'kvm' if os.access('/dev/kvm', os.R_OK | os.W_OK) else 'tcg'
        config = {
            'users': ['default', {'name': 'acceptance', 'groups': ['sudo'],
                      'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'shell': '/bin/bash',
                      'ssh_authorized_keys': [public_key]}],
            'ssh_pwauth': False, 'package_update': True,
            'packages': ['iproute2', 'iptables', 'procps', 'util-linux', 'kmod', 'ufw',
                         'openssh-server', 'python3', 'shellcheck'],
            'runcmd': [['touch', '/var/lib/gre4-acceptance-vm']],
        }
        (self.directory / 'user-data').write_text('#cloud-config\n' + json.dumps(config))
        (self.directory / 'network-config').write_text(json.dumps(network_config(role)))
        command('cloud-localds', '--network-config=' + str(self.directory / 'network-config'),
                str(self.directory / 'seed.img'), str(self.directory / 'user-data'))
        command('qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image),
                str(self.directory / 'disk.qcow2'), '8G')
        code, variables = firmware()
        shutil.copyfile(variables, self.directory / 'vars.fd')
        args = ['qemu-system-x86_64', '-name', 'gre4-' + role, '-machine', 'q35',
                '-accel', 'kvm' if self.accelerator == 'kvm' else 'tcg,thread=multi',
                '-cpu', 'host' if self.accelerator == 'kvm' else 'max', '-m', '1024', '-smp', '1',
                '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(output / (role + '-serial.log')),
                '-drive', 'if=pflash,format=raw,readonly=on,file=' + str(code),
                '-drive', 'if=pflash,format=raw,file=' + str(self.directory / 'vars.fd'),
                '-drive', 'if=virtio,format=qcow2,file=' + str(self.directory / 'disk.qcow2'),
                '-drive', 'if=virtio,format=raw,file=' + str(self.directory / 'seed.img'),
                '-netdev', f'user,id=wan,hostfwd=tcp:127.0.0.1:{self.port}-:22',
                '-device', 'virtio-net-pci,netdev=wan,mac=' + mac_address(role, 1)]
        for index, (local, remote) in enumerate(links):
            args += ['-netdev', f'socket,id=lab{index},udp=127.0.0.1:{remote},localaddr=127.0.0.1:{local}',
                     '-device', f'virtio-net-pci,netdev=lab{index},mac=' + mac_address(role, index + 2)]
        with (output / (role + '-qemu.log')).open('w') as log:
            self.process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log)

    def ssh(self, *args, check=True, timeout=180):
        result = subprocess.run(['ssh', '-i', str(self.key), '-p', str(self.port),
                                 '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                                 '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
                                 '-o', 'ConnectTimeout=3', 'acceptance@127.0.0.1', shlex.join(args)],
                                text=True, capture_output=True, timeout=timeout)
        with (self.output / (self.role + '-commands.log')).open('a') as log:
            log.write('$ ' + shlex.join(args) + '\n' + result.stdout + result.stderr)
        if check and result.returncode:
            raise RuntimeError(self.role + ': ' + shlex.join(args) + '\n' + result.stdout + result.stderr)
        return result

    def ready(self, old_boot=None):
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(self.role + ' QEMU exited; inspect its log')
            result = self.ssh('test', '-f', '/var/lib/gre4-acceptance-vm', check=False, timeout=10)
            if result.returncode == 0:
                boot = self.ssh('cat', '/proc/sys/kernel/random/boot_id').stdout.strip()
                if old_boot is None or boot != old_boot:
                    self.ssh('sudo', 'cloud-init', 'status', '--wait')
                    return
            time.sleep(2)
        raise TimeoutError(self.role + ' did not finish boot/cloud-init')

    def install_tests(self):
        self.ssh('sudo', 'mkdir', '-p', '/opt/gre4-acceptance')
        for source in GUEST_FILES:
            command('scp', '-q', '-i', str(self.key), '-P', str(self.port),
                    '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                    str(source), 'acceptance@127.0.0.1:/tmp/' + source.name)
            self.ssh('sudo', 'mv', '/tmp/' + source.name, '/opt/gre4-acceptance/' + source.name)

    def check(self, action, *args):
        return self.ssh('sudo', 'python3', '-B', '/opt/gre4-acceptance/guest_acceptance.py',
                        action, '--role', self.role, *args)

    def reboot(self):
        boot = self.ssh('cat', '/proc/sys/kernel/random/boot_id').stdout.strip()
        self.ssh('sudo', 'systemctl', 'reboot', check=False)
        self.ready(old_boot=boot)

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


def acceptance(guests, record):
    outside, first, second = guests
    for firewall in ['inactive', 'active-v4', 'active-dual']:
        record['phase'] = firewall
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(lambda guest: guest.check('setup', '--firewall', firewall), guests))
        outside.check('traffic')
        outside.check('collision')
        outside.ssh('sudo', 'systemctl', 'stop', 'gre4@iran1.service')
        outside.check('traffic', '--peer', 'iran2')
        outside.ssh('sudo', 'systemctl', 'start', 'gre4@iran1.service')
        outside.ssh('sudo', 'systemctl', 'restart', 'gre4@iran1.service')
        outside.check('check')
        outside.check('traffic')
        if firewall != 'inactive':
            outside.check('inactive-cleanup')
        if firewall == 'active-dual':
            outside.ssh('sudo', 'systemctl', 'disable', '--now', 'gre4@iran2.service')
            outside.reboot()
            assert outside.ssh('systemctl', 'is-enabled', 'gre4@iran2.service', check=False).returncode != 0
            assert outside.ssh('systemctl', 'is-active', '--quiet', 'gre4@iran2.service', check=False).returncode != 0
            outside.check('check', '--profile', 'iran1')
            outside.check('traffic', '--peer', 'iran1')
            outside.ssh('sudo', 'systemctl', 'enable', '--now', 'gre4@iran2.service')
            outside.check('check')
            for guest in [first, second]:
                guest.reboot()
                guest.check('check')
                outside.check('traffic')
        outside.check('remove', '--profile', 'iran1')
        first.check('remove', '--profile', 'iran1')
        outside.check('traffic', '--peer', 'iran2')
        for guest in guests:
            guest.check('clean')
        record.setdefault('passed', []).append(firewall + ': TCP/UDP, independent profiles, failure/retry, cleanup')
    record['phase'] = 'canonical-migration'
    for guest in [outside, first]:
        guest.check('legacy-setup')
    outside.check('traffic', '--peer', 'iran1')
    outside.check('migrate')
    outside.check('traffic', '--peer', 'iran1')
    first.check('migrate')
    outside.check('traffic', '--peer', 'iran1')
    for guest in [outside, first]:
        guest.check('remove', '--profile', 'legacy')
    record['passed'].append('canonical v1.0.1 active-pair migration with real traffic')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True, choices=list(RELEASES))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    output = (args.output or REPO / 'dist' / ('ubuntu-' + args.release)).resolve()
    output.mkdir(parents=True, exist_ok=True)
    record = {'release': args.release, 'source_sha256': hashlib.sha256((REPO / 'gre4.sh').read_bytes()).hexdigest(),
              'phase': 'preflight', 'status': 'running', 'passed': []}
    guests = []
    try:
        for tool in ['qemu-system-x86_64', 'qemu-img', 'cloud-localds', 'ssh', 'scp', 'ssh-keygen']:
            if shutil.which(tool) is None:
                raise RuntimeError('Required VM test tool missing: ' + tool)
        firmware()
        with tempfile.TemporaryDirectory(prefix='gre4-ubuntu-vm-') as temporary:
            work = Path(temporary)
            image = cloud_image(RELEASES[args.release], work, output)
            key = work / 'ssh-key'
            command('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key))
            public = key.with_suffix('.pub').read_text().strip()
            ports = lab_ports()
            links = [[(ports[0], ports[1]), (ports[2], ports[3])], [(ports[1], ports[0])], [(ports[3], ports[2])]]
            try:
                for role, networks in zip(['kharej', 'iran1', 'iran2'], links):
                    guests.append(Guest(role, work, output, image, key, public, networks))
                with ThreadPoolExecutor(max_workers=3) as pool:
                    list(pool.map(lambda guest: guest.ready(), guests))
                def prepare_guest(guest):
                    guest.install_tests()
                    details = json.loads(guest.check('versions').stdout)
                    assert 'VERSION_ID="' + args.release + '"' in details['os_release']
                    details['accelerator'] = guest.accelerator
                    (output / (guest.role + '-versions.json')).write_text(json.dumps(details, indent=2) + '\n')
                with ThreadPoolExecutor(max_workers=3) as pool:
                    list(pool.map(prepare_guest, guests))
                acceptance(guests, record)
                record['status'] = 'passed'
                print('Ubuntu ' + args.release + ': real three-VM acceptance passed', flush=True)
            finally:
                for guest in guests:
                    try:
                        guest.ssh('sudo', 'journalctl', '--no-pager', '-u', 'gre4@*', '-u', 'gre4.service', check=False)
                    except (OSError, subprocess.SubprocessError):
                        pass
                    guest.close()
    except Exception as error:
        record['status'] = 'failed'
        record['error'] = str(error)
        raise
    finally:
        (output / 'results.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
