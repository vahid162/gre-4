"""Real production-path checks, permitted only inside marked disposable guests."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import time


ROOT = Path('/opt/gre4-acceptance')
MARKER = Path('/var/lib/gre4-acceptance-vm')
SOURCE = ROOT / 'gre4.sh'
PORT = '2096'
ENDPOINTS = {'kharej': '192.0.2.1', 'iran1': '192.0.2.2', 'iran2': '198.51.100.2'}


def run(*args, check=True, input=None):
    return subprocess.run(args, input=input, text=True, capture_output=True,
                          check=check, timeout=120)


def manager(body):
    # Suppress only interactive dispatch; management and runtime commands remain real.
    source = SOURCE.read_text()
    assert source.rstrip().endswith('main "$@"')
    return run('bash', '-se', input=source.rsplit('\nmain "$@"', 1)[0] + '\n' + body)


def menu(role, profile, local, peer, subnet, udp='yes', success=True):
    choice = '2' if role == 'kharej' else '1'
    result = run('bash', str(SOURCE), input='\n'.join(
        [choice, profile, local, peer, PORT, udp, subnet, '']), check=False)
    assert (result.returncode == 0) == success, result.stdout + result.stderr


def unit(profile, action, check=True):
    return run('systemctl', action, 'gre4@' + profile + '.service', check=check)


def profiles(role):
    return ['iran1', 'iran2'] if role == 'kharej' else [role]


def assert_admin_rules():
    status = run('ufw', 'status', 'numbered').stdout
    persistent = Path('/etc/ufw/user.rules').read_text()
    tag = 'gre4-acceptance-admin'
    assert tag in status or tag.encode().hex() in persistent
    rule = '-A ufw-before-forward -p tcp --dport 29999 -j ACCEPT'
    assert rule in Path('/etc/ufw/before.rules').read_text()
    if status.startswith('Status: active'):
        run('iptables', '-C', 'ufw-before-forward', '-p', 'tcp', '--dport', '29999', '-j', 'ACCEPT')


def versions():
    commands = {
        'kernel': ['uname', '-r'], 'bash': ['bash', '--version'],
        'iproute2': ['ip', '-Version'], 'iptables': ['iptables', '--version'],
        'ufw': ['ufw', 'version'], 'systemd': ['systemctl', '--version'],
        'coreutils': ['mv', '--version'], 'chmod': ['chmod', '--version'],
    }
    return {'os_release': Path('/etc/os-release').read_text(),
            **{name: run(*command).stdout.splitlines()[0] for name, command in commands.items()}}


def setup(role, firewall):
    run('ufw', '--force', 'disable')
    defaults = Path('/etc/default/ufw')
    text, count = re.subn(r'^IPV6=.*$', 'IPV6=' + ('yes' if firewall == 'active-dual' else 'no'),
                         defaults.read_text(), flags=re.MULTILINE)
    assert count == 1
    defaults.write_text(text)
    before = Path('/etc/ufw/before.rules')
    lines = before.read_text().splitlines()
    rule = '-A ufw-before-forward -p tcp --dport 29999 -j ACCEPT'
    if rule not in lines:
        table = lines.index('*filter')
        commit = lines.index('COMMIT', table)
        lines.insert(commit, rule)
        before.write_text('\n'.join(lines) + '\n')
    run('ufw', 'allow', '22/tcp', 'comment', 'gre4-acceptance-admin')
    run('ufw', 'allow', '29999/tcp', 'comment', 'gre4-acceptance-admin')
    if firewall != 'inactive':
        run('ufw', '--force', 'enable')
    original = {key: run('sysctl', '-n', key).stdout.strip() for key in
                ['net.ipv4.ip_forward', 'net.ipv4.conf.all.forwarding']}
    (ROOT / 'original-sysctl.json').write_text(json.dumps(original))
    if role == 'kharej':
        service = Path('/etc/systemd/system/gre4-acceptance-echo.service')
        service.write_text('[Unit]\nDescription=Disposable GRE4 echo fixture\n'
                           '[Service]\nExecStart=/usr/bin/python3 /opt/gre4-acceptance/echo_server.py\n'
                           'Restart=on-failure\n[Install]\nWantedBy=multi-user.target\n')
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', '--now', service.name)
        deadline = time.monotonic() + 30
        while True:
            try:
                with socket.create_connection(('127.0.0.1', int(PORT)), timeout=2) as client:
                    client.sendall(b'ready')
                    client.shutdown(socket.SHUT_WR)
                    response = bytearray()
                    while chunk := client.recv(2048):
                        response.extend(chunk)
                    assert response == b'gre4-acceptance:ready'
                break
            except OSError:
                assert time.monotonic() < deadline, 'Echo fixture did not become ready'
                time.sleep(0.2)
        menu(role, 'iran1', ENDPOINTS[role], ENDPOINTS['iran1'], '172.16.1.0/30')
        menu(role, 'iran2', ENDPOINTS[role], ENDPOINTS['iran2'], '172.16.1.4/30', udp='no')
    else:
        menu('iran', role, ENDPOINTS[role], ENDPOINTS['kharej'],
             '172.16.1.0/30' if role == 'iran1' else '172.16.1.4/30',
             udp='yes' if role == 'iran1' else 'no')
    check(role)


def check(role, selected=None):
    for profile in selected or profiles(role):
        deadline = time.monotonic() + 90
        while run('systemctl', 'is-active', '--quiet', 'gre4@' + profile, check=False).returncode:
            assert time.monotonic() < deadline, 'Service failed to become active: ' + profile
            time.sleep(1)
        link = json.loads(run('ip', '-j', '-d', 'link', 'show', 'dev', 'g4-' + profile).stdout)[0]
        assert link.get('ifalias') == 'gre4:' + profile
        assert link['mtu'] == 1420
        addresses = json.loads(run('ip', '-j', '-4', 'addr', 'show', 'dev', 'g4-' + profile).stdout)[0]['addr_info']
        last = (2 if role == 'kharej' else 1) + (4 if profile == 'iran2' else 0)
        assert any(item['local'] == '172.16.1.' + str(last) and item['prefixlen'] == 30 for item in addresses)
        assert not Path('/var/lib/gre4/profiles/' + profile + '/cleanup-pending').exists()
    run('bash', '-n', '/usr/local/sbin/gre4-apply.sh')
    run('shellcheck', '--severity=warning', '/usr/local/sbin/gre4-apply.sh')
    assert_admin_rules()


def probe(peer, udp, expect=True):
    data = b'gre4-' + os.urandom(12).hex().encode()
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as connection:
        connection.settimeout(4)
        try:
            if udp:
                connection.sendto(data, (ENDPOINTS[peer], int(PORT)))
                response, _ = connection.recvfrom(2048)
            else:
                connection.connect((ENDPOINTS[peer], int(PORT)))
                connection.sendall(data)
                connection.shutdown(socket.SHUT_WR)
                response = bytearray()
                while chunk := connection.recv(2048):
                    response.extend(chunk)
        except (TimeoutError, ConnectionError, OSError):
            if expect:
                raise
            return
    assert expect and response == b'gre4-acceptance:' + data


def traffic(peer='both'):
    for name in ['iran1', 'iran2'] if peer == 'both' else [peer]:
        probe(name, False)
        probe(name, True, expect=name == 'iran1')


def collision():
    run('ip', 'link', 'add', 'name', 'g4-collision', 'type', 'dummy')
    menu('kharej', 'collision', ENDPOINTS['kharej'], '203.0.113.2', '172.16.1.8/30', success=False)
    run('ip', 'link', 'show', 'dev', 'g4-collision')
    assert not Path('/var/lib/gre4/profiles/collision/applied.conf').exists()
    traffic()
    run('ip', 'link', 'delete', 'g4-collision')
    unit('collision', 'start')
    manager('profile_remove collision\n')
    traffic()


def inactive_cleanup():
    run('ufw', '--force', 'disable')
    # Some systemd versions return zero for stop even when ExecStopPost fails.
    unit('iran1', 'stop', check=False)
    run('systemctl', 'is-failed', '--quiet', 'gre4@iran1.service')
    assert Path('/var/lib/gre4/profiles/iran1/cleanup-pending').exists()
    assert Path('/var/lib/gre4/profiles/iran1/applied.conf').exists()
    traffic('iran2')
    run('ufw', '--force', 'enable')
    run('/usr/local/sbin/gre4-apply.sh', 'stop', 'iran1')
    run('systemctl', 'reset-failed', 'gre4@iran1.service')
    unit('iran1', 'start')
    check('kharej')
    traffic()


def remove(profile):
    manager('profile_remove ' + shlex.quote(profile) + '\n')
    interface = 'GRE' if profile == 'legacy' else 'g4-' + profile
    assert run('ip', 'link', 'show', 'dev', interface, check=False).returncode != 0


def clean(role):
    for profile in profiles(role):
        if Path('/etc/gre4/profiles/' + profile + '.conf').exists():
            remove(profile)
    assert not list(Path('/var/lib/gre4/profiles').glob('*/applied.conf'))
    for key, value in json.loads((ROOT / 'original-sysctl.json').read_text()).items():
        assert run('sysctl', '-n', key).stdout.strip() == value
    assert_admin_rules()


def legacy_setup(role):
    assert role in ['kharej', 'iran1']
    assert not list(Path('/etc/gre4/profiles').glob('*.conf'))
    assert not list(Path('/var/lib/gre4/profiles').glob('*/applied.conf'))
    template = Path('/etc/systemd/system/gre4@.service')
    template.unlink(missing_ok=True)
    shutil.copyfile(ROOT / 'v1.0.1-apply.sh', '/usr/local/sbin/gre4-apply.sh')
    Path('/usr/local/sbin/gre4-apply.sh').chmod(0o755)
    values = {'ROLE': 'kharej' if role == 'kharej' else 'iran',
              'LOCAL_PUBLIC_IP': ENDPOINTS[role],
              'PEER_PUBLIC_IP': ENDPOINTS['iran1' if role == 'kharej' else 'kharej'],
              'SERVICE_PORTS': PORT, 'ALLOW_UDP': 'yes', 'TUN_IF': 'GRE',
              'IRAN_TUN_CIDR': '172.16.1.1/30', 'KHAREJ_TUN_CIDR': '172.16.1.2/30'}
    conf = Path('/etc/gre4.conf')
    conf.write_text(''.join(f'{key}="{value}"\n' for key, value in values.items()))
    conf.chmod(0o600)
    Path('/etc/systemd/system/gre4.service').write_text(
        '[Unit]\nDescription=GRE4 Tunnel (Iran/Kharej) + NAT/Firewall\n'
        'Wants=network-online.target\nAfter=network-online.target\n\n'
        '[Service]\nType=oneshot\nExecStart=/usr/local/sbin/gre4-apply.sh start\n'
        'ExecStopPost=/usr/local/sbin/gre4-apply.sh stop\nRemainAfterExit=yes\n\n'
        '[Install]\nWantedBy=multi-user.target\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'gre4.service')


def migrate():
    run('bash', str(SOURCE), input='6\n')
    run('systemctl', 'is-active', '--quiet', 'gre4@legacy.service')
    run('systemctl', 'is-enabled', '--quiet', 'gre4@legacy.service')
    assert not Path('/etc/gre4.conf').exists()
    link = json.loads(run('ip', '-j', '-d', 'link', 'show', 'dev', 'GRE').stdout)[0]
    assert link.get('ifalias') == 'gre4:legacy'
    assert link['mtu'] == 1420
    assert not Path('/var/backups/gre4/pending').exists()
    assert_admin_rules()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['versions', 'setup', 'check', 'traffic', 'collision',
                        'inactive-cleanup', 'remove', 'clean', 'legacy-setup', 'migrate'])
    parser.add_argument('--role', choices=list(ENDPOINTS), default='kharej')
    parser.add_argument('--firewall', choices=['inactive', 'active-v4', 'active-dual'], default='inactive')
    parser.add_argument('--peer', choices=['both', 'iran1', 'iran2'], default='both')
    parser.add_argument('--profile', choices=['iran1', 'iran2', 'legacy'])
    args = parser.parse_args()
    if os.geteuid() != 0 or not MARKER.is_file():
        parser.error('Refusing to run outside a disposable cloud-init acceptance guest')
    if args.action == 'versions':
        print(json.dumps(versions(), indent=2))
    elif args.action == 'setup':
        setup(args.role, args.firewall)
    elif args.action == 'check':
        check(args.role, [args.profile] if args.profile else None)
    elif args.action == 'traffic':
        traffic(args.peer)
    elif args.action == 'collision':
        collision()
    elif args.action == 'inactive-cleanup':
        inactive_cleanup()
    elif args.action == 'remove':
        if args.profile is None:
            parser.error('remove requires --profile')
        remove(args.profile)
    elif args.action == 'clean':
        clean(args.role)
    elif args.action == 'legacy-setup':
        legacy_setup(args.role)
    elif args.action == 'migrate':
        migrate()


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout or '')
        print(error.stderr or '')
        raise
