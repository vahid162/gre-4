"""Real production-path checks, permitted only inside marked disposable guests."""
import argparse
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


ROOT = Path('/opt/gre4-acceptance')
MARKER = Path('/var/lib/gre4-acceptance-vm')
SOURCE = ROOT / 'gre4.sh'
BASELINE = ROOT / 'v1.1.1-manager.sh'
HELPER = Path('/usr/local/sbin/gre4-apply.sh')
TEMPLATE = Path('/etc/systemd/system/gre4@.service')
RECORD = Path('/var/lib/gre4-release')
BACKUPS = Path('/var/backups/gre4')
CANONICAL_HELPERS = {
    'v1.1.1-bash51-apply.sh': 'd4b886236ae42f2b0a2e8f7a7ffd83f47137af3ef95ee2c49933098d2e7a28a8',
    'v1.1.1-bash52-apply.sh': '1bde86457fce770ff00c9e2c339fae9dae152ac5bd72f1385a31f76fa99eb86d',
}
V120_MANAGER_SHA256 = '6672dc47a9fe49c5e4e44fdefe435cfc40730b4e17d1e45b26014c8649dd2f23'
PORT = '2096'
ENDPOINTS = {'kharej': '192.0.2.1', 'iran1': '192.0.2.2', 'iran2': '198.51.100.2'}


def run(*args, check=True, input=None):
    return subprocess.run(args, input=input, text=True, capture_output=True,
                          check=check, timeout=120)


def manager(body, check=True):
    # Suppress only interactive dispatch; management and runtime commands remain real.
    source = SOURCE.read_text()
    assert source.rstrip().endswith('main "$@"')
    return run('bash', '-se', input=source.rsplit('\nmain "$@"', 1)[0] + '\n' + body, check=check)


def release_command(*args):
    # PR acceptance runs this exact candidate without downloading a prior public release.
    # The network/checksum bootstrap is covered separately with hermetic HTTP substitutes.
    # Only disposable guests use xtrace; retain the failed guard in acceptance logs.
    return ['bash', '-x', str(SOURCE), '--gre4-release', 'v' + (ROOT / 'VERSION').read_text().strip(),
            hashlib.sha256(SOURCE.read_bytes()).hexdigest(), *args]


def menu(role, profile, local, peer, subnet, udp='yes', success=True):
    choice = '2' if role == 'kharej' else '1'
    command = ['bash', str(SOURCE)] if SOURCE == BASELINE else release_command()
    result = run(*command, input='\n'.join(
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
    profile = Path('/etc/gre4/profiles/collision.conf')
    applied = Path('/var/lib/gre4/profiles/collision/applied.conf')
    inspect = ('ip', '-j', '-d', 'link', 'show', 'dev', 'g4-collision')
    run('ip', 'link', 'add', 'name', 'g4-collision', 'type', 'dummy')
    foreign = run(*inspect).stdout
    menu('kharej', 'collision', ENDPOINTS['kharej'], '203.0.113.2', '172.16.1.8/30', success=False)
    assert not profile.exists() and not applied.exists()
    assert run(*inspect).stdout == foreign
    traffic()
    run('ip', 'link', 'delete', 'g4-collision')
    menu('kharej', 'collision', ENDPOINTS['kharej'], '203.0.113.2', '172.16.1.8/30')
    unit('collision', 'stop')
    # Keep the runtime ownership check covered after Add's earlier refusal.
    run('ip', 'link', 'add', 'name', 'g4-collision', 'type', 'dummy')
    foreign = run(*inspect).stdout
    assert unit('collision', 'start', check=False).returncode != 0
    assert not applied.exists() and run(*inspect).stdout == foreign
    traffic()
    run('ip', 'link', 'delete', 'g4-collision')
    run('systemctl', 'reset-failed', 'gre4@collision.service')
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
    Path('/var/lib/gre4-release').unlink(missing_ok=True)
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
    # The verified release entry now imports a recognized singleton before its menu.
    run(*release_command(), input='4\n')
    run('systemctl', 'is-active', '--quiet', 'gre4@legacy.service')
    run('systemctl', 'is-enabled', '--quiet', 'gre4@legacy.service')
    assert not Path('/etc/gre4.conf').exists()
    link = json.loads(run('ip', '-j', '-d', 'link', 'show', 'dev', 'GRE').stdout)[0]
    assert link.get('ifalias') == 'gre4:legacy'
    assert link['mtu'] == 1420
    assert not Path('/var/backups/gre4/pending').exists()
    assert_admin_rules()


def connection_identity(profile='iran1'):
    service = run('systemctl', 'show', '--property=InvocationID', '--value',
                  'gre4@' + profile + '.service').stdout.strip()
    assert service, 'Active service has no InvocationID: ' + profile
    link = json.loads(run('ip', '-j', 'link', 'show', 'dev', 'g4-' + profile).stdout)[0]['ifindex']
    return service, link


def filesystem_snapshot(paths):
    """Detect rewrites as well as content changes, ignoring access timestamps."""
    result = {}
    for root in paths:
        entries = [root, *sorted(root.rglob('*'))] if root.is_dir() else [root]
        for path in entries:
            if not path.exists() and not path.is_symlink():
                result[str(path)] = None
                continue
            stat = path.lstat()
            value = os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None
            result[str(path)] = (stat.st_mode, stat.st_ino, stat.st_mtime_ns, value)
    return result


def runtime_snapshot(role):
    result = {
        'files': filesystem_snapshot([HELPER, TEMPLATE, Path('/etc/gre4'), Path('/var/lib/gre4'),
                                      Path('/etc/ufw/before.rules'), Path('/etc/default/ufw'),
                                      Path('/etc/sysctl.d/99-gre4-forward.conf'),
                                      Path('/etc/sysctl.d/99-gre4-conntrack.conf')]),
        'services': {}, 'interfaces': {},
    }
    for profile in profiles(role):
        active = run('systemctl', 'show', '--property=ActiveState', '--value',
                     'gre4@' + profile + '.service').stdout.strip()
        enabled = run('systemctl', 'show', '--property=UnitFileState', '--value',
                      'gre4@' + profile + '.service').stdout.strip()
        result['services'][profile] = (active, enabled)
        if active == 'active':
            result['interfaces'][profile] = connection_identity(profile)
    return result


def readonly_cli(role):
    before = runtime_snapshot(role)
    files = filesystem_snapshot([RECORD, BACKUPS, Path('/run/lock/gre4')])
    with tempfile.TemporaryDirectory(prefix='readonly-cli-', dir=ROOT) as temporary:
        tools = Path(temporary)
        attempted = tools / 'bootstrap-attempted'
        curl = tools / 'curl'
        curl.write_text('#!/bin/sh\ntouch ' + shlex.quote(str(attempted)) + '\nexit 91\n')
        curl.chmod(0o755)
        for flag in ['--help', '--status', '--doctor', '--backups']:
            # Invoke the raw entry without a verified handoff: these flags must
            # remain useful offline, even when a newer release is available.
            run('env', 'PATH=' + str(tools) + ':' + os.environ['PATH'], 'bash', str(SOURCE), flag)
            assert not attempted.exists(), 'Read-only command attempted a release download: ' + flag
            assert runtime_snapshot(role) == before, 'Read-only command changed runtime: ' + flag
            assert filesystem_snapshot([RECORD, BACKUPS, Path('/run/lock/gre4')]) == files


def opposite_canonical_helper(candidate_digest):
    helpers = {}
    for name, expected in CANONICAL_HELPERS.items():
        data = (ROOT / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == expected, 'Corrupt canonical runtime fixture: ' + name
        helpers[expected] = data
    assert candidate_digest in helpers, 'Candidate runtime is not an official canonical variant'
    return next(data for digest, data in helpers.items() if digest != candidate_digest)


def seed_opposite_canonical_runtime():
    # Both byte variants were emitted by the unmodified official manager. Their
    # difference is Bash serialization, so no edited helper or forged stamp is
    # needed to exercise a real, recognized runtime replacement in every guest.
    with tempfile.TemporaryDirectory(prefix='candidate-runtime-', dir=ROOT) as temporary:
        candidate = Path(temporary) / 'helper.sh'
        manager('APPLY_SCRIPT=' + shlex.quote(str(candidate)) + '\ninstall_apply_script\n')
        opposite = opposite_canonical_helper(hashlib.sha256(candidate.read_bytes()).hexdigest())
    HELPER.write_bytes(opposite)
    HELPER.chmod(0o755)
    RECORD.unlink(missing_ok=True)
    return opposite


def partial_install_repair(role):
    assert role == 'iran1'
    unit(role, 'stop')
    unit(role, 'disable')
    profile = Path('/etc/gre4/profiles/' + role + '.conf')
    previous = profile.read_text()
    assert previous.count('SERVICE_PORTS=2096\n') == 1
    profile.write_text(previous.replace('SERVICE_PORTS=2096\n', 'SERVICE_PORTS=2096,8787,1194\n'))
    config = profile.read_bytes()
    original_helper, original_unit = HELPER.read_bytes(), TEMPLATE.read_bytes()
    assert hashlib.sha256(original_helper).hexdigest() in CANONICAL_HELPERS.values()
    HELPER.chmod(0o711)  # Match the reported root-owned, executable partial install.
    TEMPLATE.unlink()
    RECORD.unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    assert not Path('/var/lib/gre4/profiles/' + role + '/applied.conf').exists()
    assert not Path('/var/lib/gre4/profiles/' + role + '/cleanup-pending').exists()
    assert run('ip', 'link', 'show', 'dev', 'g4-' + role, check=False).returncode != 0

    # An incomplete installation does not authorize replacing customized code.
    HELPER.write_bytes(original_helper + b'\n# disposable local customization\n')
    try:
        result = run(*release_command(), input='4\n', check=False)
        assert result.returncode != 0, result.stdout + result.stderr
        assert not TEMPLATE.exists() and not RECORD.exists()
        assert profile.read_bytes() == config
    finally:
        HELPER.write_bytes(original_helper)
    preserved = filesystem_snapshot([HELPER, profile])
    backups = set(BACKUPS.glob('install.*'))
    run(*release_command(), input='4\n')
    assert TEMPLATE.read_bytes() == original_unit
    assert TEMPLATE.stat().st_uid == 0 and TEMPLATE.stat().st_mode & 0o777 == 0o644
    assert filesystem_snapshot([HELPER, profile]) == preserved
    created = set(BACKUPS.glob('install.*')) - backups
    assert len(created) == 1, 'Known partial install did not retain exactly one repair backup'
    backup = created.pop()
    assert (backup / 'stage').read_text() == 'complete\n'
    assert (backup / 'profiles' / profile.name).read_bytes() == config
    assert (backup / 'helper').read_bytes() == original_helper
    assert (backup / 'unit-absent').is_file()
    assert (backup / 'new-unit').read_bytes() == original_unit
    assert (backup / 'manifest.sha256').is_file()
    assert backup.stat().st_uid == 0 and backup.stat().st_mode & 0o077 == 0
    assert not (BACKUPS / 'install-pending').exists()
    assert RECORD.read_text().startswith('v' + (ROOT / 'VERSION').read_text().strip() + ' ')
    assert_admin_rules()

    def inactive():
        assert unit(role, 'is-active', check=False).returncode != 0
        assert unit(role, 'is-enabled', check=False).stdout.strip() == 'disabled'
        assert run('ip', 'link', 'show', 'dev', 'g4-' + role, check=False).returncode != 0
        assert not Path('/var/lib/gre4/profiles/' + role + '/applied.conf').exists()

    inactive()
    repaired = filesystem_snapshot([HELPER, TEMPLATE, RECORD, profile, BACKUPS])
    run(*release_command(), input='4\n')
    assert filesystem_snapshot([HELPER, TEMPLATE, RECORD, profile, BACKUPS]) == repaired
    inactive()


def metadata_upgrade(role):
    assert role == 'kharej'
    unit('iran2', 'stop')  # Keep this inactive peer enabled to cover separate boot intent.
    assert hashlib.sha256(HELPER.read_bytes()).hexdigest() in CANONICAL_HELPERS.values()
    # The published v1.2.0 manager used this unchanged function and runtime pair.
    # Seed its genuine record rather than inventing a tag/hash for modified code.
    manager('GRE4_RELEASE_TAG=v1.2.0\nGRE4_RELEASE_SHA=' + V120_MANAGER_SHA256 + '\nrecord_installed_release\n')
    previous = RECORD.read_bytes()
    assert previous.startswith(b'v1.2.0 ')
    readonly_cli(role)
    before = runtime_snapshot(role)
    backups = set(BACKUPS.glob('upgrade.*'))
    run(*release_command(), input='4\n')
    assert runtime_snapshot(role) == before, 'Management-only release restarted or rewrote runtime'
    created = set(BACKUPS.glob('upgrade.*')) - backups
    assert len(created) == 1
    backup = created.pop()
    assert (backup / 'kind').read_text() == 'metadata\n'
    assert (backup / 'stage').read_text() == 'complete\n'
    assert (backup / 'release').read_bytes() == previous
    assert (backup / 'recovery.sha256').is_file()
    installed = RECORD.read_bytes()
    assert installed == (backup / 'new-release').read_bytes() and installed != previous
    run(*release_command('--recover', backup.name), input=backup.name + '\n')
    assert RECORD.read_bytes() == previous, 'Metadata recovery did not restore the original release record'
    assert runtime_snapshot(role) == before, 'Metadata recovery restarted or rewrote runtime'
    assert (backup / 'stage').read_text() == 'rolled-back\n'
    assert not (BACKUPS / 'upgrade-pending').exists()
    assert set(BACKUPS.glob('upgrade.*')) == backups | {backup}, 'Recovery ran automatic upgrade first'
    run(*release_command(), input='4\n')
    assert RECORD.read_bytes() == installed
    assert runtime_snapshot(role) == before
    traffic('iran1')


def upgrade(role):
    seed_opposite_canonical_runtime()
    configs = {path.name: path.read_bytes() for path in Path('/etc/gre4/profiles').glob('*.conf')}
    helper = Path('/usr/local/sbin/gre4-apply.sh')
    template = Path('/etc/systemd/system/gre4@.service')
    old_helper, old_template = helper.read_bytes(), template.read_bytes()
    if role == 'kharej':
        unit('iran2', 'stop')
        unit('iran2', 'disable')

    def preserved():
        assert configs == {path.name: path.read_bytes()
                           for path in Path('/etc/gre4/profiles').glob('*.conf')}
        run('systemctl', 'is-active', '--quiet', 'gre4@iran1.service')
        run('systemctl', 'is-enabled', '--quiet', 'gre4@iran1.service')
        if role == 'kharej':
            assert unit('iran2', 'is-active', check=False).returncode != 0
            assert unit('iran2', 'is-enabled', check=False).returncode != 0
        assert_admin_rules()

    before = connection_identity()
    helper.write_bytes(old_helper + b'\n# disposable local customization\n')
    try:
        result = run(*release_command(), input='4\n', check=False)
        assert result.returncode != 0, result.stdout + result.stderr
        assert connection_identity() == before
        preserved()
    finally:
        helper.write_bytes(old_helper)

    # Exercise a failed real systemd/GRE start and the actual rollback, only in this VM.
    if role == 'kharej':
        real_ip = shutil.which('ip')
        wrapper = Path('/usr/local/sbin/ip')
        fault = ROOT / 'fail-next-gre-add'
        assert real_ip and not wrapper.exists()
        wrapper.write_text('#!/bin/sh\n'
                           'if [ "$1 $2 $3 $4" = "link add name g4-iran1" ] && '
                           '[ -f ' + shlex.quote(str(fault)) + ' ]; then\n'
                           '  rm -f ' + shlex.quote(str(fault)) + '\n  exit 1\nfi\n'
                           'exec ' + shlex.quote(real_ip) + ' "$@"\n')
        wrapper.chmod(0o755)
        fault.touch()
        try:
            assert run('bash', '-c', 'command -v ip').stdout.strip() == str(wrapper)
            result = run(*release_command(), input='4\n', check=False)
            assert result.returncode != 0, result.stdout + result.stderr
            assert not fault.exists(), 'GRE start fault was not exercised'
            assert helper.read_bytes() == old_helper
            assert template.read_bytes() == old_template
            preserved()
            traffic('iran1')
        finally:
            wrapper.unlink()
            fault.unlink(missing_ok=True)

    before = connection_identity()
    run(*release_command(), input='4\n')
    preserved()
    assert connection_identity() != before, 'Changed canonical runtime did not exercise a full cutover'
    assert helper.read_bytes() != old_helper
    stamp = Path('/var/lib/gre4-release').read_bytes()
    assert stamp
    before = connection_identity()
    backups = sorted(str(path) for path in Path('/var/backups/gre4').glob('upgrade.*'))
    run(*release_command(), input='4\n')
    assert connection_identity() == before, 'Same-release invocation restarted an active connection'
    assert Path('/var/lib/gre4-release').read_bytes() == stamp
    assert sorted(str(path) for path in Path('/var/backups/gre4').glob('upgrade.*')) == backups
    preserved()
    check(role, ['iran1'])


def interrupted_upgrade():
    unit('iran2', 'stop')
    unit('iran2', 'disable')
    seed_opposite_canonical_runtime()
    tag = 'v' + (ROOT / 'VERSION').read_text().strip()
    digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    result = manager(r'''
eval "$(declare -f migration_set_stage | sed '1s/migration_set_stage/acceptance_set_stage/')"
migration_set_stage() {
  acceptance_set_stage "$@" || return
  if [[ $2 == old-clean ]]; then kill -KILL "$BASHPID"; fi
}
automatic_upgrade ''' + shlex.quote(tag) + ' ' + shlex.quote(digest) + '\n', check=False)
    assert result.returncode == 137, result.stdout + result.stderr
    backup = pending_upgrade()
    assert (backup / 'stage').read_text().strip() == 'old-clean'
    assert_interrupted_upgrade(backup)


def pending_upgrade():
    backup = Path('/var/backups/gre4/upgrade-pending').read_text().strip()
    assert Path(backup).parent == Path('/var/backups/gre4')
    assert Path(backup).name.startswith('upgrade.')
    return Path(backup)


def assert_interrupted_upgrade(backup):
    assert (backup / 'stage').read_text().strip() == 'old-clean'
    assert Path('/usr/local/sbin/gre4-apply.sh').read_bytes() == (backup / 'gre4-apply.sh').read_bytes()
    assert Path('/etc/systemd/system/gre4@.service').read_bytes() == (backup / 'gre4@.service').read_bytes()
    assert {p.name: p.read_bytes() for p in Path('/etc/gre4/profiles').glob('*.conf')} == {
        p.name: p.read_bytes() for p in (backup / 'profiles').glob('*.conf')}
    for profile in ['iran1', 'iran2']:
        assert unit(profile, 'is-enabled', check=False).stdout.strip() == 'masked'
        assert unit(profile, 'is-active', check=False).returncode != 0
        assert run('ip', 'link', 'show', 'dev', 'g4-' + profile, check=False).returncode != 0
        assert not Path('/var/lib/gre4/profiles/' + profile + '/applied.conf').exists()
    assert_admin_rules()


def recover_interrupted_upgrade():
    # Called after a real reboot: persistent masks must survive, then a verified
    # old-clean transaction can be restored using the same guarded rollback.
    backup = pending_upgrade()
    assert_interrupted_upgrade(backup)
    result = run(*release_command(), input='4\n', check=False)
    assert result.returncode != 0, result.stdout + result.stderr
    assert_interrupted_upgrade(backup)
    run(*release_command('--recover', backup.name), input=backup.name + '\n')
    assert (backup / 'stage').read_text() == 'rolled-back\n'
    assert HELPER.read_bytes() == (backup / 'gre4-apply.sh').read_bytes()
    assert TEMPLATE.read_bytes() == (backup / 'gre4@.service').read_bytes()
    assert not Path('/var/backups/gre4/upgrade-pending').exists()
    check('kharej', ['iran1'])
    run('systemctl', 'is-enabled', '--quiet', 'gre4@iran1.service')
    assert unit('iran2', 'is-active', check=False).returncode != 0
    assert unit('iran2', 'is-enabled', check=False).stdout.strip() == 'disabled'
    traffic('iran1')


def main():
    global SOURCE
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['versions', 'setup', 'check', 'traffic', 'collision',
                        'inactive-cleanup', 'remove', 'clean', 'legacy-setup', 'migrate', 'upgrade',
                        'upgrade-metadata', 'upgrade-interrupt', 'upgrade-recover', 'repair-partial'])
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--role', choices=list(ENDPOINTS), default='kharej')
    parser.add_argument('--firewall', choices=['inactive', 'active-v4', 'active-dual'], default='inactive')
    parser.add_argument('--peer', choices=['both', 'iran1', 'iran2'], default='both')
    parser.add_argument('--profile', choices=['iran1', 'iran2', 'legacy'])
    args = parser.parse_args()
    if os.geteuid() != 0 or not MARKER.is_file():
        parser.error('Refusing to run outside a disposable cloud-init acceptance guest')
    if args.baseline:
        assert args.action == 'setup'
        assert hashlib.sha256(BASELINE.read_bytes()).hexdigest() == '796b8a78b29d94509cc0ba9e8e18006b6a043fc010d1625e917a4b4196f07f7f'
        SOURCE = BASELINE
        Path('/var/lib/gre4-release').unlink(missing_ok=True)
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
    elif args.action == 'upgrade':
        upgrade(args.role)
    elif args.action == 'upgrade-metadata':
        metadata_upgrade(args.role)
    elif args.action == 'upgrade-interrupt':
        assert args.role == 'kharej'
        interrupted_upgrade()
    elif args.action == 'upgrade-recover':
        assert args.role == 'kharej'
        recover_interrupted_upgrade()
    elif args.action == 'repair-partial':
        partial_install_repair(args.role)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout or '')
        print(error.stderr or '')
        raise
