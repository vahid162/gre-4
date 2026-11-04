"""Filesystem-backed command substitutes for generated-helper lifecycle tests."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

from shell_source import FUNCTIONS


FAKE_COMMAND = r'''#!/usr/bin/env python3
from pathlib import Path
import fcntl
import json
import os
import subprocess
import sys

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
path = Path(os.environ['GRE4_FAKE_STATE'])
lock = path.with_suffix('.lock').open('a')
fcntl.flock(lock, fcntl.LOCK_EX)
state = json.loads(path.read_text())
command = ' '.join([tool] + args)
state['commands'].append(command)
rc = 0
output = ''

def value_after(token, default=''):
    return args[args.index(token) + 1] if token in args else default

if (any(command.startswith(prefix) for prefix in state['failures'])
        or (tool == 'ip' and 'alias' in args and state.get('fail_alias'))):
    rc = 1
elif tool == 'sysctl':
    def write(entry):
        key, value = entry.split('=', 1)
        previous = state['sysctl'][key]
        state['sysctl'][key] = value
        if key == 'net.ipv4.ip_forward' and previous != value:
            state['sysctl']['net.ipv4.conf.all.forwarding'] = value
    if args[0] == '-n':
        output = state['sysctl'][args[1]]
    elif args[0] == '-w':
        write(args[1])
    elif args[0] == '-p':
        for entry in Path(args[1]).read_text().splitlines():
            if entry and not entry.startswith('#'):
                write(entry)
    else:
        rc = 99
elif tool == 'ip':
    interfaces = state['interfaces']
    if args[:2] in (['link', 'add'], ['tunnel', 'add']):
        name = value_after('name') if args[0] == 'link' else args[2]
        if name in interfaces:
            rc = 2
        else:
            interfaces[name] = {'local': value_after('local'), 'remote': value_after('remote'),
                                'alias': value_after('alias'), 'addresses': [], 'up': False}
    elif args[:2] in (['tunnel', 'del'], ['tunnel', 'delete']):
        name = args[2]
        if name in interfaces:
            del interfaces[name]
        else:
            rc = 1
    elif args[:2] == ['link', 'set']:
        name = args[3] if args[2] == 'dev' else args[2]
        if name not in interfaces:
            rc = 1
        elif 'alias' in args:
            interfaces[name]['alias'] = value_after('alias')
        elif 'up' in args:
            interfaces[name]['up'] = True
    elif args[:2] in (['addr', 'add'], ['address', 'add']):
        name = value_after('dev')
        interfaces[name]['addresses'].append(args[2])
    elif 'addr' in args or 'address' in args:
        output = state.get('address_inventory', '')
        for number, (name, item) in enumerate(interfaces.items(), 1):
            output += ''.join(f'{number}: {name} inet {cidr} scope global {name}\n'
                              for cidr in item['addresses'])
    elif 'route' in args:
        output = state.get('route_inventory', '')
    elif 'show' in args and ('link' in args or 'tunnel' in args):
        name = value_after('dev')
        if not name:
            index = args.index('show')
            name = args[index + 1] if len(args) > index + 1 else ''
        selected = interfaces.items() if not name else [(name, interfaces[name])] if name in interfaces else []
        if name and not selected:
            rc = 1
        else:
            for name, item in selected:
                output += (f'1: {name}: <POINTOPOINT,UP> mtu 1420\n'
                           f'    link/gre {item["local"]} peer {item["remote"]}\n'
                           f'    gre remote {item["remote"]} local {item["local"]}\n'
                           f'    alias {item["alias"]}\n')
    else:
        rc = 99
elif tool == 'iptables':
    table = value_after('-t', 'filter')
    operation = next((part for part in args if part in ('-C', '-A', '-D', '-S')), '')
    index = args.index(operation) if operation else 0
    rule = [table] + args[index + 1:]
    if operation == '-C':
        rc = 0 if rule in state['iptables'] else 1
    elif operation == '-A':
        state['iptables'].append(rule)
    elif operation == '-D':
        if rule in state['iptables']:
            state['iptables'].remove(rule)
        else:
            rc = 1
    elif operation == '-S':
        output = '\n'.join(' '.join(rule) for rule in state['iptables'] if rule[0] == table)
    else:
        rc = 99
elif tool == 'iptables-restore':
    candidate = sys.stdin.read()
    state['validated_rules'].append(candidate)
elif tool == 'iptables-save':
    output = '# fake iptables backup'
elif tool == 'sshd':
    output = state.get('sshd', 'port 2222\n')
elif tool == 'systemctl':
    unit = next((part for part in args if part.startswith('gre4')), '')
    profile = unit.removeprefix('gre4@').removesuffix('.service') if '@' in unit else ''
    action = args[0]
    enabled = state.setdefault('enabled', {})
    active = state.setdefault('active', {})
    if action in ('enable', 'disable'):
        enabled[unit] = action == 'enable'
    dispatch = action if action in ('start', 'stop', 'restart') else (
        'start' if action == 'enable' and '--now' in args else
        'stop' if action == 'disable' and '--now' in args else '')
    if dispatch:
        state.setdefault('service_events', []).append({
            'action': dispatch, 'unit': unit, 'interfaces': state['interfaces'],
            'iptables': state['iptables']})
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(state))
        temporary.replace(path)
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
        helper = os.environ['GRE4_FAKE_HELPER']
        def invoke(operation):
            return subprocess.run(['bash', helper, operation] + ([profile] if profile else [])).returncode
        if dispatch in ('stop', 'restart'):
            rc = invoke('stop')
        if not rc and dispatch in ('start', 'restart'):
            rc = invoke('start')
            if rc:
                invoke('stop')  # ExecStopPost also runs after a failed oneshot start.
        with path.with_suffix('.lock').open('a') as final_lock:
            fcntl.flock(final_lock, fcntl.LOCK_EX)
            state = json.loads(path.read_text())
            state.setdefault('active', {})[unit] = not rc and dispatch != 'stop'
            path.write_text(json.dumps(state))
        sys.exit(rc)
    elif action in ('daemon-reload', 'enable', 'disable'):
        pass
    elif action == 'is-active':
        rc = 0 if active.get(unit, False) else 3
    elif action == 'is-enabled':
        rc = 0 if enabled.get(unit, False) else 1
    elif action == 'show':
        property_name = next((part.split('=', 1)[1] for part in args if part.startswith('--property=')), '')
        output = {'FragmentPath': os.environ['GRE4_FAKE_LEGACY_UNIT'],
                  'DropInPaths': '', 'NeedDaemonReload': 'no'}[property_name]
    elif 'status' not in args:
        rc = 99
elif tool == 'ufw':
    if args[:1] == ['status']:
        output = 'Status: ' + ('active' if state['ufw_active'] else 'inactive') + '\n'
        if state['ufw_active']:
            output += '\n'.join(f'[{index:2d}] {rule}' for index, rule in enumerate(state['ufw_rules'], 1))
    elif args[:2] == ['--force', 'delete']:
        del state['ufw_rules'][int(args[2]) - 1]
    elif args[:1] == ['allow']:
        proto = value_after('proto')
        port = value_after('port')
        destination = value_after('to')
        family = ' (v6)' if ':' in destination else ''
        comment = value_after('comment')
        state['ufw_rules'].append(f'{port}/{proto}{family} ALLOW IN Anywhere{family} # {comment}')
        # UFW numbers every IPv4 rule before every IPv6 rule.
        state['ufw_rules'].sort(key=lambda rule: '(v6)' in rule)
    elif args[:1] != ['reload']:
        rc = 99
else:
    rc = 99

temporary = path.with_suffix('.tmp')
temporary.write_text(json.dumps(state))
temporary.replace(path)
if output:
    print(output, end='' if output.endswith('\n') else '\n')
sys.exit(rc)
'''


class ProfileRuntimeCase(unittest.TestCase):
    """Base fixture, deliberately without test methods of its own."""
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="gre4 profile runtime-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.profiles = self.root / 'profiles'
        self.state_dir = self.root / 'state'
        self.sysctl_dir = self.root / 'sysctl.d'
        self.sysctl_dir.mkdir()
        self.ufw_dir = self.root / 'ufw'
        self.ufw_dir.mkdir()
        (self.root / 'ufw-defaults').write_text('IPV6=no\n')
        (self.ufw_dir / 'ufw.conf').write_text('ENABLED=yes\n')
        self.before = self.ufw_dir / 'before.rules'
        self.before.write_text('*filter\n:ufw-before-input - [0:0]\n:ufw-before-output - [0:0]\nCOMMIT\n')
        self.fake = self.root / 'fake.json'
        self.fake.write_text(json.dumps({
            'interfaces': {}, 'iptables': [], 'ufw_rules': [], 'ufw_active': False,
            'failures': [], 'commands': [], 'validated_rules': [],
            'address_inventory': ''.join(f'2: eth0 inet {address}/32 scope global eth0\n'
                                         for address in ('192.0.2.10', '198.51.100.1',
                                                         '198.51.100.2', '198.51.100.3')),
            'sysctl': {'net.ipv4.ip_forward': '0', 'net.ipv4.conf.all.forwarding': '0',
                       'net.netfilter.nf_conntrack_max': '32768'},
        }))
        for name in ('ip', 'iptables', 'iptables-save', 'iptables-restore', 'ufw', 'sysctl', 'sshd', 'systemctl'):
            executable = self.bin / name
            executable.write_text(FAKE_COMMAND)
            executable.chmod(0o755)
        self.env = dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}', GRE4_FAKE_STATE=str(self.fake))
        self.helper = self.root / 'apply.sh'
        self.env['GRE4_FAKE_HELPER'] = str(self.helper)
        self.env['GRE4_FAKE_LEGACY_UNIT'] = str(self.root / 'gre4.service')
        self.shell('install_apply_script\n')

    def shell(self, body, expected=0, timeout=15):
        result = subprocess.run(
            ['bash', '-s', '--', str(self.root)],
            input=FUNCTIONS + r'''
PROFILE_DIR=$1/profiles
STATE_DIR=$1/state
LOCK_DIR=$1/locks
SYSCTL_DIR=$1/sysctl.d
UFW_DIR=$1/ufw
UFW_BEFORE_FILE=$UFW_DIR/before.rules
UFW_DEFAULTS_FILE=$1/ufw-defaults
TEMPLATE_FILE=$1/gre4@.service
CONF_FILE=$1/legacy.conf
LEGACY_CONF_FILE=$CONF_FILE
UNIT_FILE=$1/gre4.service
LEGACY_UNIT_FILE=$UNIT_FILE
MIGRATION_BACKUP_DIR=$1/backups
APPLY_SCRIPT=$1/apply.sh
''' + body, capture_output=True, text=True, env=self.env, timeout=timeout,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def config(self, name, role='iran', number=1, ports='443', udp='no'):
        local, peer = ('192.0.2.10', f'198.51.100.{number}') if role == 'kharej' else (f'198.51.100.{number}', '192.0.2.10')
        self.shell(f'write_profile {name} {role} {local} {peer} {ports} {udp} 172.16.1.{4 * (number - 1)}/30\n')

    def runtime_shell(self, body, expected=0):
        functions = self.helper.read_text().rsplit('case "${1:-start}" in', 1)[0]
        result = subprocess.run(['bash', '-s', '--', str(self.root)],
                                input=functions + '\n' + body,
                                capture_output=True, text=True, env=self.env, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def invoke(self, action, profile, success=True):
        result = subprocess.run(['bash', str(self.helper), action, profile],
                                capture_output=True, text=True, env=self.env, timeout=15)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def data(self):
        return json.loads(self.fake.read_text())

    def update(self, **changes):
        data = self.data()
        data.update(changes)
        self.fake.write_text(json.dumps(data))
