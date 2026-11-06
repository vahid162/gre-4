"""Public operator commands and prompts use private files and read-only substitutes."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from shell_source import FUNCTIONS


class OperatorCliTests(unittest.TestCase):
    def shell(self, body, expected=0, answers=''):
        with tempfile.TemporaryDirectory(prefix='gre4-operator-') as directory:
            root = Path(directory)
            script = root / 'entry.sh'
            script.write_text(FUNCTIONS + r'''
ROOT=$1
PROFILE_DIR=$ROOT/profiles
STATE_DIR=$ROOT/state
LOCK_DIR=$ROOT/locks
MIGRATION_BACKUP_DIR=$ROOT/backups
RELEASE_STAMP_FILE=$ROOT/release
APPLY_SCRIPT=$ROOT/helper
TEMPLATE_FILE=$ROOT/unit
LEGACY_CONF_FILE=$ROOT/legacy.conf
UNIT_FILE=$ROOT/legacy.service
mkdir -p "$PROFILE_DIR" "$STATE_DIR" "$MIGRATION_BACKUP_DIR"
chmod 700 "$PROFILE_DIR" "$STATE_DIR" "$MIGRATION_BACKUP_DIR"
printf '#!/bin/bash\nexit 0\n' > "$APPLY_SCRIPT"
chmod 700 "$APPLY_SCRIPT"
printf 'private test unit\n' > "$TEMPLATE_FILE"
chmod 644 "$TEMPLATE_FILE"
helper_digest=$(sha256sum "$APPLY_SCRIPT"); unit_digest=$(sha256sum "$TEMPLATE_FILE")
printf 'v1.3.0 %s %s %s\n' "${helper_digest%% *}" "${unit_digest%% *}" "$(printf '%064d' 0)" > "$RELEASE_STAMP_FILE"
chmod 600 "$RELEASE_STAMP_FILE"
cat > "$PROFILE_DIR/alpha.conf" <<'CONF'
ROLE=iran
LOCAL_PUBLIC_IP=198.51.100.1
PEER_PUBLIC_IP=192.0.2.11
SERVICE_PORTS=443,2096
ALLOW_UDP=yes
TUN_IF=g4-alpha
IRAN_TUN_CIDR=172.16.1.1/30
KHAREJ_TUN_CIDR=172.16.1.2/30
CONF
chmod 600 "$PROFILE_DIR/alpha.conf"
mkdir -p "$STATE_DIR/profiles/alpha"
cp "$PROFILE_DIR/alpha.conf" "$STATE_DIR/profiles/alpha/applied.conf"
chmod 600 "$STATE_DIR/profiles/alpha/applied.conf"
: > "$ROOT/commands"
need_root() { :; }
release_bootstrap() { printf 'bootstrap %s\n' "$*" >> "$ROOT/commands"; return 43; }
automatic_upgrade() { echo automatic-upgrade >> "$ROOT/commands"; return 44; }
list_upgrade_backups() { echo 'Backups: private fixture'; echo list-backups >> "$ROOT/commands"; }
recover_upgrade_interactive() { printf 'recover %s\n' "$*" >> "$ROOT/commands"; }
release_verified_handoff() { GRE4_RELEASE_TAG=$1; GRE4_RELEASE_SHA=$2; }
systemctl() {
  printf 'systemctl %s\n' "$*" >> "$ROOT/commands"
  [[ $1 != is-active ]] || return 0
  [[ $1 == show ]] || return 97
  case $2 in
    --property=ActiveState) echo active ;;
    --property=UnitFileState) echo enabled ;;
    --property=FragmentPath) echo "$TEMPLATE_FILE" ;;
    --property=DropInPaths) : ;;
    --property=NeedDaemonReload) echo no ;;
    *) return 97 ;;
  esac
}
ip() {
  printf 'ip %s\n' "$*" >> "$ROOT/commands"
  case "$*" in
    '-o -4 addr show'|'-o -4 addr show dev g4-alpha')
      local host=1
      [[ ${ROLE:-iran} != kharej ]] || host=2
      printf '1: eth0 inet 198.51.100.1/24 scope global eth0\n2: g4-alpha inet 172.16.1.%s/30 scope global g4-alpha\n' "$host" ;;
    '-4 route show table all') echo '198.51.100.0/24 dev eth0' ;;
    '-d -o link show dev g4-alpha') echo '2: g4-alpha: <UP> mtu 1420 alias gre4:alpha ' ;;
    *) return 97 ;;
  esac
}
sysctl() { printf 'sysctl %s\n' "$*" >> "$ROOT/commands"; [[ $1 == -n ]] || return 97; echo 1; }
ufw() { printf 'ufw %s\n' "$*" >> "$ROOT/commands"; [[ $* == status ]] || return 97; echo 'Status: inactive'; }
iptables() { echo unexpected-iptables >> "$ROOT/commands"; return 97; }
modprobe() { echo modprobe >> "$ROOT/commands"; return 97; }
curl() { echo curl >> "$ROOT/commands"; return 97; }
''' + body + r'''
[[ ! -e "$LOCK_DIR" ]]
! grep -Eq '^(automatic-upgrade|bootstrap|curl|modprobe)|systemctl (start|stop|restart|enable|disable|mask|unmask|daemon-reload)|sysctl -[wp]|ufw --|^ip (link|tunnel|addr|address) (add|del|set)' "$ROOT/commands"
''')
            result = subprocess.run(['bash', str(script), str(root)], input=answers,
                                    text=True, capture_output=True, timeout=12)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            return result.stdout + result.stderr

    def test_readonly_commands_report_state_without_bootstrap_or_mutation(self):
        for flag in ('--status', '--doctor', '--backups'):
            with self.subTest(flag=flag):
                output = self.shell('main ' + flag + '\n')
                if flag == '--backups':
                    self.assertIn('Backups:', output)
                else:
                    self.assertIn('v1.3.0', output)
                    self.assertIn('alpha', output)

    def test_pending_recovery_is_visible_without_blocking_readonly_status(self):
        output = self.shell(r'''
printf '%s\n' "$MIGRATION_BACKUP_DIR/upgrade.fixture" > "$MIGRATION_BACKUP_DIR/upgrade-pending"
chmod 600 "$MIGRATION_BACKUP_DIR/upgrade-pending"
main --status
''')
        self.assertIn('pending', output.lower())

    def test_malformed_release_record_is_not_executed(self):
        self.shell(r'''
printf '%s\n' '$(touch "$ROOT/executed")' > "$RELEASE_STAMP_FILE"
if main --status; then exit 70; fi
[[ ! -e "$ROOT/executed" ]]
''')

    def test_release_record_with_hidden_bytes_is_rejected(self):
        self.shell(r'''
record=$(cat "$RELEASE_STAMP_FILE")
printf '\0%s\n' "$record" > "$RELEASE_STAMP_FILE"
if main --status; then exit 70; fi
''')

    def test_help_does_not_require_root_or_network(self):
        output = self.shell('need_root() { return 95; }\nmain --help\n')
        self.assertIn('--doctor', output)
        self.assertIn('--recover', output)

    def test_doctor_reports_missing_command_without_trying_to_repair_it(self):
        output = self.shell(r'''
command() {
  [[ $* != '-v ip' ]] || return 1
  builtin command "$@"
}
if main --doctor; then exit 70; fi
! grep -q '^ip ' "$ROOT/commands"
''')
        self.assertIn('ip: missing', output)

    def test_doctor_reports_changed_helper_without_overwriting_it(self):
        output = self.shell(r'''
printf '# retained local edit\n' >> "$APPLY_SCRIPT"
before=$(sha256sum "$APPLY_SCRIPT")
if main --doctor; then exit 70; fi
[[ $(sha256sum "$APPLY_SCRIPT") == "$before" ]]
''')
        self.assertIn('differs from release record', output)

    def test_status_rejects_symlinked_release_record(self):
        self.shell(r'''
mv "$RELEASE_STAMP_FILE" "$ROOT/original-release"
ln -s "$ROOT/original-release" "$RELEASE_STAMP_FILE"
if main --status; then exit 70; fi
''')

    def test_kharej_doctor_reports_missing_conntrack_without_loading_module(self):
        output = self.shell(r'''
sed -i 's/ROLE=iran/ROLE=kharej/' "$PROFILE_DIR/alpha.conf"
cp "$PROFILE_DIR/alpha.conf" "$STATE_DIR/profiles/alpha/applied.conf"
sysctl() {
  printf 'sysctl %s\n' "$*" >> "$ROOT/commands"
  [[ $1 == -n ]] || return 97
  [[ $2 != net.netfilter.nf_conntrack_max ]] || return 1
  echo 1
}
if main --doctor; then exit 70; fi
''')
        self.assertIn('Kharej conntrack key: unavailable', output)

    def test_doctor_detects_unowned_interface_without_modifying_it(self):
        output = self.shell(r'''
eval "$(declare -f ip | sed '1s/ip/fixture_ip/')"
ip() {
  if [[ $* == '-d -o link show dev g4-alpha' ]]; then
    echo '2: g4-alpha: <UP> mtu 1420 alias administrator '
  else
    fixture_ip "$@"
  fi
}
if main --doctor; then exit 70; fi
''')
        self.assertIn('Local connection health mismatch: alpha', output)

    def test_public_recover_bootstraps_with_arguments_without_running_local_recovery(self):
        self.shell(r'''
if main --recover upgrade.fixture; then exit 70; else [[ $? == 43 ]]; fi
grep -Fxq 'bootstrap --recover upgrade.fixture' "$ROOT/commands"
! grep -q '^recover ' "$ROOT/commands"
: > "$ROOT/commands"
''')

    def test_verified_recover_skips_automatic_upgrade(self):
        self.shell(r'''
main --gre4-release v1.3.0 "$(printf '%064d' 0)" --recover upgrade.fixture
grep -Fxq 'recover upgrade.fixture' "$ROOT/commands"
''')

    def test_extra_readonly_arguments_are_rejected_without_bootstrap(self):
        self.shell('if main --status unexpected; then exit 70; fi\n')

    def test_explicit_empty_command_is_rejected_before_bootstrap_or_upgrade(self):
        for command in ('main ""', 'main "" --status',
                        'main --gre4-release v1.3.0 "$(printf \'%064d\' 0)" ""'):
            with self.subTest(command=command):
                self.shell('if ' + command + '; then exit 70; fi\n')


class OperatorPromptTests(unittest.TestCase):
    def add(self, answers, expected=0):
        with tempfile.TemporaryDirectory(prefix='gre4-prompts-') as directory:
            root = Path(directory)
            script = root / 'entry.sh'
            script.write_text(FUNCTIONS + r'''
ROOT=$1
PROFILE_DIR=$ROOT/profiles
STATE_DIR=$ROOT/state
LOCK_DIR=$ROOT/locks
MIGRATION_BACKUP_DIR=$ROOT/backups
LEGACY_CONF_FILE=$ROOT/legacy.conf
UNIT_FILE=$ROOT/legacy.service
APPLY_SCRIPT=$ROOT/helper
TEMPLATE_FILE=$ROOT/unit
mkdir -p "$PROFILE_DIR" "$STATE_DIR"
chmod 700 "$PROFILE_DIR" "$STATE_DIR"
cat > "$PROFILE_DIR/alpha.conf" <<'CONF'
ROLE=iran
LOCAL_PUBLIC_IP=198.51.100.1
PEER_PUBLIC_IP=192.0.2.11
SERVICE_PORTS=443,2096
ALLOW_UDP=yes
TUN_IF=g4-alpha
IRAN_TUN_CIDR=172.16.1.1/30
KHAREJ_TUN_CIDR=172.16.1.2/30
CONF
chmod 600 "$PROFILE_DIR/alpha.conf"
acquire_management_lock() { :; }
profile_runtime_lock() { exec 8> "$ROOT/runtime-lock"; }
profile_preflight() { echo PREFLIGHT; }
install_apply_script() { echo INSTALL; }
install_profile_unit() { :; }
record_installed_release() { :; }
systemctl() { :; }
ip() {
  case "$*" in
    '-o -4 addr show') echo '1: eth0 inet 198.51.100.1/24 scope global eth0' ;;
    '-4 route show table all') echo '198.51.100.0/24 dev eth0' ;;
    *) return 97 ;;
  esac
}
add_profile_interactive iran
''')
            result = subprocess.run(['bash', str(script), str(root)], input=answers,
                                    text=True, capture_output=True, timeout=12)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            created = (root / 'profiles/new.conf').read_text() if (root / 'profiles/new.conf').exists() else None
            return result.stdout + result.stderr, created

    def test_invalid_fields_retry_and_show_summary_before_applying(self):
        output, created = self.add('\n'.join([
            'bad\r', 'alpha', 'new', '999.1.1.1', '198.51.100.4', '198.51.100.1',
            '198.51.100.1', 'invalid', '192.0.2.11', '192.0.2.10', '0', '443,2096',
            'maybe', 'yes', '172.16.1.2/30', '172.16.1.0/30', '172.16.1.4/30', '']))
        self.assertIsNotNone(created)
        self.assertIn('PEER_PUBLIC_IP=192.0.2.10', created)
        self.assertIn('IRAN_TUN_CIDR=172.16.1.5/30', created)
        self.assertIn('ALLOW_UDP=yes', created)
        self.assertLess(output.index('Planned connection'), output.index('PREFLIGHT'))
        self.assertLess(output.index('PREFLIGHT'), output.index('INSTALL'))

    def test_successful_existing_input_sequence_stays_compatible(self):
        output, created = self.add('new\n198.51.100.1\n192.0.2.10\n443,2096\nyes\n172.16.1.4/30\n')
        self.assertIsNotNone(created)
        self.assertIn('Use this matching configuration', output)

    def test_padded_id_is_rejected_instead_of_silently_trimmed(self):
        output, created = self.add('  new  \nnew\n198.51.100.1\n192.0.2.10\n443,2096\nyes\n172.16.1.4/30\n')
        self.assertIsNotNone(created)
        self.assertEqual(output.count('Invalid connection ID.'), 1)

    def test_eof_during_retry_or_later_fields_cancels_without_configuration(self):
        for answers in ('bad\r\n', 'new\n198.51.100.1\n192.0.2.10\n443\n'):
            with self.subTest(answers=answers):
                output, created = self.add(answers, expected=1)
                self.assertIsNone(created)
                self.assertNotIn('PREFLIGHT', output)
                self.assertNotIn('INSTALL', output)
