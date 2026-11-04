"""Legacy migration uses private fixtures and substitutes, never host services."""
import subprocess
import tempfile
import unittest


from shell_source import FUNCTIONS


class MigrationTests(unittest.TestCase):
    def run_migration(self, body):
        self.assertTrue("migrate_legacy_deployment()" in FUNCTIONS, "migration entry point is not implemented")
        with tempfile.TemporaryDirectory(prefix="gre4-migrate-") as scratch:
            result = subprocess.run(
                ["bash", "-s", "--", scratch],
                input=FUNCTIONS + r'''
set -euo pipefail
ROOT=$1
export MIGRATION_TEST_ROOT=$ROOT MIGRATION_TEST_LOG=$ROOT/commands
CONF_FILE=$ROOT/gre4.conf
LEGACY_CONF_FILE=$CONF_FILE
UNIT_FILE=$ROOT/gre4.service
LEGACY_UNIT_FILE=$UNIT_FILE
APPLY_SCRIPT=$ROOT/gre4-apply.sh
TEMPLATE_FILE=$ROOT/gre4@.service
PROFILE_DIR=$ROOT/profiles
STATE_DIR=$ROOT/state
SYSCTL_DIR=$ROOT/sysctl.d
LOCK_DIR=$ROOT/locks
MIGRATION_BACKUP_DIR=$ROOT/backups
mkdir -p "$PROFILE_DIR" "$STATE_DIR" "$SYSCTL_DIR" "$LOCK_DIR"
chmod 700 "$PROFILE_DIR" "$STATE_DIR"
cat > "$CONF_FILE" <<'CONF'
ROLE="iran"
LOCAL_PUBLIC_IP="192.0.2.1"
PEER_PUBLIC_IP="198.51.100.1"
SERVICE_PORTS="443,2096"
ALLOW_UDP="yes"
TUN_IF="GRE"
IRAN_TUN_CIDR="172.16.1.1/30"
KHAREJ_TUN_CIDR="172.16.1.2/30"
CONF
chmod 600 "$CONF_FILE"
cat > "$APPLY_SCRIPT" <<'HELPER'
#!/usr/bin/env bash
printf 'old-helper %s\n' "$*" >> "$MIGRATION_TEST_LOG"
[[ ! -e "$MIGRATION_TEST_ROOT/fail-old-cleanup" ]] || exit 1
rm -rf "$MIGRATION_TEST_ROOT/state/sysctl"
rm -f "$MIGRATION_TEST_ROOT/sysctl.d/99-gre4-forward.conf" "$MIGRATION_TEST_ROOT/sysctl.d/99-gre4-conntrack.conf"
HELPER
chmod 700 "$APPLY_SCRIPT"
LEGACY_HELPER_SHA256=$(sha256sum "$APPLY_SCRIPT"); LEGACY_HELPER_SHA256=${LEGACY_HELPER_SHA256%% *}
cat > "$UNIT_FILE" <<UNIT
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
chmod 600 "$UNIT_FILE"
active=no enabled=no
real_write_profile=$(declare -f write_profile)
real_install_apply_script=$(declare -f install_apply_script)
real_install_profile_unit=$(declare -f install_profile_unit)
acquire_management_lock() { :; }
systemctl() {
  printf 'systemctl %s\n' "$*" >> "$MIGRATION_TEST_LOG"
  case $1 in
    show)
      case $2 in
        --property=FragmentPath) printf '%s\n' "$LEGACY_UNIT_FILE" ;;
        --property=DropInPaths) [[ ! -e "$ROOT/with-dropin" ]] || echo "$ROOT/override.conf" ;;
        --property=NeedDaemonReload) echo no ;;
        *) return 99 ;;
      esac
      return 0 ;;
    is-active) [[ $active == yes ]] ;;
    is-enabled) [[ $enabled == yes ]] ;;
    stop|disable|enable|daemon-reload) : ;;
    start) [[ ! -e "$ROOT/fail-old-restart" ]] ;;
    *) return 99 ;;
  esac
}
write_profile() {
  printf 'write-profile %s\n' "$*" >> "$MIGRATION_TEST_LOG"
  [[ ! -e "$ROOT/fail-write-profile" ]] || return 1
  printf 'ROLE=%s\nLOCAL_PUBLIC_IP=%s\nPEER_PUBLIC_IP=%s\nSERVICE_PORTS=%s\nALLOW_UDP=%s\nTUN_IF=%s\nIRAN_TUN_CIDR=172.16.1.1/30\nKHAREJ_TUN_CIDR=172.16.1.2/30\n' "$2" "$3" "$4" "$5" "$6" "$8" > "$PROFILE_DIR/$1.conf"
  chmod 600 "$PROFILE_DIR/$1.conf"
}
install_apply_script() {
  printf 'install-new-helper\n' >> "$MIGRATION_TEST_LOG"
  [[ ! -e "$ROOT/fail-install-helper" ]] || return 1
  printf '#!/usr/bin/env bash\nexit 0\n' > "$APPLY_SCRIPT"
  chmod 700 "$APPLY_SCRIPT"
}
install_profile_unit() {
  printf 'install-new-unit\n' >> "$MIGRATION_TEST_LOG"
  printf 'new template\n' > "$TEMPLATE_FILE"
  chmod 644 "$TEMPLATE_FILE"
}
profile_start_service() {
  printf 'new-start %s\n' "$*" >> "$MIGRATION_TEST_LOG"
  [[ ! -e "$ROOT/fail-new-start" ]]
}
profile_stop_service() {
  printf 'new-stop %s\n' "$*" >> "$MIGRATION_TEST_LOG"
  [[ ! -e "$ROOT/fail-new-cleanup" ]]
}
''' + body,
                text=True, capture_output=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout + result.stderr

    def test_import_preserves_addresses_and_enabled_active_intent(self):
        self.run_migration(r'''
active=yes enabled=yes
migrate_legacy_deployment
[[ -f $PROFILE_DIR/legacy.conf && ! -e $LEGACY_CONF_FILE && ! -e $LEGACY_UNIT_FILE ]]
grep -Fxq 'TUN_IF=GRE' "$PROFILE_DIR/legacy.conf"
grep -Fxq 'IRAN_TUN_CIDR=172.16.1.1/30' "$PROFILE_DIR/legacy.conf"
grep -Fxq 'KHAREJ_TUN_CIDR=172.16.1.2/30' "$PROFILE_DIR/legacy.conf"
grep -Fxq 'systemctl enable gre4@legacy.service' "$MIGRATION_TEST_LOG"
grep -Fxq 'new-start legacy' "$MIGRATION_TEST_LOG"
old_stop=$(grep -n '^old-helper stop$' "$MIGRATION_TEST_LOG" | head -1 | cut -d: -f1)
new_install=$(grep -n '^install-new-helper$' "$MIGRATION_TEST_LOG" | cut -d: -f1)
[[ $old_stop -lt $new_install ]]
[[ ! -e $MIGRATION_BACKUP_DIR/pending ]]
''')

    def test_stopped_disabled_import_does_not_start_or_enable(self):
        self.run_migration(r'''
migrate_legacy_deployment
! grep -q '^new-start\|^systemctl enable ' "$MIGRATION_TEST_LOG"
[[ -f $PROFILE_DIR/legacy.conf ]]
''')

    def test_enabled_but_stopped_import_remains_stopped(self):
        self.run_migration(r'''
enabled=yes
migrate_legacy_deployment
grep -Fxq 'systemctl enable gre4@legacy.service' "$MIGRATION_TEST_LOG"
! grep -q '^new-start ' "$MIGRATION_TEST_LOG"
''')

    def test_active_but_disabled_import_does_not_enable_boot_start(self):
        self.run_migration(r'''
active=yes
migrate_legacy_deployment
grep -Fxq 'new-start legacy' "$MIGRATION_TEST_LOG"
grep -Fxq 'systemctl disable gre4@legacy.service' "$MIGRATION_TEST_LOG"
! grep -q '^systemctl enable gre4@legacy.service' "$MIGRATION_TEST_LOG"
''')

    def test_import_integrates_real_profile_writer_helper_and_service_template(self):
        self.run_migration(r'''
eval "$real_write_profile"
eval "$real_install_apply_script"
eval "$real_install_profile_unit"
ip() {
  case "$*" in
    '-o -4 addr show') echo '2: eth0 inet 192.0.2.1/32 scope global eth0' ;;
    '-4 route show table all') : ;;
    *) return 99 ;;
  esac
}
migrate_legacy_deployment
load_profile legacy
[[ $ROLE == iran && $TUN_IF == GRE && $SERVICE_PORTS == 443,2096 && $ALLOW_UDP == yes ]]
[[ $IRAN_TUN_CIDR == 172.16.1.1/30 && $KHAREJ_TUN_CIDR == 172.16.1.2/30 ]]
bash -n "$APPLY_SCRIPT"
grep -Fxq "ExecStart=$APPLY_SCRIPT start %i" "$TEMPLATE_FILE"
grep -Fxq "ExecStopPost=$APPLY_SCRIPT stop %i" "$TEMPLATE_FILE"
if bash "$APPLY_SCRIPT" start; then exit 1; fi
backup=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'migration.*')
printf '%s\n' "$backup" > "$MIGRATION_BACKUP_DIR/pending"
chmod 600 "$MIGRATION_BACKUP_DIR/pending"
migration_set_stage "$backup" recovery-needed
if bash "$APPLY_SCRIPT" start legacy > "$ROOT/helper-start-output" 2>&1; then exit 1; fi
grep -Fq 'Legacy migration recovery blocks profile start' "$ROOT/helper-start-output"
[[ ! -e $STATE_DIR/profiles/legacy/applied.conf ]]
''')

    def test_unknown_helper_is_rejected_before_service_changes(self):
        self.run_migration(r'''
LEGACY_HELPER_SHA256=unknown
if migrate_legacy_deployment; then exit 1; fi
[[ -f $LEGACY_CONF_FILE && -f $LEGACY_UNIT_FILE ]]
[[ ! -e $MIGRATION_TEST_LOG ]]
''')

    def test_unowned_sysctl_file_blocks_migration(self):
        self.run_migration(r'''
echo 'net.ipv4.ip_forward=1' > "$SYSCTL_DIR/99-gre4-forward.conf"
if migrate_legacy_deployment; then exit 1; fi
[[ -f $LEGACY_CONF_FILE && ! -e $PROFILE_DIR/legacy.conf ]]
! grep -q '^systemctl stop' "$MIGRATION_TEST_LOG"
''')

    def test_configuration_is_parsed_without_executing_shell(self):
        self.run_migration(r'''
printf 'ROLE="$(touch %s/injected)"\n' "$ROOT" >> "$CONF_FILE"
if migrate_legacy_deployment; then exit 1; fi
[[ ! -e $ROOT/injected && -f $LEGACY_CONF_FILE ]]
''')

    def test_legacy_cleanup_failure_keeps_original_files_and_retry_intent(self):
        self.run_migration(r'''
active=yes enabled=yes
before=$(sha256sum "$APPLY_SCRIPT")
touch "$ROOT/fail-old-cleanup"
if migrate_legacy_deployment; then exit 1; fi
[[ $(sha256sum "$APPLY_SCRIPT") == "$before" ]]
[[ -f $LEGACY_CONF_FILE && -f $LEGACY_UNIT_FILE && -f $MIGRATION_BACKUP_DIR/pending ]]
! grep -q '^install-new-helper' "$MIGRATION_TEST_LOG"
rm "$ROOT/fail-old-cleanup"
active=no enabled=no
migrate_legacy_deployment
grep -Fxq 'new-start legacy' "$MIGRATION_TEST_LOG"
grep -Fxq 'systemctl enable gre4@legacy.service' "$MIGRATION_TEST_LOG"
''')

    def test_new_start_failure_rolls_back_only_after_successful_cleanup(self):
        self.run_migration(r'''
active=yes enabled=yes
before=$(sha256sum "$APPLY_SCRIPT")
touch "$ROOT/fail-new-start"
if migrate_legacy_deployment; then exit 1; fi
[[ $(sha256sum "$APPLY_SCRIPT") == "$before" ]]
[[ -f $LEGACY_CONF_FILE && -f $LEGACY_UNIT_FILE && ! -e $PROFILE_DIR/legacy.conf ]]
grep -Fxq 'new-stop legacy' "$MIGRATION_TEST_LOG"
grep -Fxq 'systemctl start gre4.service' "$MIGRATION_TEST_LOG"
! grep -q '^systemctl enable gre4@legacy.service' "$MIGRATION_TEST_LOG" || grep -q '^systemctl disable gre4@legacy.service' "$MIGRATION_TEST_LOG"
''')

    def test_incomplete_new_cleanup_retains_recovery_and_blocks_legacy_restart(self):
        self.run_migration(r'''
active=yes enabled=yes
touch "$ROOT/fail-new-start" "$ROOT/fail-new-cleanup"
if migrate_legacy_deployment; then exit 1; fi
[[ -f $MIGRATION_BACKUP_DIR/pending && -f $PROFILE_DIR/legacy.conf ]]
! grep -Fxq 'systemctl start gre4.service' "$MIGRATION_TEST_LOG"
rm "$ROOT/fail-new-cleanup"
if migrate_legacy_deployment; then exit 1; fi
[[ -f $LEGACY_CONF_FILE && ! -e $MIGRATION_BACKUP_DIR/pending ]]
grep -Fxq 'systemctl start gre4.service' "$MIGRATION_TEST_LOG"
''')

    def test_symlinked_legacy_configuration_is_rejected(self):
        self.run_migration(r'''
mv "$CONF_FILE" "$ROOT/other.conf"
ln -s "$ROOT/other.conf" "$CONF_FILE"
if migrate_legacy_deployment; then exit 1; fi
[[ -L $CONF_FILE && ! -e $PROFILE_DIR/legacy.conf ]]
''')

    def test_effective_unit_dropin_blocks_cleanup(self):
        self.run_migration(r'''
touch "$ROOT/with-dropin"
if migrate_legacy_deployment; then exit 1; fi
[[ -f $LEGACY_CONF_FILE && -f $LEGACY_UNIT_FILE ]]
! grep -q '^old-helper\|^install-new-helper\|^systemctl stop' "$MIGRATION_TEST_LOG"
''')

    def test_interrupted_helper_install_can_resume_cutover(self):
        self.run_migration(r'''
active=yes enabled=yes
touch "$ROOT/fail-install-helper"
if migrate_legacy_deployment; then exit 1; fi
[[ -f $MIGRATION_BACKUP_DIR/pending && -f $PROFILE_DIR/legacy.conf ]]
rm "$ROOT/fail-install-helper"
active=no enabled=no
migrate_legacy_deployment
grep -Fxq 'new-start legacy' "$MIGRATION_TEST_LOG"
grep -Fxq 'systemctl enable gre4@legacy.service' "$MIGRATION_TEST_LOG"
[[ ! -e $LEGACY_UNIT_FILE && ! -e $MIGRATION_BACKUP_DIR/pending ]]
''')

    def test_completed_journal_retry_does_not_repeat_cutover(self):
        self.run_migration(r'''
migrate_legacy_deployment
backup=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'migration.*')
printf '%s\n' "$backup" > "$MIGRATION_BACKUP_DIR/pending"
chmod 600 "$MIGRATION_BACKUP_DIR/pending"
before=$(wc -l < "$MIGRATION_TEST_LOG")
migrate_legacy_deployment
[[ $(wc -l < "$MIGRATION_TEST_LOG") == "$before" && ! -e $MIGRATION_BACKUP_DIR/pending ]]
''')

    def test_changed_recovery_targets_are_rejected(self):
        self.run_migration(r'''
touch "$ROOT/fail-old-cleanup"
if migrate_legacy_deployment; then exit 1; fi
read -r backup < "$MIGRATION_BACKUP_DIR/pending"
printf 'wrong targets\n' > "$backup/targets"
before=$(wc -l < "$MIGRATION_TEST_LOG")
if migrate_legacy_deployment; then exit 1; fi
[[ $(wc -l < "$MIGRATION_TEST_LOG") == "$before" && -f $LEGACY_UNIT_FILE ]]
''')

    def test_symlinked_recovery_targets_are_rejected(self):
        self.run_migration(r'''
touch "$ROOT/fail-old-cleanup"
if migrate_legacy_deployment; then exit 1; fi
read -r backup < "$MIGRATION_BACKUP_DIR/pending"
mv "$backup/targets" "$backup/other-targets"
ln -s "$backup/other-targets" "$backup/targets"
before=$(wc -l < "$MIGRATION_TEST_LOG")
if migrate_legacy_deployment; then exit 1; fi
[[ $(wc -l < "$MIGRATION_TEST_LOG") == "$before" && -f $LEGACY_UNIT_FILE ]]
''')

    def test_backups_are_private_and_not_restored_as_live_state(self):
        self.run_migration(r'''
active=yes enabled=yes
mkdir -p "$STATE_DIR/sysctl/forward"
chmod 700 "$STATE_DIR/sysctl" "$STATE_DIR/sysctl/forward"
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.forwarding=1\n' > "$STATE_DIR/sysctl/forward/file"
printf 'net.ipv4.ip_forward 0 1\nnet.ipv4.conf.all.forwarding 0 1\n' > "$STATE_DIR/sysctl/forward/values"
cp "$STATE_DIR/sysctl/forward/file" "$SYSCTL_DIR/99-gre4-forward.conf"
chmod 600 "$STATE_DIR/sysctl/forward/file" "$STATE_DIR/sysctl/forward/values" "$SYSCTL_DIR/99-gre4-forward.conf"
touch "$ROOT/fail-new-start"
profile_stop_service() { printf 'new-stop %s\n' "$*" >> "$MIGRATION_TEST_LOG"; rm -rf "$STATE_DIR/sysctl"; }
if migrate_legacy_deployment; then exit 1; fi
[[ ! -e $STATE_DIR/sysctl ]]
for directory in "$MIGRATION_BACKUP_DIR" "$MIGRATION_BACKUP_DIR"/migration.*; do
  [[ $(stat -c %a "$directory") == 700 ]]
done
''')

    def test_rollback_interruption_blocks_reboot_start_and_recleans_before_restore(self):
        self.run_migration(r'''
active=yes enabled=yes
touch "$ROOT/fail-new-start"
real_set_stage=$(declare -f migration_set_stage)
migration_set_stage() {
  printf '%s\n' "$2" > "$1/stage"
  chmod 600 "$1/stage"
  [[ $2 != rollback-needed ]] || exit 77
}
if migrate_legacy_deployment; then exit 1; fi
read -r backup < "$MIGRATION_BACKUP_DIR/pending"
[[ $(cat "$backup/stage") == rollback-needed ]]
grep -Fxq 'systemctl disable gre4@legacy.service' "$MIGRATION_TEST_LOG"
# A fresh shell has no in-memory migration flag, as after reboot.
export MIGRATION_BACKUP_DIR
if bash -c "$(declare -f profile_migration_start_allowed legacy_owned_file legacy_safe_path err); profile_migration_start_allowed legacy"; then exit 1; fi
# Replay a start that raced the interruption; recovery must clean it again.
touch "$ROOT/live-runtime"
profile_stop_service() {
  printf 'replay-cleanup\n' >> "$MIGRATION_TEST_LOG"
  rm -f "$ROOT/live-runtime"
}
saved_systemctl=$(declare -f systemctl)
eval "${saved_systemctl/systemctl ()/fixture_systemctl ()}"
systemctl() {
  if [[ $* == 'start gre4.service' ]]; then [[ ! -e $ROOT/live-runtime ]] || return 98; fi
  fixture_systemctl "$@"
}
eval "$real_set_stage"
if migrate_legacy_deployment; then exit 1; fi
[[ ! -e $ROOT/live-runtime && ! -e $MIGRATION_BACKUP_DIR/pending ]]
grep -Fxq 'replay-cleanup' "$MIGRATION_TEST_LOG"
grep -Fxq 'systemctl start gre4.service' "$MIGRATION_TEST_LOG"
''')

    def test_partial_helper_restoration_retry_never_runs_singleton_as_profile_cleanup(self):
        self.run_migration(r'''
active=yes enabled=yes
before=$(sha256sum "$APPLY_SCRIPT")
touch "$ROOT/fail-new-start"
real_restore_file=$(declare -f migration_restore_file)
eval "${real_restore_file/migration_restore_file ()/fixture_restore_file ()}"
migration_restore_file() {
  fixture_restore_file "$@" || return
  [[ $2 != "$APPLY_SCRIPT" ]] || return 1
}
if migrate_legacy_deployment; then exit 1; fi
read -r backup < "$MIGRATION_BACKUP_DIR/pending"
[[ $(cat "$backup/stage") == restoring-legacy && $(sha256sum "$APPLY_SCRIPT") == "$before" ]]
if profile_migration_start_allowed legacy; then exit 1; fi
profile_stop_service() { echo 'unsafe-profile-cleanup' >> "$MIGRATION_TEST_LOG"; return 99; }
eval "$real_restore_file"
if migrate_legacy_deployment; then exit 1; fi
[[ ! -e $MIGRATION_BACKUP_DIR/pending && -f $LEGACY_CONF_FILE && -f $LEGACY_UNIT_FILE ]]
! grep -Fxq 'unsafe-profile-cleanup' "$MIGRATION_TEST_LOG"
grep -Fxq 'systemctl start gre4.service' "$MIGRATION_TEST_LOG"
''')

    def test_ambiguous_old_rollback_journal_preserves_live_recovery(self):
        self.run_migration(r'''
active=yes enabled=yes
touch "$ROOT/fail-new-start" "$ROOT/fail-new-cleanup"
if migrate_legacy_deployment; then exit 1; fi
read -r backup < "$MIGRATION_BACKUP_DIR/pending"
printf 'rollback-needed\n' > "$backup/stage"
rm "$backup/profile.helper"
mkdir -p "$STATE_DIR/profiles/legacy"
echo evidence > "$STATE_DIR/profiles/legacy/applied.conf"
cp "$backup/gre4-apply.sh" "$APPLY_SCRIPT"
profile_stop_service() { echo unsafe-cleanup >> "$MIGRATION_TEST_LOG"; return 99; }
if migrate_legacy_deployment; then exit 1; fi
[[ $(cat "$STATE_DIR/profiles/legacy/applied.conf") == evidence && -f $MIGRATION_BACKUP_DIR/pending ]]
! grep -q 'unsafe-cleanup\|systemctl start gre4.service' "$MIGRATION_TEST_LOG"
''')

    def test_persistent_start_guard_allows_only_safe_migration_stages(self):
        self.run_migration(r'''
profile_migration_start_allowed legacy
mkdir -p "$MIGRATION_BACKUP_DIR/migration.fixture"
backup=$MIGRATION_BACKUP_DIR/migration.fixture
chmod 700 "$MIGRATION_BACKUP_DIR" "$backup"
printf '%s\n' "$backup" > "$MIGRATION_BACKUP_DIR/pending"
chmod 600 "$MIGRATION_BACKUP_DIR/pending"
for stage in prepared legacy-clean recovery-needed rollback-needed restoring-legacy rolled-back unknown; do
  migration_set_stage "$backup" "$stage"
  if profile_migration_start_allowed legacy; then exit 1; fi
  profile_migration_start_allowed iran1
done
for stage in new-installed complete; do
  migration_set_stage "$backup" "$stage"
  profile_migration_start_allowed legacy
done
mv "$backup/stage" "$backup/real-stage"
ln -s "$backup/real-stage" "$backup/stage"
if profile_migration_start_allowed legacy; then exit 1; fi
rm "$backup/stage"
echo new-installed > "$backup/stage"
chmod 666 "$backup/stage"
if profile_migration_start_allowed legacy; then exit 1; fi
''')


if __name__ == "__main__":
    unittest.main()
