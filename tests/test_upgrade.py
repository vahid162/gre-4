"""Automatic upgrades use private files and lifecycle substitutes, not host services."""
import subprocess
import tempfile
import unittest

from shell_source import FUNCTIONS


class UpgradeTests(unittest.TestCase):
    def run_upgrade(self, body):
        with tempfile.TemporaryDirectory(prefix='gre4-upgrade-') as root:
            result = subprocess.run(['bash', '-s', '--', root], input=FUNCTIONS + r'''
ROOT=$1
export ROOT
PROFILE_DIR=$ROOT/profiles
STATE_DIR=$ROOT/state
LOCK_DIR=$ROOT/locks
APPLY_SCRIPT=$ROOT/apply.sh
TEMPLATE_FILE=$ROOT/gre4@.service
LEGACY_CONF_FILE=$ROOT/gre4.conf
UNIT_FILE=$ROOT/gre4.service
MIGRATION_BACKUP_DIR=$ROOT/backups
RELEASE_STAMP_FILE=$ROOT/release
GRE4_RELEASE_TAG=v1.2.0
GRE4_RELEASE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
mkdir -p "$PROFILE_DIR" "$STATE_DIR" "$ROOT/active" "$ROOT/enabled" "$ROOT/masked"
chmod 700 "$PROFILE_DIR" "$STATE_DIR"
cat > "$APPLY_SCRIPT" <<'HELPER'
#!/usr/bin/env bash
printf 'old-helper %s\n' "$*" >> "$ROOT/log"
[[ ! -f "$ROOT/fail-cleanup" ]] || exit 1
if [[ $1 == stop ]]; then rm -rf "$ROOT/state/profiles/$2"; fi
HELPER
chmod 700 "$APPLY_SCRIPT"
UPGRADE_V111_HELPER_SHA256=$(sha256sum "$APPLY_SCRIPT"); UPGRADE_V111_HELPER_SHA256=${UPGRADE_V111_HELPER_SHA256%% *}
systemctl() {
  printf 'systemctl %s\n' "$*" >> "$ROOT/log"
  local id=${@: -1}; id=${id#gre4@}; id=${id%.service}
  case $1 in
    show)
      [[ ${@: -1} != gre4@.service ]] || { echo 'missing the instance name' >&2; return 1; }
      case $2 in
        --property=FragmentPath) printf '%s\n' "$TEMPLATE_FILE" ;;
        --property=DropInPaths) [[ ! -f $ROOT/dropin ]] || echo /custom.conf ;;
        --property=NeedDaemonReload) echo no ;;
        --property=ActiveState) [[ -f $ROOT/active/$id ]] && echo active || echo inactive ;;
        --property=UnitFileState)
          if [[ -f $ROOT/masked/$id ]]; then echo masked
          elif [[ -f $ROOT/enabled/$id ]]; then echo enabled
          else echo disabled; fi ;;
        *) return 99 ;;
      esac ;;
    list-units) [[ ! -f $ROOT/cached-instance ]] || echo 'gre4@removed.service loaded inactive dead' ;;
    list-unit-files)
      [[ ! -f $ROOT/fail-unit-discovery ]] || { echo 'unit discovery failed' >&2; return 42; }
      if [[ ${@: -1} == 'gre4@*.service' ]]; then
        # systemctl reports no matching unit files as a failure on a fresh host.
        [[ -e $TEMPLATE_FILE || -f $ROOT/cached-instance ]] || return 1
      else
        echo 'ssh.service enabled enabled'
      fi
      [[ ! -e $TEMPLATE_FILE ]] || echo 'gre4@.service disabled enabled'
      [[ ! -f $ROOT/cached-instance ]] || echo 'gre4@removed.service disabled enabled' ;;
    is-enabled)
      [[ ! -f $ROOT/masked/$id ]] || { echo masked; return 1; }
      [[ -f $ROOT/enabled/$id ]] && { echo enabled; return 0; }; echo disabled; return 1 ;;
    is-active) [[ -f $ROOT/active/$id ]] ;;
    stop) rm -f "$ROOT/active/$id" ;;
    mask) touch "$ROOT/masked/$id" ;;
    unmask) rm -f "$ROOT/masked/$id" ;;
    daemon-reload|enable|disable) : ;;
    start)
      [[ ! -f $ROOT/masked/$id ]] || return 1
      [[ ! -f $ROOT/fail-new-start || $(head -n 2 "$APPLY_SCRIPT" | tail -1) != '# new helper' ]] || return 1
      touch "$ROOT/active/$id"
      mkdir -p "$STATE_DIR/profiles/$id"
      cp "$PROFILE_DIR/$id.conf" "$STATE_DIR/profiles/$id/applied.conf"
      chmod 600 "$STATE_DIR/profiles/$id/applied.conf" ;;
    *) return 99 ;;
  esac
}
install_profile_unit
for id in alpha beta gamma; do
  subnet=172.16.1.0/30 peer=198.51.100.1
  [[ $id != beta ]] || { subnet=172.16.1.4/30; peer=198.51.100.2; }
  [[ $id != gamma ]] || { subnet=172.16.1.8/30; peer=198.51.100.3; }
  # Static private profiles: their exact bytes must survive an upgrade.
  ip() { :; }
  write_profile "$id" iran 192.0.2.1 "$peer" 443,2096 yes "$subnet"
done
touch "$ROOT/active/alpha" "$ROOT/enabled/alpha" "$ROOT/enabled/gamma"
mkdir -p "$STATE_DIR/profiles/alpha"
cp "$PROFILE_DIR/alpha.conf" "$STATE_DIR/profiles/alpha/applied.conf"
chmod 600 "$STATE_DIR/profiles/alpha/applied.conf"
cp -a "$PROFILE_DIR" "$ROOT/original-profiles"
cp "$APPLY_SCRIPT" "$ROOT/original-helper"
cp "$TEMPLATE_FILE" "$ROOT/original-unit"
profile_preflight() { [[ ! -f $ROOT/fail-preflight ]]; }
check_local_public_ip() { :; }
check_host_network_conflicts() { :; }
upgrade_verify_health() { [[ -f $ROOT/active/$1 ]]; }
install_apply_script() {
  printf 'install-helper\n' >> "$ROOT/log"
  [[ ! -f $ROOT/fail-install ]] || return 1
  cat > "$APPLY_SCRIPT" <<'HELPER'
#!/usr/bin/env bash
# new helper
printf 'new-helper %s\n' "$*" >> "$ROOT/log"
[[ ! -f "$ROOT/fail-new-cleanup" ]] || exit 1
if [[ $1 == stop ]]; then rm -rf "$ROOT/state/profiles/$2"; fi
HELPER
  chmod 700 "$APPLY_SCRIPT"
}
: > "$ROOT/log"
# Match main's conditional call: every implementation failure needs an explicit guard.
invoke_upgrade() { automatic_upgrade "$@" || return; }
''' + body, text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout + result.stderr

    def test_upgrade_preserves_profiles_and_active_enabled_intent(self):
        self.run_upgrade(r'''
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
diff -r "$PROFILE_DIR" "$ROOT/original-profiles"
[[ -f $ROOT/active/alpha && ! -f $ROOT/active/beta && ! -f $ROOT/active/gamma ]]
[[ -f $ROOT/enabled/alpha && ! -f $ROOT/enabled/beta && -f $ROOT/enabled/gamma ]]
[[ -f $RELEASE_STAMP_FILE && ! -e $MIGRATION_BACKUP_DIR/upgrade-pending ]]
grep -q 'v1.2.0' "$RELEASE_STAMP_FILE"
backup=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'upgrade.*')
[[ -n $backup && -f $backup/gre4-apply.sh && -f $backup/intent ]]
cmp "$ROOT/original-helper" "$backup/gre4-apply.sh"
[[ -z $(find "$ROOT/masked" -type f -print -quit) ]]
''')

    def test_same_release_does_not_restart_reinstall_or_create_backup(self):
        self.run_upgrade(r'''
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
count=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'upgrade.*' | wc -l)
: > "$ROOT/log"
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
[[ $count == $(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'upgrade.*' | wc -l) ]]
! grep -Eq 'systemctl (stop|start|mask|unmask|daemon-reload)|install-helper|helper stop' "$ROOT/log"
''')

    def test_unknown_or_modified_helper_and_unit_are_not_stopped(self):
        self.run_upgrade(r'''
echo '# edited' >> "$APPLY_SCRIPT"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
! grep -Eq 'systemctl (stop|start|mask)|install-helper' "$ROOT/log"
cp "$ROOT/original-helper" "$APPLY_SCRIPT"
echo '# edited unit' >> "$TEMPLATE_FILE"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 71; fi
! grep -Eq 'systemctl (stop|start|mask)|install-helper' "$ROOT/log"
''')

    def test_stamp_does_not_hide_modified_files_or_allow_downgrade(self):
        self.run_upgrade(r'''
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
: > "$ROOT/log"
if invoke_upgrade v1.1.9 "$GRE4_RELEASE_SHA"; then exit 70; fi
echo '# edited' >> "$APPLY_SCRIPT"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 71; fi
! grep -Eq 'systemctl (stop|start|mask)|install-helper' "$ROOT/log"
''')

    def test_prerequisite_failure_leaves_existing_installation_running(self):
        self.run_upgrade(r'''
touch "$ROOT/fail-preflight"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
[[ -f $ROOT/active/alpha && ! -f $RELEASE_STAMP_FILE ]]
cmp "$ROOT/original-helper" "$APPLY_SCRIPT"
! grep -Eq 'systemctl (stop|start|mask)|install-helper' "$ROOT/log"
''')

    def test_failure_restores_old_pair_then_only_previously_active_service(self):
        self.run_upgrade(r'''
touch "$ROOT/fail-new-start"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
cmp "$ROOT/original-helper" "$APPLY_SCRIPT"
cmp "$ROOT/original-unit" "$TEMPLATE_FILE"
[[ -f $ROOT/active/alpha && ! -f $ROOT/active/beta && ! -f $ROOT/active/gamma ]]
[[ ! -e $MIGRATION_BACKUP_DIR/upgrade-pending && ! -e $RELEASE_STAMP_FILE ]]
diff -r "$PROFILE_DIR" "$ROOT/original-profiles"
backup=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'upgrade.*')
[[ $(cat "$backup/stage") == rolled-back ]]
[[ -z $(find "$ROOT/masked" -type f -print -quit) ]]
new_cleanup=$(grep -n 'new-helper stop alpha' "$ROOT/log" | cut -d: -f1)
old_start=$(grep -n 'systemctl start gre4@alpha.service' "$ROOT/log" | tail -1 | cut -d: -f1)
[[ $new_cleanup -lt $old_start ]]
rm "$ROOT/fail-new-start"
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
''')

    def test_incomplete_cleanup_retains_backup_and_blocks_repeated_mutation(self):
        self.run_upgrade(r'''
touch "$ROOT/fail-new-start" "$ROOT/fail-new-cleanup"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
[[ -f $MIGRATION_BACKUP_DIR/upgrade-pending ]]
backup=$(cat "$MIGRATION_BACKUP_DIR/upgrade-pending")
[[ -f $backup/RECOVERY.txt && -f $backup/gre4-apply.sh ]]
grep -q '# new helper' "$APPLY_SCRIPT"
: > "$ROOT/log"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 71; fi
if profile_normal_mutation_allowed; then exit 72; fi
[[ ! -s $ROOT/log ]]
''')

    def test_effective_unit_overrides_and_transitional_state_are_refused(self):
        self.run_upgrade(r'''
touch "$ROOT/dropin"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
! grep -Eq 'systemctl (stop|start|mask)|install-helper' "$ROOT/log"
''')

    def test_fresh_host_opens_menu_without_installing_runtime(self):
        self.run_upgrade(r'''
rm -rf "$PROFILE_DIR" "$STATE_DIR" "$ROOT/active" "$ROOT/enabled"
mkdir "$ROOT/active" "$ROOT/enabled"
rm "$APPLY_SCRIPT" "$TEMPLATE_FILE"
: > "$ROOT/log"
need_root() { :; }
ensure_cmd() { :; }
release_verified_handoff() { GRE4_RELEASE_TAG=$1; GRE4_RELEASE_SHA=$2; }
main_menu() { touch "$ROOT/menu-opened"; }
main --gre4-release "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA" <<<'4'
[[ -f $ROOT/menu-opened && ! -e $APPLY_SCRIPT && ! -e $TEMPLATE_FILE ]]
[[ ! -e $RELEASE_STAMP_FILE && ! -e $MIGRATION_BACKUP_DIR ]]
! grep -Eq 'systemctl (stop|start|mask)|install-helper' "$ROOT/log"
''')

    def test_unit_file_discovery_failure_remains_fatal(self):
        for fresh in (False, True):
            with self.subTest(fresh=fresh):
                preparation = ''
                if fresh:
                    preparation = 'rm -rf "$PROFILE_DIR" "$STATE_DIR"\nrm "$APPLY_SCRIPT" "$TEMPLATE_FILE"\n'
                self.run_upgrade(preparation + r'''
touch "$ROOT/fail-unit-discovery"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; else [[ $? == 42 ]]; fi
[[ ! -e $RELEASE_STAMP_FILE && ! -e $MIGRATION_BACKUP_DIR ]]
[[ ! -e $APPLY_SCRIPT ]] || cmp "$ROOT/original-helper" "$APPLY_SCRIPT"
! grep -Eq 'systemctl (stop|start|mask)|install-helper' "$ROOT/log"
''')

    def test_unknown_runtime_and_orphan_service_are_refused_before_stopping(self):
        self.run_upgrade(r'''
mkdir -p "$STATE_DIR/profiles/orphan"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
! grep -Eq 'systemctl (stop|start|mask)|install-helper' "$ROOT/log"
''')

    def test_removed_inactive_disabled_instance_can_remain_in_systemd_cache(self):
        self.run_upgrade(r'''
touch "$ROOT/cached-instance"
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
[[ -f $ROOT/active/alpha && ! -e $MIGRATION_BACKUP_DIR/upgrade-pending ]]
''')

    def test_enabled_orphan_service_still_blocks_upgrade(self):
        self.run_upgrade(r'''
touch "$ROOT/cached-instance" "$ROOT/enabled/removed"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
! grep -Eq 'systemctl (stop|start|mask)|install-helper' "$ROOT/log"
''')

    def test_stamp_is_private_and_future_upgrade_preserves_a_rollback_record(self):
        self.run_upgrade(r'''
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
cp "$RELEASE_STAMP_FILE" "$ROOT/first-release"
[[ $(stat -c %a "$RELEASE_STAMP_FILE") == 600 ]]
GRE4_RELEASE_TAG=v1.3.0
eval "$(declare -f systemctl | sed '1s/systemctl/old_systemctl/')"
systemctl() {
  if [[ $1 == start && -e $ROOT/fail-once ]]; then rm "$ROOT/fail-once"; return 1; fi
  old_systemctl "$@"
}
touch "$ROOT/fail-once"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
cmp "$RELEASE_STAMP_FILE" "$ROOT/first-release"
[[ -f $ROOT/active/alpha && ! -f $ROOT/active/beta && ! -f $ROOT/active/gamma ]]
''')

    def test_zero_profile_installation_uses_a_concrete_nonstarted_unit_probe(self):
        self.run_upgrade(r'''
rm -rf "$PROFILE_DIR" "$STATE_DIR/profiles"
mkdir "$PROFILE_DIR"
rm -f "$ROOT/active/alpha" "$ROOT/enabled/alpha" "$ROOT/enabled/gamma"
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
[[ -f $RELEASE_STAMP_FILE ]]
! grep -Eq 'systemctl (start|stop|mask|unmask)' "$ROOT/log"
! grep -Fq -- '--value gre4@.service' "$ROOT/log"
''')

    def test_preparation_failure_does_not_stop_or_mask_existing_connections(self):
        self.run_upgrade(r'''
touch "$ROOT/fail-install"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
[[ -f $ROOT/active/alpha && ! -f $RELEASE_STAMP_FILE ]]
cmp "$ROOT/original-helper" "$APPLY_SCRIPT"
cmp "$ROOT/original-unit" "$TEMPLATE_FILE"
[[ ! -e $MIGRATION_BACKUP_DIR/upgrade-pending ]]
! grep -Eq 'systemctl (stop|start|mask|unmask)' "$ROOT/log"
''')

    def test_unit_or_release_record_preparation_failure_leaves_runtime_untouched(self):
        for prepare in ('render_profile_unit', 'record_installed_release'):
            with self.subTest(prepare=prepare):
                self.run_upgrade(prepare + '() { return 1; }\n' + r'''
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
[[ -f $ROOT/active/alpha && ! -f $RELEASE_STAMP_FILE ]]
cmp "$ROOT/original-helper" "$APPLY_SCRIPT"
cmp "$ROOT/original-unit" "$TEMPLATE_FILE"
[[ ! -e $MIGRATION_BACKUP_DIR/upgrade-pending ]]
! grep -Eq 'systemctl (stop|start|mask|unmask)' "$ROOT/log"
''')

    def test_completed_migration_then_uses_normal_profile_version_recognition(self):
        self.run_upgrade(r'''
mkdir "$MIGRATION_BACKUP_DIR"
touch "$MIGRATION_BACKUP_DIR/pending"
migrate_legacy_deployment() {
  touch "$ROOT/migration-checked"
  rm "$MIGRATION_BACKUP_DIR/pending"
}
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
[[ -f $ROOT/migration-checked && -f $RELEASE_STAMP_FILE && -f $ROOT/active/alpha ]]
''')

    def test_replacement_evidence_exists_before_any_service_is_masked(self):
        self.run_upgrade(r'''
eval "$(declare -f systemctl | sed '1s/systemctl/fixture_systemctl/')"
systemctl() {
  if [[ $1 == mask ]]; then
    local prepared
    prepared=$(cat "$MIGRATION_BACKUP_DIR/upgrade-pending") || return
    [[ -f $prepared/new-helper && -f $prepared/new-unit && -f $prepared/new-release ]] || return 98
  fi
  fixture_systemctl "$@"
}
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
[[ -f $ROOT/active/alpha && ! -e $MIGRATION_BACKUP_DIR/upgrade-pending ]]
''')

    def test_failure_after_first_replacement_can_restore_from_prepared_evidence(self):
        self.run_upgrade(r'''
eval "$(declare -f migration_restore_file | sed '1s/migration_restore_file/fixture_restore_file/')"
migration_restore_file() {
  fixture_restore_file "$@" || return
  [[ $1 != */new-helper ]] || return 1
}
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
cmp "$ROOT/original-helper" "$APPLY_SCRIPT"
cmp "$ROOT/original-unit" "$TEMPLATE_FILE"
[[ -f $ROOT/active/alpha && ! -f $ROOT/active/beta && ! -f $ROOT/active/gamma ]]
[[ ! -e $MIGRATION_BACKUP_DIR/upgrade-pending && ! -e $RELEASE_STAMP_FILE ]]
[[ -z $(find "$ROOT/masked" -type f -print -quit) ]]
''')

    def test_interrupted_cutovers_keep_persistent_masks_and_refuse_mutating_retry(self):
        for phase in ('old-clean', 'new-installed'):
            with self.subTest(phase=phase):
                self.run_upgrade("INTERRUPT_PHASE=" + phase + r'''
eval "$(declare -f migration_set_stage | sed '1s/migration_set_stage/fixture_set_stage/')"
migration_set_stage() {
  fixture_set_stage "$@" || return
  [[ $2 != "$INTERRUPT_PHASE" ]] || kill -KILL "$BASHPID"
}
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
backup=$(cat "$MIGRATION_BACKUP_DIR/upgrade-pending")
[[ $(cat "$backup/stage") == "$INTERRUPT_PHASE" ]]
[[ -f $backup/gre4-apply.sh && -f $backup/new-helper && -f $backup/new-unit && -f $backup/new-release ]]
[[ -f $ROOT/masked/alpha && -f $ROOT/masked/beta && -f $ROOT/masked/gamma ]]
[[ -f $ROOT/enabled/alpha && -f $ROOT/enabled/gamma ]]
[[ ! -f $ROOT/active/alpha && ! -f $ROOT/active/beta && ! -f $ROOT/active/gamma ]]
# Simulated reboot/start cannot bypass persistent systemd mask state.
if systemctl start gre4@alpha.service; then exit 71; fi
: > "$ROOT/log"
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 72; fi
[[ ! -s $ROOT/log && -f $MIGRATION_BACKUP_DIR/upgrade-pending ]]
''')
