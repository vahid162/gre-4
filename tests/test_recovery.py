"""Guarded recovery uses private transaction fixtures, never host services."""
import unittest

import test_upgrade


class RecoveryTests(unittest.TestCase):
    def run_recovery(self, body):
        return test_upgrade.UpgradeTests().run_upgrade(body)

    def test_completed_backup_can_restore_previous_pair_after_confirmation(self):
        self.run_recovery(r'''
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
backup=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'upgrade.*')
recover_upgrade_interactive "${backup##*/}" <<<"${backup##*/}"
cmp "$ROOT/original-helper" "$APPLY_SCRIPT"
cmp "$ROOT/original-unit" "$TEMPLATE_FILE"
[[ ! -e $RELEASE_STAMP_FILE && ! -e $MIGRATION_BACKUP_DIR/upgrade-pending ]]
[[ -f $ROOT/active/alpha && ! -f $ROOT/active/beta && ! -f $ROOT/active/gamma ]]
''')

    def test_listing_is_readonly_and_identifies_legacy_manual_backups(self):
        self.run_recovery(r'''
mkdir -p "$MIGRATION_BACKUP_DIR/upgrade.legacy"
chmod 700 "$MIGRATION_BACKUP_DIR" "$MIGRATION_BACKUP_DIR/upgrade.legacy"
printf 'old-clean\n' > "$MIGRATION_BACKUP_DIR/upgrade.legacy/stage"
chmod 600 "$MIGRATION_BACKUP_DIR/upgrade.legacy/stage"
: > "$ROOT/log"
list_upgrade_backups > "$ROOT/list"
grep -Fq 'upgrade.legacy' "$ROOT/list"
grep -Fqi 'manual' "$ROOT/list"
[[ ! -s $ROOT/log ]]
''')

    def test_pending_interrupted_runtime_can_be_recovered(self):
        for phase in ('old-clean', 'new-installed'):
            with self.subTest(phase=phase):
                self.run_recovery('INTERRUPT_PHASE=' + phase + r'''
eval "$(declare -f migration_set_stage | sed '1s/migration_set_stage/fixture_set_stage/')"
migration_set_stage() {
  fixture_set_stage "$@" || return
  [[ $2 != "$INTERRUPT_PHASE" ]] || kill -KILL "$BASHPID"
}
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
backup=$(cat "$MIGRATION_BACKUP_DIR/upgrade-pending")
migration_set_stage() { fixture_set_stage "$@"; }
recover_upgrade_interactive <<<"${backup##*/}"
cmp "$ROOT/original-helper" "$APPLY_SCRIPT"
cmp "$ROOT/original-unit" "$TEMPLATE_FILE"
[[ $(cat "$backup/stage") == rolled-back && ! -e $MIGRATION_BACKUP_DIR/upgrade-pending ]]
[[ -f $ROOT/active/alpha && ! -f $ROOT/active/beta && ! -f $ROOT/active/gamma ]]
[[ -z $(find "$ROOT/masked" -type f -print -quit) ]]
''')

    def test_prepared_stopping_and_partial_masks_restore_only_captured_intent(self):
        for point, stage, mask_count in (
                ('prepared', 'prepared', 0), ('stopping', 'stopping', 3),
                ('mask-1', 'prepared', 1), ('mask-2', 'prepared', 2),
                ('cleanup-1', 'stopping', 3)):
            with self.subTest(interruption=point):
                self.run_recovery(f'INTERRUPT_POINT={point}\nEXPECTED_STAGE={stage}\nEXPECTED_MASKS={mask_count}\n' + r'''
# These unrelated artifacts must survive recovery, including a preexisting mask.
mkdir "$STATE_DIR/other-application"
printf 'snapshot evidence\n' > "$STATE_DIR/other-application/state"
chmod 600 "$STATE_DIR/other-application/state"
ln -s /dev/null "$ROOT/other.service"
touch "$ROOT/masked/other" "$ROOT/active/other" "$ROOT/enabled/other"
cp -a "$ROOT/enabled" "$ROOT/original-enabled"
eval "$(declare -f upgrade_publish_pending | sed '1s/upgrade_publish_pending/fixture_publish_pending/')"
upgrade_publish_pending() {
  fixture_publish_pending "$@" || return
  if [[ $INTERRUPT_POINT == prepared ]]; then kill -KILL "$BASHPID"; fi
}
eval "$(declare -f migration_set_stage | sed '1s/migration_set_stage/fixture_set_stage/')"
migration_set_stage() {
  fixture_set_stage "$@" || return
  if [[ $INTERRUPT_POINT == stopping && $2 == stopping ]]; then kill -KILL "$BASHPID"; fi
}
eval "$(declare -f systemctl | sed '1s/systemctl/fixture_systemctl/')"
systemctl() {
  fixture_systemctl "$@" || return
  case "$INTERRUPT_POINT:$1:${@: -1}" in
    mask-1:mask:gre4@alpha.service|mask-2:mask:gre4@beta.service) kill -KILL "$BASHPID" ;;
  esac
}
eval "$(declare -f profile_stop_service | sed '1s/profile_stop_service/fixture_stop_service/')"
profile_stop_service() {
  fixture_stop_service "$@" || return
  if [[ $INTERRUPT_POINT == cleanup-1 && $1 == alpha ]]; then kill -KILL "$BASHPID"; fi
}
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
backup=$(cat "$MIGRATION_BACKUP_DIR/upgrade-pending")
[[ $(cat "$backup/stage") == "$EXPECTED_STAGE" ]]
count=0
for id in alpha beta gamma; do
  if [[ -f $ROOT/masked/$id ]]; then
    count=$((count+1))
    [[ -L $ROOT/gre4@$id.service && $(readlink "$ROOT/gre4@$id.service") == /dev/null ]]
  else
    [[ ! -e $ROOT/gre4@$id.service && ! -L $ROOT/gre4@$id.service ]]
  fi
done
[[ $count == "$EXPECTED_MASKS" ]]
# Only the cleanup interruption has stopped the previously active connection.
if [[ $INTERRUPT_POINT == cleanup-1 ]]; then
  [[ ! -f $ROOT/active/alpha && ! -e $STATE_DIR/profiles/alpha/applied.conf ]]
else
  [[ -f $ROOT/active/alpha && -f $STATE_DIR/profiles/alpha/applied.conf ]]
fi
cmp "$ROOT/original-helper" "$APPLY_SCRIPT"
cmp "$ROOT/original-unit" "$TEMPLATE_FILE"
# New live evidence after the snapshot must not be replaced by runtime-evidence.
printf 'newer unrelated live state\n' > "$STATE_DIR/other-application/state"
unrelated_before=$(stat -c '%i:%a:%Y' "$STATE_DIR/other-application/state")
grep -Fxq 'snapshot evidence' "$backup/runtime-evidence/other-application/state"
INTERRUPT_POINT=none
: > "$ROOT/log"
recover_upgrade_interactive "$backup" <<<"${backup##*/}"
[[ $(cat "$backup/stage") == rolled-back && ! -e $MIGRATION_BACKUP_DIR/upgrade-pending ]]
[[ ! -e $RELEASE_STAMP_FILE ]]
cmp "$ROOT/original-helper" "$APPLY_SCRIPT"
cmp "$ROOT/original-unit" "$TEMPLATE_FILE"
diff -r "$PROFILE_DIR" "$ROOT/original-profiles"
diff -r "$ROOT/enabled" "$ROOT/original-enabled"
[[ -f $ROOT/active/alpha && ! -f $ROOT/active/beta && ! -f $ROOT/active/gamma ]]
[[ -f $STATE_DIR/profiles/alpha/applied.conf && ! -e $STATE_DIR/profiles/beta/applied.conf && ! -e $STATE_DIR/profiles/gamma/applied.conf ]]
[[ $(awk '$1=="systemctl" && $2=="start" {print $3}' "$ROOT/log") == gre4@alpha.service ]]
[[ $(awk '$1=="systemctl" && $2=="unmask" {print $3}' "$ROOT/log" | sort) == $'gre4@alpha.service\ngre4@beta.service\ngre4@gamma.service' ]]
for id in alpha beta gamma; do
  [[ ! -e $ROOT/masked/$id && ! -e $ROOT/gre4@$id.service && ! -L $ROOT/gre4@$id.service ]]
done
[[ -L $ROOT/other.service && $(readlink "$ROOT/other.service") == /dev/null ]]
[[ -f $ROOT/masked/other && -f $ROOT/active/other && -f $ROOT/enabled/other ]]
grep -Fxq 'newer unrelated live state' "$STATE_DIR/other-application/state"
[[ $(stat -c '%i:%a:%Y' "$STATE_DIR/other-application/state") == "$unrelated_before" ]]
''')

    def test_metadata_recovery_never_changes_runtime(self):
        for interrupted in (False, True):
            with self.subTest(interrupted=interrupted):
                interrupt = r'''
eval "$(declare -f migration_restore_file | sed '1s/migration_restore_file/fixture_restore_file/')"
migration_restore_file() {
  fixture_restore_file "$@" || return
  [[ $1 != */new-release ]] || kill -KILL "$BASHPID"
}
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
''' if interrupted else 'invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"\n'
                self.run_recovery(r'''
install_apply_script() { cp "$ROOT/original-helper" "$APPLY_SCRIPT"; }
profile_preflight() { return 99; }
''' + interrupt + r'''
backup=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'upgrade.*')
: > "$ROOT/log"
recover_upgrade_interactive "$backup" <<<"${backup##*/}"
[[ ! -e $RELEASE_STAMP_FILE && ! -e $MIGRATION_BACKUP_DIR/upgrade-pending ]]
[[ -f $ROOT/active/alpha && ! -f $ROOT/active/beta && ! -f $ROOT/active/gamma ]]
if grep -Eq 'systemctl (stop|start|mask|unmask|daemon-reload)|helper stop' "$ROOT/log"; then exit 71; fi
''')

    def test_eof_or_wrong_confirmation_preserves_completed_installation(self):
        self.run_recovery(r'''
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
backup=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'upgrade.*')
: > "$ROOT/log"
if recover_upgrade_interactive "$backup" </dev/null; then exit 70; fi
if recover_upgrade_interactive "$backup" <<<'wrong'; then exit 71; fi
cmp "$APPLY_SCRIPT" "$backup/new-helper"
cmp "$RELEASE_STAMP_FILE" "$backup/new-release"
[[ $(cat "$backup/stage") == complete && ! -e $MIGRATION_BACKUP_DIR/upgrade-pending ]]
if grep -Eq 'systemctl (stop|start|mask|unmask|daemon-reload)|helper stop' "$ROOT/log"; then exit 72; fi
''')

    def test_changed_installation_or_backup_is_refused_without_mutation(self):
        mutations = {
            'profile': 'echo "# changed" >> "$PROFILE_DIR/alpha.conf"',
            'extra-profile': 'cp "$PROFILE_DIR/alpha.conf" "$PROFILE_DIR/delta.conf"',
            'service-intent': 'touch "$ROOT/active/beta"',
            'orphan-runtime': 'mkdir -p "$STATE_DIR/profiles/orphan"',
            'helper': 'echo "# changed" >> "$APPLY_SCRIPT"',
            'record': 'echo changed > "$RELEASE_STAMP_FILE"',
            'manifest': 'echo changed >> "$backup/recovery.sha256"',
            'backup-helper': 'echo "# changed" >> "$backup/gre4-apply.sh"',
            'targets': 'echo changed >> "$backup/targets"',
            'dropin': 'touch "$ROOT/dropin"',
            'inactive-dropin': 'mkdir "$ROOT/gre4@beta.service.d"',
            'extra-boot-link': 'mkdir "$ROOT/other.target.wants"; ln -s "$TEMPLATE_FILE" "$ROOT/other.target.wants/gre4@alpha.service"',
            'unowned-mask': 'systemctl mask gre4@alpha.service',
            'profile-symlink': 'mv "$PROFILE_DIR/alpha.conf" "$ROOT/alpha.conf"; ln -s "$ROOT/alpha.conf" "$PROFILE_DIR/alpha.conf"',
        }
        for name, mutation in mutations.items():
            with self.subTest(case=name):
                self.run_recovery(r'''
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
backup=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'upgrade.*')
''' + mutation + r'''
: > "$ROOT/log"
if recover_upgrade_interactive "$backup" <<<"${backup##*/}"; then exit 70; fi
[[ $(cat "$backup/stage") == complete && ! -e $MIGRATION_BACKUP_DIR/upgrade-pending ]]
if grep -Eq 'systemctl (stop|start|mask|unmask|daemon-reload)|helper stop' "$ROOT/log"; then exit 71; fi
''')

    def test_legacy_backup_and_outside_paths_are_manual_only(self):
        self.run_recovery(r'''
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
backup=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'upgrade.*')
rm "$backup/recovery-format"
: > "$ROOT/log"
if recover_upgrade_interactive "$backup" <<<"${backup##*/}"; then exit 70; fi
if recover_upgrade_interactive "$MIGRATION_BACKUP_DIR/../outside" <<<'outside'; then exit 71; fi
ln -s "$backup" "$MIGRATION_BACKUP_DIR/upgrade.alias"
if recover_upgrade_interactive upgrade.alias <<<'upgrade.alias'; then exit 72; fi
[[ ! -e $MIGRATION_BACKUP_DIR/upgrade-pending ]]
if grep -Eq 'systemctl (stop|start|mask|unmask|daemon-reload)|helper stop' "$ROOT/log"; then exit 73; fi
''')

    def test_failed_cleanup_retains_pending_backup_and_masks(self):
        self.run_recovery(r'''
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
backup=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'upgrade.*')
touch "$ROOT/fail-new-cleanup"
if recover_upgrade_interactive "$backup" <<<"${backup##*/}"; then exit 70; fi
[[ $(cat "$MIGRATION_BACKUP_DIR/upgrade-pending") == "$backup" ]]
[[ $(cat "$backup/stage") == rollback-cleanup && -f $backup/recovery.sha256 ]]
cmp "$APPLY_SCRIPT" "$backup/new-helper"
[[ -f $ROOT/masked/alpha && -f $ROOT/masked/beta && -f $ROOT/masked/gamma ]]
# A retry may proceed only after the matching helper can finish cleanup.
rm "$ROOT/fail-new-cleanup"
recover_upgrade_interactive "$backup" <<<"${backup##*/}"
[[ ! -e $MIGRATION_BACKUP_DIR/upgrade-pending && -f $ROOT/active/alpha ]]
''')

    def test_foreign_pending_record_is_preserved(self):
        self.run_recovery(r'''
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
backup=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'upgrade.*')
printf '%s\n' "$MIGRATION_BACKUP_DIR/upgrade.foreign" > "$MIGRATION_BACKUP_DIR/upgrade-pending"
chmod 600 "$MIGRATION_BACKUP_DIR/upgrade-pending"
: > "$ROOT/log"
if recover_upgrade_interactive "$backup" <<<"${backup##*/}"; then exit 70; fi
[[ $(cat "$MIGRATION_BACKUP_DIR/upgrade-pending") == "$MIGRATION_BACKUP_DIR/upgrade.foreign" ]]
[[ ! -s $ROOT/log ]]
''')

    def test_pending_journal_must_match_its_artifacts_and_owned_masks(self):
        for mutation in (
                'fixture_set_stage "$backup" new-installed',
                'fixture_set_stage "$backup" metadata-only',
                'rm "$ROOT/gre4@alpha.service"; ln -s "$ROOT/foreign" "$ROOT/gre4@alpha.service"',
                'mv "$MIGRATION_BACKUP_DIR/upgrade-pending" "$ROOT/pending"; ln -s "$ROOT/pending" "$MIGRATION_BACKUP_DIR/upgrade-pending"'):
            with self.subTest(mutation=mutation):
                self.run_recovery(r'''
eval "$(declare -f migration_set_stage | sed '1s/migration_set_stage/fixture_set_stage/')"
migration_set_stage() {
  fixture_set_stage "$@" || return
  [[ $2 != old-clean ]] || kill -KILL "$BASHPID"
}
if invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"; then exit 70; fi
backup=$(cat "$MIGRATION_BACKUP_DIR/upgrade-pending")
''' + mutation + r'''
: > "$ROOT/log"
if recover_upgrade_interactive "$backup" <<<"${backup##*/}"; then exit 71; fi
[[ -e $MIGRATION_BACKUP_DIR/upgrade-pending || -L $MIGRATION_BACKUP_DIR/upgrade-pending ]]
if grep -Eq 'systemctl (stop|start|mask|unmask|daemon-reload)|helper stop' "$ROOT/log"; then exit 72; fi
''')

    def test_completed_rollback_marker_clears_without_another_restart(self):
        self.run_recovery(r'''
invoke_upgrade "$GRE4_RELEASE_TAG" "$GRE4_RELEASE_SHA"
backup=$(find "$MIGRATION_BACKUP_DIR" -maxdepth 1 -type d -name 'upgrade.*')
recover_upgrade_interactive "$backup" <<<"${backup##*/}"
# Interruption after writing rolled-back but before clearing its marker.
upgrade_publish_pending "$backup"
: > "$ROOT/log"
recover_upgrade_interactive "$backup" <<<"${backup##*/}"
[[ ! -e $MIGRATION_BACKUP_DIR/upgrade-pending && -f $ROOT/active/alpha ]]
if grep -Eq 'systemctl (stop|start|mask|unmask|daemon-reload)|helper stop' "$ROOT/log"; then exit 71; fi
''')
