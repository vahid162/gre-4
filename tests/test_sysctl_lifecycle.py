"""Sysctl lifecycle checks use a filesystem-backed substitute, never host sysctls."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from profile_fixture import ProfileRuntimeCase


from shell_source import FUNCTIONS
SYSCTL_STUB = r'''#!/usr/bin/env bash
set -euo pipefail
write_value() {
  local key=${1%%=*} value=${1#*=} previous
  [[ ! -e "$RUNTIME_DIR/fail.$key" ]] || return 1
  previous=$(cat "$RUNTIME_DIR/$key")
  printf '%s\n' "$key=$value" >> "$RUNTIME_DIR/writes"
  printf '%s\n' "$value" > "$RUNTIME_DIR/$key"
  # Linux ip_forward changes reset IPv4 configuration, including all.forwarding.
  if [[ $key == net.ipv4.ip_forward && $value != "$previous" ]]; then
    printf '%s\n' "$value" > "$RUNTIME_DIR/net.ipv4.conf.all.forwarding"
  fi
}
case $1 in
  -n) cat "$RUNTIME_DIR/$2" ;;
  -w) write_value "$2" ;;
  -p)
    while IFS= read -r entry; do
      [[ -z $entry || $entry == \#* ]] || write_value "$entry"
    done < "$2"
    ;;
  *) exit 99 ;;
esac
'''


class SysctlLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="gre4-sysctl-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        self.sysctls = self.root / "sysctl.d"
        self.sysctls.mkdir()
        self.state = self.root / "state"
        self.ufw = self.root / "ufw"
        self.ufw.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        executable = self.bin / "sysctl"
        executable.write_text(SYSCTL_STUB)
        executable.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        RUNTIME_DIR=str(self.runtime))
        self.values = {
            "net.ipv4.ip_forward": "0",
            "net.ipv4.conf.all.forwarding": "0",
            "net.netfilter.nf_conntrack_max": "32768",
        }
        for key, value in self.values.items():
            self.set_value(key, value)
        self.generated = self.root / "apply.sh"
        self.profiles = self.root / "profiles"
        self.profiles.mkdir(mode=0o700)
        self.config = self.root / "config with spaces"
        self.config.write_text("ROLE=iran\nSERVICE_PORTS=443\nALLOW_UDP=no\nTUN_IF=GRE\n"
                               "LOCAL_PUBLIC_IP=192.0.2.1\nPEER_PUBLIC_IP=198.51.100.1\n"
                               "IRAN_TUN_CIDR=172.16.1.1/30\nKHAREJ_TUN_CIDR=172.16.1.2/30\n")
        result = subprocess.run(
            ["bash", "-s", "--", str(self.generated), str(self.state), str(self.sysctls), str(self.config), str(self.ufw), str(self.profiles), str(self.root / "locks")],
            input=FUNCTIONS + '\nAPPLY_SCRIPT=$1\nSTATE_DIR=$2\nSYSCTL_DIR=$3\nCONF_FILE=$4\nUFW_DIR=$5\nUFW_BEFORE_FILE=$5/before.rules\nPROFILE_DIR=$6\nLOCK_DIR=$7\nMIGRATION_BACKUP_DIR=$2/migration-backups\ninstall_apply_script\n',
            text=True, capture_output=True, env=self.env, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        apply = self.generated.read_text()
        self.helpers = apply[apply.index("log()"):apply.index('case "${1:-start}" in')]

    def set_value(self, key, value):
        (self.runtime / key).write_text(str(value) + "\n")

    def value(self, key):
        return (self.runtime / key).read_text().strip()

    def run_shell(self, body, expected=0):
        result = subprocess.run(
            ["bash", "-s"], text=True, capture_output=True, env=self.env, timeout=5,
            input=("set -euo pipefail\n" + self.helpers
                   + f"\nSTATE_DIR={shlex.quote(str(self.state))}\n"
                   + f"SYSCTL_DIR={shlex.quote(str(self.sysctls))}\n"
                   + f"UFW_DIR={shlex.quote(str(self.ufw))}\n"
                   + f"UFW_BEFORE_FILE={shlex.quote(str(self.ufw / 'before.rules'))}\n"
                   + "ROLE=kharej SERVICE_PORTS=443 ALLOW_UDP=no TUN_IF=GRE\n"
                   + body),
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def assert_originals(self):
        for key, expected in self.values.items():
            self.assertEqual(self.value(key), expected, key)

    def test_repeated_apply_preserves_originals_across_processes(self):
        self.run_shell("tune_forwarding\ntune_conntrack_if_kharej\n")
        self.run_shell("tune_forwarding\ntune_conntrack_if_kharej\n")
        self.assertEqual(self.value("net.ipv4.ip_forward"), "1")
        self.assertEqual(self.value("net.ipv4.conf.all.forwarding"), "1")
        self.run_shell("restore_sysctl\nrestore_sysctl\n")
        self.assert_originals()
        self.assertFalse(list(self.sysctls.iterdir()))
        self.assertFalse(self.state.exists())

    def test_forwarding_values_are_captured_before_either_write(self):
        self.set_value("net.ipv4.conf.all.forwarding", "1")
        self.run_shell("tune_forwarding\nrestore_sysctl\n")
        self.assertEqual(self.value("net.ipv4.ip_forward"), "0")
        self.assertEqual(self.value("net.ipv4.conf.all.forwarding"), "1")
        writes = (self.runtime / "writes").read_text().splitlines()
        self.assertEqual(writes[-2:], ["net.ipv4.ip_forward=0", "net.ipv4.conf.all.forwarding=1"])

    def test_administrator_runtime_changes_survive_forwarding_reset(self):
        self.run_shell("tune_forwarding\ntune_conntrack_if_kharej\n")
        self.set_value("net.ipv4.conf.all.forwarding", "2")
        self.set_value("net.netfilter.nf_conntrack_max", "99999")
        self.run_shell("restore_sysctl\n")
        self.assertEqual(self.value("net.ipv4.ip_forward"), "0")
        self.assertEqual(self.value("net.ipv4.conf.all.forwarding"), "2")
        self.assertEqual(self.value("net.netfilter.nf_conntrack_max"), "99999")

    def test_unowned_existing_file_is_never_changed(self):
        path = self.sysctls / "99-gre4-forward.conf"
        path.write_text("# administrator's file\nnet.ipv4.ip_forward=0\n")
        before = path.read_bytes()
        output = self.run_shell("tune_forwarding\n", expected=1)
        self.assertIn("unowned", output.lower())
        self.assertEqual(path.read_bytes(), before)
        self.assert_originals()
        output = self.run_shell("restore_sysctl\n", expected=1)
        self.assertIn("manually", output)
        self.assertEqual(path.read_bytes(), before)

    def test_unowned_symlink_is_never_followed(self):
        target = self.root / "administrator.conf"
        target.write_text("untouched\n")
        (self.sysctls / "99-gre4-forward.conf").symlink_to(target)
        self.run_shell("tune_forwarding\n", expected=1)
        self.assertEqual(target.read_text(), "untouched\n")
        self.assert_originals()

    def test_failed_start_retains_originals_for_cleanup(self):
        (self.runtime / "fail.net.ipv4.conf.all.forwarding").touch()
        self.run_shell("tune_forwarding\n", expected=1)
        self.assertTrue(self.state.exists())
        (self.runtime / "fail.net.ipv4.conf.all.forwarding").unlink()
        self.run_shell("restore_sysctl\n")
        self.assert_originals()
        self.assertFalse(self.state.exists())

    def test_failed_restore_retries_after_forwarding_reset(self):
        self.set_value("net.ipv4.conf.all.forwarding", "1")
        self.run_shell("tune_forwarding\n")
        (self.runtime / "fail.net.ipv4.conf.all.forwarding").touch()
        self.run_shell("restore_sysctl\n", expected=1)
        self.assertEqual(self.value("net.ipv4.ip_forward"), "0")
        self.assertTrue(self.state.exists())
        (self.runtime / "fail.net.ipv4.conf.all.forwarding").unlink()
        self.run_shell("restore_sysctl\n")
        self.assertEqual(self.value("net.ipv4.conf.all.forwarding"), "1")
        self.assertFalse(self.state.exists())

    def test_retry_restores_reboot_values_after_owned_file_removal_fails(self):
        self.run_shell("tune_forwarding\n")
        self.run_shell(r'''
failed_file_remove=no
rm() {
  if [[ $# == 2 && $1 == -f && $2 == "$SYSCTL_DIR/99-gre4-forward.conf" && $failed_file_remove == no ]]; then
    failed_file_remove=yes
    return 1
  fi
  command rm "$@"
}
restore_sysctl
''', expected=1)
        # Failed persistent-file removal must stop before runtime restoration.
        self.assertEqual(self.value("net.ipv4.ip_forward"), "1")
        self.assertEqual(self.value("net.ipv4.conf.all.forwarding"), "1")
        path = self.sysctls / "99-gre4-forward.conf"
        self.assertTrue(path.exists())
        self.assertTrue(self.state.exists())
        # A reboot can reapply the owned file that cleanup failed to remove.
        self.run_shell('sysctl -p "$SYSCTL_DIR/99-gre4-forward.conf"\n')
        self.assertEqual(self.value("net.ipv4.ip_forward"), "1")
        self.assertEqual(self.value("net.ipv4.conf.all.forwarding"), "1")
        self.run_shell("restore_sysctl\n")
        self.assert_originals()
        self.assertFalse(path.exists())
        self.assertFalse(self.state.exists())

    def test_failed_file_removal_does_not_partially_restore_runtime(self):
        self.run_shell("tune_forwarding\n")
        self.run_shell(r'''
rm() {
  if [[ ${*: -1} == "$SYSCTL_DIR/99-gre4-forward.conf" ]]; then return 1; fi
  command rm "$@"
}
restore_sysctl
''', expected=1)
        self.assertEqual(self.value("net.ipv4.ip_forward"), "1")
        self.assertEqual(self.value("net.ipv4.conf.all.forwarding"), "1")
        self.set_value("net.ipv4.conf.all.forwarding", "0")
        self.run_shell("restore_sysctl\n")
        self.assertEqual(self.value("net.ipv4.ip_forward"), "0")
        self.assertEqual(self.value("net.ipv4.conf.all.forwarding"), "0")
        self.assertFalse(self.state.exists())

    def check_administrator_change_after_failed_ip_restore(self, administrator_value):
        self.set_value("net.ipv4.conf.all.forwarding", "1")
        self.run_shell("tune_forwarding\n")
        failure = self.runtime / "fail.net.ipv4.ip_forward"
        failure.touch()
        self.run_shell("restore_sysctl\n", expected=1)
        self.assertEqual(self.value("net.ipv4.ip_forward"), "1")
        self.assertEqual(self.value("net.ipv4.conf.all.forwarding"), "1")
        self.assertTrue(self.state.exists())
        self.set_value("net.ipv4.conf.all.forwarding", administrator_value)
        failure.unlink()
        self.run_shell("restore_sysctl\n")
        self.assertEqual(self.value("net.ipv4.ip_forward"), "0")
        self.assertEqual(self.value("net.ipv4.conf.all.forwarding"), administrator_value)
        self.assertFalse(self.state.exists())

    def test_retry_preserves_administrator_zero_after_failed_ip_restore(self):
        self.check_administrator_change_after_failed_ip_restore("0")

    def test_retry_preserves_administrator_change_after_failed_ip_restore(self):
        self.check_administrator_change_after_failed_ip_restore("2")

    def test_administrator_file_edit_is_preserved_on_repeated_stop(self):
        self.run_shell("tune_forwarding\n")
        path = self.sysctls / "99-gre4-forward.conf"
        path.write_text("# changed after start\nnet.ipv4.ip_forward=1\n")
        before = path.read_bytes()
        self.run_shell("restore_sysctl\n")
        self.assertEqual(path.read_bytes(), before)
        self.assert_originals()
        self.set_value("net.ipv4.ip_forward", "1")
        self.set_value("net.ipv4.conf.all.forwarding", "1")
        self.run_shell("restore_sysctl\n")
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.value("net.ipv4.ip_forward"), "1")
        self.assertEqual(self.value("net.ipv4.conf.all.forwarding"), "1")
        self.run_shell("tune_forwarding\n", expected=1)

    def test_malformed_numeric_recovery_data_is_not_executed(self):
        self.run_shell("tune_forwarding\n")
        marker = self.root / "must-not-exist"
        values = self.state / "sysctl" / "forward" / "values"
        values.write_text(f"net.ipv4.ip_forward $(touch {marker}) 1\n")
        self.run_shell("restore_sysctl\n", expected=1)
        self.assertFalse(marker.exists())
        self.assertTrue(self.state.exists())
        self.assertEqual(self.value("net.ipv4.ip_forward"), "1")

    def test_generated_helper_cleans_partial_start_on_stop(self):
        profile = self.profiles / 'legacy.conf'
        profile.write_text(self.config.read_text())
        profile.chmod(0o600)
        for name, script in {
            "ip": "#!/bin/bash\nif [[ $* == '-o -4 addr show' ]]; then echo '2: eth0 inet 192.0.2.1/32 scope global eth0'; exit 0; fi\nif [[ $* == '-4 route show table all' || $* == '-o link show' ]]; then exit 0; fi\nexit 1\n",
            "iptables": "#!/bin/bash\nexit 1\n",
            "ufw": "#!/bin/bash\necho 'Status: inactive'\n",
        }.items():
            executable = self.bin / name
            executable.write_text(script)
            executable.chmod(0o755)
        (self.runtime / "fail.net.ipv4.conf.all.forwarding").touch()
        result = subprocess.run(["bash", str(self.generated), "start", "legacy"],
                                capture_output=True, text=True, env=self.env, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.value("net.ipv4.ip_forward"), "1")
        self.assertTrue(self.state.exists())
        (self.runtime / "fail.net.ipv4.conf.all.forwarding").unlink()
        result = subprocess.run(["bash", str(self.generated), "stop", "legacy"],
                                capture_output=True, text=True, env=self.env, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.config.unlink()
        self.assert_originals()
        self.assertFalse(list(self.state.glob('profiles/*/applied.conf')))
        self.assertFalse(list((self.state / 'sysctl').glob('*')))
        self.assertFalse(list(self.sysctls.iterdir()))


class ProfileSysctlCleanupTests(ProfileRuntimeCase):
    def test_failed_profile_cleanup_keeps_shared_settings_until_retry(self):
        self.config('iran1')
        self.invoke('start', 'iran1')
        self.update(failures=['ip tunnel del g4-iran1'])
        self.invoke('stop', 'iran1', success=False)
        self.assertEqual(self.data()['sysctl']['net.ipv4.ip_forward'], '1')
        self.assertTrue((self.state_dir / 'profiles/iran1/applied.conf').exists())
        self.update(failures=[])
        self.invoke('stop', 'iran1')
        self.assertEqual(self.data()['sysctl']['net.ipv4.ip_forward'], '0')
        self.assertFalse((self.state_dir / 'profiles/iran1/applied.conf').exists())


if __name__ == "__main__":
    unittest.main()
