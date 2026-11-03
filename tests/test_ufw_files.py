"""Exercise generated UFW file edits without touching the host firewall."""
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from test_gre4 import FUNCTIONS


NAT_RULES = """# administrator rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.0.0.0/8 -j MASQUERADE
COMMIT

"""
FILTER_RULES = """*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
-A ufw-before-input -p 47 -s 203.0.113.5 -j ACCEPT
-A ufw-before-input -p tcp --dport 22 -j ACCEPT
COMMIT

"""
MANGLE_RULES = """*mangle
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp -j MARK --set-mark 1
COMMIT
# administrator footer
"""
BEFORE_RULES = NAT_RULES + FILTER_RULES + MANGLE_RULES
GRE_BLOCK = """# gre4.sh BEGIN
-A ufw-before-input -p 47 -s 198.51.100.20 -d 192.0.2.10 -j ACCEPT
-A ufw-before-output -p 47 -s 192.0.2.10 -d 198.51.100.20 -j ACCEPT
# gre4.sh END
"""
WITH_GRE = (NAT_RULES
            + FILTER_RULES.replace("COMMIT\n", GRE_BLOCK + "COMMIT\n")
            + MANGLE_RULES)


class UfwFileTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="gre4-ufw-files-")
        self.addCleanup(scratch.cleanup)
        self.directory = Path(scratch.name)
        self.before = self.directory / "before rules"
        self.before.write_text(BEFORE_RULES)
        self.restore_log = self.directory / "restore.log"
        self.restore_candidate = self.directory / "restore.rules"
        generated = self.directory / "apply.sh"
        result = subprocess.run(
            ["bash", "-s", "--", str(generated)],
            input=FUNCTIONS + '\nAPPLY_SCRIPT=$1\ninstall_apply_script\n',
            text=True, capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        apply = generated.read_text()
        self.functions = apply[apply.index("log()"):apply.index('case "${1:-start}" in')]

    def run_action(self, action, restore_exit=0):
        self.restore_log.unlink(missing_ok=True)
        self.restore_candidate.unlink(missing_ok=True)
        return subprocess.run(
            ["bash", "-s", "--", str(self.before), str(self.restore_log),
             str(self.restore_candidate), str(restore_exit), action],
            input="set -euo pipefail\n" + self.functions + r'''
UFW_BEFORE_FILE=$1
RESTORE_LOG=$2
RESTORE_CANDIDATE=$3
RESTORE_EXIT=$4
LOCAL_PUBLIC_IP=192.0.2.10
PEER_PUBLIC_IP=198.51.100.20
iptables-restore() {
  printf '%s\n' "$*" >> "$RESTORE_LOG"
  cat > "$RESTORE_CANDIDATE"
  [[ $# == 1 && $1 == --test ]] || return 99
  return "$RESTORE_EXIT"
}
# Conditional callers must get the same error handling as direct callers.
if "$5"; then exit 0; else exit $?; fi
''',
            text=True, capture_output=True, timeout=5,
        )

    def assert_tested(self, candidate):
        self.assertEqual(self.restore_log.read_text(), "--test\n")
        self.assertEqual(self.restore_candidate.read_text(), candidate)

    def test_inserts_only_inside_filter_and_preserves_other_rules(self):
        result = self.run_action("ufw_allow_gre_proto47")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.before.read_text(), WITH_GRE)
        self.assert_tested(WITH_GRE)

    def test_replaces_existing_managed_block_without_duplication(self):
        old_block = GRE_BLOCK.replace("198.51.100.20", "198.51.100.99")
        for table in ("nat", "filter"):
            with self.subTest(previous_table=table):
                if table == "nat":
                    original = (NAT_RULES.replace("COMMIT\n", old_block + "COMMIT\n")
                                + FILTER_RULES + MANGLE_RULES)
                else:
                    original = (NAT_RULES
                                + FILTER_RULES.replace("COMMIT\n", old_block + "COMMIT\n")
                                + MANGLE_RULES)
                self.before.write_text(original)
                result = self.run_action("ufw_allow_gre_proto47")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.before.read_text(), WITH_GRE)
                self.assert_tested(WITH_GRE)

    def test_removes_only_the_managed_block(self):
        self.before.write_text(WITH_GRE)
        result = self.run_action("ufw_remove_gre_proto47_block")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.before.read_text(), BEFORE_RULES)
        self.assert_tested(BEFORE_RULES)

    def test_rejected_insert_preserves_original(self):
        original = self.before.read_bytes()
        result = self.run_action("ufw_allow_gre_proto47", restore_exit=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.before.read_bytes(), original)
        self.assert_tested(WITH_GRE)

    def test_rejected_removal_preserves_original(self):
        self.before.write_text(WITH_GRE)
        original = self.before.read_bytes()
        result = self.run_action("ufw_remove_gre_proto47_block", restore_exit=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.before.read_bytes(), original)
        self.assert_tested(BEFORE_RULES)

    def test_missing_filter_fails_without_overwriting(self):
        self.before.write_text(NAT_RULES + MANGLE_RULES)
        original = self.before.read_bytes()
        result = self.run_action("ufw_allow_gre_proto47")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr)
        self.assertEqual(self.before.read_bytes(), original)
        self.assertFalse(self.restore_log.exists())

    def test_malformed_managed_block_fails_without_overwriting(self):
        markers = ("# gre4.sh BEGIN\n", "# gre4.sh END\n",
                   "# gre4.sh BEGIN\n# gre4.sh BEGIN\n# gre4.sh END\n")
        for action in ("ufw_allow_gre_proto47", "ufw_remove_gre_proto47_block"):
            for malformed in markers:
                with self.subTest(action=action, markers=malformed):
                    self.before.write_text(BEFORE_RULES + malformed)
                    original = self.before.read_bytes()
                    result = self.run_action(action)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(result.stderr)
                    self.assertEqual(self.before.read_bytes(), original)
                    self.assertFalse(self.restore_log.exists())

    def test_successful_edits_preserve_original_mode(self):
        for action, original in (("ufw_allow_gre_proto47", BEFORE_RULES),
                                 ("ufw_remove_gre_proto47_block", WITH_GRE)):
            with self.subTest(action=action):
                self.before.write_text(original)
                self.before.chmod(0o640)
                result = self.run_action(action)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(stat.S_IMODE(self.before.stat().st_mode), 0o640)


if __name__ == "__main__":
    unittest.main()
