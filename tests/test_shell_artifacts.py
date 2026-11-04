"""Check the actual generated shell helper as well as the downloadable entry script."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

from shell_source import FUNCTIONS


class ShellArtifactTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="gre4-shell-artifacts-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.generated = self.root / "generated apply.sh"
        result = subprocess.run(
            ["bash", "-s", "--", str(self.root), str(self.generated)],
            input=FUNCTIONS + r'''
PROFILE_DIR=$1/profiles
STATE_DIR=$1/state
LOCK_DIR=$1/locks
MIGRATION_BACKUP_DIR=$1/backups
CONF_FILE=$1/legacy.conf
TEMPLATE_FILE=$1/gre4@.service
APPLY_SCRIPT=$2
install_apply_script
''', capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_entry_and_generated_helper_bash_syntax(self):
        for script in (Path(__file__).resolve().parents[1] / "gre4.sh", self.generated):
            with self.subTest(script=script.name):
                result = subprocess.run(["bash", "-n", str(script)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_generated_helper_shellcheck_warnings(self):
        if not shutil.which("shellcheck"):
            if os.environ.get("GRE4_REQUIRE_SHELLCHECK") == "1":
                self.fail("ShellCheck must be installed when GRE4_REQUIRE_SHELLCHECK=1")
            self.skipTest("ShellCheck is optional locally and required in CI")
        result = subprocess.run(
            ["shellcheck", "--severity=warning", str(self.generated)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
