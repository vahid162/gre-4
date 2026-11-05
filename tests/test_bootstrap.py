"""Release bootstrap exercises real Bash/checksums against a private curl substitute."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from shell_source import FUNCTIONS


class BootstrapTests(unittest.TestCase):
    def run_bootstrap(self, mode='ok', args=(), exit_status=0, integrated=False):
        self.assertTrue('release_bootstrap()' in FUNCTIONS, 'release bootstrap is not implemented')
        with tempfile.TemporaryDirectory(prefix='gre4-bootstrap-test-') as directory:
            root = Path(directory)
            (root / 'bin').mkdir()
            (root / 'temporary').mkdir()
            host_boundaries = r'''
need_root() { :; }
ensure_cmd() {
  case "$1" in ip|sysctl|flock) return 0 ;; esac
  command -v "$1" >/dev/null 2>&1
}
automatic_upgrade() {
  printf '%s\0' --gre4-release "$@" > "$BOOTSTRAP_TEST_ROOT/executed"
  printf 'upgrade\n' >> "$BOOTSTRAP_TEST_ROOT/events"
}
main_menu() { printf 'menu\n' >> "$BOOTSTRAP_TEST_ROOT/events"; }
list_profiles() {
  printf 'list\n' >> "$BOOTSTRAP_TEST_ROOT/events"
  IFS= read -r line || return
  printf '%s\n' "$line" > "$BOOTSTRAP_TEST_ROOT/input"
  return "$BOOTSTRAP_TEST_EXIT"
}
'''
            payload_dispatch = r'''
payload_main() {
  if [[ ${1:-} != --gre4-release ]]; then release_bootstrap "$@"; return; fi
  release_verified_handoff "$2" "$3" "${BASH_SOURCE[0]}" || return
printf '%s\0' "$@" > "$BOOTSTRAP_TEST_ROOT/executed"
IFS= read -r line
printf '%s\n' "$line" > "$BOOTSTRAP_TEST_ROOT/input"
exit "$BOOTSTRAP_TEST_EXIT"
}
payload_main "$@"
'''
            payload = (FUNCTIONS + (host_boundaries + '\nmain "$@"\n'
                                    if integrated else payload_dispatch)).encode()
            (root / 'payload').write_bytes(payload)
            checksum = hashlib.sha256(payload).hexdigest() + '  gre4.sh\n'
            manifests = {
                'mismatch': '0' * 64 + '  gre4.sh\n',
                'second-line': checksum + '0' * 64 + '  /etc/passwd\n',
                'wrong-name': checksum.replace('  gre4.sh', '  ../gre4.sh'),
                'missing-newline': checksum.rstrip('\n'),
                'nul-byte': checksum.rstrip('\n') + '\0\n',
            }
            (root / 'manifest').write_bytes(manifests.get(mode, checksum).encode())
            curl = root / 'bin/curl'
            curl.write_text(r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

root = Path(os.environ['BOOTSTRAP_TEST_ROOT'])
mode = os.environ['BOOTSTRAP_TEST_MODE']
args = sys.argv[1:]
with (root / 'requests').open('a') as log:
    log.write(json.dumps(args) + '\n')
assert args[args.index('--proto') + 1] == '=https'
assert args[args.index('--proto-redir') + 1] == '=https'
assert '--location' in args and '--fail' in args
assert '--connect-timeout' in args and '--max-time' in args
destination = Path(args[args.index('--output') + 1])
url = args[-1]
if url == 'https://github.com/vahid162/gre-4/releases/latest':
    if mode == 'resolution-fails':
        sys.exit(22)
    redirects = {
        'wrong-host': 'https://example.com/vahid162/gre-4/releases/tag/v2.3.4',
        'prerelease': 'https://github.com/vahid162/gre-4/releases/tag/v2.3.4-rc1',
        'leading-zero': 'https://github.com/vahid162/gre-4/releases/tag/v02.3.4',
        'http': 'http://github.com/vahid162/gre-4/releases/tag/v2.3.4',
    }
    print(redirects.get(mode, 'https://github.com/vahid162/gre-4/releases/tag/v2.3.4'), end='')
elif url == 'https://github.com/vahid162/gre-4/releases/download/v2.3.4/gre4.sh':
    destination.write_bytes((root / 'payload').read_bytes())
    if mode == 'payload-fails':
        sys.exit(18)
elif url == 'https://github.com/vahid162/gre-4/releases/download/v2.3.4/SHA256SUMS':
    destination.write_bytes((root / 'manifest').read_bytes())
    if mode == 'manifest-fails':
        sys.exit(22)
else:
    raise AssertionError('Unpinned or unexpected URL: ' + url)
''')
            curl.chmod(0o700)
            launcher = root / 'launcher.sh'
            launcher.write_text(FUNCTIONS + (host_boundaries + '\nmain "$@"\n'
                                            if integrated else '\nrelease_bootstrap "$@"\n'))
            environment = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'],
                               TMPDIR=str(root / 'temporary'), BOOTSTRAP_TEST_ROOT=str(root),
                               BOOTSTRAP_TEST_MODE=mode, BOOTSTRAP_TEST_EXIT=str(exit_status))
            result = subprocess.run(['bash', str(launcher), *args],
                                    input=('4\n' if integrated else '') + 'kept input\n',
                                    text=True, capture_output=True, env=environment, timeout=15)
            request_file = root / 'requests'
            requests = [json.loads(line) for line in request_file.read_text().splitlines()] if request_file.exists() else []
            executed = (root / 'executed').read_bytes().split(b'\0')[:-1] if (root / 'executed').exists() else None
            received_input = (root / 'input').read_text() if (root / 'input').exists() else None
            if integrated:
                event_file = root / 'events'
                events = event_file.read_text().splitlines() if event_file.exists() else []
                self.assertEqual(events, ['upgrade', 'menu', 'list'] if executed else [])
            self.assertEqual(list((root / 'temporary').iterdir()), [], 'temporary release directory was retained')
            return result, requests, executed, received_input, hashlib.sha256(payload).hexdigest()

    def test_public_main_bootstraps_verified_main_before_menu_and_preserves_input(self):
        result, requests, executed, received_input, digest = self.run_bootstrap(integrated=True, exit_status=37)
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertEqual([request[-1] for request in requests], [
            'https://github.com/vahid162/gre-4/releases/latest',
            'https://github.com/vahid162/gre-4/releases/download/v2.3.4/gre4.sh',
            'https://github.com/vahid162/gre-4/releases/download/v2.3.4/SHA256SUMS',
        ])
        self.assertEqual(executed, [b'--gre4-release', b'v2.3.4', digest.encode()])
        self.assertEqual(received_input, 'kept input\n')

    def test_public_main_download_or_checksum_failure_never_reaches_upgrade_or_menu(self):
        for mode in ('resolution-fails', 'payload-fails', 'manifest-fails', 'mismatch'):
            with self.subTest(mode=mode):
                result, _, executed, received_input, _ = self.run_bootstrap(mode, integrated=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(executed)
                self.assertIsNone(received_input)

    def test_verified_main_rejects_bad_handoff_before_upgrade_without_downloading(self):
        result, requests, executed, received_input, _ = self.run_bootstrap(
            args=('--gre4-release', 'v2.3.4', '0' * 64), integrated=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(requests, [])
        self.assertIsNone(executed)
        self.assertIsNone(received_input)

    def test_latest_is_resolved_once_and_both_assets_are_pinned_before_execution(self):
        result, requests, executed, received_input, digest = self.run_bootstrap(args=('two words', '$literal'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([request[-1] for request in requests], [
            'https://github.com/vahid162/gre-4/releases/latest',
            'https://github.com/vahid162/gre-4/releases/download/v2.3.4/gre4.sh',
            'https://github.com/vahid162/gre-4/releases/download/v2.3.4/SHA256SUMS',
        ])
        self.assertEqual(executed, [b'--gre4-release', b'v2.3.4', digest.encode(), b'two words', b'$literal'])
        self.assertEqual(received_input, 'kept input\n')

    def test_payload_exit_status_is_preserved_and_temporary_files_are_removed(self):
        result, _, executed, _, _ = self.run_bootstrap(exit_status=37)
        self.assertEqual(result.returncode, 37)
        self.assertIsNotNone(executed)

    def test_failed_resolution_or_asset_download_never_executes_a_partial_payload(self):
        for mode in ('resolution-fails', 'payload-fails', 'manifest-fails'):
            with self.subTest(mode=mode):
                result, _, executed, _, _ = self.run_bootstrap(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(executed)

    def test_unexpected_redirect_or_non_stable_tag_is_rejected_before_asset_download(self):
        for mode in ('wrong-host', 'prerelease', 'leading-zero', 'http'):
            with self.subTest(mode=mode):
                result, requests, executed, _, _ = self.run_bootstrap(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(requests), 1)
                self.assertIsNone(executed)

    def test_checksum_mismatch_or_noncanonical_manifest_never_executes(self):
        for mode in ('mismatch', 'second-line', 'wrong-name', 'missing-newline', 'nul-byte'):
            with self.subTest(mode=mode):
                result, _, executed, _, _ = self.run_bootstrap(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(executed)

    def test_handoff_checks_the_payload_and_sets_release_identity_without_network(self):
        self.assertTrue('release_verified_handoff()' in FUNCTIONS, 'verified handoff is not implemented')
        with tempfile.TemporaryDirectory(prefix='gre4-handoff-test-') as directory:
            payload = Path(directory) / 'payload.sh'
            payload.write_text('#!/bin/bash\nexit 0\n')
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            shell = FUNCTIONS + r'''
release_verified_handoff "$1" "$2" "$3"
[[ $GRE4_RELEASE_TAG == "$1" && $GRE4_RELEASE_SHA == "$2" ]]
'''
            for tag, candidate, expected in (
                    ('v2.3.4', digest, 0), ('v2.3.4', '0' * 64, 1),
                    ('v2.3.4-rc1', digest, 1), ('v02.3.4', digest, 1),
                    ('v2.3.4', 'not-a-hash', 1)):
                with self.subTest(tag=tag, candidate=candidate):
                    result = subprocess.run(['bash', '-s', '--', tag, candidate, str(payload)],
                                            input=shell, text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
