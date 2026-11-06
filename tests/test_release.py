"""Release publishing tests use in-memory GitHub responses, never credentials."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('release', Path(__file__).resolve().parents[1] / 'tools/release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
SHA = 'a' * 40
REPOSITORY = 'example/gre-4'
TAG = 'v1.1.1'


class FakeGitHub:
    def __init__(self):
        self.files = {'VERSION': b'1.1.1\n', 'gre4.sh': b'#!/bin/bash\necho fixture\n',
                      'CHANGELOG.md': '## Unreleased\n\n## 1.1.1 - 2026-11-05\n\nEnglish notes.\n\n### فارسی\n\nتوضیح فارسی\n\n## 1.1.0 - 2026-11-04\n\nOld notes.\n'.encode()}
        self.assets = {'gre4.sh': self.files['gre4.sh'],
                       'SHA256SUMS': (hashlib.sha256(self.files['gre4.sh']).hexdigest() + '  gre4.sh\n').encode()}
        self.refs, self.release, self.blobs, self.calls = [], None, {}, []
        self.visibility_delays = {'create': 0, 'upload': 0, 'publish': 0}
        self.stale_release, self.stale_reads = None, 0
        self.read_failures = []
        self.asset_failures = []

    def delay_visibility(self, operation, previous):
        self.stale_release = previous
        self.stale_reads = self.visibility_delays[operation]

    def visible_release(self):
        if self.stale_reads:
            self.stale_reads -= 1
            return self.stale_release
        return self.release

    def existing(self, draft, names=('gre4.sh', 'SHA256SUMS')):
        self.refs = [{'ref': 'refs/tags/' + TAG, 'object': {'type': 'commit', 'sha': SHA}}]
        self.release = {'id': 123, 'tag_name': TAG, 'draft': draft, 'prerelease': False,
                        'target_commitish': SHA, 'assets': []}
        for name in names:
            self.add_asset(name, self.assets[name])

    def add_asset(self, name, content):
        identifier = len(self.blobs) + 1
        self.blobs[identifier] = content
        self.release['assets'].append({'id': identifier, 'name': name})

    def command(self, *args):
        self.calls.append(args)
        if args[0] == 'git':
            self.assert_source(args[-1])
            return self.files[args[-1].split(':', 1)[1]]
        if args[:2] == ('gh', 'api'):
            if '--method' not in args and self.read_failures:
                raise self.read_failures.pop(0)
            if '-H' in args:
                if self.asset_failures:
                    raise self.asset_failures.pop(0)
                return self.blobs[int(args[-1].rsplit('/', 1)[1])]
            endpoint = args[2].removeprefix('repos/' + REPOSITORY + '/')
            if endpoint == 'releases?per_page=100':
                assert '--paginate' in args and '--slurp' in args
                visible = self.visible_release()
                return json.dumps([[visible] if visible else []]).encode()
            if endpoint == 'releases/123':
                return json.dumps(self.visible_release()).encode()
            if endpoint == 'git/matching-refs/tags/' + TAG:
                return json.dumps(self.refs).encode()
            if endpoint.startswith('git/tags/'):
                return json.dumps({'object': {'type': 'commit', 'sha': SHA}}).encode()
            if endpoint == 'git/refs' and '--method' in args:
                assert 'ref=refs/tags/' + TAG in args and 'sha=' + SHA in args
                self.refs.append({'ref': 'refs/tags/' + TAG, 'object': {'type': 'commit', 'sha': SHA}})
                return b'{}'
        if args[:3] == ('gh', 'release', 'create'):
            assert self.release is None and '--draft' in args and '--verify-tag' in args
            assert args[args.index('--target') + 1] == SHA
            self.notes = Path(args[args.index('--notes-file') + 1]).read_text()
            self.release = {'id': 123, 'tag_name': TAG, 'draft': True, 'prerelease': False,
                            'target_commitish': SHA, 'assets': []}
            self.delay_visibility('create', None)
            return b''
        if args[:3] == ('gh', 'release', 'upload'):
            assert self.release['draft'] and '--clobber' not in args
            previous = copy.deepcopy(self.release)
            for filename in args[6:]:
                path = Path(filename)
                assert path.name not in {item['name'] for item in self.release['assets']}
                self.add_asset(path.name, path.read_bytes())
            self.delay_visibility('upload', previous)
            return b''
        if args[:3] == ('gh', 'release', 'edit'):
            assert self.release['draft'] and '--draft=false' in args and '--latest' in args
            assert set(item['name'] for item in self.release['assets']) == set(self.assets)
            previous = copy.deepcopy(self.release)
            self.release['draft'] = False
            self.delay_visibility('publish', previous)
            return b''
        raise AssertionError('Unexpected command: ' + repr(args))

    @staticmethod
    def assert_source(reference):
        assert reference.startswith(SHA + ':'), reference

    def mutations(self):
        return [args for args in self.calls if '--method' in args or
                args[:3] in [('gh', 'release', 'create'), ('gh', 'release', 'upload'), ('gh', 'release', 'edit')]]


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.github = FakeGitHub()

    def publish(self):
        with patch.object(release, 'command', side_effect=self.github.command), patch.object(release.time, 'sleep'):
            release.publish(Path('/fixture'), REPOSITORY, SHA)

    def test_fresh_release_pins_tested_commit_and_verifies_assets_before_publication(self):
        # The prefix endpoint may also contain a similarly named, unrelated tag.
        self.github.refs = [{'ref': 'refs/tags/' + TAG + '0', 'object': {'type': 'commit', 'sha': 'b' * 40}}]
        self.publish()
        self.assertFalse(self.github.release['draft'])
        self.assertEqual(set(self.github.blobs.values()), set(self.github.assets.values()))
        self.assertIn('English notes.', self.github.notes)
        self.assertIn('توضیح فارسی', self.github.notes)
        self.assertNotIn('Old notes.', self.github.notes)
        edit = next(index for index, args in enumerate(self.github.calls) if args[:3] == ('gh', 'release', 'edit'))
        downloads = [index for index, args in enumerate(self.github.calls) if args[:3] == ('gh', 'api', '-H')]
        self.assertEqual(len(downloads), 2)
        self.assertTrue(all(index < edit for index in downloads))

    def test_matching_published_retry_is_read_only(self):
        self.github.existing(draft=False)
        before = copy.deepcopy(self.github.release)
        self.publish()
        self.assertEqual(self.github.release, before)
        self.assertEqual(self.github.mutations(), [])

    def test_partial_draft_retry_uploads_only_missing_asset(self):
        self.github.existing(draft=True, names=('gre4.sh',))
        self.publish()
        uploads = [args for args in self.github.calls if args[:3] == ('gh', 'release', 'upload')]
        self.assertEqual(len(uploads), 1)
        self.assertEqual([Path(arg).name for arg in uploads[0][6:]], ['SHA256SUMS'])
        self.assertFalse(self.github.release['draft'])

    def test_created_draft_visibility_delay_does_not_repeat_creation(self):
        self.github.visibility_delays['create'] = 2
        self.publish()
        self.assertFalse(self.github.release['draft'])
        self.assertEqual(sum(args[:3] == ('gh', 'release', 'create') for args in self.github.calls), 1)

    def test_uploaded_asset_visibility_delay_does_not_repeat_upload(self):
        self.github.existing(draft=True, names=())
        self.github.visibility_delays['upload'] = 2
        self.publish()
        self.assertFalse(self.github.release['draft'])
        self.assertEqual(sum(args[:3] == ('gh', 'release', 'upload') for args in self.github.calls), 1)

    def test_publication_visibility_delay_does_not_repeat_edit(self):
        self.github.existing(draft=True)
        self.github.visibility_delays['publish'] = 2
        self.publish()
        self.assertFalse(self.github.release['draft'])
        self.assertEqual(sum(args[:3] == ('gh', 'release', 'edit') for args in self.github.calls), 1)

    def test_transient_reads_retry_without_replaying_mutations(self):
        for failure in [subprocess.CalledProcessError(1, ['gh', 'api'], stderr=b'HTTP 502: Bad Gateway'),
                        subprocess.CalledProcessError(1, ['gh', 'api'], stderr=b'HTTP 429: Too Many Requests'),
                        subprocess.TimeoutExpired(['gh', 'api'], 30)]:
            with self.subTest(failure=failure):
                self.github = FakeGitHub()
                self.github.read_failures = [failure]
                self.publish()
                for operation in ('create', 'upload', 'edit'):
                    self.assertEqual(sum(args[:3] == ('gh', 'release', operation)
                                         for args in self.github.calls), 1)

    def test_authentication_and_permission_errors_are_not_retried(self):
        for code in (401, 403):
            with self.subTest(code=code):
                self.github = FakeGitHub()
                self.github.read_failures = [subprocess.CalledProcessError(
                    1, ['gh', 'api'], stderr=('HTTP ' + str(code) + ': denied').encode())]
                with self.assertRaises(subprocess.CalledProcessError):
                    self.publish()
                self.assertEqual(len(self.github.calls), 4)
                self.assertEqual(self.github.mutations(), [])

    def test_transient_asset_reads_retry_without_changing_a_published_release(self):
        self.github.existing(draft=False)
        previous = copy.deepcopy(self.github.release)
        self.github.asset_failures = [subprocess.CalledProcessError(
            1, ['gh', 'api'], stderr=b'HTTP 503: Service Unavailable'),
            subprocess.TimeoutExpired(['gh', 'api'], 30)]
        self.publish()
        self.assertEqual(self.github.asset_failures, [])
        self.assertEqual(self.github.release, previous)
        self.assertEqual(self.github.mutations(), [])

    def test_transient_read_retries_stop_without_mutating_when_exhausted(self):
        self.github.read_failures = [subprocess.CalledProcessError(
            1, ['gh', 'api'], stderr=b'HTTP 502: Bad Gateway') for _ in range(20)]
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish()
        self.assertEqual(sum(args[:2] == ('gh', 'api') for args in self.github.calls), 5)
        self.assertEqual(self.github.mutations(), [])

    def test_visibility_wait_is_bounded_and_preserves_an_unseen_draft(self):
        self.github.visibility_delays['create'] = 100
        with self.assertRaisesRegex(ValueError, 'Expected draft'):
            self.publish()
        self.assertTrue(self.github.release['draft'])
        self.assertEqual(sum(args[:3] == ('gh', 'release', 'create') for args in self.github.calls), 1)
        self.assertFalse(any(args[:3] in [('gh', 'release', 'upload'), ('gh', 'release', 'edit')]
                             for args in self.github.calls))
        self.assertEqual(sum(args[:3] == ('gh', 'api', 'repos/' + REPOSITORY + '/releases?per_page=100')
                             for args in self.github.calls), 8)

    def test_wrong_target_observed_after_create_is_not_waited_away(self):
        def command(*args):
            result = self.github.command(*args)
            if args[:3] == ('gh', 'release', 'create'):
                self.github.release['target_commitish'] = 'b' * 40
            return result
        with patch.object(release, 'command', side_effect=command), patch.object(release.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'unexpected target'):
                release.publish(Path('/fixture'), REPOSITORY, SHA)
        sleep.assert_not_called()
        self.assertFalse(any(args[:3] == ('gh', 'release', 'upload') for args in self.github.calls))

    def test_mutation_timeout_is_not_retried_and_next_run_reconciles_existing_state(self):
        for operation in ('create', 'upload', 'edit'):
            with self.subTest(operation=operation):
                self.github = FakeGitHub()

                def command(*args):
                    result = self.github.command(*args)
                    if args[:3] == ('gh', 'release', operation):
                        # GitHub applied the mutation, but the response was lost.
                        raise subprocess.TimeoutExpired(args, 30)
                    return result

                with patch.object(release, 'command', side_effect=command), patch.object(release.time, 'sleep'):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        release.publish(Path('/fixture'), REPOSITORY, SHA)
                self.assertEqual(sum(args[:3] == ('gh', 'release', operation)
                                     for args in self.github.calls), 1)
                self.publish()
                self.assertFalse(self.github.release['draft'])
                self.assertEqual(sum(args[:3] == ('gh', 'release', operation)
                                     for args in self.github.calls), 1)

    def test_published_retry_uses_tag_identity_when_target_is_a_branch_name(self):
        self.github.existing(draft=False)
        self.github.release['target_commitish'] = 'main'
        self.publish()
        self.assertEqual(self.github.mutations(), [])

    def test_corrupt_uploaded_bytes_keep_the_release_unpublished(self):
        def command(*args):
            result = self.github.command(*args)
            if args[:3] == ('gh', 'release', 'upload'):
                self.github.blobs[1] = b'corrupt upload'
            return result
        with patch.object(release, 'command', side_effect=command):
            with self.assertRaisesRegex(ValueError, 'asset differs'):
                release.publish(Path('/fixture'), REPOSITORY, SHA)
        self.assertTrue(self.github.release['draft'])
        self.assertFalse(any(args[:3] == ('gh', 'release', 'edit') for args in self.github.calls))

    def test_annotated_matching_tag_is_peeled_without_replacement(self):
        self.github.existing(draft=False)
        self.github.refs[0]['object'] = {'type': 'tag', 'sha': 'c' * 40}
        self.publish()
        self.assertEqual(self.github.mutations(), [])

    def test_tag_for_other_commit_fails_before_mutation(self):
        self.github.existing(draft=False)
        self.github.refs[0]['object']['sha'] = 'b' * 40
        with self.assertRaisesRegex(ValueError, 'different commit'):
            self.publish()
        self.assertEqual(self.github.mutations(), [])

    def test_corrupt_existing_asset_is_never_overwritten(self):
        for draft in [False, True]:
            with self.subTest(draft=draft):
                self.github = FakeGitHub()
                self.github.existing(draft=draft)
                self.github.blobs[2] = b'bad checksum\n'
                with self.assertRaisesRegex(ValueError, 'asset differs'):
                    self.publish()
                self.assertEqual(self.github.mutations(), [])

    def test_incomplete_published_release_is_not_repaired_in_place(self):
        self.github.existing(draft=False, names=('gre4.sh',))
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.publish()
        self.assertEqual(self.github.mutations(), [])

    def test_wrong_draft_target_and_prerelease_are_not_modified(self):
        for field, value in [('target_commitish', 'b' * 40), ('prerelease', True)]:
            with self.subTest(field=field):
                self.github = FakeGitHub()
                self.github.existing(draft=True)
                self.github.release[field] = value
                with self.assertRaisesRegex(ValueError, 'unexpected target'):
                    self.publish()
                self.assertEqual(self.github.mutations(), [])

    def test_version_and_changelog_are_validated_before_github_calls(self):
        for path, content in [('VERSION', b'1.1.1\nextra\n'), ('VERSION', b'01.1.1\n'),
                              ('CHANGELOG.md', b'## Unreleased\n')]:
            with self.subTest(path=path, content=content):
                self.github = FakeGitHub()
                self.github.files[path] = content
                with self.assertRaises(ValueError):
                    self.publish()
                self.assertFalse(any(args[0] == 'gh' for args in self.github.calls))

    def test_github_failure_is_not_treated_as_a_missing_release(self):
        failure = subprocess.CalledProcessError(1, ['gh', 'api'], stderr=b'authentication failed')
        def command(*args):
            if args[0] == 'gh':
                raise failure
            return self.github.command(*args)
        with patch.object(release, 'command', side_effect=command):
            with self.assertRaises(subprocess.CalledProcessError):
                release.publish(Path('/fixture'), REPOSITORY, SHA)
        self.assertEqual(self.github.mutations(), [])


if __name__ == '__main__':
    unittest.main()
