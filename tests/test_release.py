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

    def existing(self, draft, names=('gre4.sh', 'SHA256SUMS')):
        self.refs = [{'ref': 'refs/tags/' + TAG, 'object': {'type': 'commit', 'sha': SHA}}]
        self.release = {'tag_name': TAG, 'draft': draft, 'prerelease': False,
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
            if '-H' in args:
                return self.blobs[int(args[-1].rsplit('/', 1)[1])]
            endpoint = args[2].removeprefix('repos/' + REPOSITORY + '/')
            if endpoint == 'releases?per_page=100':
                assert '--paginate' in args and '--slurp' in args
                return json.dumps([[self.release] if self.release else []]).encode()
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
            self.release = {'tag_name': TAG, 'draft': True, 'prerelease': False,
                            'target_commitish': SHA, 'assets': []}
            return b''
        if args[:3] == ('gh', 'release', 'upload'):
            assert self.release['draft'] and '--clobber' not in args
            for filename in args[6:]:
                path = Path(filename)
                assert path.name not in {item['name'] for item in self.release['assets']}
                self.add_asset(path.name, path.read_bytes())
            return b''
        if args[:3] == ('gh', 'release', 'edit'):
            assert self.release['draft'] and '--draft=false' in args and '--latest' in args
            assert set(item['name'] for item in self.release['assets']) == set(self.assets)
            self.release['draft'] = False
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
        with patch.object(release, 'command', side_effect=self.github.command):
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
