"""Publish the tested main commit without replacing published tags or assets."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def command(*args):
    return subprocess.run(args, check=True, capture_output=True).stdout


def api(repository, path, *args):
    return json.loads(command('gh', 'api', 'repos/' + repository + '/' + path, *args))


def publish(root, repository, sha):
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('Release requires an exact commit SHA')
    def source(path):
        return command('git', '-C', str(root), 'show', sha + ':' + path)
    version_file = source('VERSION').decode()
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\n', version_file):
        raise ValueError('VERSION must contain one stable semantic version and a newline')
    version, tag = version_file.strip(), 'v' + version_file.strip()
    notes = re.search(r'^## ' + re.escape(version) + r' - [0-9]{4}-[0-9]{2}-[0-9]{2}\n(.*?)(?=^## |\Z)',
                      source('CHANGELOG.md').decode(), re.MULTILINE | re.DOTALL)
    if not notes or not notes[1].strip():
        raise ValueError('CHANGELOG lacks release notes for VERSION')
    script = source('gre4.sh')
    assets = {'gre4.sh': script,
              'SHA256SUMS': (hashlib.sha256(script).hexdigest() + '  gre4.sh\n').encode()}

    def find_release():
        pages = api(repository, 'releases?per_page=100', '--paginate', '--slurp')
        return next((item for page in pages for item in page if item['tag_name'] == tag), None)

    def check_tag():
        refs = api(repository, 'git/matching-refs/tags/' + tag)
        target = next((item['object'] for item in refs if item['ref'] == 'refs/tags/' + tag), None)
        if target is None:
            return False
        while target['type'] == 'tag':
            target = api(repository, 'git/tags/' + target['sha'])['object']
        if target['type'] != 'commit' or target['sha'] != sha:
            raise ValueError('Existing release tag points to a different commit; bump VERSION')
        return True

    def verify_assets(release):
        uploaded = {item['name']: item for item in release['assets']}
        if len(uploaded) != len(release['assets']) or not set(uploaded) <= set(assets):
            raise ValueError('Unexpected release assets; retaining the existing release')
        for name, item in uploaded.items():
            content = command('gh', 'api', '-H', 'Accept: application/octet-stream',
                              'repos/' + repository + '/releases/assets/' + str(item['id']))
            if content != assets[name]:
                raise ValueError('Existing release asset differs: ' + name)
        return set(assets) - set(uploaded)

    release = find_release()
    tagged = check_tag()
    if release and (release['prerelease'] or
                    (release['draft'] and release['target_commitish'] != sha)):
        raise ValueError('Existing release has unexpected target or prerelease state')
    if release and not release['draft']:
        if not tagged or verify_assets(release):
            raise ValueError('Published release is incomplete; retaining it unchanged')
        print('Verified existing published release: ' + tag)
        return

    with tempfile.TemporaryDirectory(prefix='gre4-release-') as directory:
        work = Path(directory)
        for name, content in assets.items():
            (work / name).write_bytes(content)
        (work / 'notes.md').write_text('# GRE4 ' + tag + '\n\n' + notes[1].strip() + '\n')
        if not tagged:
            api(repository, 'git/refs', '--method', 'POST', '-f', 'ref=refs/tags/' + tag, '-f', 'sha=' + sha)
        if release is None:
            command('gh', 'release', 'create', tag, '--repo', repository, '--verify-tag',
                    '--target', sha, '--draft', '--title', 'GRE4 ' + tag,
                    '--notes-file', str(work / 'notes.md'))
            release = find_release()
        if release is None or not release['draft'] or release['target_commitish'] != sha:
            raise ValueError('Expected draft release was not found')
        missing = verify_assets(release)
        if missing:
            command('gh', 'release', 'upload', tag, '--repo', repository,
                    *(str(work / name) for name in sorted(missing)))
            release = find_release()
        if release is None or verify_assets(release) or not check_tag():
            raise ValueError('Draft assets or tag failed verification')
        command('gh', 'release', 'edit', tag, '--repo', repository,
                '--draft=false', '--prerelease=false', '--latest')
        release = find_release()
        if release is None or release['draft'] or release['prerelease'] or not check_tag():
            raise ValueError('Published release failed verification')
        print('Published verified release: ' + tag)


if __name__ == '__main__':
    try:
        if os.environ.get('GITHUB_EVENT_NAME') != 'push' or os.environ.get('GITHUB_REF') != 'refs/heads/main':
            raise ValueError('Release publishing is restricted to pushes on main after CI')
        publish(Path(__file__).resolve().parents[1], os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA'])
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.stderr.decode(errors='replace')) from error
    except (KeyError, ValueError) as error:
        raise SystemExit(str(error)) from error
