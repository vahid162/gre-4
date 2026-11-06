"""Publish the tested main commit without replacing published tags or assets."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


READ_RETRY_DELAYS = (1, 2, 4, 8)
VISIBILITY_DELAYS = (1, 2, 4, 8, 16, 30)


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=30).stdout


def read_command(*args):
    for delay in (*READ_RETRY_DELAYS, None):
        try:
            return command(*args)
        except subprocess.CalledProcessError as error:
            message = (error.stderr or b'').decode(errors='replace')
            codes = [int(code) for code in re.findall(r'\bHTTP(?:/\S+)?\s+([1-5][0-9]{2})\b', message)]
            transient = (all(code == 429 or 500 <= code <= 599 for code in codes) if codes else
                         bool(re.search(r'timed out|connection reset|connection refused|temporary failure in name resolution|unexpected EOF|no such host', message, re.IGNORECASE)))
            if not transient or delay is None:
                raise
        except subprocess.TimeoutExpired:
            if delay is None:
                raise
        time.sleep(delay)


def wait_for(read, ready, message):
    for delay in (*VISIBILITY_DELAYS, None):
        observed = read()
        if ready(observed):
            return observed
        if delay is None:
            raise ValueError(message)
        time.sleep(delay)


def api(repository, path, *args):
    return json.loads(command('gh', 'api', 'repos/' + repository + '/' + path, *args))


def read_api(repository, path, *args):
    return json.loads(read_command('gh', 'api', 'repos/' + repository + '/' + path, *args))


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
        pages = read_api(repository, 'releases?per_page=100', '--paginate', '--slurp')
        return next((item for page in pages for item in page if item['tag_name'] == tag), None)

    def validate_release(item, strict_target=False):
        if item and (item['tag_name'] != tag or item['prerelease'] or
                     ((strict_target or item['draft']) and item['target_commitish'] != sha)):
            raise ValueError('Existing release has unexpected target or prerelease state')

    def draft_visible(item):
        validate_release(item, strict_target=True)
        if item and not item['draft']:
            raise ValueError('Expected draft release has already been published')
        return item is not None

    def check_tag():
        refs = read_api(repository, 'git/matching-refs/tags/' + tag)
        target = next((item['object'] for item in refs if item['ref'] == 'refs/tags/' + tag), None)
        if target is None:
            return False
        while target['type'] == 'tag':
            target = read_api(repository, 'git/tags/' + target['sha'])['object']
        if target['type'] != 'commit' or target['sha'] != sha:
            raise ValueError('Existing release tag points to a different commit; bump VERSION')
        return True

    def verify_assets(release):
        uploaded = {item['name']: item for item in release['assets']}
        if len(uploaded) != len(release['assets']) or not set(uploaded) <= set(assets):
            raise ValueError('Unexpected release assets; retaining the existing release')
        for name, item in uploaded.items():
            content = read_command('gh', 'api', '-H', 'Accept: application/octet-stream',
                                   'repos/' + repository + '/releases/assets/' + str(item['id']))
            if content != assets[name]:
                raise ValueError('Existing release asset differs: ' + name)
        return set(assets) - set(uploaded)

    release = find_release()
    tagged = check_tag()
    validate_release(release)
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
            wait_for(check_tag, bool, 'Created release tag was not found')
        if release is None:
            command('gh', 'release', 'create', tag, '--repo', repository, '--verify-tag',
                    '--target', sha, '--draft', '--title', 'GRE4 ' + tag,
                    '--notes-file', str(work / 'notes.md'))
            release = wait_for(find_release, draft_visible, 'Expected draft release was not found')
        identifier = release['id']
        if not isinstance(identifier, int) or isinstance(identifier, bool) or identifier <= 0:
            raise ValueError('Invalid release identity')

        def read_release():
            item = read_api(repository, 'releases/' + str(identifier))
            validate_release(item, strict_target=True)
            if item is None or item['id'] != identifier:
                raise ValueError('Release identity changed during publication')
            return item

        def draft_complete(item):
            draft_visible(item)
            return not verify_assets(item) and check_tag()

        def published(item):
            return not item['draft'] and check_tag()

        missing = verify_assets(release)
        if missing:
            command('gh', 'release', 'upload', tag, '--repo', repository,
                    *(str(work / name) for name in sorted(missing)))
            wait_for(read_release, draft_complete, 'Draft assets or tag failed verification')
        elif not check_tag():
            raise ValueError('Draft tag failed verification')
        command('gh', 'release', 'edit', tag, '--repo', repository,
                '--draft=false', '--prerelease=false', '--latest')
        wait_for(read_release, published, 'Published release failed verification')
        print('Published verified release: ' + tag)


if __name__ == '__main__':
    try:
        if os.environ.get('GITHUB_EVENT_NAME') != 'push' or os.environ.get('GITHUB_REF') != 'refs/heads/main':
            raise ValueError('Release publishing is restricted to pushes on main after CI')
        publish(Path(__file__).resolve().parents[1], os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA'])
    except subprocess.CalledProcessError as error:
        raise SystemExit((error.stderr or b'').decode(errors='replace')) from error
    except subprocess.TimeoutExpired as error:
        raise SystemExit('Release command timed out; inspect the existing release before retrying.') from error
    except (KeyError, ValueError) as error:
        raise SystemExit(str(error)) from error
