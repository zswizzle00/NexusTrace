"""Pins app/utils/storage.py - the local/GCS record-store abstraction.

No network and no real `data/`: `storage.LOCAL_ROOT` is repointed at a temp tree for the
whole run (`check_isolation` refuses to proceed otherwise), and the GCS backend is driven
through `storage.GCS_CLIENT_FACTORY` with a recording fake, so `google.cloud.storage` is
never imported and need not be installed.

The traversal battery is the point of most of this file: one key allowlist is the
path-traversal boundary for five stores at once, so every rejected key is asserted
against every method that takes one, and asserted to have created and read nothing.
"""
import io
import os
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import logging

from app.utils import storage

logging.disable(logging.CRITICAL)

failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


def raises(exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type:
        return True
    except Exception:
        return False
    return False


def check_isolation():
    """Refuse to run against the real data directory under any circumstances."""
    real = (Path(storage.__file__).resolve().parent.parent.parent / 'data').resolve()
    root = Path(storage.LOCAL_ROOT).resolve()
    if root == real or real in root.parents or root in real.parents:
        raise SystemExit(f'REFUSING TO RUN: {root} overlaps the real data store {real}')


def fresh(name='scans'):
    st = storage.store(name)
    shutil.rmtree(st.root, ignore_errors=True)
    return st


def test_backend_selection():
    check(storage.backend_name() == 'local', 'default backend should be local')
    os.environ['STORAGE_BACKEND'] = 'LOCAL'
    check(storage.backend_name() == 'local', 'backend name should be case-insensitive')
    os.environ['STORAGE_BACKEND'] = 'bogus'
    check(raises(ValueError, storage.backend_name),
          'an unknown STORAGE_BACKEND must raise, never default to local')
    del os.environ['STORAGE_BACKEND']
    check(storage.backend_name() == 'local', 'unset backend should be local')

    for name in storage.STORES:
        st = storage.store(name)
        check(st.backend == 'local' and st.name == name, f'store({name!r}) misbuilt')
        check(Path(st.root).name == name, f'store({name!r}) root should end in {name}')
    check(storage.store('scans') is storage.store('scans'),
          'store() should memoise per backend+name')
    for bad in ('bogus', '', None, 'scans/', 42, 'Scans'):
        check(raises(ValueError, storage.store, bad),
              f'store({bad!r}) must raise ValueError')


def test_text_round_trip():
    st = fresh('scans')
    check(st.read_text('a.json') is None, 'read_text of a missing key must be None')
    check(st.read_bytes('a.json') is None, 'read_bytes of a missing key must be None')
    check(st.exists('a.json') is False, 'exists of a missing key must be False')
    check(st.open_stream('a.json') is None, 'open_stream of a missing key must be None')
    check(st.local_path('a.json') is None, 'local_path of a missing key must be None')
    check(st.delete('a.json') is False, 'delete of a missing key must be False')
    check(st.list() == [], 'list of a missing directory must be []')

    st.write_text('a.json', '{"id": "a", "unicode": "\u00e9\u2713"}')
    check(st.read_text('a.json') == '{"id": "a", "unicode": "\u00e9\u2713"}',
          'text round trip failed')
    check(st.read_bytes('a.json') == '{"id": "a", "unicode": "\u00e9\u2713"}'.encode('utf-8'),
          'text should be stored as utf-8')
    check(st.exists('a.json') is True, 'exists should be True after write')

    st.write_text('a.json', 'replaced')
    check(st.read_text('a.json') == 'replaced', 'write_text should overwrite')

    path = st.local_path('a.json')
    check(isinstance(path, Path) and path.is_file(),
          'local_path should return a real Path on the local backend')
    check(path.read_text(encoding='utf-8') == 'replaced',
          'local_path should point at the written bytes')

    with st.open_stream('a.json') as handle:
        check(handle.read() == b'replaced', 'open_stream should yield the bytes')

    check(st.delete('a.json') is True, 'delete of a present key must be True')
    check(st.exists('a.json') is False, 'key should be gone after delete')
    check(st.delete('a.json') is False, 'second delete must be False')


def test_bytes_round_trip():
    st = fresh('screenshots')
    png = b'\x89PNG\r\n\x1a\n' + bytes(range(256))
    st.write_bytes('shot.png', png)
    check(st.read_bytes('shot.png') == png, 'bytes round trip failed')
    check(st.write_bytes('shot.png', png) is None, 'write_bytes should return None')

    st.write_bytes('mv.png', memoryview(b'abc'))
    check(st.read_bytes('mv.png') == b'abc', 'memoryview should be accepted')
    st.write_bytes('ba.png', bytearray(b'def'))
    check(st.read_bytes('ba.png') == b'def', 'bytearray should be accepted')
    check(raises(TypeError, st.write_bytes, 'str.png', 'not bytes'),
          'write_bytes of a str must raise TypeError')

    st.write_bytes('empty.png', b'')
    check(st.read_bytes('empty.png') == b'', 'empty write should round trip as b""')
    check(st.exists('empty.png') is True, 'an empty object still exists')


def test_atomic_write():
    st = fresh('analyses')
    st.write_text('rec.json', 'first')

    def names():
        return sorted(p.name for p in Path(st.root).iterdir())

    st.write_text('rec.json', 'x' * 200000)
    check(names() == ['rec.json'],
          f'write_text left artefacts behind: {names()}')
    check([e['key'] for e in st.list()] == ['rec.json'],
          'list() must only report real keys')

    st.write_bytes('blob.bin', b'y' * 200000)
    check(names() == ['blob.bin', 'rec.json'],
          f'write_bytes left artefacts behind: {names()}')

    # A failure between "temp file written" and "replace" must leave the previous
    # record intact and no temp file lying around - that is what os.replace buys.
    real_replace = storage.os.replace

    def boom(src, dst):
        raise OSError('simulated replace failure')

    storage.os.replace = boom
    try:
        failed = raises(OSError, st.write_text, 'rec.json', 'second')
    finally:
        storage.os.replace = real_replace
    check(failed, 'a replace failure should propagate')
    check(st.read_text('rec.json') == 'x' * 200000,
          'a failed write must not damage the previous record')
    check(names() == ['blob.bin', 'rec.json'],
          f'a failed write must clean up its temp file: {names()}')


def test_exclusive_and_private():
    st = fresh('quarantine')
    key = 'a' * 64 + '-11111111-2222-3333-4444-555555555555.bin'
    st.write_bytes(key, b'malware', exclusive=True, private=True)
    check(st.read_bytes(key) == b'malware', 'exclusive write should store the bytes')

    mode = stat.S_IMODE(Path(st.root, key).stat().st_mode)
    check(mode == 0o600, f'private=True should yield 0600, got {oct(mode)}')

    check(raises(FileExistsError, st.write_bytes, key, b'other', exclusive=True),
          'a second exclusive write must raise FileExistsError')
    check(st.read_bytes(key) == b'malware',
          'a refused exclusive write must not have touched the existing object')

    # A symlink planted in the store must never redirect I/O outside it - the realpath
    # guard refuses it, and O_NOFOLLOW is the second line on the exclusive path.
    outside_dir = Path(tempfile.mkdtemp())
    outside = outside_dir / 'target'
    outside.write_bytes(b'secret')
    link = Path(st.root) / 'link.bin'
    os.symlink(outside, link)
    try:
        for label, call in (('write_bytes', lambda: st.write_bytes('link.bin', b'e')),
                            ('exclusive', lambda: st.write_bytes('link.bin', b'e',
                                                                 exclusive=True)),
                            ('read_bytes', lambda: st.read_bytes('link.bin')),
                            ('open_stream', lambda: st.open_stream('link.bin')),
                            ('delete', lambda: st.delete('link.bin'))):
            blocked = False
            try:
                call()
            except (ValueError, OSError):
                blocked = True
            check(blocked, f'{label} through a symlink out of the store must fail')
        check(outside.read_bytes() == b'secret',
              'the symlink target must not have been written or removed')
        check(link.is_symlink(), 'the planted symlink itself should be untouched')
        check('link.bin' not in [e['key'] for e in st.list()],
              'list must not report a symlink as a record')
    finally:
        link.unlink()
        shutil.rmtree(outside_dir, ignore_errors=True)

    st.write_bytes('plain.bin', b'x')
    plain = stat.S_IMODE(Path(st.root, 'plain.bin').stat().st_mode)
    check(plain == 0o644, f'default mode should be 0644, got {oct(plain)}')

    st.write_bytes('priv.bin', b'x', private=True)
    priv = stat.S_IMODE(Path(st.root, 'priv.bin').stat().st_mode)
    check(priv == 0o600, f'private=True without exclusive should be 0600, got {oct(priv)}')

    st.write_text('rec.json', 'x')
    text_mode = stat.S_IMODE(Path(st.root, 'rec.json').stat().st_mode)
    check(text_mode == 0o644, f'write_text should be 0644, got {oct(text_mode)}')


def test_listing():
    st = fresh('scans')
    for index, key in enumerate(('old.json', 'mid.json', 'new.json', 'other.txt')):
        st.write_text(key, 'x' * (index + 1))
        os.utime(Path(st.root, key), (1_700_000_000 + index, 1_700_000_000 + index))

    keys = [e['key'] for e in st.list()]
    check(keys == ['other.txt', 'new.json', 'mid.json', 'old.json'],
          f'list should be newest-first, got {keys}')

    entry = st.list()[0]
    check(set(entry) == {'key', 'size', 'modified'},
          f'list entries should carry exactly key/size/modified, got {sorted(entry)}')
    check(entry['size'] == 4 and entry['modified'] == 1_700_000_003.0,
          f'list entry metadata is wrong: {entry}')

    json_keys = [e['key'] for e in st.list(suffix='.json')]
    check(json_keys == ['new.json', 'mid.json', 'old.json'],
          f'suffix filter failed: {json_keys}')
    check([e['key'] for e in st.list(limit=2)] == ['other.txt', 'new.json'],
          'limit should keep the newest entries')
    check([e['key'] for e in st.list(suffix='.json', limit=1)] == ['new.json'],
          'suffix and limit should compose')
    check(st.list(limit=0) == [], 'limit=0 should return nothing')
    check(len(st.list(limit=-5)) == 0, 'a negative limit should clamp to 0')
    check(len(st.list(limit='nonsense')) == 4, 'an unparseable limit should mean no limit')
    check(len(st.list(limit=None)) == 4, 'limit=None should mean no limit')

    Path(st.root, '.tmp-leftover.part').write_text('junk', encoding='utf-8')
    Path(st.root, 'has space.json').write_text('junk', encoding='utf-8')
    (Path(st.root) / 'subdir').mkdir()
    check(len(st.list()) == 4, 'list must skip artefacts, dotfiles and directories')


BAD_KEYS = (
    '../etc/passwd', '/etc/passwd', 'a/b', 'a\\b', '..', '.hidden', 'x\x00y', '',
    'x' * 300, '.', './a', 'a/../b', '....', 'C:\\windows', 'a b', 'a:b', 'a;b',
    'a\nb', 'a.json\n', 'sub/dir/file.json', '~root', '%2e%2e', 'a|b', '\u0130.json',
    None, 42, b'bytes.json', ('tuple',), Path('a.json'),
)


def test_key_validation():
    st = fresh('scans')
    st.write_text('sentinel.json', 'sentinel')
    before = sorted(p.name for p in Path(st.root).iterdir())
    outside = Path(st.root).parent
    outside_before = sorted(p.name for p in outside.iterdir())

    methods = (
        ('write_text', lambda k: st.write_text(k, 'x')),
        ('write_bytes', lambda k: st.write_bytes(k, b'x')),
        ('write_bytes/exclusive', lambda k: st.write_bytes(k, b'x', exclusive=True)),
        ('read_text', lambda k: st.read_text(k)),
        ('read_bytes', lambda k: st.read_bytes(k)),
        ('exists', lambda k: st.exists(k)),
        ('delete', lambda k: st.delete(k)),
        ('open_stream', lambda k: st.open_stream(k)),
        ('local_path', lambda k: st.local_path(k)),
    )
    for key in BAD_KEYS:
        for label, call in methods:
            check(raises(ValueError, call, key),
                  f'{label}({key!r}) must raise ValueError')
        check(raises(ValueError, storage.validate_key, key),
              f'validate_key({key!r}) must raise ValueError')

    check(sorted(p.name for p in Path(st.root).iterdir()) == before,
          'a rejected key must not create anything inside the store')
    check(sorted(p.name for p in outside.iterdir()) == outside_before,
          'a rejected key must not create anything outside the store')
    check(st.read_text('sentinel.json') == 'sentinel',
          'a rejected key must not have disturbed an existing record')

    for key in ('a.json', 'A-b_c.1.json', 'x', 'x' * 255,
                'a' * 64 + '-11111111-2222-3333-4444-555555555555.bin',
                '11111111-2222-3333-4444-555555555555-after-scroll.png'):
        check(storage.validate_key(key) == key, f'validate_key({key!r}) should pass')
    check(raises(ValueError, storage.validate_key, 'x' * 256),
          'a 256-character key must be rejected')


class FakeNotFound(Exception):
    code = 404


class FakePrecondition(Exception):
    code = 412


class FakeBlob:
    def __init__(self, bucket, name):
        self.bucket = bucket
        self.name = name
        self.size = 0
        self.updated = None
        self.uploads = []

    def _stored(self):
        return self.bucket.objects.get(self.name)

    def upload_from_string(self, data, **kwargs):
        self.uploads.append((data, kwargs))
        self.bucket.uploads.append((self.name, kwargs))
        if kwargs.get('if_generation_match') == 0 and self.name in self.bucket.objects:
            raise FakePrecondition(self.name)
        self.bucket.objects[self.name] = data
        self.size = len(data)

    def download_as_bytes(self):
        data = self._stored()
        if data is None:
            raise FakeNotFound(self.name)
        return data

    def exists(self):
        return self.name in self.bucket.objects

    def delete(self):
        if self.name not in self.bucket.objects:
            raise FakeNotFound(self.name)
        del self.bucket.objects[self.name]


class FakeBucket:
    def __init__(self, name):
        self.name = name
        self.objects = {}
        self.blob_names = []
        self.uploads = []
        self.list_prefixes = []
        self.times = {}

    def blob(self, name):
        self.blob_names.append(name)
        blob = FakeBlob(self, name)
        blob.size = len(self.objects.get(name, b''))
        blob.updated = self.times.get(name)
        return blob

    def list_blobs(self, prefix=None):
        self.list_prefixes.append(prefix)
        out = []
        for name in sorted(self.objects):
            if prefix and not name.startswith(prefix):
                continue
            blob = FakeBlob(self, name)
            blob.size = len(self.objects[name])
            blob.updated = self.times.get(name)
            out.append(blob)
        return out


class FakeClient:
    def __init__(self):
        self.buckets = {}

    def bucket(self, name):
        return self.buckets.setdefault(name, FakeBucket(name))


def test_gcs_backend():
    client = FakeClient()
    os.environ['STORAGE_BACKEND'] = 'gcs'
    os.environ.pop('GCS_BUCKET', None)
    storage.reset_cache()
    try:
        check(storage.backend_name() == 'gcs', 'STORAGE_BACKEND=gcs should select gcs')
        check(raises(RuntimeError, storage.store, 'scans'),
              'gcs with no GCS_BUCKET must raise at construction, not fall back')

        os.environ['GCS_BUCKET'] = 'nexustrace-records'
        storage.reset_cache()
        storage.GCS_CLIENT_FACTORY = lambda: client

        st = storage.store('scans')
        check(st.backend == 'gcs', 'gcs backend not selected')
        check(st.read_text('missing.json') is None,
              'a missing blob must read as None, not raise')
        check(st.read_bytes('missing.json') is None,
              'a missing blob must read as None, not raise')
        check(st.exists('missing.json') is False, 'exists should be False when absent')
        check(st.delete('missing.json') is False, 'delete should be False when absent')
        check(st.open_stream('missing.json') is None,
              'open_stream should be None when absent')
        check(st.local_path('missing.json') is None,
              'local_path must always be None on gcs')

        st.write_text('a.json', '{"id": "a"}')
        bucket = client.buckets['nexustrace-records']
        check(bucket.objects.get('scans/a.json') == b'{"id": "a"}',
              f'object should land at scans/a.json, got {sorted(bucket.objects)}')
        check('scans/a.json' in bucket.blob_names,
              'blob name should be prefixed with the store name')
        check(st.read_text('a.json') == '{"id": "a"}', 'gcs text round trip failed')
        check(st.exists('a.json') is True, 'exists should be True after write')

        shots = storage.store('screenshots')
        shots.write_bytes('s.png', b'\x89PNG')
        check(bucket.objects.get('screenshots/s.png') == b'\x89PNG',
              'screenshot should land under the screenshots prefix')
        kinds = dict((name, kw) for name, kw in bucket.uploads)
        check(kinds['screenshots/s.png'].get('content_type') == 'image/png',
              'png content type should be set')
        check(kinds['scans/a.json'].get('content_type') == 'application/json',
              'json content type should be set')
        check('if_generation_match' not in kinds['scans/a.json'],
              'a non-exclusive write must not send a generation precondition')

        quarantine = storage.store('quarantine')
        key = 'b' * 64 + '-11111111-2222-3333-4444-555555555555.bin'
        quarantine.write_bytes(key, b'malware', exclusive=True, private=True)
        sent = [kw for name, kw in bucket.uploads if name == f'quarantine/{key}']
        check(sent and sent[-1].get('if_generation_match') == 0,
              f'exclusive=True must send ifGenerationMatch=0, got {sent}')
        check(raises(FileExistsError, quarantine.write_bytes, key, b'other',
                    exclusive=True),
              'a 412 precondition failure must surface as FileExistsError')
        check(bucket.objects[f'quarantine/{key}'] == b'malware',
              'a refused exclusive write must not replace the object')

        with st.open_stream('a.json') as handle:
            check(isinstance(handle, io.BytesIO) and handle.read() == b'{"id": "a"}',
                  'gcs open_stream should yield a readable byte stream')

        bucket.times['scans/a.json'] = datetime(2026, 1, 1, tzinfo=timezone.utc)
        st.write_text('b.json', 'bb')
        bucket.times['scans/b.json'] = datetime(2026, 6, 1, tzinfo=timezone.utc)
        st.write_text('c.txt', 'ccc')
        bucket.times['scans/c.txt'] = datetime(2026, 3, 1, tzinfo=timezone.utc)
        bucket.objects['scans/nested/deep.json'] = b'{}'

        listed = st.list()
        check([e['key'] for e in listed] == ['b.json', 'c.txt', 'a.json'],
              f'gcs list should be newest-first, got {[e["key"] for e in listed]}')
        check(bucket.list_prefixes[-1] == 'scans/',
              f'list should be prefix-scoped, got {bucket.list_prefixes[-1]!r}')
        check(all('/' not in e['key'] for e in listed),
              'a nested object name must not be reported as a key')
        check([e['key'] for e in st.list(suffix='.json')] == ['b.json', 'a.json'],
              'gcs suffix filter failed')
        check([e['key'] for e in st.list(limit=1)] == ['b.json'], 'gcs limit failed')
        check(listed[0]['size'] == 2, f'gcs list size is wrong: {listed[0]}')

        check(st.delete('a.json') is True, 'gcs delete of a present blob must be True')
        check(st.exists('a.json') is False, 'blob should be gone after delete')

        for bad in ('../etc/passwd', 'a/b', '.hidden', '', None, 'x' * 300):
            check(raises(ValueError, st.write_text, bad, 'x'),
                  f'gcs write_text({bad!r}) must raise ValueError')
            check(raises(ValueError, st.read_bytes, bad),
                  f'gcs read_bytes({bad!r}) must raise ValueError')
            check(raises(ValueError, st.local_path, bad),
                  f'gcs local_path({bad!r}) must raise ValueError')
    finally:
        storage.GCS_CLIENT_FACTORY = None
        os.environ.pop('STORAGE_BACKEND', None)
        os.environ.pop('GCS_BUCKET', None)
        storage.reset_cache()


def test_google_import_stayed_lazy():
    """google-cloud-storage is optional: importing storage.py, and driving the GCS
    backend through the seam, must not have imported it."""
    check('google.cloud.storage' not in sys.modules,
          'storage.py must import google.cloud.storage lazily, inside GCSStore only')


def main():
    real_root = storage.LOCAL_ROOT
    root = Path(tempfile.mkdtemp(prefix='nexustrace-storage-test-'))
    storage.LOCAL_ROOT = root
    storage.reset_cache()
    saved_backend = os.environ.get('STORAGE_BACKEND')
    saved_bucket = os.environ.get('GCS_BUCKET')
    os.environ.pop('STORAGE_BACKEND', None)
    os.environ.pop('GCS_BUCKET', None)
    check_isolation()
    try:
        test_backend_selection()
        test_text_round_trip()
        test_bytes_round_trip()
        test_atomic_write()
        test_exclusive_and_private()
        test_listing()
        test_key_validation()
        test_gcs_backend()
        test_google_import_stayed_lazy()
    finally:
        storage.LOCAL_ROOT = real_root
        storage.GCS_CLIENT_FACTORY = None
        storage.reset_cache()
        for name, value in (('STORAGE_BACKEND', saved_backend),
                            ('GCS_BUCKET', saved_bucket)):
            os.environ.pop(name, None)
            if value is not None:
                os.environ[name] = value
        shutil.rmtree(root, ignore_errors=True)

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {checks} storage cases')


if __name__ == '__main__':
    main()
