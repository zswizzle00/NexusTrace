"""Record storage for the five filesystem-backed stores, on local disk or GCS.

NexusTrace persists five kinds of record as flat files named after a UUID (or, for
quarantine, a digest plus a UUID):

    scans        data/scans/<uuid>.json
    screenshots  data/screenshots/<uuid>[-<stage>].png
    analyses     data/analyses/<uuid>.json
    submissions  data/submissions/<uuid>.json
    quarantine   data/quarantine/<sha256>-<uuid>.bin

On Docker and in dev that filesystem is real and shared. On Cloud Run it is an
in-memory tmpfs that is per-instance and evaporates with the container, so a scan
written by one instance is invisible to the next request. This module is the seam:
one flat key/value interface with a local backend that keeps the current on-disk
semantics exactly, and a GCS backend for Cloud Run.

Backend selection is by environment, read once per process:

    STORAGE_BACKEND=local   (default)
    STORAGE_BACKEND=gcs     requires GCS_BUCKET

**A `gcs` backend with no `GCS_BUCKET` raises instead of falling back to local.**
On Cloud Run a silent fallback writes to tmpfs and loses the data with no error
anywhere - the loud failure is the whole point of the check.

`google-cloud-storage` is an optional dependency, imported lazily inside the GCS
backend only, so nothing on the local/Docker path needs it installed.

**Keys are untrusted.** They arrive from URL path segments (`/url_scan/<scan_id>`,
`?stage=`) and are the path-traversal boundary for all five stores at once, so
`validate_key()` is a strict allowlist - `[A-Za-z0-9._-]`, no separators, no leading
dot - and every method funnels through it before touching a backend.
"""

import io
import logging
import os
import re
import tempfile
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

STORES = ('scans', 'screenshots', 'analyses', 'submissions', 'quarantine')

BACKENDS = ('local', 'gcs')

# Long enough for every name the app generates (a quarantine key is 101 chars) and
# short enough to stay under every filesystem's per-component limit.
MAX_KEY_LENGTH = 255

# Matched with fullmatch(), not match(): `$` also matches before a trailing newline,
# which would accept "a.json\n" as a key.
_KEY_RE = re.compile(r'[A-Za-z0-9._-]+')

_BASE = Path(__file__).resolve().parent.parent.parent

# Read on every access, not captured at construction, so tests can repoint the whole
# local tree at a temp directory the same way test_submissions.py repoints its stores.
LOCAL_ROOT = _BASE / 'data'

# Test seam. When set to a zero-argument callable, the GCS backend calls it instead of
# importing google.cloud.storage, which is how test_storage.py exercises the GCS paths
# without the dependency installed and without a network.
GCS_CLIENT_FACTORY = None

_CONTENT_TYPES = {
    '.json': 'application/json',
    '.png': 'image/png',
    '.txt': 'text/plain',
    '.bin': 'application/octet-stream',
}

_cache = {}
_cache_lock = threading.Lock()


def validate_key(key):
    """Return `key` unchanged, or raise ValueError.

    Rejects anything that is not a single flat filename: separators (`/`, `\\`),
    `..`, a leading dot, NUL, absolute paths, and every character outside
    `[A-Za-z0-9._-]`. The allowlist is what makes the rest of this module free of
    per-call traversal reasoning - there is no way to express a parent directory,
    a hidden file, or a device name in an accepted key.
    """
    if not isinstance(key, str):
        raise ValueError(f'storage key must be a str, got {type(key).__name__}')
    if not key:
        raise ValueError('storage key must not be empty')
    if len(key) > MAX_KEY_LENGTH:
        raise ValueError(f'storage key exceeds {MAX_KEY_LENGTH} characters')
    if key.startswith('.'):
        raise ValueError('storage key must not start with a dot')
    if '..' in key:
        raise ValueError('storage key must not contain ".."')
    if not _KEY_RE.fullmatch(key):
        raise ValueError('storage key contains disallowed characters')
    return key


def _content_type(key, default='application/octet-stream'):
    return _CONTENT_TYPES.get(os.path.splitext(key)[1].lower(), default)


def backend_name():
    """'local' or 'gcs'. An unrecognised STORAGE_BACKEND raises rather than
    defaulting, for the same reason a missing GCS_BUCKET does: a typo that silently
    means "local" on Cloud Run is data loss with no signal."""
    name = (os.environ.get('STORAGE_BACKEND') or 'local').strip().lower()
    if name not in BACKENDS:
        raise ValueError(f'unknown STORAGE_BACKEND {name!r}; expected one of '
                         f'{", ".join(BACKENDS)}')
    return name


def store(name):
    """The Store for one of STORES. Raises ValueError for an unknown name."""
    if not isinstance(name, str) or name not in STORES:
        raise ValueError(f'unknown store {name!r}; expected one of '
                         f'{", ".join(STORES)}')
    backend = backend_name()
    with _cache_lock:
        cached = _cache.get((backend, name))
        if cached is None:
            cached = GCSStore(name) if backend == 'gcs' else LocalStore(name)
            _cache[(backend, name)] = cached
        return cached


def reset_cache():
    """Drop memoised Store objects. Needed only after changing STORAGE_BACKEND or
    GCS_BUCKET inside a running process, which in practice means tests."""
    with _cache_lock:
        _cache.clear()


class Store:
    """Flat key/value store. `key` is a single filename, validated on every call.

    `list()` entries are `{'key', 'size', 'modified'}` where `modified` is a POSIX
    timestamp (float, UTC) - `st_mtime` locally, `blob.updated.timestamp()` on GCS -
    so newest-first ordering means the same thing on both backends.
    """

    name = None
    backend = None

    def write_text(self, key, text):
        raise NotImplementedError

    def write_bytes(self, key, data, *, exclusive=False, private=False):
        raise NotImplementedError

    def read_text(self, key):
        raise NotImplementedError

    def read_bytes(self, key):
        raise NotImplementedError

    def exists(self, key):
        raise NotImplementedError

    def delete(self, key):
        raise NotImplementedError

    def list(self, *, suffix=None, limit=None):
        raise NotImplementedError

    def open_stream(self, key):
        raise NotImplementedError

    def local_path(self, key):
        raise NotImplementedError

    def __repr__(self):
        return f'<{type(self).__name__} {self.name}>'


def _clamp_limit(limit):
    if limit is None:
        return None
    try:
        return max(0, int(limit))
    except (TypeError, ValueError):
        return None


def _apply_listing(entries, suffix, limit):
    if suffix:
        entries = [e for e in entries if e['key'].endswith(suffix)]
    entries.sort(key=lambda e: e['modified'], reverse=True)
    bound = _clamp_limit(limit)
    return entries if bound is None else entries[:bound]


class LocalStore(Store):
    """The filesystem backend. Preserves the semantics the services had before this
    module existed: `os.replace` for record writes, `O_CREAT|O_EXCL|O_NOFOLLOW` plus
    an explicit chmod for quarantined samples, and mtime-ordered listings."""

    backend = 'local'

    def __init__(self, name):
        self.name = name

    @property
    def root(self):
        return Path(LOCAL_ROOT) / self.name

    def _path(self, key):
        validate_key(key)
        root = self.root
        path = root / key
        # Defence in depth against the two things validate_key() cannot see: a future
        # edit that loosens the allowlist, and a symlink planted in the store
        # directory that points outside it. realpath() resolves the final component,
        # so a link that leaves the store is refused for *reads* too - O_NOFOLLOW only
        # guards the exclusive-create path, and plain open()/read_bytes() would
        # otherwise follow it.
        if os.path.dirname(os.path.realpath(path)) != os.path.realpath(root):
            raise ValueError(f'storage key {key!r} escapes {self.name}')
        return path

    def _ensure_root(self):
        root = self.root
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _atomic_write(self, key, data, mode):
        """Write via a temp file in the same directory, then `os.replace`.

        Same-directory means same filesystem, which is what makes the replace atomic:
        a concurrent reader sees either the whole previous file or the whole new one,
        never a truncated record. The temp name starts with a dot, so it can never
        collide with a valid key and never appears in `list()`.
        """
        path = self._path(key)
        root = self._ensure_root()
        fd, tmp = tempfile.mkstemp(dir=str(root), prefix='.tmp-', suffix='.part')
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(data)
            # mkstemp creates 0600; set the intended mode explicitly rather than
            # letting it depend on the process umask.
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def write_text(self, key, text):
        self._atomic_write(key, str(text).encode('utf-8'), 0o644)

    def write_bytes(self, key, data, *, exclusive=False, private=False):
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        if not isinstance(data, bytes):
            raise TypeError('data must be bytes')
        mode = 0o600 if private else 0o644
        if not exclusive:
            self._atomic_write(key, data, mode)
            return
        # Exclusive creation cannot go through the temp-and-replace path: replace
        # would overwrite. These are the flags the quarantine store was written and
        # mutation-tested with - O_EXCL because a pre-existing file under a name only
        # this app can derive means something is wrong and truncating it would destroy
        # a sample, O_NOFOLLOW so a planted symlink cannot redirect the write out of
        # the store.
        path = self._path(key)
        self._ensure_root()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, mode)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        # Explicit, because the create mode above is masked by the process umask.
        os.chmod(path, mode)

    def read_bytes(self, key):
        path = self._path(key)
        try:
            return path.read_bytes()
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            return None

    def read_text(self, key):
        data = self.read_bytes(key)
        return None if data is None else data.decode('utf-8', errors='replace')

    def exists(self, key):
        return self._path(key).is_file()

    def delete(self, key):
        path = self._path(key)
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        except IsADirectoryError:
            return False
        return True

    def list(self, *, suffix=None, limit=None):
        root = self.root
        entries = []
        try:
            scan = os.scandir(root)
        except (FileNotFoundError, NotADirectoryError):
            return []
        with scan:
            for item in scan:
                try:
                    validate_key(item.name)
                except ValueError:
                    # Temp artefacts and anything hand-dropped in the directory are
                    # not records; a name this store could not have written is skipped.
                    continue
                try:
                    if not item.is_file(follow_symlinks=False):
                        continue
                    st = item.stat(follow_symlinks=False)
                except OSError:
                    continue
                entries.append({'key': item.name, 'size': st.st_size,
                                'modified': st.st_mtime})
        return _apply_listing(entries, suffix, limit)

    def open_stream(self, key):
        path = self._path(key)
        try:
            return open(path, 'rb')
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            return None

    def local_path(self, key):
        """The real path, or None when the key is absent.

        Existence-checked on purpose: the caller's fallback for "no path" is
        `open_stream()`, which also returns None for a missing key, so a route can
        try `local_path` then `open_stream` then 404 without a third branch. This is
        not a write handle - use `write_bytes()`.
        """
        path = self._path(key)
        return path if path.is_file() else None


class GCSStore(Store):
    """The Google Cloud Storage backend, for Cloud Run.

    Objects live at `<store>/<key>` in one bucket. `google.cloud.storage` is imported
    lazily here and nowhere else, so the local path never needs the dependency.
    """

    backend = 'gcs'

    def __init__(self, name):
        self.name = name
        bucket = (os.environ.get('GCS_BUCKET') or '').strip()
        if not bucket:
            # Loud, at construction. Falling back to local here would write Cloud Run
            # records to a per-instance tmpfs and lose them with no error anywhere.
            raise RuntimeError('STORAGE_BACKEND=gcs requires GCS_BUCKET to be set')
        self.bucket_name = bucket
        self._client = None
        self._bucket = None

    def _blob_name(self, key):
        validate_key(key)
        return f'{self.name}/{key}'

    def _get_bucket(self):
        if self._bucket is None:
            if GCS_CLIENT_FACTORY is not None:
                self._client = GCS_CLIENT_FACTORY()
            else:
                from google.cloud import storage as gcs
                self._client = gcs.Client()
            self._bucket = self._client.bucket(self.bucket_name)
            # Logged once per store: when records go missing on Cloud Run, the first
            # question is always whether this instance was on GCS or on tmpfs.
            logger.info('Store %s -> gs://%s/%s/', self.name, self.bucket_name,
                        self.name)
        return self._bucket

    def _blob(self, key):
        return self._get_bucket().blob(self._blob_name(key))

    @staticmethod
    def _status(exc):
        for attr in ('code', 'status_code'):
            value = getattr(exc, attr, None)
            if isinstance(value, int):
                return value
        return None

    @classmethod
    def _is_missing(cls, exc):
        return cls._status(exc) == 404 or type(exc).__name__ == 'NotFound'

    @classmethod
    def _is_precondition(cls, exc):
        return (cls._status(exc) == 412
                or type(exc).__name__ in ('PreconditionFailed', 'FailedPrecondition'))

    def write_text(self, key, text):
        # GCS object writes are atomic by construction: an upload either completes and
        # becomes the new generation or it does not, and a reader never observes a
        # partial object. There is no temp-and-replace equivalent to perform.
        self._blob(key).upload_from_string(
            str(text).encode('utf-8'),
            content_type=_content_type(key, 'text/plain'))

    def write_bytes(self, key, data, *, exclusive=False, private=False):
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        if not isinstance(data, bytes):
            raise TypeError('data must be bytes')
        # `private` is meaningless here: GCS objects have no POSIX mode, and with
        # uniform bucket-level access their ACLs are IAM-controlled. Confidentiality
        # of the quarantine store on GCS is bucket IAM, nothing this call can set.
        blob = self._blob(key)
        kwargs = {'content_type': _content_type(key)}
        if exclusive:
            # The GCS equivalent of O_EXCL: generation 0 means "only if this object
            # does not exist yet". Server-side, so it is not a check-then-write race.
            kwargs['if_generation_match'] = 0
        try:
            blob.upload_from_string(data, **kwargs)
        except Exception as exc:
            if exclusive and self._is_precondition(exc):
                raise FileExistsError(
                    f'{self._blob_name(key)} already exists') from exc
            raise

    def read_bytes(self, key):
        blob = self._blob(key)
        try:
            return blob.download_as_bytes()
        except Exception as exc:
            if self._is_missing(exc):
                return None
            raise

    def read_text(self, key):
        data = self.read_bytes(key)
        return None if data is None else data.decode('utf-8', errors='replace')

    def exists(self, key):
        return bool(self._blob(key).exists())

    def delete(self, key):
        blob = self._blob(key)
        try:
            blob.delete()
        except Exception as exc:
            if self._is_missing(exc):
                return False
            raise
        return True

    def list(self, *, suffix=None, limit=None):
        prefix = f'{self.name}/'
        entries = []
        for blob in self._get_bucket().list_blobs(prefix=prefix):
            key = (blob.name or '')[len(prefix):]
            try:
                validate_key(key)
            except ValueError:
                continue
            updated = getattr(blob, 'updated', None)
            entries.append({
                'key': key,
                'size': int(getattr(blob, 'size', 0) or 0),
                'modified': updated.timestamp() if updated is not None else 0.0,
            })
        return _apply_listing(entries, suffix, limit)

    def open_stream(self, key):
        """A file object over the object's bytes, or None when it is absent.

        Buffered in memory rather than streamed: the only consumer is `send_file` for
        screenshots and quarantined samples, both already bounded, and a BytesIO
        behaves identically on both backends with no open connection to leak.
        """
        data = self.read_bytes(key)
        return None if data is None else io.BytesIO(data)

    def local_path(self, key):
        """Always None - a GCS object has no filesystem path. Callers that need to
        hand bytes to `send_file` use `open_stream()`."""
        validate_key(key)
        return None
