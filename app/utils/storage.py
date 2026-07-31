"""Record storage for the five filesystem-backed stores, on local disk or GCS.

    scans        data/scans/<uuid>.json
    screenshots  data/screenshots/<uuid>[-<stage>].png
    analyses     data/analyses/<uuid>.json
    submissions  data/submissions/<uuid>.json
    quarantine   data/quarantine/<sha256>-<uuid>.bin

On Docker and in dev that filesystem is real and shared. On Cloud Run it is a
per-instance tmpfs that evaporates with the container, so a scan written by one
instance is invisible to the next request. This module is the seam: one flat key/value
interface, a local backend keeping the previous on-disk semantics exactly, and a GCS
backend for Cloud Run, selected by `STORAGE_BACKEND`. `google-cloud-storage` is
imported lazily inside the GCS backend only, so the local path never needs it.

**A `gcs` backend with no `GCS_BUCKET` raises instead of falling back to local.**
On Cloud Run a silent fallback writes to tmpfs and loses the data with no error
anywhere; the loud failure is the whole point of the check.

**Keys are untrusted.** They arrive from URL path segments (`/url_scan/<scan_id>`,
`?stage=`) and are the path-traversal boundary for all five stores at once, so
`validate_key()` is a strict allowlist (`[A-Za-z0-9._-]`, no separators, no leading
dot, no `..`, max 255), and every method funnels through it before touching a backend.
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

# Fits every name the app generates (a quarantine key is 101 chars) and every filesystem.
MAX_KEY_LENGTH = 255

# Matched with fullmatch(), not match(): `$` also matches before a trailing newline,
# which would accept "a.json\n" as a key.
_KEY_RE = re.compile(r'[A-Za-z0-9._-]+')

_BASE = Path(__file__).resolve().parent.parent.parent

# Re-read on every access, not captured at construction, so tests can repoint the tree.
LOCAL_ROOT = _BASE / 'data'

# Test seam: called instead of importing google.cloud.storage, so the GCS paths are
# exercisable without the dependency installed.
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
    """Return `key` unchanged, or raise ValueError. Rejects anything that is not a single
    flat filename: separators, `..`, a leading dot, NUL, absolute paths, and every
    character outside `[A-Za-z0-9._-]`. The allowlist frees the rest of this module from
    per-call traversal reasoning - an accepted key cannot express a parent directory, a
    hidden file, or a device name."""
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
    """'local' or 'gcs'. An unrecognised STORAGE_BACKEND raises rather than defaulting,
    for the same reason a missing GCS_BUCKET does: a typo that silently means "local" on
    Cloud Run is data loss with no signal."""
    name = (os.environ.get('STORAGE_BACKEND') or 'local').strip().lower()
    if name not in BACKENDS:
        raise ValueError(f'unknown STORAGE_BACKEND {name!r}; expected one of '
                         f'{", ".join(BACKENDS)}')
    return name


def store(name):
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
    """Drop memoised Store objects. Only needed after changing STORAGE_BACKEND or GCS_BUCKET
    inside a running process."""
    with _cache_lock:
        _cache.clear()


class Store:
    """Flat key/value store. `key` is a single filename, validated on every call.
    `list()` entries are `{'key', 'size', 'modified'}`, `modified` being a POSIX
    timestamp (`st_mtime` locally, `blob.updated.timestamp()` on GCS) so newest-first
    ordering means the same thing on both backends."""

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
    """The filesystem backend, preserving the semantics the services had before this module
    existed: `os.replace` for record writes, `O_CREAT|O_EXCL|O_NOFOLLOW` plus an explicit
    chmod for quarantined samples, mtime-ordered listings."""

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
        # Defence in depth against what validate_key() cannot see: a future edit that
        # loosens the allowlist, and a symlink planted in the store directory pointing
        # outside it. realpath() resolves the final component, so a link that leaves the
        # store is refused for *reads* too - O_NOFOLLOW only guards exclusive create.
        if os.path.dirname(os.path.realpath(path)) != os.path.realpath(root):
            raise ValueError(f'storage key {key!r} escapes {self.name}')
        return path

    def _ensure_root(self):
        root = self.root
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _atomic_write(self, key, data, mode):
        """Same-directory temp file, then `os.replace`. Same directory means same
        filesystem, which is what makes the replace atomic: a concurrent reader sees the
        whole previous file or the whole new one, never a truncated record. The temp name
        starts with a dot, so it can never collide with a valid key nor appear in `list()`."""
        path = self._path(key)
        root = self._ensure_root()
        fd, tmp = tempfile.mkstemp(dir=str(root), prefix='.tmp-', suffix='.part')
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(data)
            # Explicit, so the final mode does not depend on the process umask.
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
        # Cannot go through temp-and-replace: replace would overwrite. O_EXCL because a
        # pre-existing file under a name only this app can derive means something is wrong
        # and truncating it would destroy a sample; O_NOFOLLOW so a planted symlink cannot
        # redirect the write out of the store.
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
                    # A name this store could not have written is not a record: temp
                    # artefacts and anything hand-dropped into the directory.
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
        """The real path, or None when the key is absent. Existence-checked on purpose: the
        caller's fallback for "no path" is `open_stream()`, which also returns None for a
        missing key, so a route is `local_path()` -> `open_stream()` -> 404 with no third
        branch. Not a write handle."""
        path = self._path(key)
        return path if path.is_file() else None


class GCSStore(Store):
    """The Google Cloud Storage backend, for Cloud Run. Objects live at `<store>/<key>`
    in one bucket. Atomicity is inherent, exclusivity is an `ifGenerationMatch=0`
    precondition, and POSIX mode is meaningless - bucket IAM is the control that `0600`
    provided locally."""

    backend = 'gcs'

    def __init__(self, name):
        self.name = name
        bucket = (os.environ.get('GCS_BUCKET') or '').strip()
        if not bucket:
            # Loud, at construction: see the module docstring.
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
            # Once per store: when records go missing on Cloud Run the first question is
            # always whether this instance was on GCS or on tmpfs.
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
        # No temp-and-replace equivalent to perform: an upload either becomes the new
        # generation or it does not, and a reader never observes a partial object.
        self._blob(key).upload_from_string(
            str(text).encode('utf-8'),
            content_type=_content_type(key, 'text/plain'))

    def write_bytes(self, key, data, *, exclusive=False, private=False):
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        if not isinstance(data, bytes):
            raise TypeError('data must be bytes')
        # `private` is deliberately ignored: GCS objects have no POSIX mode, so
        # confidentiality of the quarantine store is bucket IAM, not anything set here.
        blob = self._blob(key)
        kwargs = {'content_type': _content_type(key)}
        if exclusive:
            # The GCS O_EXCL: generation 0 is "only if this object does not exist yet",
            # evaluated server-side, so it is not a check-then-write race.
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
        """A file object over the object's bytes, or None when absent. Buffered in memory
        rather than streamed: the only consumer is `send_file` for screenshots and
        quarantined samples, both already bounded, and a BytesIO leaks no connection."""
        data = self.read_bytes(key)
        return None if data is None else io.BytesIO(data)

    def local_path(self, key):
        """Always None: a GCS object has no filesystem path, so callers fall through to
        `open_stream()`."""
        validate_key(key)
        return None
