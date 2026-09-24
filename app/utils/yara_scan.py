"""YARA matching against operator-supplied rules.

Pure module, no Flask import. The app ships with no rules: `data/yara/` is empty until
an operator runs `scripts/setup_yara_rules.py`, and an empty directory means the card
never renders, exactly as a missing API key makes a provider card absent.

Five things verified against yara-python 4.5.4 that are bugs if assumed otherwise:

- `yara.SyntaxError` is NOT the builtin SyntaxError. Catch `yara.Error`, the common
  base of SyntaxError, TimeoutError and WarningError.
- `timeout=` is whole INTEGER seconds. A float raises TypeError.
- `yara.compile()` has no directory argument. Walk the tree and build a filepaths
  dict; its keys become `match.namespace` verbatim, which gives free grouping.
- Match objects are not JSON-serializable and `matched_data` is bytes, so hits are
  converted before they can reach a `data/*.json` record.
- The GIL IS released during match(), and one module-scope Rules object is safe to
  scan from several threads at once: 16 scans across 8 threads gave a 7.86x speedup
  with no errors. So compile once here and share it.

The `pid` keyword of `match()` scans a LIVE PROCESS. It is never passed, and a test
asserts the module source does not contain it at all.
"""
import logging
import os

logger = logging.getLogger(__name__)

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES_DIR = os.environ.get('NEXUSTRACE_YARA_DIR') or os.path.join(_BASE, 'data', 'yara')

MATCH_TIMEOUT_SECONDS = 10          # int, not float: a float raises TypeError
MAX_MATCHES = 50
MAX_INSTANCES_PER_STRING = 20
MAX_MATCHED_DATA_BYTES = 64

# The default ruleset (Neo23x0/signature-base) references these and will not compile
# without them declared. Real values are supplied per scan.
EXTERNALS = {'filename': '', 'filepath': '', 'extension': '', 'filetype': '', 'owner': ''}

SIGNAL_LABELS = {
    'yara_rule_match': 'Matched an operator-supplied detection rule',
    'analysis_timed_out': 'Rule matching exceeded its time budget',
    'analysis_error': 'Analysis failed',
}

_rules = None
_rule_count = 0


def _signal(key, detail=None):
    return {'key': key, 'label': SIGNAL_LABELS.get(key, key), 'detail': detail}


def RULES_LOADED():
    """True when an operator has supplied rules."""
    return _rules is not None


def load_rules(rules_dir=RULES_DIR):
    """Compile every `.yar`/`.yara` under `rules_dir` and cache it. Returns the file
    count, or 0 when unconfigured or unusable. Never raises: a broken ruleset must
    disable the feature, not break every upload."""
    global _rules, _rule_count
    _rules, _rule_count = None, 0
    if not rules_dir or not os.path.isdir(rules_dir):
        return 0

    import yara

    paths = {}
    for root, _dirs, names in os.walk(rules_dir):
        for name in names:
            if name.endswith(('.yar', '.yara')):
                full = os.path.join(root, name)
                # The namespace is the path relative to the rules root, which gives
                # the result card free grouping by ruleset family.
                paths[os.path.relpath(full, rules_dir)] = full
    if not paths:
        return 0

    try:
        _rules = yara.compile(filepaths=paths, externals=EXTERNALS)
    except yara.Error as exc:               # NOT the builtin SyntaxError
        logger.error('YARA rules failed to compile, matching disabled: %s', exc)
        _rules = None
        return 0
    _rule_count = len(paths)
    return _rule_count


def _serialize(match):
    """A Match is not JSON-serializable and matched_data is bytes."""
    strings = []
    for string_match in match.strings[:MAX_MATCHES]:
        instances = []
        for instance in string_match.instances[:MAX_INSTANCES_PER_STRING]:
            instances.append({
                'offset': instance.offset,
                'matched_length': instance.matched_length,
                'matched_data': instance.matched_data[:MAX_MATCHED_DATA_BYTES].hex(),
            })
        strings.append({'identifier': string_match.identifier, 'instances': instances})
    meta = match.meta or {}
    return {
        'rule': match.rule,
        'namespace': match.namespace,
        'tags': list(match.tags or []),
        # DRL 1.1 requires that match messages retain the author. The template renders
        # this; dropping it here would put the project out of compliance.
        'author': meta.get('author'),
        'meta': meta,
        'strings': strings,
    }


def scan(path):
    """Never raises. An unconfigured scanner returns an empty record, not an error."""
    record = {'matches': [], 'rules_loaded': _rule_count, 'signals': [], 'error': None}
    if _rules is None:
        return record

    import yara

    externals = dict(EXTERNALS)
    externals['filename'] = os.path.basename(path)
    externals['filepath'] = path
    externals['extension'] = os.path.splitext(path)[1].lstrip('.')

    try:
        # timeout is INT seconds. Live-process scanning is never requested: only a
        # filepath is passed.
        hits = _rules.match(path, externals=externals, timeout=MATCH_TIMEOUT_SECONDS)
    except yara.TimeoutError:
        record['signals'].append(_signal('analysis_timed_out'))
        return record
    except yara.Error as exc:
        record['error'] = f'{type(exc).__name__}: {exc}'
        record['signals'].append(_signal('analysis_error', record['error']))
        return record

    record['matches'] = [_serialize(hit) for hit in hits[:MAX_MATCHES]]
    if record['matches']:
        names = ', '.join(sorted({m['rule'] for m in record['matches']})[:5])
        record['signals'].append(_signal('yara_rule_match', names))
    return record


load_rules()
