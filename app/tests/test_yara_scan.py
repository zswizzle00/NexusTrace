"""YARA rule matching.

Four API facts here were established by running yara-python 4.5.4, and each one is a
bug if assumed the other way: yara.SyntaxError is NOT the builtin SyntaxError; timeout
takes whole integer seconds and rejects a float; yara.compile() has no directory
argument; and Match objects are not JSON-serializable because matched_data is bytes.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils import yara_scan

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


RULE = '''
rule NexusTrace_Probe : testtag
{
    meta:
        author = "nexustrace"
        description = "fixture"
    strings:
        $a = "SENTINEL-STRING-9c1f"
    condition:
        $a
}
'''


def with_rules(source, body=b'nothing here'):
    """Compile `source` into a temp rules dir and scan a temp file. Returns the record."""
    with tempfile.TemporaryDirectory() as box:
        rules_dir = os.path.join(box, 'yara')
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, 'probe.yar'), 'w') as handle:
            handle.write(source)
        target = os.path.join(box, 'sample.bin')
        with open(target, 'wb') as handle:
            handle.write(body)
        yara_scan.load_rules(rules_dir)
        try:
            return yara_scan.scan(target)
        finally:
            yara_scan.load_rules(None)


def test_absent_rules_directory_is_not_an_error():
    """A missing rules dir means the feature is unconfigured, exactly like a missing
    API key: the card never renders and nothing errors."""
    yara_scan.load_rules(None)
    with tempfile.TemporaryDirectory() as box:
        target = os.path.join(box, 'x.bin')
        with open(target, 'wb') as handle:
            handle.write(b'abc')
        result = yara_scan.scan(target)
    check(result['rules_loaded'] == 0, 'rules were reported loaded with no directory')
    check(result['matches'] == [], 'matches appeared with no rules')
    check(result['error'] is None, f'an unconfigured scan errored: {result["error"]}')


def test_a_match_carries_the_author_meta():
    """DRL 1.1, the licence on the default ruleset, requires that messages based on
    matches retain identification of the author. The record must carry it or the
    template cannot render it."""
    result = with_rules(RULE, body=b'xx SENTINEL-STRING-9c1f xx')
    check(len(result['matches']) == 1, f'expected one match, got {result["matches"]}')
    if result['matches']:
        match = result['matches'][0]
        check(match['rule'] == 'NexusTrace_Probe', f'wrong rule name: {match["rule"]!r}')
        check(match['author'] == 'nexustrace', f'author meta lost: {match!r}')
        check('testtag' in match['tags'], f'tags lost: {match["tags"]!r}')


def test_the_record_is_json_serializable():
    """Match objects are not JSON-serializable and matched_data is bytes. The record
    is written to data/ as JSON, so this must survive json.dumps."""
    result = with_rules(RULE, body=b'SENTINEL-STRING-9c1f')
    serialized = True
    detail = ''
    try:
        json.dumps(result)
    except TypeError as exc:
        serialized = False
        detail = str(exc)
    check(serialized, f'the scan record is not JSON-serializable: {detail}')


def test_a_broken_rule_surfaces_as_an_error_not_a_crash():
    """yara.SyntaxError is not the builtin, so `except SyntaxError` silently misses
    it and the exception escapes into the request."""
    with tempfile.TemporaryDirectory() as box:
        rules_dir = os.path.join(box, 'yara')
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, 'broken.yar'), 'w') as handle:
            handle.write('rule Broken { strings: $a = ')
        try:
            loaded = yara_scan.load_rules(rules_dir)
        except Exception as exc:  # noqa: BLE001 - that is the point
            failures.append(f'a broken rule escaped load_rules as {type(exc).__name__}')
            loaded = -1
        check(loaded == 0, f'a broken ruleset reported {loaded} rules loaded')
    yara_scan.load_rules(None)


def test_match_instances_are_capped():
    """Review Focus 2: a rule matching tens of thousands of times must not produce an
    unbounded record. The record is stored and rendered."""
    result = with_rules(RULE, body=b'SENTINEL-STRING-9c1f ' * 20000)
    # Without this the cap assertion below passes vacuously on a record with no hits.
    check(bool(result['matches']), f'the cap fixture did not match: {result!r}')
    if result['matches']:
        instances = result['matches'][0]['strings'][0]['instances']
        check(len(instances) <= yara_scan.MAX_INSTANCES_PER_STRING,
              f'{len(instances)} instances recorded, cap is '
              f'{yara_scan.MAX_INSTANCES_PER_STRING}')


def test_pid_scanning_is_never_used():
    """match(pid) scans a live process. It must never be reachable from a request, so
    the keyword must not appear in the module source at all."""
    source_path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), 'utils', 'yara_scan.py')
    with open(source_path) as handle:
        source = handle.read()
    check('pid=' not in source,
          'yara_scan.py references pid=, which enables live process scanning')


def test_the_timeout_is_whole_seconds():
    """yara-python rejects a float timeout with TypeError, so the constant has to be
    an int and not merely int-valued."""
    check(isinstance(yara_scan.MATCH_TIMEOUT_SECONDS, int)
          and not isinstance(yara_scan.MATCH_TIMEOUT_SECONDS, bool),
          f'MATCH_TIMEOUT_SECONDS is {type(yara_scan.MATCH_TIMEOUT_SECONDS).__name__}, '
          'a float raises TypeError inside match()')


def test_rules_loaded_reports_configuration():
    """file_service gates the whole analyzer on this, so an unconfigured install must
    report False rather than raising or reporting a stale True."""
    yara_scan.load_rules(None)
    check(yara_scan.RULES_LOADED() is False,
          'RULES_LOADED() is true with no rules directory')
    with tempfile.TemporaryDirectory() as box:
        rules_dir = os.path.join(box, 'yara')
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, 'probe.yar'), 'w') as handle:
            handle.write(RULE)
        yara_scan.load_rules(rules_dir)
        check(yara_scan.RULES_LOADED() is True,
              'RULES_LOADED() is false after a successful compile')
    yara_scan.load_rules(None)


def main():
    test_absent_rules_directory_is_not_an_error()
    test_a_match_carries_the_author_meta()
    test_the_record_is_json_serializable()
    test_a_broken_rule_surfaces_as_an_error_not_a_crash()
    test_match_instances_are_capped()
    test_pid_scanning_is_never_used()
    test_the_timeout_is_whole_seconds()
    test_rules_loaded_reports_configuration()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
