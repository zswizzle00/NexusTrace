"""Pins app/utils/identity_findings.py. Pure: no network, no subprocess, no Flask.

This file exists because tasks/lessons.md (2026-07-28, "Hand-authored matching logic is
where my own defects cluster") identifies exactly this shape of code as the highest
defect density in the project. The merge decides what an analyst is told about a real
person, and both directions are harmful: a false "found" invents an account, a false
"not found" hides one.

The distinction the cases guard hardest is "not covered" versus "said no". Only one
engine covers most sites, so collapsing those two into a single negative would let the
page imply both engines checked when only one did.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils.identity_findings import (STATUS_RANK, merge, normalize_sherlock,
                                         normalize_user_scanner, summarize)

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


# Sherlock's QueryStatus values, verified against sherlock-project 0.16.2.
SHERLOCK_STATUS_CASES = [
    ('Claimed', 'found'),
    ('Available', 'not_found'),
    ('WAF', 'blocked'),
    ('Unknown', 'unknown'),
    ('Illegal', 'not_applicable'),
]

# user-scanner's Status values, verified against user-scanner 1.5.2.
USER_SCANNER_STATUS_CASES = [
    ('TAKEN', 'found'),
    ('AVAILABLE', 'not_found'),
    ('ERROR', 'unknown'),
    ('SKIPPED', 'not_applicable'),
]


def test_sherlock_status_mapping():
    for raw, expected in SHERLOCK_STATUS_CASES:
        got = normalize_sherlock('GitHub', {'status': raw,
                                            'url_user': 'https://github.com/x'})
        check(got['status'] == expected,
              f'normalize_sherlock status {raw!r} -> {got["status"]!r}, expected {expected!r}')
        check(got['engines'] == ['sherlock'],
              f'normalize_sherlock did not tag its engine for {raw!r}')


def test_user_scanner_status_mapping():
    for raw, expected in USER_SCANNER_STATUS_CASES:
        got = normalize_user_scanner({'site_name': 'GitHub', 'status': raw,
                                      'url': 'https://github.com/x',
                                      'category': 'dev'})
        check(got['status'] == expected,
              f'normalize_user_scanner status {raw!r} -> {got["status"]!r}, '
              f'expected {expected!r}')
        check(got['engines'] == ['user-scanner'],
              f'normalize_user_scanner did not tag its engine for {raw!r}')


def test_unknown_vendor_status_is_unknown_not_a_crash():
    """A vendor version bump that adds a status must degrade, not raise or silently
    become a negative."""
    got = normalize_sherlock('GitHub', {'status': 'SOMETHING_NEW', 'url_user': ''})
    check(got['status'] == 'unknown',
          f'an unrecognised Sherlock status became {got["status"]!r}, expected unknown')
    got = normalize_user_scanner({'site_name': 'GitHub', 'status': 'SOMETHING_NEW'})
    check(got['status'] == 'unknown',
          f'an unrecognised user-scanner status became {got["status"]!r}, expected unknown')


def test_merge_corroborates_when_both_engines_agree():
    merged = merge([
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'found',
         'engines': ['sherlock'], 'category': None, 'metadata': {}, 'reason': None},
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'found',
         'engines': ['user-scanner'], 'category': 'dev', 'metadata': {'bio': 'hi'},
         'reason': None},
    ])
    check(len(merged) == 1, f'two reports of one site produced {len(merged)} rows')
    row = merged[0]
    check(sorted(row['engines']) == ['sherlock', 'user-scanner'],
          f'corroboration lost: engines={row["engines"]!r}')
    check(row['status'] == 'found', f'merged status={row["status"]!r}')
    check(row['category'] == 'dev', 'the richer category was dropped in the merge')
    check(row['metadata'].get('bio') == 'hi', 'metadata was dropped in the merge')


def test_merge_dedupes_on_registrable_domain_not_raw_host():
    """www.example.com and example.com are the same site. registrable_domain() is reused
    rather than reimplemented, because it already backs the scanner's redirect logic and
    .eml spoofing detection and a second implementation would drift."""
    merged = merge([
        {'site': 'Example', 'url': 'https://www.example.com/alice', 'status': 'found',
         'engines': ['sherlock'], 'category': None, 'metadata': {}, 'reason': None},
        {'site': 'Example', 'url': 'https://example.com/alice', 'status': 'found',
         'engines': ['user-scanner'], 'category': None, 'metadata': {}, 'reason': None},
    ])
    check(len(merged) == 1, f'www and apex were not merged: {len(merged)} rows')


def test_merge_keeps_different_sites_apart():
    merged = merge([
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'found',
         'engines': ['sherlock'], 'category': None, 'metadata': {}, 'reason': None},
        {'site': 'GitLab', 'url': 'https://gitlab.com/alice', 'status': 'found',
         'engines': ['user-scanner'], 'category': None, 'metadata': {}, 'reason': None},
    ])
    check(len(merged) == 2, f'two distinct sites collapsed into {len(merged)} rows')


def test_merge_resolves_status_conflict_to_the_stronger_claim():
    """found > blocked > unknown > not_found > not_applicable. The losing claim is kept
    in `reason`, because a disagreement between engines is information, not noise."""
    merged = merge([
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'not_found',
         'engines': ['sherlock'], 'category': None, 'metadata': {}, 'reason': None},
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'found',
         'engines': ['user-scanner'], 'category': None, 'metadata': {}, 'reason': None},
    ])
    check(len(merged) == 1, 'conflict case did not merge')
    row = merged[0]
    check(row['status'] == 'found',
          f'conflict resolved to {row["status"]!r}, expected the stronger claim')
    check(row['reason'] and 'sherlock' in row['reason'].lower(),
          f'the losing claim was discarded instead of recorded: reason={row["reason"]!r}')


def test_status_rank_is_total_and_ordered():
    order = ['found', 'blocked', 'unknown', 'not_found', 'not_applicable']
    for stronger, weaker in zip(order, order[1:]):
        check(STATUS_RANK[stronger] > STATUS_RANK[weaker],
              f'{stronger} does not outrank {weaker}')


def test_summarize_counts_corroboration_separately():
    merged = [
        {'site': 'A', 'status': 'found', 'engines': ['sherlock', 'user-scanner'],
         'agreeing': ['sherlock', 'user-scanner'],
         'url': 'https://a.test/x', 'category': None, 'metadata': {}, 'reason': None},
        {'site': 'B', 'status': 'found', 'engines': ['sherlock'],
         'agreeing': ['sherlock'],
         'url': 'https://b.test/x', 'category': None, 'metadata': {}, 'reason': None},
        {'site': 'C', 'status': 'not_found', 'engines': ['user-scanner'],
         'agreeing': ['user-scanner'],
         'url': None, 'category': None, 'metadata': {}, 'reason': None},
        {'site': 'D', 'status': 'blocked', 'engines': ['sherlock'],
         'agreeing': ['sherlock'],
         'url': None, 'category': None, 'metadata': {}, 'reason': None},
    ]
    s = summarize(merged)
    check(s['found'] == 2, f'found={s["found"]!r}, expected 2')
    check(s['corroborated'] == 1, f'corroborated={s["corroborated"]!r}, expected 1')
    check(s['blocked'] == 1, f'blocked={s["blocked"]!r}, expected 1')
    check(s['checked'] == 4, f'checked={s["checked"]!r}, expected 4')


def test_summarize_has_no_verdict_or_score():
    s = summarize([])
    for banned in ('verdict', 'score', 'level', 'malicious'):
        check(banned not in s,
              f'summarize emitted {banned!r}; this surface renders no verdict')


def test_merge_survives_junk_rows():
    """The worker is a separate process parsing vendor output. A missing url, a None
    site, or an empty dict must not take down the merge."""
    try:
        merged = merge([
            {'site': None, 'url': None, 'status': 'found', 'engines': ['sherlock'],
             'category': None, 'metadata': {}, 'reason': None},
            {},
            {'site': 'GitHub', 'status': 'found', 'engines': ['user-scanner']},
        ])
    except Exception as exc:  # noqa: BLE001 - the point of the case
        failures.append(f'merge raised on junk rows: {exc!r}')
        return
    check(isinstance(merged, list), 'merge did not return a list for junk rows')


# The real collision pairs from sherlock-project 0.16.2's bundled data.json.
COLLIDING_SITES = [
    ('Steam Community (User)', 'https://steamcommunity.com/id/alice',
     'Steam Community (Group)', 'https://steamcommunity.com/groups/alice'),
    ('Genius (Users)', 'https://genius.com/alice',
     'Genius (Artists)', 'https://genius.com/artists/alice'),
    ('Apple Developer', 'https://developer.apple.com/alice',
     'Apple Discussions', 'https://discussions.apple.com/profile/alice'),
]


def test_two_services_on_one_domain_do_not_merge():
    """Sherlock's own list has 10 registrable domains carrying 20 distinct sites. Keyed
    on domain alone they merge, the merge takes the stronger status, and a `found` on one
    invents an account on the other under the other's name."""
    for name_a, url_a, name_b, url_b in COLLIDING_SITES:
        merged = merge([
            {'site': name_a, 'url': url_a, 'status': 'not_found',
             'engines': ['sherlock'], 'category': None, 'metadata': {}, 'reason': None},
            {'site': name_b, 'url': url_b, 'status': 'found',
             'engines': ['sherlock'], 'category': None, 'metadata': {}, 'reason': None},
        ])
        check(len(merged) == 2,
              f'{name_a!r} and {name_b!r} merged into {len(merged)} row(s)')
        found = [r for r in merged if r['status'] == 'found']
        check(len(found) == 1 and found[0]['site'] == name_b,
              f'the found status landed on {found and found[0]["site"]!r}, '
              f'expected {name_b!r}')


def test_losing_claim_names_only_the_engines_that_made_it():
    merged = merge([
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'not_found',
         'engines': ['sherlock'], 'category': None, 'metadata': {}, 'reason': None},
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'found',
         'engines': ['user-scanner'], 'category': None, 'metadata': {}, 'reason': None},
    ])
    reason = (merged[0].get('reason') or '').lower()
    check('sherlock reported not_found' in reason,
          f'reason={reason!r}, expected only sherlock credited with not_found')
    check('user-scanner reported not_found' not in reason,
          f'reason={reason!r} credits user-scanner with a claim it never made')


def test_merge_is_order_independent():
    a = {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'not_found',
         'engines': ['sherlock'], 'category': None, 'metadata': {}, 'reason': None}
    b = {'site': 'GitHub', 'url': 'https://www.github.com/alice', 'status': 'found',
         'engines': ['user-scanner'], 'category': 'dev', 'metadata': {}, 'reason': None}
    forward, reverse = merge([a, b]), merge([b, a])
    check(len(forward) == len(reverse) == 1, 'order changed the row count')
    for field in ('status', 'engines', 'reason'):
        check(forward[0][field] == reverse[0][field],
              f'{field} depends on input order: '
              f'{forward[0][field]!r} vs {reverse[0][field]!r}')


def test_duplicate_engine_is_not_corroboration():
    s = summarize([{'site': 'A', 'status': 'found',
                    'engines': ['sherlock', 'sherlock'], 'url': None,
                    'category': None, 'metadata': {}, 'reason': None}])
    check(s['corroborated'] == 0,
          f'one engine reported twice counted as corroborated={s["corroborated"]!r}')


def test_three_way_conflict_is_order_independent():
    """Two engines can still produce three claims for one site, because one engine can
    report a site twice. An earlier version passed the two-input order test while a
    third claim still made the text depend on arrival order."""
    import itertools

    base = {'site': 'GitHub', 'url': 'https://github.com/alice', 'category': None,
            'metadata': {}, 'reason': None}
    claims = [
        {**base, 'status': 'not_found', 'engines': ['sherlock']},
        {**base, 'status': 'found', 'engines': ['user-scanner']},
        {**base, 'status': 'blocked', 'engines': ['third-engine']},
    ]

    seen = set()
    for permutation in itertools.permutations(claims):
        merged = merge(list(permutation))
        if len(merged) != 1:
            failures.append(f'a 3-way conflict produced {len(merged)} rows')
            return
        row = merged[0]
        seen.add((row['status'], tuple(row['engines']), row['reason']))

    check(len(seen) == 1,
          f'a 3-way conflict is order dependent: {len(seen)} distinct outcomes {seen}')


def test_each_engine_is_credited_only_with_its_own_claim():
    merged = merge([
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'not_found',
         'engines': ['sherlock'], 'category': None, 'metadata': {}, 'reason': None},
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'found',
         'engines': ['user-scanner'], 'category': None, 'metadata': {}, 'reason': None},
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'blocked',
         'engines': ['third-engine'], 'category': None, 'metadata': {}, 'reason': None},
    ])
    row = merged[0]
    check(row['claims'] == {'sherlock': 'not_found', 'user-scanner': 'found',
                            'third-engine': 'blocked'},
          f'claims={row["claims"]!r} does not record each engine''s own status')
    reason = row['reason'] or ''
    check('user-scanner reported blocked' not in reason,
          f'reason={reason!r} credits user-scanner with a claim it never made')
    check('sherlock reported not_found' in reason and 'third-engine reported blocked' in reason,
          f'reason={reason!r} dropped a genuine dissenting claim')


# (url, should_survive)
URL_SCHEME_CASES = [
    ('http://ok.test/alice', True),
    ('https://ok.test/alice', True),
    ('HtTpS://ok.test/alice', True),      # scheme comparison is case-insensitive
    ('  https://ok.test/alice  ', True),  # padding is stripped, not a rejection
    ('javascript:alert(1)', False),
    ('data:text/html,<script>alert(1)</script>', False),
    ('vbscript:msgbox(1)', False),
    ('file:///etc/passwd', False),
    ('//evil.test/alice', False),         # protocol-relative: browser inherits ours
    ('', False),
    (None, False),
    (12345, False),
]


def test_only_http_urls_survive_normalisation():
    """These URLs come from a vendor site list, not from the user, and they land in an
    href. Jinja escapes HTML metacharacters, not URI schemes, so the allowlist has to
    sit here at the data boundary."""
    for url, should_survive in URL_SCHEME_CASES:
        got = normalize_sherlock('X', {'status': 'Claimed', 'url_user': url})['url']
        check(bool(got) == should_survive,
              f'normalize_sherlock url={url!r} -> {got!r}, '
              f'expected {"kept" if should_survive else "dropped"}')

        got = normalize_user_scanner({'site_name': 'X', 'status': 'TAKEN',
                                      'url': url})['url']
        check(bool(got) == should_survive,
              f'normalize_user_scanner url={url!r} -> {got!r}, '
              f'expected {"kept" if should_survive else "dropped"}')


def test_a_rejected_url_loses_the_link_not_the_finding():
    """Dropping an unsafe URL must not drop the account it points at. The row still
    matters; it just stops being clickable. It then dedupes by name rather than by
    host, so corroboration across engines still works."""
    rows = merge([
        normalize_sherlock('GitHub', {'status': 'Claimed',
                                      'url_user': 'javascript:alert(1)'}),
        normalize_user_scanner({'site_name': 'GitHub', 'status': 'TAKEN',
                                'url': 'javascript:alert(1)'}),
    ])
    check(len(rows) == 1, f'the finding split into {len(rows)} rows instead of merging')
    check(rows[0]['status'] == 'found', 'the finding was lost with its URL')
    check(rows[0]['url'] is None, f'an unsafe URL survived: {rows[0]["url"]!r}')
    check(sorted(rows[0]['engines']) == ['sherlock', 'user-scanner'],
          f'corroboration lost when the URL was dropped: {rows[0]["engines"]!r}')


def test_disagreement_is_not_corroboration():
    """`engines` lists everyone who reported, including dissenters. A corroboration badge
    built on it claims two engines confirmed an account when one of them said the
    opposite, about a named person."""
    rows = merge([
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'found',
         'engines': ['sherlock'], 'category': None, 'metadata': {}, 'reason': None},
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'not_found',
         'engines': ['user-scanner'], 'category': None, 'metadata': {}, 'reason': None},
    ])
    row = rows[0]
    check(row['agreeing'] == ['sherlock'],
          f'agreeing={row.get("agreeing")!r}, expected only the engine that found it')
    check(summarize(rows)['corroborated'] == 0,
          'a disagreement was counted as corroboration')

    agreed = merge([
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'found',
         'engines': ['sherlock'], 'category': None, 'metadata': {}, 'reason': None},
        {'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'found',
         'engines': ['user-scanner'], 'category': None, 'metadata': {}, 'reason': None},
    ])
    check(agreed[0]['agreeing'] == ['sherlock', 'user-scanner'],
          f'genuine agreement was not recorded: {agreed[0].get("agreeing")!r}')
    check(summarize(agreed)['corroborated'] == 1,
          'genuine corroboration was not counted')


def main():
    test_sherlock_status_mapping()
    test_user_scanner_status_mapping()
    test_unknown_vendor_status_is_unknown_not_a_crash()
    test_merge_corroborates_when_both_engines_agree()
    test_merge_dedupes_on_registrable_domain_not_raw_host()
    test_merge_keeps_different_sites_apart()
    test_merge_resolves_status_conflict_to_the_stronger_claim()
    test_status_rank_is_total_and_ordered()
    test_summarize_counts_corroboration_separately()
    test_summarize_has_no_verdict_or_score()
    test_merge_survives_junk_rows()
    test_two_services_on_one_domain_do_not_merge()
    test_losing_claim_names_only_the_engines_that_made_it()
    test_merge_is_order_independent()
    test_duplicate_engine_is_not_corroboration()
    test_three_way_conflict_is_order_independent()
    test_each_engine_is_credited_only_with_its_own_claim()
    test_only_http_urls_survive_normalisation()
    test_a_rejected_url_loses_the_link_not_the_finding()
    test_disagreement_is_not_corroboration()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
