#!/usr/bin/env python3
"""NexusTrace - operator review queue for outbound abuse.ch submissions.

Nothing NexusTrace collects is published automatically. An analyst proposing a
submission only writes data/submissions/<uuid>.json with status `pending`, and any
sample bytes are held in data/quarantine/ mode 0600. It stays there until an
operator runs this tool.

    approve  is the only command in the whole system that transmits to abuse.ch.
    list, show, reject and purge never touch the network.

Usage:
    python3 scripts/manage_submissions.py list [--status pending] [--limit 20]
    python3 scripts/manage_submissions.py show <id>
    python3 scripts/manage_submissions.py approve <id> [--yes]
    python3 scripts/manage_submissions.py reject <id> --reason "known-good CDN host"
    python3 scripts/manage_submissions.py purge [--max-age-days 30] [--yes]

approve prints the complete publication preview first - every indicator verbatim,
the malware family, threat and IOC type, tags, comment, reference, the attached
sample's name, size and SHA-256, and whether the record goes out anonymously or
attributed to your abuse.ch account - and then asks you to type `yes`. You should
never have to open the JSON to know what leaves the box. Sample bytes are never
printed; name, size and digest only. --yes skips the question for unattended runs.

--yes does not skip the question when the record is flagged `fp_listed`. That means
the indicator is on abuse.ch's own false-positive list: publishing it pollutes a
public dataset other defenders act on, so that confirmation is always interactive
and wants the word PUBLISH. Approval is one-way - nothing in this tool can retract a
submission once it has been sent.

reject requires --reason, and the service deletes the record's quarantined bytes as
it writes the decision.

purge is a dry run unless --yes is passed, matching scripts/purge_data.py. It ages
out quarantined samples only, and it will not delete the bytes of a submission that
is still pending or approved however old they are - that would leave an approval
that can no longer be honoured. Those are listed for you to decide instead. For the
whole-application retention sweep, including the submission records themselves, use
scripts/purge_data.py.

Exit status: 0 success, 1 failure, 2 no such submission (and, from argparse, a usage
error), 3 declined at the prompt.

An operator tool: deliberately not wired into the app, a cron, the Dockerfile, or
start.sh.
"""
import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = Path(__file__).resolve().parent
for _entry in (str(REPO_ROOT), str(SCRIPT_DIR)):
    if _entry not in sys.path:
        sys.path.append(_entry)

from purge_data import RECORD_RE, SAMPLE_RE, fmt_bytes, remove  # noqa: E402

try:
    from app.services import submissions as service
    IMPORT_ERROR = None
except Exception as exc:  # --help and usage errors must still work without the app
    service = None
    IMPORT_ERROR = exc

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_NOT_FOUND = 2
EXIT_DECLINED = 3

# Statuses approve() would silently no-op on. Refusing up front is clearer than
# printing a publication preview for something that will not be published.
ALREADY_DECIDED = ('sent', 'rejected')

DESTINATION_NAMES = {
    'threatfox': 'ThreatFox (public IOC database)',
    'malwarebazaar': 'MalwareBazaar (public malware sample repository)',
    'urlhaus': 'URLhaus (public malware URL database)',
}

RULE = '=' * 78


def _service():
    if service is None:
        sys.exit(f'app.services.submissions could not be imported: {IMPORT_ERROR}')
    return service


def _short_time(value):
    text = str(value or '')
    return text[:19] if len(text) > 19 else text


def _line(label, value):
    print(f'  {label:<16}: {value}')


def _dict(value):
    return value if isinstance(value, dict) else {}


def _joined(values):
    if isinstance(values, (list, tuple)):
        return ', '.join(str(v) for v in values) if values else '-'
    return str(values) if values not in (None, '') else '-'


def _sample_summary(record):
    """Name, size and digest of the attached sample - never its bytes."""
    quarantine = _dict(record.get('quarantine'))
    if not quarantine:
        return None
    payload = _dict(record.get('payload'))
    size = quarantine.get('size')
    return {
        'filename': payload.get('filename') or 'sample.bin',
        'size': fmt_bytes(size) if isinstance(size, int) else (size or 'unknown size'),
        'sha256': quarantine.get('sha256') or '-',
        'stored': bool(quarantine.get('stored')),
        'removed_reason': quarantine.get('removed_reason'),
    }


def print_publication(record):
    """Everything that would leave the box, in one block."""
    payload = _dict(record.get('payload'))
    destination = record.get('destination')
    anonymous = record.get('anonymous')

    _line('submission', record.get('id'))
    _line('kind', record.get('kind') or '-')
    _line('destination', DESTINATION_NAMES.get(destination, destination or 'unknown'))
    if anonymous is True:
        _line('attribution', 'ANONYMOUS - not published under your account name')
    elif anonymous is False:
        _line('attribution', 'ATTRIBUTED - published under your abuse.ch account')
    else:
        _line('attribution', 'UNKNOWN - the record does not say; assume ATTRIBUTED')

    indicators = record.get('indicators') or []
    print(f'  {"indicators":<16}: {len(indicators)}')
    for value in indicators:
        print(f'      {value}')

    _line('malware', payload.get('malware') or '-')
    _line('threat type', payload.get('threat_type') or '-')
    _line('ioc type', payload.get('ioc_type') or '-')
    if payload.get('confidence_level') is not None:
        _line('confidence', payload.get('confidence_level'))
    _line('tags', _joined(payload.get('tags')))
    _line('comment', payload.get('comment') or payload.get('context') or '-')
    _line('reference', payload.get('reference') or _joined(payload.get('references')))
    if payload.get('delivery_method'):
        _line('delivery', payload.get('delivery_method'))

    sample = _sample_summary(record)
    if sample is None:
        _line('sample file', 'none - indicators only')
    else:
        _line('sample file', f"{sample['filename']}  ({sample['size']})")
        _line('sample sha256', sample['sha256'])
        if not sample['stored']:
            _line('sample bytes', 'MISSING from quarantine'
                  + (f" ({sample['removed_reason']})" if sample['removed_reason'] else ''))

    _line('queued by', record.get('queued_by') or '-')
    _line('from analysis', record.get('source_analysis') or '-')
    _line('created', record.get('created_at') or '-')


def print_fp_warning(record):
    matches = record.get('fp_matches') or []
    print()
    print('  !! ' + '-' * 70)
    print('  !! KNOWN FALSE POSITIVE')
    print('  !! This indicator is on abuse.ch\'s own false-positive list. Publishing')
    print('  !! it pollutes a public dataset that other defenders act on.')
    for entry in matches[:5]:
        print(f'  !!   matched: {entry}')
    if len(matches) > 5:
        print(f'  !!   ... and {len(matches) - 5} more')
    print('  !! ' + '-' * 70)


def fetch(svc, sid):
    """One record, or None with the reason already reported. A record file that
    exists but will not load is a different problem from a typo'd id, and an
    operator chasing a queued submission needs to be told which one it is."""
    record = svc.get_submission(sid)
    if record is not None:
        return record
    # RECORD_RE is the same UUID allowlist the stores use; an id that fails it never
    # reaches the filesystem.
    if RECORD_RE.match(f'{sid}.json') and (Path(svc.SUBMISSION_DIR) / f'{sid}.json').exists():
        print(f'Submission {sid} exists but could not be read; the record is corrupt.',
              file=sys.stderr)
    else:
        print(f'No such submission: {sid}', file=sys.stderr)
    return None


def confirm(prompt, expected):
    """Read one line from the operator. A closed stdin is a refusal, not consent."""
    try:
        answer = input(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer.strip() == expected


def cmd_list(args):
    svc = _service()
    rows = svc.list_submissions(status=args.status, limit=args.limit)
    if not rows:
        scope = f" with status '{args.status}'" if args.status else ''
        print(f'No submissions{scope}.')
        return EXIT_OK

    header = (f'{"ID":<36}  {"STATUS":<9}  {"KIND":<6}  {"DESTINATION":<13}  '
              f'{"FP":<3}  {"CREATED":<19}  INDICATOR')
    print(header)
    print('-' * len(header))
    for row in rows:
        indicators = row.get('indicators') or []
        first = str(indicators[0]) if indicators else (row.get('filename') or '-')
        if len(indicators) > 1:
            first += f' (+{len(indicators) - 1} more)'
        print(f'{row.get("id", ""):<36}  {str(row.get("status") or ""):<9}  '
              f'{str(row.get("kind") or ""):<6}  {str(row.get("destination") or ""):<13}  '
              f'{("FP!" if row.get("fp_listed") else ""):<3}  '
              f'{_short_time(row.get("created_at")):<19}  {first}')
    print(f'\n{len(rows)} submission(s).')
    return EXIT_OK


def cmd_show(args):
    svc = _service()
    record = fetch(svc, args.id)
    if record is None:
        return EXIT_NOT_FOUND

    print(RULE)
    print(f'  SUBMISSION {record.get("id")}  [{record.get("status")}]')
    print(RULE)
    print_publication(record)
    print()
    _line('status', record.get('status') or '-')
    _line('updated', record.get('updated_at') or '-')
    _line('approved at', record.get('approved_at') or '-')
    _line('rejected at', record.get('rejected_at') or '-')
    _line('reject reason', record.get('reject_reason') or '-')
    _line('sent at', record.get('sent_at') or '-')
    _line('send attempts', record.get('attempts') if record.get('attempts') is not None else '-')
    _line('error', record.get('error') or '-')
    _line('fp checked', bool(record.get('fp_checked')))
    _line('fp listed', bool(record.get('fp_listed')))

    result = _dict(record.get('result'))
    if result:
        _line('last result', f"state={result.get('state')} "
                             f"reference={result.get('reference') or '-'}")
        raw = _dict(result.get('raw'))
        if raw:
            _line('result detail', raw)

    history = record.get('history') or []
    if history:
        print(f'  {"history":<16}:')
        for step in history:
            step = _dict(step)
            print(f"      {step.get('at', '?')}  {step.get('status', '?')}")

    if record.get('fp_listed'):
        print_fp_warning(record)
    print(RULE)
    return EXIT_OK


def cmd_approve(args):
    svc = _service()
    record = fetch(svc, args.id)
    if record is None:
        return EXIT_NOT_FOUND

    status = record.get('status')
    if status in ALREADY_DECIDED:
        print(f'Submission {args.id} is already {status}; nothing to publish.',
              file=sys.stderr)
        return EXIT_FAIL

    print(RULE)
    print('  ABOUT TO PUBLISH TO abuse.ch - THIS CANNOT BE UNDONE')
    print(RULE)
    print_publication(record)
    if status and status != 'pending':
        print()
        _line('note', f'this record is {status}; approving again re-sends it')
    fp_listed = bool(record.get('fp_listed'))
    if fp_listed:
        print_fp_warning(record)
    print(RULE)

    if fp_listed:
        if args.yes:
            print('--yes is ignored for a false-positive-listed submission.')
        if not confirm('Type PUBLISH to publish a known false positive: ', 'PUBLISH'):
            print('Declined. Nothing was sent.')
            return EXIT_DECLINED
    elif not args.yes:
        if not confirm('Type yes to publish this submission to abuse.ch: ', 'yes'):
            print('Declined. Nothing was sent.')
            return EXIT_DECLINED

    result = svc.approve(args.id)
    if result is None:
        print(f'Submission {args.id} disappeared during approval.', file=sys.stderr)
        return EXIT_NOT_FOUND

    final = result.get('status')
    envelope = _dict(result.get('result'))
    print(f'\nSubmission {result.get("id")} is now {final}.')
    if envelope:
        print(f'  provider state : {envelope.get("state")}')
        if envelope.get('reference'):
            print(f'  reference      : {envelope.get("reference")}')
    if final == 'sent':
        return EXIT_OK
    print(f'  error          : {result.get("error") or "unknown"}', file=sys.stderr)
    print('  The record stays approvable; re-run approve to retry.', file=sys.stderr)
    return EXIT_FAIL


def cmd_reject(args):
    svc = _service()
    record = fetch(svc, args.id)
    if record is None:
        return EXIT_NOT_FOUND
    if record.get('status') in ALREADY_DECIDED:
        print(f'Submission {args.id} is already {record.get("status")}.', file=sys.stderr)
        return EXIT_FAIL

    result = svc.reject(args.id, reason=args.reason)
    if result is None:
        print(f'No such submission: {args.id}', file=sys.stderr)
        return EXIT_NOT_FOUND
    print(f'Submission {result.get("id")} rejected: {result.get("reject_reason")}')
    quarantine = _dict(result.get('quarantine'))
    if quarantine:
        state = 'removed' if not quarantine.get('stored') else 'STILL PRESENT'
        print(f'  quarantined sample: {state}')
    return EXIT_OK


def _owning_status(svc, name):
    """(submission id, status) for one quarantine filename.

    A name this script cannot parse, or a record it cannot read, comes back as
    'unreadable' - which the caller treats as awaiting a decision, so the failure
    mode is keeping malware bytes rather than deleting a live submission's sample.
    """
    match = SAMPLE_RE.match(name)
    if not match:
        return None, 'unreadable'
    sid = match.group(1)
    record = svc.get_submission(sid)
    if record is not None:
        return sid, str(record.get('status') or 'unreadable')
    if (Path(svc.SUBMISSION_DIR) / f'{sid}.json').exists():
        return sid, 'unreadable'
    return sid, 'orphan'


def cmd_purge(args):
    svc = _service()
    # The service's own sweep has no awaiting-decision rule, so it is only ever
    # called in report mode here; this command applies that rule and then deletes
    # what survives it.
    stats = svc.purge_quarantine(args.max_age_days, apply=False)

    doomed, held = [], []
    for name in stats.get('files', []):
        sid, status = _owning_status(svc, name)
        (doomed if status in ('sent', 'rejected', 'failed', 'orphan') else held).append(
            (name, sid, status))

    mode = 'APPLY - files will be deleted' if args.apply else 'DRY RUN - nothing will be deleted'
    print(f'NexusTrace quarantine purge  [{mode}]')
    print(f'  directory : {svc.QUARANTINE_DIR}')
    print(f'  retention : {args.max_age_days:g} days')
    print(f'  checked   : {stats.get("checked", 0)} file(s), '
          f'{stats.get("matched", 0)} past retention')

    verb = 'deleting' if args.apply else 'would delete'
    print(f'\n  {verb}: {len(doomed)}')
    for name, sid, status in doomed:
        print(f'    - {name}  [{status}]')
    if held:
        print(f'\n  held - submission still awaiting a decision: {len(held)}')
        for name, sid, status in held:
            print(f'    ~ {name}  [{status}]  decide with: '
                  f'manage_submissions.py show {sid}')
    for name in stats.get('unexpected', []):
        print(f'    ? {name}  [unrecognised, left alone]')

    if not args.apply:
        print(f'\nDry run: {len(doomed)} file(s) would be deleted. '
              'Re-run with --yes to apply.')
        return EXIT_OK

    store_dir = Path(svc.QUARANTINE_DIR)
    failures = 0
    for name, _sid, _status in doomed:
        try:
            remove(store_dir / name, store_dir)
        except Exception as exc:
            failures += 1
            print(f'FAILED to delete {name}: {exc}', file=sys.stderr)
    print(f'\nDeleted {len(doomed) - failures} file(s).')
    return EXIT_FAIL if failures else EXIT_OK


def build_parser():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='command')

    p_list = sub.add_parser('list', help='list queued submissions, newest first')
    p_list.add_argument('--status', choices=['pending', 'approved', 'rejected',
                                             'sent', 'failed'],
                        help='show only submissions in this status')
    p_list.add_argument('--limit', type=int, default=50,
                        help='maximum rows to show (default: 50)')
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser('show', help='print one submission in full')
    p_show.add_argument('id')
    p_show.set_defaults(func=cmd_show)

    p_approve = sub.add_parser(
        'approve', help='PUBLISH one submission to abuse.ch after confirmation')
    p_approve.add_argument('id')
    p_approve.add_argument('--yes', action='store_true',
                           help='skip the confirmation (never for an fp_listed record)')
    p_approve.set_defaults(func=cmd_approve)

    p_reject = sub.add_parser('reject', help='reject one submission and drop its sample')
    p_reject.add_argument('id')
    p_reject.add_argument('--reason', required=True,
                          help='why it was rejected; recorded on the submission')
    p_reject.set_defaults(func=cmd_reject)

    p_purge = sub.add_parser('purge', help='age out quarantined sample bytes')
    p_purge.add_argument('--max-age-days', type=float, default=30,
                         help='retention window in days (default: 30)')
    p_purge.add_argument('--yes', '--apply', dest='apply', action='store_true',
                         help='actually delete; without this the run is a dry run')
    p_purge.set_defaults(func=cmd_purge)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, 'command', None):
        parser.print_help()
        return EXIT_FAIL
    if args.command == 'purge' and args.max_age_days < 0:
        parser.error('--max-age-days must not be negative')
    if args.command == 'list' and args.limit is not None and args.limit < 0:
        parser.error('--limit must not be negative')
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
