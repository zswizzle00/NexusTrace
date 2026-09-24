"""Identity scan routes. Registered without a URL prefix, like email_routes.py, which is
this module's closest analogue: no URL prefix, a record id off the URL, and a
confirm-then-delete pair.

**There is no listing route.** The e-mail and URL scanner listings were removed from this
app because any visitor could browse other people's submissions, and this surface
enumerates a named person's accounts, which would be a worse instance of the same
problem. A record is reachable only by its direct link.

Imports the service names directly, not the module, because app/tests/test_identity_routes.py
patches `identity_routes.run_identity_scan`: that patch only takes effect on a name bound in
this module's own namespace.
"""
import json
import logging
import re
import uuid
from datetime import datetime, timezone

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)

from ..services.identity_service import run_identity_scan, ScannerBusy
from ..utils.identity_findings import safe_url
from ..utils.storage import store, validate_key

logger = logging.getLogger(__name__)

identity_bp = Blueprint('identity', __name__)

# A username cannot contain '@' on any platform either engine checks, so the target
# itself says which mode it is. Asking the analyst to restate it was a way to get it
# wrong: Sherlock is username-only and user-scanner runs a different orchestrator per
# mode, so a mismatched answer silently scanned the wrong thing.
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$')


def detect_mode(target):
    """'email' when the target is an e-mail address, otherwise 'username'."""
    return 'email' if _EMAIL_RE.match((target or '').strip()) else 'username'


def _record_key(scan_id):
    """The identity-store key for an id off the URL, or None when the id could never
    name a record. A rejected id is a 404, not a ValueError at the store."""
    try:
        return validate_key(f'{scan_id}.json')
    except ValueError:
        return None


def _get_record(scan_id):
    key = _record_key(scan_id)
    if key is None:
        return None
    raw = store('identity').read_text(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


@identity_bp.route('/identity_scan', methods=['GET'])
def identity_scan_form():
    return render_template('identity_scan.html',
                           target=request.args.get('target', ''))


@identity_bp.route('/identity_scan', methods=['POST'])
def identity_scan_submit():
    target = (request.form.get('target') or '').strip()
    mode = detect_mode(target)

    if not target:
        flash('Enter a username or e-mail address to scan.', 'error')
        return redirect(url_for('identity.identity_scan_form'))

    try:
        record = run_identity_scan(target, mode=mode)
    except ScannerBusy:
        flash('Two identity scans are already running. Try again in a minute.', 'error')
        return redirect(url_for('identity.identity_scan_form'))

    scan_id = str(uuid.uuid4())
    record['id'] = scan_id
    record['created_at'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    store('identity').write_text(f'{scan_id}.json', json.dumps(record))

    return redirect(url_for('identity.identity_scan_result', scan_id=scan_id))


@identity_bp.route('/identity_scan/<scan_id>', methods=['GET'])
def identity_scan_result(scan_id):
    record = _get_record(scan_id)
    if record is None:
        abort(404)
    # Guard again on read, not only on write. There is exactly one writer today and it
    # already normalises every URL, but this is the one choke point every store passes
    # through, and a record written to disk before the scheme allowlist landed is not
    # protected by fixing the writer alone.
    for finding in record.get('findings') or ():
        if isinstance(finding, dict):
            finding['url'] = safe_url(finding.get('url'))
    return render_template('identity_result.html', record=record)


@identity_bp.route('/identity_scan/<scan_id>/delete', methods=['GET'])
def identity_scan_delete_confirm(scan_id):
    record = _get_record(scan_id)
    if record is None:
        abort(404)
    return render_template(
        'confirm_delete.html',
        kind='identity scan',
        summary=record.get('target') or '(no target)',
        removes='Removes the stored findings and breach exposure data for this target.',
        action=url_for('identity.identity_scan_delete', scan_id=scan_id),
        cancel=url_for('identity.identity_scan_result', scan_id=scan_id),
    )


@identity_bp.route('/identity_scan/<scan_id>/delete', methods=['POST'])
def identity_scan_delete(scan_id):
    key = _record_key(scan_id)
    if key is None or _get_record(scan_id) is None:
        abort(404)
    store('identity').delete(key)
    logger.info('Deleted identity scan %s', scan_id)
    flash('Identity scan deleted.', 'info')
    return redirect(url_for('identity.identity_scan_form'))
