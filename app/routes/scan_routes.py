import logging
from flask import Blueprint, render_template, request, redirect, url_for, send_file, abort, flash
from ..services.scan_service import (
    get_scan,
    run_scan,
    screenshot_key,
    screenshot_local_path,
    screenshot_stream,
)
from ..utils.storage import store, validate_key
from ..utils.url_guard import is_scannable

logger = logging.getLogger(__name__)

scan_bp = Blueprint('scan', __name__)


def _scan_record_key(scan_id):
    """The scans-store key for an id off the URL, or None when the id could never
    name a record. The store's allowlist is the traversal boundary, so a rejected
    id has to become a 404 here rather than a ValueError at the store."""
    try:
        return validate_key(f'{scan_id}.json')
    except ValueError:
        return None


def _screenshot_keys(scan_id):
    """Every screenshot stored for a scan: the full-page `<id>.png` plus each staged
    `<id>-<stage>.png`. Enumerated from the store, not from the record's
    `screenshots` list; a frame the record never mentioned still has to go."""
    full = screenshot_key(scan_id)
    prefix = f'{scan_id}-'
    return [entry['key'] for entry in store('screenshots').list(suffix='.png')
            if entry['key'] == full or entry['key'].startswith(prefix)]


@scan_bp.route('/url_scan', methods=['GET'])
def url_scan_form():
    return render_template('url_scan.html')


@scan_bp.route('/url_scan', methods=['POST'])
def url_scan_submit():
    url = (request.form.get('url') or '').strip()
    device = request.form.get('device', 'desktop')
    if device not in ('desktop', 'mobile'):
        device = 'desktop'

    if not url:
        flash('Please enter a URL to scan.', 'error')
        return redirect(url_for('scan.url_scan_form'))

    if not is_scannable(url):
        flash('That URL is not allowed (private, local, or non-HTTP address).', 'error')
        return redirect(url_for('scan.url_scan_form'))

    scan = run_scan(url, device=device)
    from ..services.scan_service import save_scan
    save_scan(scan)

    return redirect(url_for('scan.url_scan_result', scan_id=scan['id']))


@scan_bp.route('/url_scan/<scan_id>', methods=['GET'])
def url_scan_result(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    return render_template('scan_result.html', scan=scan)


@scan_bp.route('/url_scan/<scan_id>/delete', methods=['GET'])
def url_scan_delete_confirm(scan_id):
    scan = get_scan(scan_id)
    if not scan or _scan_record_key(scan_id) is None:
        abort(404)
    return render_template(
        'confirm_delete.html',
        kind='scan',
        summary=scan.get('url') or scan_id,
        removes='Removes the scan record and every screenshot taken for it.',
        action=url_for('scan.url_scan_delete', scan_id=scan_id),
        cancel=url_for('scan.url_scan_result', scan_id=scan_id),
    )


@scan_bp.route('/url_scan/<scan_id>/delete', methods=['POST'])
def url_scan_delete(scan_id):
    record_key = _scan_record_key(scan_id)
    if record_key is None or get_scan(scan_id) is None:
        abort(404)
    shots = _screenshot_keys(scan_id)
    for key in shots:
        store('screenshots').delete(key)
    store('scans').delete(record_key)
    logger.info('Deleted scan %s and %d screenshot(s)', scan_id, len(shots))
    flash('Scan deleted.', 'info')
    return redirect(url_for('scan.url_scan_form'))


@scan_bp.route('/url_scan/screenshot/<scan_id>', methods=['GET'])
def url_scan_screenshot(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    # ?stage=load|after-scroll|after-consent selects a staged frame; no stage is
    # the full-page shot. Whitelisted, never used to build a path from raw input.
    stage = request.args.get('stage')
    if stage is not None and stage not in ('load', 'after-scroll', 'after-consent'):
        abort(404)
    # Served from disk when the store is local, and from its bytes otherwise;
    # a GCS-backed screenshot has no filesystem path.
    path = screenshot_local_path(scan_id, stage)
    if path is not None:
        return send_file(path, mimetype='image/png')
    stream = screenshot_stream(scan_id, stage)
    if stream is None:
        abort(404)
    return send_file(stream, mimetype='image/png')
