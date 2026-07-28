"""URL scanner routes."""
import logging
from flask import Blueprint, render_template, request, redirect, url_for, send_file, abort, flash
from ..services.scan_service import run_scan, get_scan, list_scans, screenshot_path
from ..utils.url_guard import is_scannable

logger = logging.getLogger(__name__)

scan_bp = Blueprint('scan', __name__)


@scan_bp.route('/url_scan', methods=['GET'])
def url_scan_form():
    recent = list_scans(10)
    return render_template('url_scan.html', recent=recent)


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


@scan_bp.route('/url_scan/screenshot/<scan_id>', methods=['GET'])
def url_scan_screenshot(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    path = screenshot_path(scan_id)
    if not path.exists():
        abort(404)
    return send_file(path, mimetype='image/png')
