"""Uploaded-file analysis routes.

Two entry points share one pipeline: `POST /api/file/analyze_file` answers JSON for
SIEM/SOAR callers, `POST /api/file/analyze` renders the browser page. Both are CSRF
protected - neither is exempted.

Results are rendered synchronously and never stored. The upload lands in a
per-request temp directory under a random name and is unlinked in a `finally`.
"""

import logging
import os
import tempfile
import uuid

from flask import (Blueprint, flash, jsonify, render_template, request,
                   url_for)
from werkzeug.utils import secure_filename

from ..services.file_service import analyze_file

logger = logging.getLogger(__name__)

file_bp = Blueprint('file', __name__)

ALLOWED_EXTENSIONS = {
    'exe', 'dll', 'sys', 'scr', 'msi',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'zip', 'rar', '7z', 'tar', 'gz',
    'js', 'vbs', 'ps1', 'bat', 'cmd',
    'jar', 'class',
    'apk',
    'dmg', 'pkg',
    'elf', 'so',
    'bin', 'dat',
    # Delivery formats a phishing triage queue actually receives. 'lnk' is the one
    # that matters most: shortcut lures were rejected outright before this, so the
    # shell-link parser had no way to be reached from an upload.
    'lnk', 'hta', 'wsf', 'rtf', 'one', 'iso', 'img', 'eml', 'msg', 'chm', 'iqy',
    'svg',
}


def allowed_file(filename):
    """Check if the file extension is allowed for analysis."""
    if '.' not in filename:
        return True  # Allow files without extension for analysis
    return filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _validate_upload():
    """Pull the upload off the request and vet it. Returns (file, name, error)."""
    if 'file' not in request.files:
        return None, None, 'No file provided'

    uploaded = request.files['file']
    if uploaded.filename == '':
        return None, None, 'No file selected'

    filename = secure_filename(uploaded.filename) or 'unnamed_file'
    if not allowed_file(filename):
        return None, None, 'File type not allowed for analysis'

    return uploaded, filename, None


def _analyze_upload(uploaded, filename):
    """Save to a private temp path, analyze, and always unlink."""
    # Random on-disk name so no part of user input reaches the path.
    extension = os.path.splitext(filename)[1] if '.' in filename else ''
    temp_dir = tempfile.mkdtemp(prefix='nexustrace_')
    temp_path = os.path.join(temp_dir, f'{uuid.uuid4().hex}{extension}')

    try:
        uploaded.save(temp_path)
        os.chmod(temp_path, 0o600)
        logger.info('Analyzing file: %s (%s bytes on disk)',
                    filename, os.path.getsize(temp_path))
        return analyze_file(temp_path, filename)
    finally:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)
        except OSError as exc:
            logger.warning(f"Failed to clean up temp file: {exc}")


@file_bp.route('/analyze_file', methods=['POST'])
def analyze_file_api():
    """Static analysis + hash reputation for an uploaded file (JSON)."""
    try:
        uploaded, filename, error = _validate_upload()
        if error:
            return jsonify({'error': error}), 400

        record = dict(_analyze_upload(uploaded, filename))
        # Pre-existing callers key off these two names; the record uses
        # `digests.sha256` / `filename`.
        record['sha256'] = record['digests'].get('sha256')
        record['original_filename'] = record['filename']
        return jsonify(record)

    except Exception as e:
        logger.error(f"File analysis error: {str(e)}")
        return jsonify({'error': 'File analysis failed'}), 500


def _render(analysis, status=200):
    """file_analysis.html points its own form at `submit_url`, defaulting to the JSON
    endpoint. Every render from here must set it to this route or the result page's
    form would submit to the API and hand the analyst raw JSON."""
    return render_template(
        'file_analysis.html', analysis=analysis,
        submit_url=url_for('file.analyze_file_page'),
    ), status


@file_bp.route('/analyze', methods=['POST'])
def analyze_file_page():
    """Same analysis, rendered into file_analysis.html.

    Errors re-render the form page with a flash rather than redirecting, so this does
    not depend on the name of the GET route that serves the empty form.
    """
    uploaded, filename, error = _validate_upload()
    if error:
        flash(error, 'error')
        return _render(None, 400)

    try:
        record = _analyze_upload(uploaded, filename)
    except Exception:
        logger.exception('File analysis failed')
        flash('Analysis failed. The file could not be processed.', 'error')
        return _render(None, 500)

    return _render(record)
