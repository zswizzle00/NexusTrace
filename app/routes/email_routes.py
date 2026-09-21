"""E-mail analysis routes. Registered without a URL prefix, like scan_bp."""
import logging

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)

from ..services.email_service import analyze_email, get_analysis, save_analysis
from ..utils.storage import store, validate_key

logger = logging.getLogger(__name__)

email_bp = Blueprint('email', __name__)


# Pasted source is capped separately from the app-wide 50 MB upload limit: a
# textarea is trivially easy to fill with megabytes of junk.
MAX_PASTE_BYTES = 10 * 1024 * 1024


def _analysis_record_key(analysis_id):
    """The analyses-store key for an id off the URL, or None when the id could never
    name a record. A rejected id is a 404, not a ValueError at the store."""
    try:
        return validate_key(f'{analysis_id}.json')
    except ValueError:
        return None


@email_bp.route('/email_analysis', methods=['GET'])
def email_analysis_form():
    return render_template('email_analysis.html')


@email_bp.route('/email_analysis', methods=['POST'])
def email_analysis_submit():
    raw = None
    source = 'upload'

    uploaded = request.files.get('file')
    if uploaded and uploaded.filename:
        raw = uploaded.read()
    else:
        pasted = request.form.get('raw') or ''
        if pasted.strip():
            encoded = pasted.encode('utf-8', 'replace')
            if len(encoded) > MAX_PASTE_BYTES:
                flash('That pasted message is too large (10 MB limit).', 'error')
                return redirect(url_for('email.email_analysis_form'))
            raw = encoded
            source = 'paste'

    if not raw:
        flash('Upload an .eml file or paste the message source.', 'error')
        return redirect(url_for('email.email_analysis_form'))

    try:
        analysis = analyze_email(raw, source=source)
        save_analysis(analysis)
    except Exception:
        logger.exception('E-mail analysis failed')
        flash('Analysis failed. The message could not be processed.', 'error')
        return redirect(url_for('email.email_analysis_form'))

    return redirect(url_for('email.email_analysis_result', analysis_id=analysis['id']))


@email_bp.route('/email_analysis/<analysis_id>', methods=['GET'])
def email_analysis_result(analysis_id):
    analysis = get_analysis(analysis_id)
    if not analysis:
        abort(404)
    return render_template('email_result.html', analysis=analysis)


@email_bp.route('/email_analysis/<analysis_id>/delete', methods=['GET'])
def email_analysis_delete_confirm(analysis_id):
    analysis = get_analysis(analysis_id)
    if not analysis or _analysis_record_key(analysis_id) is None:
        abort(404)
    headers = analysis.get('headers') or {}
    return render_template(
        'confirm_delete.html',
        kind='e-mail analysis',
        summary=headers.get('subject') or '(no subject)',
        removes='Removes the stored findings for this message.',
        action=url_for('email.email_analysis_delete', analysis_id=analysis_id),
        cancel=url_for('email.email_analysis_result', analysis_id=analysis_id),
    )


@email_bp.route('/email_analysis/<analysis_id>/delete', methods=['POST'])
def email_analysis_delete(analysis_id):
    record_key = _analysis_record_key(analysis_id)
    if record_key is None or get_analysis(analysis_id) is None:
        abort(404)
    store('analyses').delete(record_key)
    logger.info('Deleted e-mail analysis %s', analysis_id)
    flash('E-mail analysis deleted.', 'info')
    return redirect(url_for('email.email_analysis_form'))
