"""E-mail analysis routes. Registered without a URL prefix, like scan_bp."""
import logging

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)

from ..services.email_service import (analyze_email, get_analysis,
                                      list_analyses, save_analysis)

logger = logging.getLogger(__name__)

email_bp = Blueprint('email', __name__)

# Pasted source is capped separately from the app-wide 50 MB upload limit: a
# textarea is trivially easy to fill with megabytes of junk.
MAX_PASTE_BYTES = 10 * 1024 * 1024


@email_bp.route('/email_analysis', methods=['GET'])
def email_analysis_form():
    return render_template('email_analysis.html', recent=list_analyses(10))


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
