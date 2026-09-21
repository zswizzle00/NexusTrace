"""Phone number lookup. Registered without a URL prefix, like scan_bp and email_bp.

Nothing is stored. The result is rendered once, so there is no record, no delete route,
no retention window and no entry in scripts/purge_data.py.
"""
import logging

from flask import Blueprint, render_template, request

from ..services.phone_service import build_report

logger = logging.getLogger(__name__)

phone_bp = Blueprint('phone', __name__)


@phone_bp.route('/phone_analysis', methods=['GET', 'POST'])
def phone_analysis():
    raw = (request.form.get('number') or request.args.get('number') or '').strip()
    region = (request.form.get('region') or request.args.get('region') or '').strip().upper()
    report = build_report(raw, region or None) if raw else None
    return render_template('phone_analysis.html', report=report, raw=raw, region=region)
