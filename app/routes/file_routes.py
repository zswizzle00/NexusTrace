from flask import Blueprint, request, jsonify
import os
import tempfile
import uuid
import logging
from werkzeug.utils import secure_filename
from ..services.file_service import get_combined_file_analysis

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
}


def allowed_file(filename):
    """Check if the file extension is allowed for analysis."""
    if '.' not in filename:
        return True  # Allow files without extension for analysis
    return filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@file_bp.route('/analyze_file', methods=['POST'])
def analyze_file():
    """Hash an uploaded file and check its reputation (AlienVault OTX)."""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        original_filename = secure_filename(file.filename)
        if not original_filename:
            original_filename = 'unnamed_file'

        if not allowed_file(original_filename):
            return jsonify({'error': 'File type not allowed for analysis'}), 400

        # Random on-disk name so no part of user input reaches the path.
        file_ext = os.path.splitext(original_filename)[1] if '.' in original_filename else ''
        random_filename = f"{uuid.uuid4().hex}{file_ext}"

        temp_dir = tempfile.mkdtemp(prefix='nexustrace_')
        temp_path = os.path.join(temp_dir, random_filename)

        try:
            file.save(temp_path)
            os.chmod(temp_path, 0o600)

            logger.info(f"Analyzing file: {original_filename} (saved as {random_filename})")

            analysis_result = get_combined_file_analysis(file_path=temp_path)

            if not analysis_result:
                return jsonify({'error': 'Could not analyze file'}), 500

            analysis_result['original_filename'] = original_filename
            return jsonify(analysis_result)

        finally:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                if os.path.exists(temp_dir):
                    os.rmdir(temp_dir)
            except OSError as e:
                logger.warning(f"Failed to clean up temp file: {e}")

    except Exception as e:
        logger.error(f"File analysis error: {str(e)}")
        return jsonify({'error': 'File analysis failed'}), 500
