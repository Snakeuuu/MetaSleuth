import os

# The folder this file sits in — used as a starting point for all paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Where uploaded evidence files will be temporarily stored
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')

# Where finished PDF reports will be saved
REPORT_FOLDER = os.path.join(BASE_DIR, 'reports')

# Where copies of files uploaded for "Verify"/"Compare" checks are kept
# permanently, so you can always look back at exactly what was compared
# against each piece of evidence. Kept separate from UPLOAD_FOLDER so
# comparison copies never get mistaken for the original evidence files.
COMPARISON_FOLDER = os.path.join(BASE_DIR, 'comparisons')

# Where the database file lives
DATABASE = os.path.join(BASE_DIR, 'database', 'metasleuth.db')

# Maximum file size allowed — 200MB (200 * 1024 * 1024 bytes)
MAX_FILE_SIZE = 200 * 1024 * 1024

# File types MetaSleuth can analyze
ALLOWED_EXTENSIONS = {
    'jpg', 'jpeg', 'png', 'tiff', 'tif',  # Images
    'pdf',                                   # PDFs
    'docx',                                  # Word documents
    'mp3', 'wav', 'flac',                   # Audio
    'mp4', 'mov',                            # Video
    'zip'                                    # Archives
}

# The analyst name that appears in audit logs and reports
ANALYST_NAME = "analyst@metasleuth"

# Tool version — update this when you improve the project
TOOL_VERSION = "1.0.0"