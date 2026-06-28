import os
import sys
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from datetime import datetime
from forensic.report import generate_report
from forensic.antiforensics import detect_antiforensics


# Import our own files
from config import (UPLOAD_FOLDER, REPORT_FOLDER, DATABASE,
                    MAX_FILE_SIZE, ALLOWED_EXTENSIONS,
                    ANALYST_NAME, TOOL_VERSION)

from database.db       import (create_tables, log_action, save_file_record,
                                save_metadata, save_indicators, get_all_files,
                                get_file_metadata, get_file_indicators,
                                get_audit_log, get_dashboard_stats,
                                search_metadata, get_correlations)

from analyzers.image   import analyze_image
from analyzers.pdf     import analyze_pdf
from analyzers.word    import analyze_word
from analyzers.audio   import analyze_audio
from analyzers.video   import analyze_video

from forensic.indicators import analyze_indicators
from forensic.timeline   import build_timeline
from forensic.hashing    import calculate_hashes

# ---------------------------------------------------------------
# CREATE THE FLASK APP
# ---------------------------------------------------------------
# Flask(__name__) creates the web application.
# __name__ tells Flask where to look for templates and
# static files — it uses the current file's location.
# ---------------------------------------------------------------
app = Flask(__name__)

# Tell Flask where uploads go and the max size allowed
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE


# ---------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------

def allowed_file(filename):
    """
    Checks if the uploaded file has an extension we support.
    
    '.' in filename ensures the file actually HAS an extension.
    .rsplit('.', 1) splits "photo.jpg" into ["photo", "jpg"]
    [1] grabs the "jpg" part.
    .lower() makes it case-insensitive (JPG = jpg = JPEG = jpeg).
    """
    return ('.' in filename and
            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS)


def get_file_type(filename):
    """
    Translates a file extension into our internal category name.
    This tells the app which analyzer to use.
    """
    ext = filename.rsplit('.', 1)[1].lower()

    type_map = {
        'jpg':  'image', 'jpeg': 'image',
        'png':  'image', 'tiff': 'image', 'tif': 'image',
        'pdf':  'pdf',
        'docx': 'word',
        'mp3':  'audio', 'wav':  'audio', 'flac': 'audio',
        'mp4':  'video', 'mov':  'video',
        'zip':  'zip'
    }

    return type_map.get(ext, 'unknown')


def run_analysis(filepath, filename):
    """
    The master function that orchestrates everything.
    Called once per uploaded file.
    
    Order of operations:
    1. Calculate file hashes (fingerprint)
    2. Identify file type
    3. Run the right analyzer
    4. Check for suspicious indicators
    5. Build forensic timeline
    6. Save everything to database
    7. Log the action to audit trail
    8. Return results
    """

    # STEP 1 — Fingerprint the file immediately on arrival
    # This must happen BEFORE any analysis so we have a
    # baseline hash of the evidence as it was received
    hashes    = calculate_hashes(filepath)
    file_size = os.path.getsize(filepath)
    file_type = get_file_type(filename)

    log_action('HASH', f'{filename} — SHA256: {hashes["sha256"][:16]}...',
            ANALYST_NAME, TOOL_VERSION)

    # STEP 2 — Run the right analyzer based on file type
    metadata = {}

    if file_type == 'image':
        metadata = analyze_image(filepath)
        log_action('ANALYZE', f'Image analysis complete: {filename}',
                ANALYST_NAME, TOOL_VERSION)

    elif file_type == 'pdf':
        metadata = analyze_pdf(filepath)
        log_action('ANALYZE', f'PDF analysis complete: {filename}',
                ANALYST_NAME, TOOL_VERSION)

    elif file_type == 'word':
        metadata = analyze_word(filepath)
        log_action('ANALYZE', f'Word document analysis complete: {filename}',
                ANALYST_NAME, TOOL_VERSION)

    elif file_type == 'audio':
        metadata = analyze_audio(filepath)
        log_action('ANALYZE', f'Audio analysis complete: {filename}',
                ANALYST_NAME, TOOL_VERSION)

    elif file_type == 'video':
        metadata = analyze_video(filepath)
        log_action('ANALYZE', f'Video analysis complete: {filename}',
                ANALYST_NAME, TOOL_VERSION)

    else:
        metadata = {'Status': 'File type not supported for deep analysis'}

    # STEP 3 — Run forensic checks on the extracted metadata
    indicators = analyze_indicators(metadata, file_type)
    antiforensics_findings = detect_antiforensics(metadata, filepath, file_type)

# Convert antiforensics findings to indicator format
# so they appear in the same indicators list
    for finding in antiforensics_findings:
        indicators.append({
            'severity':    finding['confidence'],
            'description': f"[ANTI-FORENSICS] {finding['description']}"
        })

    high_count = sum(1 for i in indicators if i['severity'] == 'HIGH')
    if high_count > 0:
        log_action('FLAG',
                f'{high_count} HIGH severity indicator(s) in {filename}',
                ANALYST_NAME, TOOL_VERSION)

    # STEP 4 — Build the forensic timeline from timestamps
    timeline = build_timeline(metadata, filename)

    # STEP 5 — Save the file record to the database
    file_id = save_file_record(
        filename  = filename,
        file_type = file_type,
        file_size = file_size,
        md5       = hashes['md5'],
        sha1      = hashes['sha1'],
        sha256    = hashes['sha256'],
        analyst   = ANALYST_NAME
    )

    # STEP 6 — Save all metadata and indicators linked to this file
    save_metadata(file_id, metadata)
    save_indicators(file_id, indicators)

    log_action('SAVE',
            f'Results saved to database — File ID: {file_id}',
            ANALYST_NAME, TOOL_VERSION)

    # STEP 7 — Return everything so Flask can send it to the dashboard
    return {
        'file_id':    file_id,
        'filename':   filename,
        'file_type':  file_type,
        'file_size':  file_size,
        'hashes':     hashes,
        'metadata':   metadata,
        'indicators': indicators,
        'timeline':   timeline
    }


# ---------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------
# A "route" is a URL that Flask listens for.
# When you visit http://localhost:5000/
# Flask runs the function directly below @app.route('/')
#
# Think of routes like doors in a building —
# each URL is a different door that leads to a different room.
# ---------------------------------------------------------------

@app.route('/')
def dashboard():
    """
    The main dashboard page.
    Loads all files, stats, audit log, and correlations
    then passes them to the HTML template to display.
    """
    files        = get_all_files()
    stats        = get_dashboard_stats()
    audit_log    = get_audit_log()
    correlations = get_correlations()

    # render_template() reads the HTML file from /templates/
    # and fills in the {{ variables }} with real data
    return render_template('dashboard.html',
                        files        = files,
                        stats        = stats,
                        audit_log    = audit_log,
                        correlations = correlations,
                        analyst      = ANALYST_NAME,
                        version      = TOOL_VERSION)


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handles file uploads from the dashboard.
    
    methods=['POST'] means this route only responds to
    form submissions / file uploads — not regular page visits.
    
    The browser sends the file here, we analyze it,
    and send back JSON results that the dashboard displays.
    """

    # Check a file was actually included in the request
    if 'file' not in request.files:
        return jsonify({'error': 'No file in request'}), 400

    file = request.files['file']

    # An empty filename means the user clicked upload without
    # actually selecting a file
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not supported'}), 400

    # secure_filename() sanitizes the filename —
    # prevents attacks like "../../../etc/passwd" as a filename
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Save the file to the uploads folder
    file.save(filepath)

    log_action('UPLOAD', f'Evidence received: {filename}',
            ANALYST_NAME, TOOL_VERSION)

    # Run the full analysis pipeline
    results = run_analysis(filepath, filename)

    return jsonify(results)


@app.route('/file/<int:file_id>')
def file_detail(file_id):
    """
    Shows detailed results for one specific file.
    The <int:file_id> in the URL is a variable —
    visiting /file/3 passes file_id=3 to this function.
    """
    metadata   = get_file_metadata(file_id)
    indicators = get_file_indicators(file_id)

    return render_template('file_detail.html',
                        file_id    = file_id,
                        metadata   = metadata,
                        indicators = indicators)


@app.route('/search')
def search():
    """
    Searches all metadata for a query string.
    The search term comes from the URL:
    /search?q=photoshop  → finds all files mentioning Photoshop
    /search?q=John Smith → finds all files authored by John Smith
    """
    query   = request.args.get('q', '')
    results = search_metadata(query) if query else []

    return render_template('search.html',
                        results = results,
                        query   = query)


@app.route('/api/stats')
def api_stats():
    """
    Returns live dashboard statistics as JSON.
    The dashboard JavaScript calls this every 30 seconds
    to refresh the stat cards without reloading the whole page.
    """
    return jsonify(get_dashboard_stats())


@app.route('/report/<int:file_id>')
def export_report(file_id):
    """
    Generates a PDF report for one specific file
    and sends it to the browser as a download.
    """
    # Get everything we need from the database
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM files WHERE id = ?', (file_id,))
    file_row = cursor.fetchone()
    conn.close()

    if not file_row:
        return jsonify({'error': 'File not found'}), 404

    file_record   = dict(file_row)
    metadata_rows = get_file_metadata(file_id)
    indicator_rows= get_file_indicators(file_id)
    audit_rows    = get_audit_log()

    # Convert SQLite Row objects to plain dictionaries
    metadata   = {row['key']:   row['value']       for row in metadata_rows}
    indicators = [{'severity':  row['severity'],
                   'description': row['description']} for row in indicator_rows]
    audit      = [dict(row) for row in audit_rows]

    # Build a timeline from the metadata we have
    from forensic.timeline import build_timeline
    timeline = build_timeline(metadata, file_record['filename'])

    # Generate the report file
    report_filename = f'MetaSleuth_Report_{file_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    report_path     = os.path.join(REPORT_FOLDER, report_filename)

    generate_report(
        output_path   = report_path,
        file_record   = file_record,
        metadata      = metadata,
        indicators    = indicators,
        timeline      = timeline,
        audit_entries = audit,
        case_id       = 'CASE-001'
    )

    log_action('REPORT',
               f'PDF report exported for file ID {file_id}: {report_filename}',
               ANALYST_NAME, TOOL_VERSION)

    # Send the file to the browser as a download
    return send_file(
        report_path,
        as_attachment = True,
        download_name = report_filename,
        mimetype      = 'application/pdf'
    )

@app.route('/api/correlations')
def api_correlations():
    """
    Returns cross-file correlation data as JSON.
    Used by the correlations panel on the dashboard.
    """
    corr = get_correlations()
    # Convert SQLite Row objects to plain dictionaries
    # so they can be converted to JSON
    return jsonify({
        'shared_authors': [dict(r) for r in corr['shared_authors']],
        'shared_gps':     [dict(r) for r in corr['shared_gps']]
    })


# ---------------------------------------------------------------
# STARTUP
# ---------------------------------------------------------------

if __name__ == '__main__':
    """
    This block only runs when you execute:
        python app.py
    
    It doesn't run when Flask imports this file internally.
    The if __name__ == '__main__' check is a Python convention
    that prevents code from running unintentionally on import.
    """

    # Create upload and report folders if they don't exist yet
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

    # Set up the database tables on first run
    create_tables()

    log_action('STARTUP',
            f'MetaSleuth {TOOL_VERSION} started',
            ANALYST_NAME, TOOL_VERSION)

    print(f'''
    ╔══════════════════════════════════════╗
    ║       MetaSleuth DFIR Toolkit        ║
    ║       Version {TOOL_VERSION}         ║
    ╠══════════════════════════════════════╣
    ║  Dashboard → http://localhost:5000   ║
    ║  Analyst   → {ANALYST_NAME}          ║
    ║  Database  → metasleuth.db           ║
    ╚══════════════════════════════════════╝
    ''')

    # debug=True means Flask will show detailed error messages
    # and automatically restart when you save changes to any file.
    # ALWAYS set debug=False before sharing with anyone else.
    app.run(debug=True, host='0.0.0.0', port=5000)