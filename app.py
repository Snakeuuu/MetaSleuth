import os
import sys
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from datetime import datetime

from config import (UPLOAD_FOLDER, REPORT_FOLDER, DATABASE,
                    MAX_FILE_SIZE, ALLOWED_EXTENSIONS,
                    ANALYST_NAME, TOOL_VERSION)

from database.db import (create_tables, log_action, save_file_record,
                          save_metadata, save_indicators, get_all_files,
                          get_file_metadata, get_file_indicators,
                          get_audit_log, get_dashboard_stats,
                          search_metadata, get_correlations,
                          get_connection, get_gps_findings,
                          save_comparison, get_comparisons)

from analyzers.image  import analyze_image
from analyzers.pdf    import analyze_pdf
from analyzers.word   import analyze_word
from analyzers.audio  import analyze_audio
from analyzers.video  import analyze_video

from forensic.indicators   import analyze_indicators
from forensic.timeline     import build_timeline
from forensic.hashing      import calculate_hashes
from forensic.report       import generate_report
from forensic.antiforensics import detect_antiforensics


# ---------------------------------------------------------------
# CREATE THE FLASK APP
# ---------------------------------------------------------------
app = Flask(__name__)
app.config['UPLOAD_FOLDER']      = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE


# ---------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------

def allowed_file(filename):
    """
    Checks if the uploaded file has an extension we support.
    """
    return ('.' in filename and
            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS)


def get_file_type(filename):
    """
    Translates a file extension into our internal category name.
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
    """

    hashes    = calculate_hashes(filepath)
    file_size = os.path.getsize(filepath)
    file_type = get_file_type(filename)

    log_action('HASH', f'{filename} — SHA256: {hashes["sha256"][:16]}...',
               ANALYST_NAME, TOOL_VERSION)

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

    # Run forensic indicator checks (includes magic bytes check)
    indicators = analyze_indicators(metadata, file_type,
                                     filepath=filepath, filename=filename)

    # Run anti-forensics detection
    antiforensics_findings = detect_antiforensics(metadata, filepath, file_type)
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

    timeline = build_timeline(metadata, filename)

    file_id = save_file_record(
        filename  = filename,
        file_type = file_type,
        file_size = file_size,
        md5       = hashes['md5'],
        sha1      = hashes['sha1'],
        sha256    = hashes['sha256'],
        analyst   = ANALYST_NAME
    )

    save_metadata(file_id, metadata)
    save_indicators(file_id, indicators)

    log_action('SAVE',
               f'Results saved to database — File ID: {file_id}',
               ANALYST_NAME, TOOL_VERSION)

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

@app.route('/')
def dashboard():
    """
    The main dashboard page.
    """
    files        = get_all_files()
    stats        = get_dashboard_stats()
    audit_log    = get_audit_log()
    correlations = get_correlations()
    gps_findings = get_gps_findings()

    return render_template('dashboard.html',
                           files        = files,
                           stats        = stats,
                           audit_log    = audit_log,
                           correlations = correlations,
                           gps_findings = gps_findings,
                           analyst      = ANALYST_NAME,
                           version      = TOOL_VERSION)


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handles file uploads from the dashboard.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file in request'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not supported'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    file.save(filepath)

    log_action('UPLOAD', f'Evidence received: {filename}',
               ANALYST_NAME, TOOL_VERSION)

    results = run_analysis(filepath, filename)

    return jsonify(results)


@app.route('/file/<int:file_id>')
def file_detail(file_id):
    """
    Shows detailed results for one specific file.
    """
    metadata    = get_file_metadata(file_id)
    indicators  = get_file_indicators(file_id)
    comparisons = get_comparisons(file_id)

    return render_template('file_detail.html',
                           file_id     = file_id,
                           metadata    = metadata,
                           indicators  = indicators,
                           comparisons = comparisons)


@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    """
    Deletes a file record and everything linked to it —
    metadata, indicators, and the physical file from disk.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT filename FROM files WHERE id = ?', (file_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({'error': 'File not found'}), 404

    filename = row['filename']

    log_action(
        'DELETE',
        f'File permanently deleted: {filename} (ID: {file_id})',
        ANALYST_NAME,
        TOOL_VERSION
    )

    cursor.execute('DELETE FROM indicators   WHERE file_id = ?', (file_id,))
    cursor.execute('DELETE FROM metadata     WHERE file_id = ?', (file_id,))
    cursor.execute('DELETE FROM comparisons  WHERE file_id = ?', (file_id,))
    cursor.execute('DELETE FROM files        WHERE id = ?',      (file_id,))
    conn.commit()
    conn.close()

    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(filepath):
        os.remove(filepath)

    return jsonify({'success': True, 'deleted': filename})


@app.route('/report/<int:file_id>')
def export_report(file_id):
    """
    Generates a PDF report for one specific file
    and sends it to the browser as a download.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM files WHERE id = ?', (file_id,))
    file_row = cursor.fetchone()
    conn.close()

    if not file_row:
        return jsonify({'error': 'File not found'}), 404

    file_record    = dict(file_row)
    metadata_rows  = get_file_metadata(file_id)
    indicator_rows = get_file_indicators(file_id)
    audit_rows     = get_audit_log()
    comparisons    = get_comparisons(file_id)

    metadata   = {row['key']: row['value'] for row in metadata_rows}
    indicators = [{'severity': row['severity'],
                   'description': row['description']} for row in indicator_rows]
    audit      = [dict(row) for row in audit_rows]

    timeline = build_timeline(metadata, file_record['filename'])

    report_filename = f'MetaSleuth_Report_{file_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    report_path     = os.path.join(REPORT_FOLDER, report_filename)

    generate_report(
        output_path   = report_path,
        file_record   = file_record,
        metadata      = metadata,
        indicators    = indicators,
        timeline      = timeline,
        audit_entries = audit,
        comparisons   = comparisons,
        case_id       = 'CASE-001'
    )

    log_action('REPORT',
               f'PDF report exported for file ID {file_id}: {report_filename}',
               ANALYST_NAME, TOOL_VERSION)

    return send_file(
        report_path,
        as_attachment = True,
        download_name = report_filename,
        mimetype      = 'application/pdf'
    )


@app.route('/evidence')
def evidence_files():
    """
    Full evidence file listing page.
    """
    files = get_all_files()
    return render_template('evidence.html', files=files)


@app.route('/timeline')
def timeline_page():
    """
    Cross-file forensic timeline page.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT m.key, m.value, f.filename, f.id, f.file_type
        FROM metadata m
        JOIN files f ON m.file_id = f.id
        WHERE m.key IN (
            "DateTime", "DateTimeOriginal", "DateTimeDigitized",
            "Created", "Modified", "Creation Date", "Modified Date",
            "Last Printed", "Encoded Date", "Tagged Date"
        )
        ORDER BY m.value ASC
    ''')
    raw_events = cursor.fetchall()
    conn.close()

    events = []
    for row in raw_events:
        events.append({
            'key':       row['key'],
            'value':     row['value'],
            'filename':  row['filename'],
            'file_id':   row['id'],
            'file_type': row['file_type'],
        })

    return render_template('timeline.html', events=events)


@app.route('/indicators')
def indicators_page():
    """
    All indicators across every file, grouped by severity.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT i.severity, i.description,
               f.filename, f.id as file_id, f.file_type
        FROM indicators i
        JOIN files f ON i.file_id = f.id
        ORDER BY
            CASE i.severity
                WHEN "HIGH"   THEN 1
                WHEN "MEDIUM" THEN 2
                ELSE 3
            END,
            f.upload_time DESC
    ''')
    rows = cursor.fetchall()
    conn.close()

    indicators = [dict(r) for r in rows]
    high   = [i for i in indicators if i['severity'] == 'HIGH']
    medium = [i for i in indicators if i['severity'] == 'MEDIUM']
    low    = [i for i in indicators if i['severity'] == 'LOW']

    return render_template('indicators.html',
                           indicators=indicators,
                           high=high,
                           medium=medium,
                           low=low)


@app.route('/search')
def search_page():
    """
    Metadata search page.
    """
    query   = request.args.get('q', '').strip()
    results = search_metadata(query) if query else []
    return render_template('search.html',
                           results=results,
                           query=query)


@app.route('/correlations')
def correlations_page():
    """
    Cross-file correlation findings page.
    """
    corr = get_correlations()
    return render_template('correlations.html',
                           shared_authors=corr['shared_authors'],
                           shared_gps=corr['shared_gps'])


@app.route('/cases')
def cases_page():
    """
    Case manager overview page.
    """
    files = get_all_files()
    stats = get_dashboard_stats()
    return render_template('cases.html',
                           files=files,
                           stats=stats,
                           analyst=ANALYST_NAME,
                           version=TOOL_VERSION)


@app.route('/auditlog')
def auditlog_page():
    """
    Full chain of custody / audit log page.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_log ORDER BY timestamp DESC')
    rows = cursor.fetchall()
    conn.close()
    entries = [dict(r) for r in rows]
    return render_template('auditlog.html', entries=entries)


@app.route('/api/stats')
def api_stats():
    """
    Returns live dashboard statistics as JSON.
    """
    return jsonify(get_dashboard_stats())


@app.route('/api/correlations')
def api_correlations():
    """
    Returns cross-file correlation data as JSON.
    """
    corr = get_correlations()
    return jsonify({
        'shared_authors': [dict(r) for r in corr['shared_authors']],
        'shared_gps':     [dict(r) for r in corr['shared_gps']]
    })

@app.route('/verify/<int:file_id>', methods=['POST'])
def verify_file(file_id):
    """
    Re-hashes the file currently in the uploads folder
    and compares it against the hash stored at time of upload.
    
    If they match — file is intact, chain of custody holds.
    If they differ — file was modified after upload, serious finding.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM files WHERE id = ?', (file_id,))
    file_row = cursor.fetchone()
    conn.close()

    if not file_row:
        return jsonify({'error': 'File not found in database'}), 404

    filename = file_row['filename']
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    if not os.path.exists(filepath):
        return jsonify({
            'verified':  False,
            'error':     'Physical file not found in uploads folder. '
                         'It may have been moved or deleted outside MetaSleuth.'
        }), 404
    
@app.route('/verify-external/<int:file_id>', methods=['POST'])
def verify_external_file(file_id):
    """
    Compares an externally supplied copy of a file (e.g. a copy the
    analyst found on another machine, USB drive, email attachment, etc.)
    against the hash recorded for this evidence item at time of upload.

    Unlike /verify/<file_id> — which re-hashes the file already sitting
    in our own uploads folder — this route lets you check a copy that
    lives OUTSIDE MetaSleuth. That copy is hashed from a temporary file
    and then deleted immediately. It is never written into the uploads
    folder permanently and never touches the evidence record, so this
    check cannot contaminate the chain of custody.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM files WHERE id = ?', (file_id,))
        file_row = cursor.fetchone()
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

    if not file_row:
        return jsonify({'error': 'File not found in database'}), 404

    if 'compare_file' not in request.files:
        return jsonify({'error': 'No comparison file was received.'}), 400

    upload = request.files['compare_file']

    if upload.filename == '':
        return jsonify({'error': 'No comparison file was selected.'}), 400

    tmp_path = None
    try:
        # Save to a throwaway temp path just long enough to hash it —
        # this file is never analyzed, listed, or kept afterwards.
        safe_name = secure_filename(upload.filename) or 'comparison_file'
        tmp_path = os.path.join(
            UPLOAD_FOLDER,
            f'.tmp_compare_{file_id}_{safe_name}'
        )
        upload.save(tmp_path)

        current_hashes = calculate_hashes(tmp_path)

    except Exception as e:
        return jsonify({'error': f'Could not read comparison file: {str(e)}'}), 500

    finally:
        # Always clean up the temp file, even if hashing failed
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    original_sha256 = file_row['sha256']
    current_sha256  = current_hashes.get('sha256', '')
    match = bool(current_sha256) and original_sha256 == current_sha256

    # Record this comparison permanently against THIS file only —
    # it will never appear on another file's comparison log.
    try:
        save_comparison(
            file_id,
            upload.filename,
            current_hashes.get('md5', ''),
            current_sha256,
            match,
            ANALYST_NAME
        )
    except Exception:
        pass  # a logging failure shouldn't block the result being returned

    log_action(
        'VERIFY_EXTERNAL',
        f'External comparison for {file_row["filename"]} against '
        f'"{upload.filename}" — {"MATCH" if match else "MISMATCH"}',
        ANALYST_NAME,
        TOOL_VERSION
    )

    return jsonify({
        'verified':          match,
        'filename':          file_row['filename'],
        'compared_filename': upload.filename,
        'original_sha256':   original_sha256,
        'current_sha256':    current_sha256,
        'original_md5':      file_row['md5'],
        'current_md5':       current_hashes.get('md5', ''),
        'timestamp':         datetime.now().isoformat(),
    })

    # Recalculate hashes right now
    current_hashes = calculate_hashes(filepath)

    # Compare against what was stored on upload
    original_sha256 = file_row['sha256']
    current_sha256  = current_hashes['sha256']

    match = original_sha256 == current_sha256

    log_action(
        'VERIFY',
        f'Integrity check for {filename} — '
        f'{"PASSED" if match else "FAILED — hash mismatch detected"}',
        ANALYST_NAME,
        TOOL_VERSION
    )

    return jsonify({
        'verified':       match,
        'filename':       filename,
        'original_sha256': original_sha256,
        'current_sha256':  current_sha256,
        'original_md5':    file_row['md5'],
        'current_md5':     current_hashes['md5'],
    })

# ---------------------------------------------------------------
# STARTUP
# ---------------------------------------------------------------

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

    create_tables()

    log_action('STARTUP',
               f'MetaSleuth {TOOL_VERSION} started',
               ANALYST_NAME, TOOL_VERSION)

    print(f'''
    ============================================
           MetaSleuth DFIR Toolkit
           Version {TOOL_VERSION}
    ============================================
    Dashboard -> http://localhost:5000
    Analyst   -> {ANALYST_NAME}
    Database  -> metasleuth.db
    ============================================
    ''')

    app.run(debug=True, host='0.0.0.0', port=5000)