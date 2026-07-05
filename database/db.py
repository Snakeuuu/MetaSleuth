import sqlite3
import os
from datetime import datetime
from config import DATABASE


def get_connection():
    """
    Opens a connection to the database file.
    Every time we want to read or write data, we call this first.
    Think of it like opening a filing cabinet drawer.
    """
    conn = sqlite3.connect(DATABASE)
    # This makes results come back as dictionaries (name: value)
    # instead of plain lists — much easier to work with
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    """
    Creates all the tables if they don't exist yet.
    Like setting up blank filing folders before your first case.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # TABLE 1: One row per file analyzed
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            filename    TEXT NOT NULL,
            file_type   TEXT NOT NULL,
            file_size   INTEGER,
            md5         TEXT,
            sha1        TEXT,
            sha256      TEXT,
            upload_time TEXT NOT NULL,
            analyst     TEXT
        )
    ''')
    # AUTOINCREMENT means SQLite automatically gives each file
    # a unique ID number — 1, 2, 3, etc.

    # TABLE 2: All the metadata extracted from each file
    # One row per piece of information (author, GPS, camera model etc.)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metadata (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            key     TEXT NOT NULL,
            value   TEXT,
            FOREIGN KEY (file_id) REFERENCES files(id)
        )
    ''')
    # FOREIGN KEY means "this file_id must exist in the files table"
    # It links metadata rows back to the file they came from

    # TABLE 3: Suspicious findings
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id     INTEGER NOT NULL,
            severity    TEXT NOT NULL,
            description TEXT NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files(id)
        )
    ''')

    # TABLE 4: Audit log — every action taken, permanent record.
    # file_id links an entry back to the evidence file it concerns.
    # It's nullable because some actions (e.g. STARTUP) aren't tied
    # to any one file.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action    TEXT NOT NULL,
            detail    TEXT,
            analyst   TEXT,
            tool_ver  TEXT,
            file_id   INTEGER,
            FOREIGN KEY (file_id) REFERENCES files(id)
        )
    ''')
    # If an older database already has an audit_log table without
    # file_id, add the column on the fly so upgrades don't crash.
    cursor.execute("PRAGMA table_info(audit_log)")
    existing_cols = [row[1] for row in cursor.fetchall()]
    if 'file_id' not in existing_cols:
        cursor.execute('ALTER TABLE audit_log ADD COLUMN file_id INTEGER')

    # TABLE 5: External comparison log — one row per "Compare External
    # Copy" check. Tied to file_id so each evidence file has its own
    # independent history; comparisons are never mixed between files.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comparisons (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id            INTEGER NOT NULL,
            compared_filename  TEXT NOT NULL,
            compared_md5       TEXT,
            compared_sha256    TEXT,
            match              INTEGER NOT NULL,
            timestamp          TEXT NOT NULL,
            analyst            TEXT,
            FOREIGN KEY (file_id) REFERENCES files(id)
        )
    ''')

    # TABLE 6: Verification log — one row per re-verification attempt
    # against a stored original hash. Created here up front instead of
    # lazily inside save_verification, so the table always exists.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS verifications (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id           INTEGER NOT NULL,
            verified_at       TEXT NOT NULL,
            compared_filename TEXT NOT NULL,
            original_sha256   TEXT NOT NULL,
            submitted_sha256  TEXT NOT NULL,
            result            TEXT NOT NULL,
            analyst           TEXT,
            FOREIGN KEY (file_id) REFERENCES files(id)
        )
    ''')

    conn.commit()  # "commit" means save everything permanently
    conn.close()   # always close the connection when done


def log_action(action, detail, analyst, tool_ver, file_id=None):
    """
    Writes one row to the audit log.
    Called every time something important happens —
    upload, analysis, report export etc.
    Pass file_id when the action concerns a specific evidence file,
    so its trail can be pulled up on its own later. Leave it as
    None for system-level events (e.g. app startup) that aren't
    tied to any one file.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_log (timestamp, action, detail, analyst, tool_ver, file_id)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (datetime.now().isoformat(), action, detail, analyst, tool_ver, file_id))
    # The ? marks are placeholders — Python fills them in safely.
    # Never put variables directly into SQL strings (security risk).
    conn.commit()
    conn.close()


def save_file_record(filename, file_type, file_size, md5, sha1, sha256, analyst):
    """
    Saves a new file entry to the files table.
    Returns the ID number SQLite assigned to it —
    we need that ID to link metadata and indicators to this file.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO files (filename, file_type, file_size, md5, sha1, sha256, upload_time, analyst)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (filename, file_type, file_size, md5, sha1, sha256,
        datetime.now().isoformat(), analyst))
    file_id = cursor.lastrowid  # grab the auto-assigned ID
    conn.commit()
    conn.close()
    return file_id


def save_metadata(file_id, metadata_dict):
    """
    Saves all extracted metadata for one file.
    metadata_dict looks like: {"Author": "John", "GPS": "28.6, 77.2"}
    We loop through it and save one row per key-value pair.
    """
    conn = get_connection()
    cursor = conn.cursor()
    for key, value in metadata_dict.items():
        if value:  # only save if there's actually a value
            cursor.execute('''
                INSERT INTO metadata (file_id, key, value)
                VALUES (?, ?, ?)
            ''', (file_id, str(key), str(value)))
    conn.commit()
    conn.close()


def save_indicators(file_id, indicators_list):
    """
    Saves suspicious findings for one file.
    indicators_list looks like:
    [{"severity": "HIGH", "description": "GPS data found"}]
    """
    conn = get_connection()
    cursor = conn.cursor()
    for indicator in indicators_list:
        cursor.execute('''
            INSERT INTO indicators (file_id, severity, description)
            VALUES (?, ?, ?)
        ''', (file_id, indicator['severity'], indicator['description']))
    conn.commit()
    conn.close()


def get_all_files():
    """
    Returns every file ever analyzed — for the dashboard file list.

    Includes case_number: a sequential 1, 2, 3... position among the
    files that currently exist, ordered by when they were added. This
    is separate from the raw database id, which is never reused —
    deleting File #7 shouldn't make the next upload "File #7" again,
    but it also shouldn't leave everyone staring at "File #22" when
    there are only 3 files left. case_number gives a clean count while
    id stays a stable, permanent reference for chain-of-custody.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT f.*, 
        COUNT(DISTINCT i.id) as indicator_count,
        MAX(i.severity) as highest_severity,
        ROW_NUMBER() OVER (ORDER BY f.id ASC) as case_number
        FROM files f
        LEFT JOIN indicators i ON f.id = i.file_id
        GROUP BY f.id
        ORDER BY f.upload_time DESC
    ''')
    # LEFT JOIN means "include files even if they have zero indicators"
    # COUNT(DISTINCT i.id) counts how many indicators each file has
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_case_number(file_id):
    """
    Returns the sequential display position of a single file among
    the files that currently exist (1, 2, 3...), based on id order.
    Used on the file detail page so it can show "File #3" instead of
    the raw, never-reused database id.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM files WHERE id <= ?', (file_id,))
    case_number = cursor.fetchone()[0]
    conn.close()
    return case_number


def get_file_metadata(file_id):
    """ Returns all metadata for one specific file. """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT key, value FROM metadata WHERE file_id = ?', (file_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_file_indicators(file_id):
    """ Returns all suspicious indicators for one specific file. """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT severity, description FROM indicators WHERE file_id = ?', (file_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def save_comparison(file_id, compared_filename, compared_md5, compared_sha256, match, analyst):
    """
    Records one "Compare External Copy" check against a specific file.
    Each row is permanently tied to file_id, so File #3's comparison
    history never shows up on File #7's page, and vice versa.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO comparisons
            (file_id, compared_filename, compared_md5, compared_sha256, match, timestamp, analyst)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        file_id,
        compared_filename,
        compared_md5,
        compared_sha256,
        1 if match else 0,
        datetime.now().isoformat(),
        analyst
    ))
    comparison_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return comparison_id


def get_comparisons(file_id):
    """
    Returns the full comparison history for ONE file only,
    newest first. Used on the file detail page and in the
    exported PDF report — always scoped to a single file_id.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM comparisons
        WHERE file_id = ?
        ORDER BY timestamp DESC
    ''', (file_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_verification(file_id, compared_filename, original_sha256,
                       submitted_sha256, match, analyst):
    """
    Saves a permanent record of every verification attempt —
    who verified, what file they used, when, and whether it passed.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO verifications
            (file_id, verified_at, compared_filename,
             original_sha256, submitted_sha256, result, analyst)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            file_id,
            datetime.now().isoformat(),
            compared_filename,
            original_sha256,
            submitted_sha256,
            'PASSED' if match else 'FAILED',
            analyst
        ))
    conn.commit()
    conn.close()


def get_verifications(file_id):
    """
    Returns all verification attempts for a specific file,
    newest first.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM verifications
        WHERE file_id = ?
        ORDER BY verified_at DESC
    ''', (file_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_audit_log(file_id=None, limit=None):
    """
    Returns audit log entries, newest first.

    - get_audit_log()            -> every entry, no limit
    - get_audit_log(limit=50)    -> most recent 50 entries, any file
    - get_audit_log(file_id=22)  -> only entries tied to file #22,
                                     e.g. for that file's detail page
                                     or its exported PDF report, so
                                     one file's history never bleeds
                                     into another's.
    """
    conn = get_connection()
    cursor = conn.cursor()

    query  = 'SELECT * FROM audit_log'
    params = []

    if file_id is not None:
        query += ' WHERE file_id = ?'
        params.append(file_id)

    query += ' ORDER BY timestamp DESC'

    if limit is not None:
        query += ' LIMIT ?'
        params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_dashboard_stats():
    """ Returns summary numbers for the dashboard stat cards. """
    conn = get_connection()
    cursor = conn.cursor()

    stats = {}

    cursor.execute('SELECT COUNT(*) FROM files')
    stats['total'] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM files WHERE file_type = 'image'")
    stats['images'] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM files WHERE file_type IN ('pdf','word')")
    stats['documents'] = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM indicators')
    stats['total_indicators'] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM indicators WHERE severity = 'HIGH'")
    stats['high'] = cursor.fetchone()[0]

    conn.close()
    return stats


def search_metadata(query):
    """
    Searches across all metadata values.
    Used by the search bar — finds files by author, GPS, software etc.
    The % around query means "anything before or after this word".
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT DISTINCT f.id, f.filename, f.file_type, m.key, m.value
        FROM files f
        JOIN metadata m ON f.id = m.file_id
        WHERE m.value LIKE ?
        ORDER BY f.upload_time DESC
    ''', (f'%{query}%',))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_gps_findings():
    """Returns all files that have GPS coordinates embedded."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT f.filename, f.id, m.value as gps
        FROM files f
        JOIN metadata m ON f.id = m.file_id
        WHERE m.key = 'GPS Coordinates'
        ORDER BY f.upload_time DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_correlations():
    """
    Finds cross-file patterns:
    - Same author appearing in multiple files
    - Same GPS coordinates in multiple files
    These are the most forensically interesting findings.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Authors shared across more than one file
    cursor.execute('''
        SELECT value as author, COUNT(DISTINCT file_id) as file_count
        FROM metadata
        WHERE key IN ('Author', 'Last Modified By', 'Creator')
        GROUP BY value
        HAVING file_count > 1
        ORDER BY file_count DESC
    ''')
    shared_authors = cursor.fetchall()

    # GPS coordinates shared across more than one file
    cursor.execute('''
        SELECT value as gps, COUNT(DISTINCT file_id) as file_count
        FROM metadata
        WHERE key = 'GPS Coordinates'
        GROUP BY value
        HAVING file_count > 1
    ''')
    shared_gps = cursor.fetchall()

    conn.close()
    return {
        'shared_authors': shared_authors,
        'shared_gps': shared_gps
    }