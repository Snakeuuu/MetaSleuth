import sqlite3
import os
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

    # TABLE 4: Audit log — every action taken, permanent record
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action    TEXT NOT NULL,
            detail    TEXT,
            analyst   TEXT,
            tool_ver  TEXT
        )
    ''')

    conn.commit()  # "commit" means save everything permanently
    conn.close()   # always close the connection when done


def log_action(action, detail, analyst, tool_ver):
    """
    Writes one row to the audit log.
    Called every time something important happens —
    upload, analysis, report export etc.
    """
    from datetime import datetime
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_log (timestamp, action, detail, analyst, tool_ver)
        VALUES (?, ?, ?, ?, ?)
    ''', (datetime.now().isoformat(), action, detail, analyst, tool_ver))
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
    from datetime import datetime
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
    """ Returns every file ever analyzed — for the dashboard file list. """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT f.*, 
        COUNT(DISTINCT i.id) as indicator_count,
        MAX(i.severity) as highest_severity
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


def get_audit_log():
    """ Returns the full audit log, newest entries first. """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 50')
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