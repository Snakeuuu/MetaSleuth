from datetime import datetime
from forensic.magic_bytes import verify_file_type


def analyze_indicators(metadata, file_type, filepath=None, filename=None):
    """
    Runs forensic checks and produces a risk score from 0-100.

    Instead of flagging individual findings as HIGH/MEDIUM/LOW,
    each finding contributes points to a cumulative risk score.
    The final score determines the overall risk level:

        0  - 30  → LOW
        31 - 60  → MEDIUM
        61 - 100 → HIGH

    This mirrors how real forensic triage tools work —
    no single indicator is definitive, but the combination
    of multiple anomalies builds a defensible risk assessment.
    """
    findings   = []
    risk_score = 0

    # ── MAGIC BYTES CHECK ─────────────────────────────────────────
    # Compare declared extension against actual file signature.
    # A mismatch is one of the strongest indicators of tampering.
    if filepath and filename and '.' in filename:
        ext          = filename.rsplit('.', 1)[1]
        magic_result = verify_file_type(filepath, ext)

        if magic_result['is_executable']:
            risk_score += 40
            findings.append({
                'points':      40,
                'description': f'DANGER — Executable file disguised as .{ext}. '
                               f'Magic bytes: {magic_result["signature"]}',
                'recommendation': 'Do not open this file. Treat as potential malware.'
            })
        elif not magic_result['match']:
            risk_score += 30
            findings.append({
                'points':      30,
                'description': f'File extension mismatch — declared as .{ext} but '
                               f'file signature indicates {magic_result["detected"]}. '
                               f'Signature: {magic_result["signature"]}',
                'recommendation': 'Verify file origin. Extension mismatch '
                                  'may indicate deliberate renaming.'
            })
        else:
            findings.append({
                'points':      0,
                'description': f'File signature verified — extension matches '
                               f'magic bytes ({magic_result["signature"]})',
                'recommendation': None
            })

    # ── NO METADATA AT ALL ────────────────────────────────────────
    # Complete absence is suspicious but not definitive on its own.
    if not metadata or len(metadata) == 0:
        risk_score += 30
        findings.append({
            'points':      30,
            'description': 'No metadata found — may have been deliberately stripped',
            'recommendation': 'Investigate whether metadata removal tool was used. '
                              'Check file history if available.'
        })
        return _finalise(findings, risk_score)

    # ── MISSING EXIF IN IMAGE ─────────────────────────────────────
    # Every modern camera writes EXIF automatically.
    # Absence strongly suggests deliberate removal.
    if file_type == 'image' and 'EXIF Status' in metadata:
        risk_score += 30
        findings.append({
            'points':      30,
            'description': 'No EXIF data in image — all modern cameras write EXIF '
                           'automatically. Complete absence suggests deliberate removal.',
            'recommendation': 'Check if metadata was stripped using tools like '
                              'MAT2 or ExifEraser. Request original device if possible.'
        })

    # ── GPS COORDINATES ───────────────────────────────────────────
    # GPS presence is informational — useful, not alarming.
    if 'GPS Coordinates' in metadata:
        risk_score += 5
        findings.append({
            'points':      5,
            'description': f'GPS location embedded: {metadata["GPS Coordinates"]}',
            'recommendation': 'Verify whether the location is consistent with '
                              'the claimed origin of the file.'
        })

    # ── EDITING SOFTWARE ──────────────────────────────────────────
    # Presence of editing software doesn't prove tampering,
    # but it means the file passed through an editing application.
    editing_tools = [
        'photoshop', 'gimp', 'lightroom', 'affinity',
        'pixelmator', 'paint.net', 'darktable'
    ]
    software = metadata.get('Software', '').lower()
    for tool in editing_tools:
        if tool in software:
            risk_score += 15
            findings.append({
                'points':      15,
                'description': f'Image editing software detected: {metadata.get("Software")}',
                'recommendation': 'This does not confirm tampering but indicates '
                                  'the file was processed through editing software. '
                                  'Request original unedited version for comparison.'
            })
            break

    # ── TIMESTAMP INCONSISTENCY ───────────────────────────────────
    # Modified before created is physically impossible
    # unless timestamps were manually altered.
    created_str  = (metadata.get('DateTime') or
                    metadata.get('DateTimeOriginal') or
                    metadata.get('Created') or
                    metadata.get('Creation Date'))

    modified_str = (metadata.get('DateTimeDigitized') or
                    metadata.get('Modified') or
                    metadata.get('Modified Date'))

    if created_str and modified_str:
        created_dt  = parse_date(str(created_str))
        modified_dt = parse_date(str(modified_str))

        if created_dt and modified_dt:
            if modified_dt < created_dt:
                risk_score += 20
                findings.append({
                    'points':      20,
                    'description': f'Timestamp inconsistency — modified '
                                   f'({modified_str}) is BEFORE created ({created_str}). '
                                   f'This is physically impossible without manual alteration.',
                    'recommendation': 'Timestamp manipulation is a common anti-forensic '
                                      'technique. Treat file timestamps as unreliable.'
                })
            elif (modified_dt - created_dt).days > 365:
                risk_score += 5
                findings.append({
                    'points':      5,
                    'description': f'File modified more than 1 year after creation',
                    'recommendation': 'Note the time gap when building the '
                                      'investigation timeline.'
                })

    # ── AUTHOR vs MODIFIER MISMATCH ───────────────────────────────
    author   = metadata.get('Author', '').strip()
    modifier = metadata.get('Last Modified By', '').strip()

    if author and modifier and author.lower() != modifier.lower():
        risk_score += 10
        findings.append({
            'points':      10,
            'description': f"Author '{author}' differs from last modifier '{modifier}'",
            'recommendation': 'Document changed hands or was modified by a '
                              'different person. Verify both identities.'
        })

    # ── SUSPICIOUS AUTHOR NAME ────────────────────────────────────
    suspicious_names = [
        'admin', 'user', 'test', 'default', 'owner',
        'unknown', 'anonymous', 'guest', 'temp'
    ]
    if author and author.lower() in suspicious_names:
        risk_score += 10
        findings.append({
            'points':      10,
            'description': f"Generic author name detected: '{author}' — "
                           f'suggests the user profile was not properly configured, '
                           f'possibly to avoid identification.',
            'recommendation': 'Attempt to identify the actual author through '
                              'other means such as file access logs.'
        })

    # ── ENCRYPTED PDF ─────────────────────────────────────────────
    if metadata.get('Encryption Status'):
        risk_score += 10
        findings.append({
            'points':      10,
            'description': 'PDF is password protected / encrypted',
            'recommendation': 'Attempt decryption with known passwords. '
                              'Note encryption in chain of custody.'
        })

    # ── MISSING CAMERA INFO IN IMAGE ──────────────────────────────
    if file_type == 'image':
        has_make  = 'Make' in metadata or 'Camera Make' in metadata
        has_model = 'Model' in metadata or 'Camera Model' in metadata
        if not has_make and not has_model and 'EXIF Status' not in metadata:
            risk_score += 10
            findings.append({
                'points':      10,
                'description': 'Camera make and model missing from image metadata — '
                               'most cameras write this automatically.',
                'recommendation': 'Camera information absence may indicate '
                                  'metadata was selectively removed.'
            })

    # ── HIGH REVISION COUNT ───────────────────────────────────────
    revision = metadata.get('Revision Number')
    if revision:
        try:
            if int(str(revision)) > 20:
                risk_score += 5
                findings.append({
                    'points':      5,
                    'description': f'High revision count ({revision}) — '
                                   f'document was heavily edited over time.',
                    'recommendation': 'Review revision history if available '
                                      'to understand document evolution.'
                })
        except ValueError:
            pass

    # ── CLEAN FILE ────────────────────────────────────────────────
    # If no suspicious indicators were found, say so explicitly.
    suspicious = [f for f in findings if f['points'] > 0]
    if len(suspicious) == 0:
        findings.append({
            'points':      0,
            'description': 'No anomalies detected — file metadata appears consistent.',
            'recommendation': 'File passed all automated triage checks. '
                              'Manual review is still recommended for critical evidence.'
        })

    return _finalise(findings, risk_score)


def _finalise(findings, raw_score):
    """
    Caps the score at 100, determines overall risk level,
    and formats findings in the structure the rest of the
    app expects — keeping backward compatibility with
    the existing database schema and dashboard display.
    """
    score = min(raw_score, 100)

    if score <= 30:
        overall = 'LOW'
    elif score <= 60:
        overall = 'MEDIUM'
    else:
        overall = 'HIGH'

    result = []
    for f in findings:
        # Map point contribution to severity for display
        if f['points'] >= 20:
            severity = 'HIGH'
        elif f['points'] >= 10:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'

        description = f['description']
        if f['recommendation']:
            description += f' | RECOMMENDATION: {f["recommendation"]}'

        result.append({
            'severity':    severity,
            'description': description,
            'points':      f['points'],
        })

    # Add the overall score as the first entry so it's
    # always visible at the top of the indicators list
    result.insert(0, {
        'severity':    overall,
        'description': f'RISK SCORE: {score}/100 — Overall assessment: {overall}. '
                       f'{_score_explanation(score)}',
        'points':      score,
    })

    return result


def _score_explanation(score):
    """
    Returns professional recommendation language based on score.
    Avoids definitive conclusions — mirrors real forensic practice.
    """
    if score <= 30:
        return ('No significant anomalies detected. '
                'File appears consistent with stated origin. '
                'Standard evidence handling procedures apply.')
    elif score <= 60:
        return ('File contains anomalies warranting further examination. '
                'Do not rely solely on automated analysis. '
                'Consider detailed forensic review.')
    else:
        return ('File contains multiple anomalies that warrant detailed '
                'forensic examination before use as evidence. '
                'Do not draw conclusions from automated analysis alone.')


def parse_date(date_string):
    """
    Converts a date string to a datetime object.
    Tries multiple formats since different software writes dates differently.
    """
    formats = [
        '%Y:%m:%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d',
        'D:%Y%m%d%H%M%S',
    ]

    date_string = date_string.replace("'", "").strip()

    for fmt in formats:
        try:
            return datetime.strptime(date_string[:19], fmt)
        except ValueError:
            continue

    return None