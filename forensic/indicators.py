from datetime import datetime

def analyze_indicators(metadata, file_type):
    """
    Takes all the metadata extracted from a file and
    runs it through a series of forensic checks.
    
    Each check asks one specific question.
    If the answer is suspicious, it creates an "indicator" —
    a finding with a severity level and a description.
    
    Severity levels:
        HIGH   — Needs immediate attention. Strong sign of tampering.
        MEDIUM — Worth investigating. Could be innocent, could be not.
        LOW    — Informational. Good to know but not alarming.
    
    Returns a list of indicators like:
    [
        {"severity": "HIGH",   "description": "GPS coordinates found"},
        {"severity": "MEDIUM", "description": "Author differs from modifier"},
    ]
    """
    indicators = []

    # ----------------------------------------------------------------
    # CHECK 1: No metadata at all
    # ----------------------------------------------------------------
    # A completely clean file with zero metadata is suspicious.
    # Normal files always have at least some metadata.
    # If it's missing entirely, someone likely used a metadata
    # removal tool (like MAT2 or ExifEraser) to hide their tracks.
    # ----------------------------------------------------------------
    if not metadata or len(metadata) == 0:
        indicators.append({
            'severity':    'HIGH',
            'description': 'No metadata found — may have been deliberately stripped'
        })
        return indicators
    # We return early here because if there's no metadata,
    # all the checks below have nothing to work with

    # ----------------------------------------------------------------
    # CHECK 2: EXIF specifically missing from an image
    # ----------------------------------------------------------------
    # Every modern camera and phone writes EXIF automatically.
    # A photo with no EXIF was either taken by a very old camera,
    # or someone removed it — which is a red flag in investigations.
    # ----------------------------------------------------------------
    if file_type == 'image' and 'EXIF Status' in metadata:
        indicators.append({
            'severity':    'HIGH',
            'description': 'No EXIF data in image — metadata may have been stripped'
        })

    # ----------------------------------------------------------------
    # CHECK 3: GPS coordinates present
    # ----------------------------------------------------------------
    # GPS in a file is not automatically bad — but it's always
    # worth flagging because it reveals physical location.
    # In fraud cases, a document with GPS from another country
    # can contradict a suspect's claimed whereabouts.
    # ----------------------------------------------------------------
    if 'GPS Coordinates' in metadata:
        indicators.append({
            'severity':    'HIGH',
            'description': f"GPS location embedded: {metadata['GPS Coordinates']}"
        })

    # ----------------------------------------------------------------
    # CHECK 4: Editing software detected
    # ----------------------------------------------------------------
    # If an image was opened in Photoshop and saved,
    # Photoshop writes its name into the EXIF.
    # In legal cases, a "original" photo that was
    # actually edited is a serious finding.
    # ----------------------------------------------------------------
    editing_software = [
        'photoshop', 'gimp', 'lightroom', 'affinity',
        'pixelmator', 'paint.net', 'darktable'
    ]
    software_field = metadata.get('Software', '').lower()
    producer_field = metadata.get('Producer', '').lower()
    creator_field  = metadata.get('Creator',  '').lower()

    for software in editing_software:
        if software in software_field:
            indicators.append({
                'severity':    'HIGH',
                'description': f"Image editing software detected: {metadata.get('Software')}"
            })
            break  # Only flag once even if multiple matches

    # Check PDF-specific editing software
    for software in editing_software:
        if software in producer_field or software in creator_field:
            indicators.append({
                'severity':    'MEDIUM',
                'description': f"Document processed through editing software: {metadata.get('Producer') or metadata.get('Creator')}"
            })
            break

    # ----------------------------------------------------------------
    # CHECK 5: Timestamp inconsistency
    # ----------------------------------------------------------------
    # This is one of the most telling forensic indicators.
    # A file's modified date should NEVER be earlier than
    # its creation date — that's physically impossible
    # unless someone manually changed the timestamps.
    # This is called "timestamp manipulation" and is a
    # common anti-forensics technique.
    # ----------------------------------------------------------------
    created_str  = metadata.get('DateTime')           or \
                   metadata.get('DateTimeOriginal')   or \
                   metadata.get('Created')            or \
                   metadata.get('Creation Date')

    modified_str = metadata.get('DateTimeDigitized') or \
                   metadata.get('Modified')           or \
                   metadata.get('Modified Date')

    if created_str and modified_str:
        created_dt  = parse_date(str(created_str))
        modified_dt = parse_date(str(modified_str))

        if created_dt and modified_dt:
            if modified_dt < created_dt:
                indicators.append({
                    'severity':    'HIGH',
                    'description': f'Timestamp inconsistency — modified ({modified_str}) is BEFORE created ({created_str})'
                })
            elif (modified_dt - created_dt).days > 365:
                # Modified more than a year after creation
                # Not necessarily bad but worth noting
                indicators.append({
                    'severity':    'LOW',
                    'description': f'File modified more than 1 year after creation'
                })

    # ----------------------------------------------------------------
    # CHECK 6: Author vs Last Modified By mismatch
    # ----------------------------------------------------------------
    # Word documents and PDFs store both the original author
    # and whoever last saved the file.
    # If these are different people, the document changed hands —
    # which matters a lot in fraud or contract dispute cases.
    # ----------------------------------------------------------------
    author   = metadata.get('Author',           '').strip()
    modifier = metadata.get('Last Modified By', '').strip()

    if author and modifier and author.lower() != modifier.lower():
        indicators.append({
            'severity':    'MEDIUM',
            'description': f"Author '{author}' differs from last modifier '{modifier}'"
        })

    # ----------------------------------------------------------------
    # CHECK 7: Suspicious author names
    # ----------------------------------------------------------------
    # Default usernames like "Admin", "User", "Test" suggest
    # someone used a computer without setting up a real profile —
    # often done deliberately to avoid identification.
    # ----------------------------------------------------------------
    suspicious_names = [
        'admin', 'user', 'test', 'default', 'owner',
        'unknown', 'anonymous', 'guest', 'temp'
    ]
    if author and author.lower() in suspicious_names:
        indicators.append({
            'severity':    'MEDIUM',
            'description': f"Generic/suspicious author name: '{author}'"
        })

    # ----------------------------------------------------------------
    # CHECK 8: PDF encryption
    # ----------------------------------------------------------------
    # An encrypted PDF in an evidence set is worth flagging.
    # It might just be a protected form, or it might be
    # someone hiding what's inside.
    # ----------------------------------------------------------------
    if metadata.get('Encryption Status'):
        indicators.append({
            'severity':    'MEDIUM',
            'description': 'PDF is password protected / encrypted'
        })

    # ----------------------------------------------------------------
    # CHECK 9: High revision count on Word documents
    # ----------------------------------------------------------------
    # A document with 30+ revisions was heavily worked on.
    # In legal cases, this can reveal a document was
    # drafted and redrafted many times — contradicting claims
    # that it was written quickly or by one person.
    # ----------------------------------------------------------------
    revision = metadata.get('Revision Number')
    if revision:
        try:
            if int(str(revision)) > 20:
                indicators.append({
                    'severity':    'LOW',
                    'description': f'High revision count ({revision}) — document was heavily edited'
                })
        except ValueError:
            pass  # revision wasn't a number, skip

    # ----------------------------------------------------------------
    # CHECK 10: Very long editing time
    # ----------------------------------------------------------------
    # Word tracks total time the document was open for editing.
    # More than 5 hours of editing on a "simple" document is notable.
    # ----------------------------------------------------------------
    editing_time = metadata.get('Total Editing Time')
    if editing_time:
        try:
            minutes = int(str(editing_time))
            if minutes > 300:  # 300 minutes = 5 hours
                indicators.append({
                    'severity':    'LOW',
                    'description': f'Extensive editing time: {minutes} minutes ({minutes//60}h {minutes%60}m)'
                })
        except ValueError:
            pass

    # ----------------------------------------------------------------
    # CHECK 11: Hidden comments or custom properties
    # ----------------------------------------------------------------
    # Documents sometimes contain hidden comments or custom
    # metadata fields that authors forget are there —
    # these can contain internal project names, client info,
    # or notes the author didn't intend to share.
    # ----------------------------------------------------------------
    if metadata.get('Keywords') or metadata.get('Description') or metadata.get('Subject'):
        indicators.append({
            'severity':    'LOW',
            'description': 'Document contains keywords/description fields — may reveal internal information'
        })

    # ----------------------------------------------------------------
    # CHECK 12: No indicators found — file looks clean
    # ----------------------------------------------------------------
    if len(indicators) == 0:
        indicators.append({
            'severity':    'LOW',
            'description': 'No suspicious indicators detected — file appears clean'
        })

    return indicators


def parse_date(date_string):
    """
    Tries to convert a date string into a Python datetime object
    so we can compare dates mathematically.
    
    The problem is different software writes dates in different formats:
    - EXIF uses:    "2026:05:14 09:32:11"
    - Word uses:    "2026-05-14 09:32:11"  
    - PDF uses:     "D:20260514093211"
    
    We try each format until one works.
    """
    formats = [
        '%Y:%m:%d %H:%M:%S',    # EXIF standard format
        '%Y-%m-%d %H:%M:%S',    # ISO format (Word, general)
        '%Y-%m-%dT%H:%M:%S',    # ISO with T separator
        '%Y-%m-%d',              # Date only
        "D:%Y%m%d%H%M%S",       # PDF format
        '%Y%m%d%H%M%S',         # Compact format
    ]

    # Clean up common PDF date artifacts
    date_string = date_string.replace("'", "").strip()

    for fmt in formats:
        try:
            return datetime.strptime(date_string[:len(fmt)], fmt)
        except ValueError:
            continue
            # ValueError means this format didn't match,
            # so we try the next one

    return None
    # If nothing worked, return None —
    # the calling code checks for None before comparing