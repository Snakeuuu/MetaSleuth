def detect_antiforensics(metadata, filepath, file_type):
    """
    Looks for traces of deliberate metadata removal.

    Tools like MAT2, ExifEraser, and ExifTool (in wipe mode)
    leave recognizable patterns when they scrub files:

    1. A JPEG with zero EXIF but valid image structure
       — cameras always write EXIF, so absence means removal

    2. A PDF where Creator and Producer fields are both blank
       — PDF software always writes these automatically

    3. A JPEG whose thumbnail doesn't match the main image
       — editing tools sometimes update main image but
         forget to update the embedded thumbnail

    4. Structural tells — certain scrubbing tools leave
       their own markers or create unusual byte patterns

    Returns a list of anti-forensics indicators.
    """
    findings = []

    if file_type == 'image':
        findings.extend(_check_image_antiforensics(metadata, filepath))

    elif file_type == 'pdf':
        findings.extend(_check_pdf_antiforensics(metadata))

    elif file_type == 'word':
        findings.extend(_check_word_antiforensics(metadata))

    return findings


def _check_image_antiforensics(metadata, filepath):
    findings = []

    # PATTERN 1: Image has no EXIF at all
    # A camera ALWAYS writes EXIF — exposure, date, camera model.
    # A phone ALWAYS writes EXIF — GPS, device model, date.
    # Zero EXIF on a camera/phone photo means it was removed.
    if 'EXIF Status' in metadata:
        findings.append({
            'type':        'METADATA_STRIPPED',
            'confidence':  'HIGH',
            'description': 'Complete EXIF absence in image — '
                           'consistent with MAT2, ExifEraser, or ExifTool -all= wipe',
            'detail':      'All camera/phone images contain at minimum: '
                           'DateTimeOriginal, Make, Model. '
                           'Complete absence indicates deliberate removal.'
        })

    # PATTERN 2: Software field was cleared but other fields remain
    # Scrubbing tools sometimes miss fields or clear only some
    has_camera_data = ('Make' in metadata or 'Model' in metadata)
    missing_software = 'Software' not in metadata

    if has_camera_data and missing_software:
        findings.append({
            'type':        'PARTIAL_WIPE',
            'confidence':  'MEDIUM',
            'description': 'Camera data present but Software field removed — '
                           'suggests selective metadata scrubbing',
            'detail':      f'Camera: {metadata.get("Make","")} {metadata.get("Model","")}'
                           f' | Software field: absent'
        })

    # PATTERN 3: GPS reference fields present but coordinates missing
    # MAT2 sometimes removes coordinate values but
    # leaves the reference fields (N/S, E/W) behind
    has_gps_ref = ('GPSLatitudeRef' in metadata or 'GPSLongitudeRef' in metadata)
    missing_coords = 'GPS Coordinates' not in metadata

    if has_gps_ref and missing_coords:
        findings.append({
            'type':        'GPS_PARTIAL_WIPE',
            'confidence':  'HIGH',
            'description': 'GPS reference fields present but coordinates removed — '
                           'strong indicator of deliberate GPS scrubbing',
            'detail':      'Tool left direction references (N/S/E/W) '
                           'but removed the actual coordinate values'
        })

    # PATTERN 4: Check file size vs image dimensions
    # A "cleaned" image that was re-saved by a scrubbing tool
    # often has an unusual file size for its dimensions —
    # the tool re-encodes the image without its metadata
    try:
        import os
        from PIL import Image
        file_size = os.path.getsize(filepath)
        img = Image.open(filepath)
        width, height = img.size

        if width and height and file_size:
            # Rough check: for a JPEG, file size should be
            # roughly width * height * 0.1 to 0.5 bytes
            # (JPEG compression ratio)
            ratio = file_size / (width * height)

            # Very low ratio can indicate aggressive re-encoding
            # which scrubbing tools often do
            if ratio < 0.05:
                findings.append({
                    'type':        'SUSPICIOUS_COMPRESSION',
                    'confidence':  'LOW',
                    'description': 'Unusually high compression ratio — '
                                   'may indicate re-encoding by a scrubbing tool',
                    'detail':      f'File: {file_size} bytes | '
                                   f'Dimensions: {width}x{height} | '
                                   f'Ratio: {ratio:.3f}'
                })
    except Exception:
        pass  # Image couldn't be read for size check — skip this pattern

    return findings


def _check_pdf_antiforensics(metadata):
    findings = []

    # PATTERN: PDF with no Creator, Producer, or Author
    # Every PDF tool writes at least one of these.
    # All three missing = scrubbed.
    has_creator  = bool(metadata.get('Creator'))
    has_producer = bool(metadata.get('Producer'))
    has_author   = bool(metadata.get('Author'))

    if not has_creator and not has_producer and not has_author:
        findings.append({
            'type':        'PDF_METADATA_STRIPPED',
            'confidence':  'HIGH',
            'description': 'PDF has no Creator, Producer, or Author fields — '
                           'all three absent suggests metadata was deliberately removed',
            'detail':      'Normal PDF software always writes at minimum '
                           'the Producer field identifying the PDF library used.'
        })

    # PATTERN: Creation and modification dates both missing
    has_created  = bool(metadata.get('Creation Date'))
    has_modified = bool(metadata.get('Modified Date'))

    if not has_created and not has_modified:
        findings.append({
            'type':        'PDF_DATES_STRIPPED',
            'confidence':  'MEDIUM',
            'description': 'PDF creation and modification dates both absent — '
                           'dates are written automatically by all PDF software',
            'detail':      'Missing dates in a PDF strongly suggest '
                           'the Info Dictionary was cleared.'
        })

    return findings


def _check_word_antiforensics(metadata):
    findings = []

    # PATTERN: Word document with no author at all
    # Word always writes the author from the Office profile.
    # Missing author means the profile was cleared or
    # the document was sanitized.
    if not metadata.get('Author'):
        findings.append({
            'type':        'WORD_AUTHOR_REMOVED',
            'confidence':  'MEDIUM',
            'description': 'Word document has no Author field — '
                           'Microsoft Word always records the author from '
                           'the user profile at time of creation',
            'detail':      'Absent author field suggests the document '
                           'properties were manually cleared or the file '
                           'was processed by a document sanitizer.'
        })

    # PATTERN: Revision number is 1 but editing time is high
    # If someone scrubbed revision history, the revision counter
    # resets — but editing time might not reset correctly
    revision     = metadata.get('Revision Number', '0')
    editing_time = metadata.get('Total Editing Time', '0')

    try:
        rev  = int(str(revision))
        mins = int(str(editing_time))
        # Revision 1 but more than 30 minutes of editing is suspicious
        # A real first-save document wouldn't have 30+ minutes logged
        if rev <= 1 and mins > 30:
            findings.append({
                'type':        'REVISION_MISMATCH',
                'confidence':  'MEDIUM',
                'description': f'Revision count ({rev}) inconsistent with '
                               f'editing time ({mins} minutes) — '
                               f'revision history may have been reset',
                'detail':      'Document sanitizers sometimes reset the '
                               'revision counter without resetting editing time, '
                               'leaving this detectable inconsistency.'
            })
    except ValueError:
        pass

    return findings