def verify_file_type(filepath, claimed_extension):
    """
    Reads the first few bytes of a file — its "magic bytes" —
    and compares them to what the file extension claims to be.

    Every file format has a unique signature baked into
    its first bytes by the software that created it.
    These bytes cannot be faked by simply renaming a file.

    A .jpg renamed to look like a .pdf still has JPEG
    magic bytes — and we'll catch that.

    Returns a dict:
    {
        "claimed":   "jpg",
        "detected":  "jpeg",
        "match":     True or False,
        "signature": "FF D8 FF"   (the actual bytes we read)
    }
    """

    # This dictionary maps the first bytes of each format
    # to a readable name.
    # Format: bytes_signature → file_type_name
    MAGIC_SIGNATURES = {

        # Images
        b'\xff\xd8\xff'          : 'jpeg',
        b'\x89PNG\r\n\x1a\n'    : 'png',
        b'II*\x00'               : 'tiff',   # TIFF little-endian
        b'MM\x00*'               : 'tiff',   # TIFF big-endian
        b'GIF87a'                : 'gif',
        b'GIF89a'                : 'gif',
        b'BM'                    : 'bmp',
        b'RIFF'                  : 'webp',   # also used by WAV

        # Documents
        b'%PDF'                  : 'pdf',
        b'PK\x03\x04'           : 'zip_based',  # ZIP, DOCX, XLSX are all ZIP inside
        b'\xd0\xcf\x11\xe0'     : 'ms_office_old',  # old .doc .xls format

        # Audio
        b'ID3'                   : 'mp3',
        b'\xff\xfb'              : 'mp3',
        b'\xff\xf3'              : 'mp3',
        b'fLaC'                  : 'flac',

        # Video
        b'\x00\x00\x00\x18ftyp' : 'mp4',
        b'\x00\x00\x00\x1cftyp' : 'mp4',
        b'\x1aE\xdf\xa3'        : 'mkv',

        # Executables — dangerous if renamed as something else
        b'MZ'                    : 'exe_or_dll',   # Windows executable
        b'\x7fELF'               : 'linux_executable',

        # Archives
        b'Rar!\x1a\x07'         : 'rar',
        b'\x1f\x8b'             : 'gzip',
        b'7z\xbc\xaf\x27\x1c'  : '7zip',
    }

    # Extension groups — what magic bytes are acceptable
    # for each file extension we support
    EXTENSION_ALLOWED_TYPES = {
        'jpg':  ['jpeg'],
        'jpeg': ['jpeg'],
        'png':  ['png'],
        'tiff': ['tiff'],
        'tif':  ['tiff'],
        'pdf':  ['pdf'],
        # DOCX is a ZIP file internally — Word packs everything
        # into a ZIP container with XML files inside
        'docx': ['zip_based'],
        'mp3':  ['mp3'],
        'flac': ['flac'],
        # WAV uses RIFF container — same as some WebP images
        'wav':  ['riff'],
        'mp4':  ['mp4'],
        'mov':  ['mp4'],
        'zip':  ['zip_based'],
    }

    result = {
        'claimed':   claimed_extension.lower(),
        'detected':  'unknown',
        'match':     False,
        'signature': '',
        'is_executable': False
    }

    try:
        # Read only the first 16 bytes —
        # that's all we need for the signature check
        with open(filepath, 'rb') as f:
            header = f.read(16)

        # Convert to hex string for display in the report
        # e.g. b'\xff\xd8\xff' → "FF D8 FF"
        result['signature'] = ' '.join(f'{byte:02X}' for byte in header[:8])

        # Check which magic signature matches our header
        detected_type = 'unknown'
        for magic, file_type in MAGIC_SIGNATURES.items():
            if header.startswith(magic):
                detected_type = file_type
                break

        result['detected'] = detected_type

        # Flag executables immediately — always suspicious
        if detected_type in ['exe_or_dll', 'linux_executable']:
            result['is_executable'] = True
            result['match'] = False
            return result

        # Check if the detected type is acceptable
        # for the claimed extension
        ext = claimed_extension.lower().strip('.')
        allowed = EXTENSION_ALLOWED_TYPES.get(ext, [])
        result['match'] = detected_type in allowed

    except Exception as e:
        result['detected'] = f'Error reading file: {str(e)}'

    return result