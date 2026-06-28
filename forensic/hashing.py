import hashlib

def calculate_hashes(filepath):
    """
    Reads a file and calculates three different hash values.
    
    Why three? Each algorithm has different strengths:
    
    MD5    — Fast, short (32 characters). Used for quick comparisons.
              Not considered secure for cryptography anymore, but
              still standard in forensics for integrity checking.
    
    SHA1   — Slower, longer (40 characters). More unique than MD5.
              Git (the version control system) uses SHA1 to track files.
    
    SHA256 — Slowest, longest (64 characters). Most reliable.
              The gold standard in modern forensics and cybersecurity.
              Used by courts and law enforcement as the definitive
              file fingerprint.
    
    We calculate all three because older forensic tools and
    databases (like VirusTotal) may only accept one format.
    """

    # Create three "calculator" objects — one per algorithm
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        # We open the file in binary mode (rb = read binary)
        # and read it in chunks of 65536 bytes (64KB) at a time.
        #
        # Why chunks? A 2GB video file can't fit in memory all at once.
        # Reading in chunks means we can hash ANY size file safely.
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(65536)

                # An empty chunk means we've reached the end of the file
                if not chunk:
                    break

                # Feed each chunk into all three calculators
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        # .hexdigest() converts the raw mathematical result
        # into the readable string format you see in forensic reports
        return {
            'md5':    md5.hexdigest(),
            'sha1':   sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }

    except Exception as e:
        return {
            'md5':    'error',
            'sha1':   'error',
            'sha256': f'Could not hash file: {str(e)}'
        }


def verify_hash(filepath, known_sha256):
    """
    Checks if a file still matches a previously recorded hash.
    
    This is used to verify evidence integrity —
    if you analyzed a file last week and stored its SHA256,
    you can run this today to prove the file hasn't changed.
    
    Returns True  (file is intact) or
            False (file has been modified — serious problem)
    """
    current_hashes = calculate_hashes(filepath)
    current_sha256 = current_hashes.get('sha256', '')

    return current_sha256.lower() == known_sha256.lower()
    # .lower() because some systems write hashes in uppercase,
    # some in lowercase — we normalize both before comparing