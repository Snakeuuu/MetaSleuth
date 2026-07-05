from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

def analyze_image(filepath):
    """
    Opens an image file and extracts all hidden EXIF metadata.
    Returns a dictionary of everything found.
    
    EXIF stands for Exchangeable Image File Format.
    It's a standard that camera manufacturers agreed on —
    every camera writes the same kinds of hidden data
    in the same format, which is why we can read any camera's photos.
    """
    metadata = {}

    try:
        # Open the image file — Pillow handles JPEG, PNG, TIFF
        image = Image.open(filepath)

        # .getexif() reads the hidden EXIF layer
        # If no EXIF exists, it returns None
        exif_data = image.getexif()

        if not exif_data:
            # No EXIF found — this itself is suspicious
            # (could mean it was deliberately stripped)
            metadata['EXIF Status'] = 'No EXIF data found'
            return metadata

        # EXIF stores data as number codes, not readable names
        # TAGS is a dictionary that translates codes to names
        # e.g. 271 → "Make", 272 → "Model"
        for tag_code, value in exif_data.items():
            tag_name = TAGS.get(tag_code)

            # Skip raw binary thumbnail data — not useful as text
            if tag_name == 'MakerNote':
                continue
            if isinstance(value, bytes):
                continue

            value_str = str(value)

            if tag_name is None:
                # Pillow doesn't have a friendly name for this tag code —
                # usually a newer standard tag or manufacturer-specific
                # field it hasn't caught up to yet. If it's genuinely
                # empty (0, "", None) it carries no forensic value, so
                # skip it rather than clutter the report with noise.
                # If it DOES have real content, keep it but label clearly
                # so it doesn't look like a random unlabeled number.
                if value_str in ('0', '', 'None'):
                    continue
                tag_name = f'Unknown Tag ({tag_code})'

            metadata[tag_name] = value_str

        # GPS data is nested inside EXIF under a special tag (34853)
        # It needs its own extraction process
        gps_info = exif_data.get_ifd(34853)
        if gps_info:
            gps_metadata = extract_gps(gps_info)
            metadata.update(gps_metadata)

    except Exception as e:
        metadata['Error'] = f'Could not read image: {str(e)}'

    return metadata


def extract_gps(gps_info):
    """
    GPS inside EXIF is stored as raw degrees/minutes/seconds numbers.
    This function converts that into a readable coordinate
    like "28.6139, 77.2090".
    
    Think of it like converting "28° 36' 50.04" N" 
    into the decimal format Google Maps uses.
    """
    gps_metadata = {}

    # Translate GPS tag codes to readable names
    # e.g. 1 → "GPSLatitudeRef" (N or S)
    #      2 → "GPSLatitude" (the actual numbers)
    decoded = {}
    for tag_code, value in gps_info.items():
        tag_name = GPSTAGS.get(tag_code, str(tag_code))
        decoded[tag_name] = value

    try:
        # Extract latitude — stored as 3 numbers: degrees, minutes, seconds
        lat_raw  = decoded.get('GPSLatitude')
        lat_ref  = decoded.get('GPSLatitudeRef', 'N')   # N or S
        lon_raw  = decoded.get('GPSLongitude')
        lon_ref  = decoded.get('GPSLongitudeRef', 'E')  # E or W

        if lat_raw and lon_raw:
            # Convert degrees/minutes/seconds to decimal
            # Formula: degrees + (minutes/60) + (seconds/3600)
            lat = float(lat_raw[0]) + float(lat_raw[1])/60 + float(lat_raw[2])/3600
            lon = float(lon_raw[0]) + float(lon_raw[1])/60 + float(lon_raw[2])/3600

            # Southern latitudes and Western longitudes are negative
            if lat_ref == 'S':
                lat = -lat
            if lon_ref == 'W':
                lon = -lon

            gps_metadata['GPS Coordinates'] = f'{lat:.6f}, {lon:.6f}'
            gps_metadata['GPS Latitude']    = f'{lat:.6f} {lat_ref}'
            gps_metadata['GPS Longitude']   = f'{lon:.6f} {lon_ref}'
            # Build a direct Google Maps link for the report
            gps_metadata['GPS Maps Link']   = f'https://maps.google.com/?q={lat},{lon}'

    except Exception:
        gps_metadata['GPS Status'] = 'GPS data present but could not be decoded'

    return gps_metadata