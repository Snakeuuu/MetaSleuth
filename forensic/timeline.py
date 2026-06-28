from datetime import datetime

def build_timeline(metadata, filename):
    """
    Pulls every timestamp out of the metadata dictionary
    and sorts them into a chronological list.
    
    In a real investigation, this timeline becomes the backbone
    of your report — it answers "what happened, and when?"
    
    Returns a list of events sorted oldest to newest:
    [
        {"date": "2026-01-10", "event": "File Created", "file": "doc.pdf"},
        {"date": "2026-01-12", "event": "Last Modified", "file": "doc.pdf"},
    ]
    """
    events = []

    # This dictionary maps metadata key names to
    # human-readable event descriptions
    # We check each one and if it has a value, add it to the timeline
    timestamp_fields = {
        # Image timestamps
        'DateTimeOriginal':   'Photo Originally Taken',
        'DateTime':           'File Date/Time',
        'DateTimeDigitized':  'Image Digitized',

        # Document timestamps  
        'Created':            'Document Created',
        'Modified':           'Last Modified',
        'Creation Date':      'Document Created',
        'Modified Date':      'Last Modified',
        'Last Printed':       'Last Printed',

        # Video timestamps
        'Encoded Date':       'Video Encoded',
        'Tagged Date':        'Video Tagged',
    }

    for field, event_name in timestamp_fields.items():
        raw_date = metadata.get(field)

        if raw_date:
            parsed = parse_date_flexible(str(raw_date))

            if parsed:
                events.append({
                    'date':       parsed.strftime('%Y-%m-%d'),
                    'time':       parsed.strftime('%H:%M:%S'),
                    'datetime':   parsed,         # kept for sorting
                    'event':      event_name,
                    'raw':        str(raw_date),  # original value for reference
                    'file':       filename
                })

    # Add GPS detection as a timeline event if present
    if 'GPS Coordinates' in metadata:
        events.append({
            'date':     'N/A',
            'time':     'N/A',
            'datetime': datetime.min,   # sorts to the beginning
            'event':    f"GPS Location Embedded: {metadata['GPS Coordinates']}",
            'raw':      metadata['GPS Coordinates'],
            'file':     filename
        })

    # Sort all events from oldest to newest
    # We sort by the datetime object so the comparison is accurate
    events.sort(key=lambda x: x['datetime'])

    # Remove the datetime object before returning —
    # it's not JSON-serializable and we don't need it anymore
    for event in events:
        del event['datetime']

    return events


def parse_date_flexible(date_string):
    """
    Same date parsing logic as in indicators.py —
    tries multiple formats until one works.
    
    (In a larger project you'd put this in a shared
    utils.py file to avoid repeating it — that's called
    the DRY principle: Don't Repeat Yourself.
    For now, keeping it simple.)
    """
    formats = [
        '%Y:%m:%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d',
        "D:%Y%m%d%H%M%S",
    ]

    date_string = date_string.replace("'", "").strip()

    for fmt in formats:
        try:
            return datetime.strptime(date_string[:19], fmt)
        except ValueError:
            continue

    return None