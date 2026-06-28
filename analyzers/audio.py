import mutagen
from mutagen.mp3  import MP3
from mutagen.flac import FLAC
from mutagen.wave import WAVE

def analyze_audio(filepath):
    """
    Extracts metadata from audio files.
    
    Audio metadata is called ID3 tags (for MP3) or Vorbis comments (for FLAC).
    These were originally designed for music info (artist, album, track)
    but also capture encoder software and technical recording specs —
    which is what we care about forensically.
    """
    metadata = {}

    try:
        # mutagen.File() is smart enough to detect the format automatically
        audio = mutagen.File(filepath)

        if audio is None:
            metadata['Status'] = 'Could not identify audio format'
            return metadata

        # Duration stored in seconds — convert to minutes:seconds
        if hasattr(audio, 'info') and hasattr(audio.info, 'length'):
            total_seconds = int(audio.info.length)
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            metadata['Duration'] = f'{minutes}m {seconds}s'

        # Bitrate — quality of the audio (higher = better quality / larger file)
        if hasattr(audio.info, 'bitrate'):
            metadata['Bitrate'] = f'{audio.info.bitrate // 1000} kbps'

        # Sample rate — how many audio snapshots per second (usually 44100 Hz)
        if hasattr(audio.info, 'sample_rate'):
            metadata['Sample Rate'] = f'{audio.info.sample_rate} Hz'

        # Tags contain artist, album, encoder, software etc.
        # audio.tags is a dictionary — we loop through all of it
        if audio.tags:
            for key, value in audio.tags.items():
                clean_key   = str(key).strip()
                clean_value = str(value).strip()
                if clean_value:
                    metadata[clean_key] = clean_value

    except Exception as e:
        metadata['Error'] = f'Could not read audio file: {str(e)}'

    return metadata