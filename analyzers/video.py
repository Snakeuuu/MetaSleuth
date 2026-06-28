from pymediainfo import MediaInfo

def analyze_video(filepath):
    """
    Extracts metadata from video files.
    
    Videos have multiple "tracks" inside them —
    a video track, an audio track, sometimes subtitles.
    pymediainfo reads all tracks and their technical details.
    Some cameras also embed GPS into video files, 
    which we extract separately.
    """
    metadata = {}

    try:
        # Parse the file — MediaInfo reads all tracks at once
        media_info = MediaInfo.parse(filepath)

        for track in media_info.tracks:

            if track.track_type == 'General':
                # General track = file-level information
                fields = {
                    'Duration':          track.duration,
                    'File Size':         track.file_size,
                    'Format':            track.format,
                    'Encoded Date':      track.encoded_date,
                    'Tagged Date':       track.tagged_date,
                    'Writing App':       track.writing_application,
                    'Writing Library':   track.writing_library,
                    'Encoded By':        track.encoded_by,
                    'Comment':           track.comment,
                }
                for key, value in fields.items():
                    if value:
                        metadata[key] = str(value)

            elif track.track_type == 'Video':
                # Video track = resolution, frame rate, codec
                fields = {
                    'Resolution':     f'{track.width}x{track.height}' if track.width else None,
                    'Frame Rate':     f'{track.frame_rate} fps'        if track.frame_rate else None,
                    'Codec':          track.codec_id,
                    'Bit Depth':      track.bit_depth,
                    'Color Space':    track.color_space,
                }
                for key, value in fields.items():
                    if value:
                        metadata[f'Video — {key}'] = str(value)

            elif track.track_type == 'Audio':
                # Audio track inside the video
                fields = {
                    'Audio Codec':    track.codec_id,
                    'Audio Channels': track.channel_s,
                    'Audio Rate':     track.sampling_rate,
                }
                for key, value in fields.items():
                    if value:
                        metadata[f'Audio — {key}'] = str(value)

    except Exception as e:
        metadata['Error'] = f'Could not read video file: {str(e)}'

    return metadata