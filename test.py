"""
Run this file to test each analyzer independently.
Usage: python test.py
Put a real file path where it says FILE_PATH_HERE
"""

import sys
import os

# Add the project root to Python's search path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_image(filepath):
    from analyzers.image import analyze_image
    from forensic.indicators import analyze_indicators
    from forensic.timeline import build_timeline
    from forensic.hashing import calculate_hashes

    print(f'\n{"="*50}')
    print(f'Testing image: {filepath}')
    print('='*50)

    # Test hashing
    print('\n[1] Calculating hashes...')
    hashes = calculate_hashes(filepath)
    for algo, value in hashes.items():
        print(f'    {algo.upper()}: {value}')

    # Test metadata extraction
    print('\n[2] Extracting metadata...')
    metadata = analyze_image(filepath)
    if metadata:
        for key, value in list(metadata.items())[:10]:
            print(f'    {key}: {value}')
        if len(metadata) > 10:
            print(f'    ... and {len(metadata)-10} more fields')
    else:
        print('    No metadata found')

    # Test indicators
    print('\n[3] Checking indicators...')
    indicators = analyze_indicators(metadata, 'image')
    for ind in indicators:
        print(f'    [{ind["severity"]}] {ind["description"]}')

    # Test timeline
    print('\n[4] Building timeline...')
    timeline = build_timeline(metadata, os.path.basename(filepath))
    if timeline:
        for event in timeline:
            print(f'    {event["date"]} {event["time"]} — {event["event"]}')
    else:
        print('    No timestamp data found')

    print('\n✓ Image test complete')


def test_pdf(filepath):
    from analyzers.pdf import analyze_pdf
    from forensic.indicators import analyze_indicators

    print(f'\n{"="*50}')
    print(f'Testing PDF: {filepath}')
    print('='*50)

    metadata = analyze_pdf(filepath)
    print('\nExtracted metadata:')
    for key, value in metadata.items():
        print(f'    {key}: {value}')

    indicators = analyze_indicators(metadata, 'pdf')
    print('\nIndicators:')
    for ind in indicators:
        print(f'    [{ind["severity"]}] {ind["description"]}')


def test_word(filepath):
    from analyzers.word import analyze_word
    from forensic.indicators import analyze_indicators

    print(f'\n{"="*50}')
    print(f'Testing Word document: {filepath}')
    print('='*50)

    metadata = analyze_word(filepath)
    print('\nExtracted metadata:')
    for key, value in metadata.items():
        print(f'    {key}: {value}')

    indicators = analyze_indicators(metadata, 'word')
    print('\nIndicators:')
    for ind in indicators:
        print(f'    [{ind["severity"]}] {ind["description"]}')


def test_database():
    from database.db import create_tables, get_dashboard_stats

    print(f'\n{"="*50}')
    print('Testing database connection...')
    print('='*50)

    try:
        create_tables()
        print('    ✓ Tables created successfully')

        stats = get_dashboard_stats()
        print(f'    ✓ Stats query works: {dict(stats)} ')

        print('\n✓ Database test complete')
    except Exception as e:
        print(f'    ✗ Database error: {e}')


# ── RUN TESTS ──────────────────────────────────────────────────

if __name__ == '__main__':

    # Always test the database first
    test_database()

    # Change these paths to real files on your computer
    # Any photo from your phone will work for the image test

    # test_image(r'C:\Users\YourName\Pictures\photo.jpg')
    # test_pdf(r'C:\Users\YourName\Documents\document.pdf')
    # test_word(r'C:\Users\YourName\Documents\report.docx')

    print('\nUncomment the test lines above with real file paths to test.')
    print('Example:  test_image(r"C:\\Users\\YourName\\Pictures\\photo.jpg")')