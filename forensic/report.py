import os
import sys
import platform
from datetime import datetime

from reportlab.lib.pagesizes  import A4
from reportlab.lib.styles     import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units      import mm
from reportlab.lib            import colors
from reportlab.platypus       import (SimpleDocTemplate, Paragraph, Spacer,
                                       Table, TableStyle, HRFlowable,
                                       PageBreak, KeepTogether)

from config import TOOL_VERSION, ANALYST_NAME

# ── COLOUR PALETTE ───────────────────────────────────────────────
# Matching the dark cybersecurity theme of the dashboard
# but adapted for print (dark backgrounds on a white page
# look professional and readable)

VOID      = colors.HexColor('#070710')
CYAN      = colors.HexColor('#00d4ff')
VIOLET    = colors.HexColor('#7b2fff')
ALERT     = colors.HexColor('#ff3366')
WARN      = colors.HexColor('#ffaa00')
OK        = colors.HexColor('#00c97a')
PANEL     = colors.HexColor('#0e0e1f')
SURFACE   = colors.HexColor('#13132a')
TEXT      = colors.HexColor('#1a1a2e')
MUTED     = colors.HexColor('#6b7a99')
WHITE     = colors.white
LIGHT_BG  = colors.HexColor('#f0f4f8')


def build_styles():
    """
    Creates all the text styles used throughout the report.
    Think of these like CSS classes — each one defines
    font, size, colour, and spacing for a type of text.
    """
    base = getSampleStyleSheet()

    styles = {}

    # Cover page title — large, white, bold
    styles['cover_title'] = ParagraphStyle(
        'cover_title',
        fontName  = 'Helvetica-Bold',
        fontSize  = 28,
        textColor = WHITE,
        spaceAfter= 6,
        leading   = 34,
    )

    # Cover page subtitle
    styles['cover_sub'] = ParagraphStyle(
        'cover_sub',
        fontName  = 'Helvetica',
        fontSize  = 12,
        textColor = CYAN,
        spaceAfter= 4,
        leading   = 16,
    )

    # Cover meta info (analyst, date, version)
    styles['cover_meta'] = ParagraphStyle(
        'cover_meta',
        fontName  = 'Courier',
        fontSize  = 9,
        textColor = colors.HexColor('#a0aec0'),
        spaceAfter= 3,
        leading   = 14,
    )

    # Section heading (e.g. "1. File Information")
    styles['section_head'] = ParagraphStyle(
        'section_head',
        fontName   = 'Helvetica-Bold',
        fontSize   = 13,
        textColor  = VOID,
        spaceBefore= 18,
        spaceAfter = 6,
        leading    = 16,
        borderPad  = (0, 0, 4, 0),
    )

    # Subsection heading
    styles['sub_head'] = ParagraphStyle(
        'sub_head',
        fontName   = 'Helvetica-Bold',
        fontSize   = 10,
        textColor  = colors.HexColor('#2d3748'),
        spaceBefore= 10,
        spaceAfter = 4,
    )

    # Normal body text
    styles['body'] = ParagraphStyle(
        'body',
        fontName  = 'Helvetica',
        fontSize  = 9,
        textColor = TEXT,
        spaceAfter= 4,
        leading   = 14,
    )

    # Monospace — for hashes, file paths, metadata values
    styles['mono'] = ParagraphStyle(
        'mono',
        fontName  = 'Courier',
        fontSize  = 8,
        textColor = TEXT,
        spaceAfter= 3,
        leading   = 12,
        backColor = LIGHT_BG,
        leftIndent= 8,
        rightIndent= 8,
        borderPad = 4,
    )

    # HIGH severity indicator
    styles['ind_high'] = ParagraphStyle(
        'ind_high',
        fontName   = 'Helvetica-Bold',
        fontSize   = 9,
        textColor  = ALERT,
        spaceAfter = 3,
        leftIndent = 12,
    )

    # MEDIUM severity indicator
    styles['ind_medium'] = ParagraphStyle(
        'ind_medium',
        fontName   = 'Helvetica-Bold',
        fontSize   = 9,
        textColor  = WARN,
        spaceAfter = 3,
        leftIndent = 12,
    )

    # LOW severity indicator
    styles['ind_low'] = ParagraphStyle(
        'ind_low',
        fontName   = 'Helvetica',
        fontSize   = 9,
        textColor  = OK,
        spaceAfter = 3,
        leftIndent = 12,
    )

    # Timeline event
    styles['tl_event'] = ParagraphStyle(
        'tl_event',
        fontName  = 'Helvetica-Bold',
        fontSize  = 9,
        textColor = TEXT,
        spaceAfter= 1,
    )

    styles['tl_date'] = ParagraphStyle(
        'tl_date',
        fontName  = 'Courier',
        fontSize  = 8,
        textColor = MUTED,
        spaceAfter= 6,
        leftIndent= 12,
    )

    # Footer text
    styles['footer'] = ParagraphStyle(
        'footer',
        fontName  = 'Courier',
        fontSize  = 7,
        textColor = MUTED,
    )

    return styles


def draw_page_header_footer(canvas, doc):
    """
    This function runs automatically for EVERY page.
    ReportLab calls it after drawing the page content.

    It adds:
    - A coloured header bar at the top
    - The page number at the bottom
    - A thin footer line with tool info
    """
    canvas.saveState()

    page_width, page_height = A4

    # ── HEADER BAR ──
    # Draw a dark rectangle across the top of every page
    # (except the cover — page 1 has its own full design)
    if doc.page > 1:
        canvas.setFillColor(VOID)
        canvas.rect(0, page_height - 20*mm, page_width, 20*mm, fill=1, stroke=0)

        # Cyan accent line under the header bar
        canvas.setFillColor(CYAN)
        canvas.rect(0, page_height - 20*mm - 1, page_width, 1.5, fill=1, stroke=0)

        # Tool name in header
        canvas.setFont('Helvetica-Bold', 9)
        canvas.setFillColor(WHITE)
        canvas.drawString(15*mm, page_height - 13*mm, 'MetaSleuth — Forensic Analysis Report')

        # Page number on the right
        canvas.setFont('Courier', 8)
        canvas.setFillColor(CYAN)
        canvas.drawRightString(
            page_width - 15*mm,
            page_height - 13*mm,
            f'Page {doc.page}'
        )

    # ── FOOTER LINE ──
    canvas.setStrokeColor(colors.HexColor('#e2e8f0'))
    canvas.setLineWidth(0.5)
    canvas.line(15*mm, 12*mm, page_width - 15*mm, 12*mm)

    canvas.setFont('Courier', 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(
        15*mm, 8*mm,
        f'MetaSleuth v{TOOL_VERSION}  |  Analyst: {ANALYST_NAME}  |  '
        f'CONFIDENTIAL — For authorised use only'
    )
    canvas.drawRightString(
        page_width - 15*mm, 8*mm,
        f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
    )

    canvas.restoreState()


def build_cover_page(story, styles, file_record, case_id, indicator_count, high_count):
    """
    Builds the first page of the report — the cover.
    Dark background, tool name, case details, classification.

    In ReportLab, you can't directly draw coloured backgrounds
    on a page from the Platypus (flow-based) system.
    We use a Table with a coloured background instead —
    it's a common ReportLab technique for styled containers.
    """
    page_width, _ = A4
    inner_width   = page_width - 30*mm  # subtract margins

    # Everything on the cover goes inside one big dark table
    cover_content = []

    # Spacer at the top
    cover_content.append(Paragraph('', styles['body']))
    cover_content.append(Spacer(1, 20*mm))

    # Classification banner
    class_style = ParagraphStyle(
        'class',
        fontName  = 'Helvetica-Bold',
        fontSize  = 8,
        textColor = ALERT,
        alignment = 1,  # centred
        spaceAfter= 20,
        letterSpacing = 3,
    )
    cover_content.append(Paragraph('CONFIDENTIAL — FORENSIC EVIDENCE REPORT', class_style))

    # Tool logo text
    logo_style = ParagraphStyle(
        'logo',
        fontName  = 'Helvetica-Bold',
        fontSize  = 36,
        textColor = CYAN,
        alignment = 1,
        spaceAfter= 0,
        leading   = 42,
    )
    cover_content.append(Paragraph('MetaSleuth', logo_style))

    sub_style = ParagraphStyle(
        'sub',
        fontName      = 'Courier',
        fontSize      = 10,
        textColor     = colors.HexColor('#a0aec0'),
        alignment     = 1,
        spaceAfter    = 30,
        letterSpacing = 4,
    )
    cover_content.append(Paragraph('DIGITAL FORENSICS &amp; INCIDENT RESPONSE TOOLKIT', sub_style))

    cover_content.append(Spacer(1, 10*mm))

    # Horizontal rule
    cover_content.append(HRFlowable(
        width     = '80%',
        thickness = 1,
        color     = VIOLET,
        spaceAfter= 10*mm,
    ))

    # Report title
    title_style = ParagraphStyle(
        'rtitle',
        fontName  = 'Helvetica-Bold',
        fontSize  = 18,
        textColor = WHITE,
        alignment = 1,
        spaceAfter= 6,
    )
    cover_content.append(Paragraph('Forensic Metadata Analysis Report', title_style))

    # File being reported on
    file_style = ParagraphStyle(
        'fstyle',
        fontName  = 'Courier',
        fontSize  = 11,
        textColor = CYAN,
        alignment = 1,
        spaceAfter= 20,
    )
    cover_content.append(Paragraph(
        file_record.get('filename', 'Unknown File'),
        file_style
    ))

    cover_content.append(Spacer(1, 8*mm))

    # Case details in a small table
    meta_style = ParagraphStyle(
        'cmeta',
        fontName  = 'Courier',
        fontSize  = 9,
        textColor = colors.HexColor('#a0aec0'),
        alignment = 1,
        spaceAfter= 4,
    )

    details = [
        f"Case ID:         {case_id}",
        f"Analyst:         {ANALYST_NAME}",
        f"Analysis Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"Tool Version:    MetaSleuth v{TOOL_VERSION}",
        f"Python Version:  {sys.version.split()[0]}",
        f"Platform:        {platform.system()} {platform.release()}",
        f"Indicators:      {indicator_count} total  |  {high_count} HIGH severity",
    ]
    for line in details:
        cover_content.append(Paragraph(line, meta_style))

    cover_content.append(Spacer(1, 10*mm))
    cover_content.append(HRFlowable(
        width     = '80%',
        thickness = 1,
        color     = VIOLET,
        spaceAfter= 8*mm,
    ))

    # Severity summary box
    sev_text = (
        f'<font color="#ff3366"><b>{high_count} HIGH</b></font>  '
        f'severity indicators detected in this evidence file.'
    ) if high_count > 0 else (
        '<font color="#00c97a"><b>No HIGH severity indicators detected.</b></font>'
    )
    sev_style = ParagraphStyle(
        'sevbox',
        fontName  = 'Helvetica',
        fontSize  = 11,
        textColor = WHITE,
        alignment = 1,
    )
    cover_content.append(Paragraph(sev_text, sev_style))

    # Wrap everything in a dark background table
    cover_table = Table(
        [[cover_content]],
        colWidths=[inner_width]
    )
    cover_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), VOID),
        ('TOPPADDING',    (0,0), (-1,-1), 20),
        ('BOTTOMPADDING', (0,0), (-1,-1), 30),
        ('LEFTPADDING',   (0,0), (-1,-1), 20),
        ('RIGHTPADDING',  (0,0), (-1,-1), 20),
        ('ROUNDEDCORNERS', (0,0), (-1,-1), [8, 8, 8, 8]),
    ]))

    story.append(cover_table)
    story.append(PageBreak())


def build_file_info_section(story, styles, file_record):
    """
    Section 1 — File Information.
    Shows the basic facts about the evidence file:
    name, size, type, upload time, and all three hashes.
    """
    story.append(Paragraph('1.  File Information', styles['section_head']))
    story.append(HRFlowable(width='100%', thickness=0.5, color=CYAN, spaceAfter=8))

    # File details table
    file_size = file_record.get('file_size', 0) or 0
    if file_size > 1_048_576:
        size_str = f'{file_size/1_048_576:.2f} MB'
    else:
        size_str = f'{file_size/1024:.1f} KB'

    rows = [
        # Header row
        [
            Paragraph('<b>Field</b>', styles['body']),
            Paragraph('<b>Value</b>', styles['body'])
        ],
        [Paragraph('Filename',    styles['body']), Paragraph(str(file_record.get('filename',    'N/A')), styles['mono'])],
        [Paragraph('File Type',   styles['body']), Paragraph(str(file_record.get('file_type',   'N/A')), styles['body'])],
        [Paragraph('File Size',   styles['body']), Paragraph(size_str,                                    styles['body'])],
        [Paragraph('Upload Time', styles['body']), Paragraph(str(file_record.get('upload_time', 'N/A')), styles['body'])],
        [Paragraph('Analyst',     styles['body']), Paragraph(str(file_record.get('analyst',     'N/A')), styles['body'])],
    ]

    table = Table(rows, colWidths=[50*mm, 120*mm])
    table.setStyle(TableStyle([
        # Header row styling
        ('BACKGROUND',   (0,0), (-1,0),  VOID),
        ('TEXTCOLOR',    (0,0), (-1,0),  WHITE),
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,0),  9),
        # Alternating row colours
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, LIGHT_BG]),
        ('FONTSIZE',     (0,1), (-1,-1),  9),
        ('TOPPADDING',   (0,0), (-1,-1),  5),
        ('BOTTOMPADDING',(0,0), (-1,-1),  5),
        ('LEFTPADDING',  (0,0), (-1,-1),  8),
        ('GRID',         (0,0), (-1,-1),  0.3, colors.HexColor('#e2e8f0')),
        ('ROUNDEDCORNERS',(0,0),(-1,-1),  [4,4,4,4]),
    ]))
    story.append(table)
    story.append(Spacer(1, 8))

    # Hashes section
    story.append(Paragraph('File Integrity Hashes', styles['sub_head']))
    story.append(Paragraph(
        'The following cryptographic hashes were calculated immediately upon '
        'receipt of the evidence file, before any analysis was performed. '
        'These values can be used to verify the file has not been altered.',
        styles['body']
    ))

    hash_rows = [
        [Paragraph('<b>Algorithm</b>', styles['body']), Paragraph('<b>Hash Value</b>', styles['body'])],
        [Paragraph('MD5',    styles['body']), Paragraph(str(file_record.get('md5',    'N/A')), styles['mono'])],
        [Paragraph('SHA1',   styles['body']), Paragraph(str(file_record.get('sha1',   'N/A')), styles['mono'])],
        [Paragraph('SHA256', styles['body']), Paragraph(str(file_record.get('sha256', 'N/A')), styles['mono'])],
    ]

    hash_table = Table(hash_rows, colWidths=[25*mm, 145*mm])
    hash_table.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  PANEL),
        ('TEXTCOLOR',    (0,0), (-1,0),  CYAN),
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,0),  9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, LIGHT_BG]),
        ('FONTSIZE',     (0,1), (-1,-1),  8),
        ('TOPPADDING',   (0,0), (-1,-1),  5),
        ('BOTTOMPADDING',(0,0), (-1,-1),  5),
        ('LEFTPADDING',  (0,0), (-1,-1),  8),
        ('GRID',         (0,0), (-1,-1),  0.3, colors.HexColor('#e2e8f0')),
    ]))
    story.append(hash_table)


def build_metadata_section(story, styles, metadata):
    """
    Section 2 — Extracted Metadata.
    Every key-value pair pulled from the file,
    displayed in a clean two-column table.
    """
    story.append(Paragraph('2.  Extracted Metadata', styles['section_head']))
    story.append(HRFlowable(width='100%', thickness=0.5, color=CYAN, spaceAfter=8))
    story.append(Paragraph(
        f'{len(metadata)} metadata fields extracted from this evidence file.',
        styles['body']
    ))

    if not metadata:
        story.append(Paragraph(
            'No metadata could be extracted from this file.',
            styles['ind_high']
        ))
        return

    rows = [
        [Paragraph('<b>Field</b>', styles['body']),
         Paragraph('<b>Value</b>', styles['body'])]
    ]

    for key, value in metadata.items():
        # Truncate very long values so they don't break the table layout
        display_value = str(value)
        if len(display_value) > 200:
            display_value = display_value[:197] + '...'

        rows.append([
            Paragraph(str(key), styles['body']),
            Paragraph(display_value, styles['mono'])
        ])

    meta_table = Table(rows, colWidths=[55*mm, 115*mm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  VOID),
        ('TEXTCOLOR',    (0,0), (-1,0),  WHITE),
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,0),  9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, LIGHT_BG]),
        ('FONTSIZE',     (0,1), (-1,-1),  8),
        ('TOPPADDING',   (0,0), (-1,-1),  4),
        ('BOTTOMPADDING',(0,0), (-1,-1),  4),
        ('LEFTPADDING',  (0,0), (-1,-1),  8),
        ('GRID',         (0,0), (-1,-1),  0.3, colors.HexColor('#e2e8f0')),
        ('VALIGN',       (0,0), (-1,-1),  'TOP'),
    ]))
    story.append(meta_table)


def build_indicators_section(story, styles, indicators):
    """
    Section 3 — Forensic Indicators.
    Each finding displayed with its severity level,
    colour-coded exactly like the dashboard.
    High severity findings get a coloured background
    to make them impossible to miss.
    """
    story.append(Paragraph('3.  Forensic Indicators', styles['section_head']))
    story.append(HRFlowable(width='100%', thickness=0.5, color=ALERT, spaceAfter=8))

    high_count   = sum(1 for i in indicators if i.get('severity') == 'HIGH')
    medium_count = sum(1 for i in indicators if i.get('severity') == 'MEDIUM')
    low_count    = sum(1 for i in indicators if i.get('severity') == 'LOW')

    story.append(Paragraph(
        f'Summary: {high_count} HIGH  |  {medium_count} MEDIUM  |  {low_count} LOW',
        styles['body']
    ))
    story.append(Spacer(1, 6))

    if not indicators:
        story.append(Paragraph('No indicators detected.', styles['body']))
        return

    for indicator in indicators:
        severity    = indicator.get('severity', 'LOW')
        description = indicator.get('description', '')

        # Choose prefix symbol and colour based on severity
        if severity == 'HIGH':
            prefix     = '[HIGH]   '
            text_style = styles['ind_high']
            bg_color   = colors.HexColor('#fff5f5')
            border_col = ALERT
        elif severity == 'MEDIUM':
            prefix     = '[MEDIUM] '
            text_style = styles['ind_medium']
            bg_color   = colors.HexColor('#fffbf0')
            border_col = WARN
        else:
            prefix     = '[LOW]    '
            text_style = styles['ind_low']
            bg_color   = colors.HexColor('#f0fff8')
            border_col = OK

        # Each indicator is a small table so we can give it
        # a coloured background and left border
        ind_content = [[
            Paragraph(f'{prefix}{description}', text_style)
        ]]
        ind_table = Table(ind_content, colWidths=[170*mm])
        ind_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,-1), bg_color),
            ('LEFTPADDING',   (0,0), (-1,-1), 12),
            ('RIGHTPADDING',  (0,0), (-1,-1), 8),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LINEBEFORESTYLE', (0,0), (0,-1), [3, border_col]),
        ]))

        story.append(KeepTogether([ind_table, Spacer(1, 4)]))


def build_timeline_section(story, styles, timeline):
    """
    Section 4 — Forensic Timeline.
    A chronological list of every timestamp event
    found in the file's metadata.
    This is what investigators use to reconstruct
    what happened to a file and when.
    """
    story.append(Paragraph('4.  Forensic Timeline', styles['section_head']))
    story.append(HRFlowable(width='100%', thickness=0.5, color=VIOLET, spaceAfter=8))
    story.append(Paragraph(
        'The following events were reconstructed from timestamps '
        'embedded in the file metadata, ordered chronologically.',
        styles['body']
    ))
    story.append(Spacer(1, 6))

    if not timeline:
        story.append(Paragraph('No timestamp data found in this file.', styles['body']))
        return

    for i, event in enumerate(timeline):
        is_last = (i == len(timeline) - 1)

        # Each timeline event = event name + date/time below it
        story.append(Paragraph(f"▸  {event.get('event', 'Unknown Event')}", styles['tl_event']))
        story.append(Paragraph(
            f"   {event.get('date', 'N/A')}  {event.get('time', '')}  —  {event.get('file', '')}",
            styles['tl_date']
        ))

        # Add a small divider between events (but not after the last one)
        if not is_last:
            story.append(HRFlowable(
                width     = '40%',
                thickness = 0.3,
                color     = colors.HexColor('#e2e8f0'),
                spaceAfter= 2,
                spaceBefore= 2,
            ))


def build_provenance_section(story, styles):
    """
    Section 5 — Tool & Environment Provenance.
    This is what makes findings legally defensible.
    Documents exactly what version of everything was used
    so the analysis is reproducible.
    An opposing lawyer can't argue 'we don't know what
    tool was used or whether it was reliable'
    because this section answers every question.
    """
    story.append(Paragraph('5.  Tool &amp; Environment Provenance', styles['section_head']))
    story.append(HRFlowable(width='100%', thickness=0.5, color=VIOLET, spaceAfter=8))
    story.append(Paragraph(
        'This section documents the exact environment in which this analysis '
        'was performed. These details ensure findings are reproducible and '
        'defensible under forensic scrutiny.',
        styles['body']
    ))
    story.append(Spacer(1, 6))

    # Gather environment details
    import importlib.metadata

    # Try to get installed library versions
    libraries = [
        'flask', 'pillow', 'pypdf',
        'python-docx', 'mutagen', 'pymediainfo', 'reportlab'
    ]
    lib_versions = {}
    for lib in libraries:
        try:
            lib_versions[lib] = importlib.metadata.version(lib)
        except Exception:
            lib_versions[lib] = 'unknown'

    prov_rows = [
        [Paragraph('<b>Component</b>', styles['body']),
         Paragraph('<b>Version / Detail</b>', styles['body'])],

        [Paragraph('Tool',             styles['body']), Paragraph(f'MetaSleuth v{TOOL_VERSION}',    styles['mono'])],
        [Paragraph('Python',           styles['body']), Paragraph(sys.version,                       styles['mono'])],
        [Paragraph('Operating System', styles['body']), Paragraph(f'{platform.system()} {platform.release()} ({platform.machine()})', styles['mono'])],
        [Paragraph('Analysis Date',    styles['body']), Paragraph(datetime.now().isoformat(),         styles['mono'])],
        [Paragraph('Analyst',          styles['body']), Paragraph(ANALYST_NAME,                       styles['mono'])],
    ]

    # Add each library version
    for lib, version in lib_versions.items():
        prov_rows.append([
            Paragraph(f'Library: {lib}', styles['body']),
            Paragraph(version,            styles['mono'])
        ])

    prov_table = Table(prov_rows, colWidths=[55*mm, 115*mm])
    prov_table.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  VOID),
        ('TEXTCOLOR',    (0,0), (-1,0),  WHITE),
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,0),  9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, LIGHT_BG]),
        ('FONTSIZE',     (0,1), (-1,-1),  8),
        ('TOPPADDING',   (0,0), (-1,-1),  5),
        ('BOTTOMPADDING',(0,0), (-1,-1),  5),
        ('LEFTPADDING',  (0,0), (-1,-1),  8),
        ('GRID',         (0,0), (-1,-1),  0.3, colors.HexColor('#e2e8f0')),
    ]))
    story.append(prov_table)


def build_audit_section(story, styles, audit_entries):
    """
    Section 6 — Chain of Custody / Audit Log.
    Every action taken against this evidence file,
    in chronological order.
    This is the legal backbone of the report.
    """
    story.append(Paragraph('6.  Chain of Custody — Audit Log', styles['section_head']))
    story.append(HRFlowable(width='100%', thickness=0.5, color=OK, spaceAfter=8))
    story.append(Paragraph(
        'Every action performed on this evidence file has been automatically '
        'logged. This log establishes an unbroken chain of custody from '
        'initial acquisition through to report generation.',
        styles['body']
    ))
    story.append(Spacer(1, 6))

    if not audit_entries:
        story.append(Paragraph('No audit entries found.', styles['body']))
        return

    audit_rows = [
        [
            Paragraph('<b>Timestamp</b>',  styles['body']),
            Paragraph('<b>Action</b>',     styles['body']),
            Paragraph('<b>Detail</b>',     styles['body']),
            Paragraph('<b>Analyst</b>',    styles['body']),
        ]
    ]

    for entry in audit_entries:
        audit_rows.append([
            Paragraph(str(entry.get('timestamp', ''))[:19], styles['mono']),
            Paragraph(str(entry.get('action',    '')),       styles['body']),
            Paragraph(str(entry.get('detail',    '')),       styles['body']),
            Paragraph(str(entry.get('analyst',   '')),       styles['body']),
        ])

    audit_table = Table(audit_rows, colWidths=[38*mm, 22*mm, 80*mm, 30*mm])
    audit_table.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  VOID),
        ('TEXTCOLOR',    (0,0), (-1,0),  WHITE),
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,0),  8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, LIGHT_BG]),
        ('FONTSIZE',     (0,1), (-1,-1),  7),
        ('TOPPADDING',   (0,0), (-1,-1),  4),
        ('BOTTOMPADDING',(0,0), (-1,-1),  4),
        ('LEFTPADDING',  (0,0), (-1,-1),  6),
        ('GRID',         (0,0), (-1,-1),  0.3, colors.HexColor('#e2e8f0')),
        ('VALIGN',       (0,0), (-1,-1),  'TOP'),
    ]))
    story.append(audit_table)


def build_comparison_section(story, styles, comparisons):
    """
    Section 7 — External Copy Comparison Log.

    Every time an analyst used "Compare External Copy" on THIS file,
    it created one row here. This section is scoped to a single file —
    comparisons made against other evidence files never appear here.

    This documents every attempt to check this evidence against
    outside copies, which strengthens (or challenges) the integrity
    story told elsewhere in this report.
    """
    story.append(Paragraph('7.  External Copy Comparison Log', styles['section_head']))
    story.append(HRFlowable(width='100%', thickness=0.5, color=CYAN, spaceAfter=8))
    story.append(Paragraph(
        'The following is a complete record of every time this specific '
        'evidence file was compared against an externally supplied copy '
        '(e.g. a file found on another device, drive, or attachment). '
        'Each comparison re-hashes the external file and checks it '
        'against the SHA256 recorded for this evidence item at upload.',
        styles['body']
    ))
    story.append(Spacer(1, 6))

    if not comparisons:
        story.append(Paragraph(
            'No external comparisons have been performed for this file.',
            styles['body']
        ))
        return

    comp_rows = [
        [
            Paragraph('<b>Timestamp</b>',        styles['body']),
            Paragraph('<b>Compared File</b>',     styles['body']),
            Paragraph('<b>Result</b>',            styles['body']),
            Paragraph('<b>Compared SHA256</b>',   styles['body']),
        ]
    ]

    for entry in comparisons:
        result_text  = 'MATCH' if entry.get('match') else 'MISMATCH'
        result_hex   = '#' + OK.hexval()[2:] if entry.get('match') else '#' + ALERT.hexval()[2:]
        comp_rows.append([
            Paragraph(str(entry.get('timestamp', ''))[:19],       styles['mono']),
            Paragraph(str(entry.get('compared_filename', '')),    styles['body']),
            Paragraph(f'<font color="{result_hex}"><b>{result_text}</b></font>', styles['body']),
            Paragraph(str(entry.get('compared_sha256', ''))[:24] + '…', styles['mono']),
        ])

    comp_table = Table(comp_rows, colWidths=[32*mm, 45*mm, 23*mm, 70*mm])
    comp_table.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  VOID),
        ('TEXTCOLOR',    (0,0), (-1,0),  WHITE),
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,0),  8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, LIGHT_BG]),
        ('FONTSIZE',     (0,1), (-1,-1),  7),
        ('TOPPADDING',   (0,0), (-1,-1),  4),
        ('BOTTOMPADDING',(0,0), (-1,-1),  4),
        ('LEFTPADDING',  (0,0), (-1,-1),  6),
        ('GRID',         (0,0), (-1,-1),  0.3, colors.HexColor('#e2e8f0')),
        ('VALIGN',       (0,0), (-1,-1),  'TOP'),
    ]))
    story.append(comp_table)

    

def generate_report(output_path, file_record, metadata,
                    indicators, timeline, audit_entries,
                    comparisons=None, case_id='CASE-001'):
    """
    The main function — assembles all sections and
    writes the final PDF to output_path.

    Call this from app.py like:
        generate_report(
            output_path  = 'reports/report_001.pdf',
            file_record  = dict(file_db_row),
            metadata     = dict of extracted metadata,
            indicators   = list of indicator dicts,
            timeline     = list of timeline event dicts,
            audit_entries= list of audit log dicts,
            comparisons  = list of external-comparison dicts for THIS file,
            case_id      = 'CASE-001'
        )
    """

    styles = build_styles()

    # Page margins
    doc = SimpleDocTemplate(
        output_path,
        pagesize     = A4,
        leftMargin   = 15*mm,
        rightMargin  = 15*mm,
        topMargin    = 25*mm,
        bottomMargin = 20*mm,
        title        = f'MetaSleuth Forensic Report — {file_record.get("filename","Unknown")}',
        author       = ANALYST_NAME,
        subject      = f'Case {case_id}',
        creator      = f'MetaSleuth v{TOOL_VERSION}',
    )

    story = []  # story = the list of all content blocks in order

    # Count severity totals for the cover page
    high_count = sum(1 for i in indicators if i.get('severity') == 'HIGH')

    # Build each section in order
    build_cover_page(story, styles, file_record, case_id,
                     len(indicators), high_count)

    build_file_info_section(story, styles, file_record)
    story.append(Spacer(1, 8))

    build_metadata_section(story, styles, metadata)
    story.append(PageBreak())

    build_indicators_section(story, styles, indicators)
    story.append(Spacer(1, 8))

    build_timeline_section(story, styles, timeline)
    story.append(PageBreak())

    build_provenance_section(story, styles)
    story.append(Spacer(1, 8))

    build_audit_section(story, styles, audit_entries)
    story.append(PageBreak())

    build_comparison_section(story, styles, comparisons or [])

    # Build the PDF — this is where ReportLab actually
    # writes the file to disk

    # Build the PDF — this is where ReportLab actually
    # writes the file to disk
    doc.build(
        story,
        onFirstPage = draw_page_header_footer,
        onLaterPages= draw_page_header_footer,
    )

    return output_path