import pypdf

def analyze_pdf(filepath):
    """
    Extracts metadata from a PDF file.
    
    PDF metadata lives in a section called the "Info Dictionary" —
    a standard block that PDF software writes automatically.
    Most people don't know it contains their name, company,
    the software they used, and exactly when they made changes.
    """
    metadata = {}

    try:
        # Open the PDF — rb means "read binary"
        # PDFs aren't plain text, they're binary files
        with open(filepath, 'rb') as f:
            reader = pypdf.PdfReader(f)

            # Check if the PDF is encrypted/password protected
            if reader.is_encrypted:
                metadata['Encryption Status'] = 'ENCRYPTED — password protected'
                # We can still try to open it with an empty password
                # (many "encrypted" PDFs have no actual password set)
                try:
                    reader.decrypt('')
                except:  # noqa: E722
                    return metadata

            # .metadata contains the Info Dictionary
            info = reader.metadata

            if info:
                # These are the standard PDF metadata fields
                # The slash prefix (/Author) is PDF format convention
                fields = {
                    'Author':           info.get('/Author'),
                    'Creator':          info.get('/Creator'),
                    'Producer':         info.get('/Producer'),
                    'Subject':          info.get('/Subject'),
                    'Title':            info.get('/Title'),
                    'Keywords':         info.get('/Keywords'),
                    'Creation Date':    info.get('/CreationDate'),
                    'Modified Date':    info.get('/ModDate'),
                }

                # Only store fields that actually have values
                for key, value in fields.items():
                    if value:
                        metadata[key] = str(value)

            # Page count — useful for context
            metadata['Page Count'] = str(len(reader.pages))

            # PDF version tells us how old or new the format is
            metadata['PDF Version'] = str(reader.pdf_header)

    except Exception as e:
        metadata['Error'] = f'Could not read PDF: {str(e)}'

    return metadata