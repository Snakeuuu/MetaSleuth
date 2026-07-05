from docx import Document

def analyze_word(filepath):
    """
    Extracts metadata from a .docx file.
    
    Word documents are actually ZIP files in disguise.
    Inside them is an XML file called "docProps/core.xml"
    that stores all the authorship information.
    python-docx opens all of this automatically.
    """
    metadata = {}

    try:
        doc = Document(filepath)

        # .core_properties is python-docx's interface
        # to that XML properties file
        props = doc.core_properties

        # NOTE: python-docx's CoreProperties only exposes the fields
        # actually stored in docProps/core.xml. 'company', 'template',
        # and 'total_time' were never real attributes on this object —
        # that typo/assumption is what raised
        # "'CoreProperties' object has no attribute 'company'" and
        # made every Word file fail with the same one error.
        fields = {
            'Author':            props.author,
            'Last Modified By':  props.last_modified_by,
            'Created':           props.created,
            'Modified':          props.modified,
            'Last Printed':      props.last_printed,
            'Category':          props.category,
            'Keywords':          props.keywords,
            'Subject':           props.subject,
            'Title':             props.title,
            'Revision Number':   props.revision,
            'Comments':          props.comments,
            'Content Status':    props.content_status,
            'Identifier':        props.identifier,
            'Language':          props.language,
            'Version':           props.version,
        }

        for key, value in fields.items():
            if value is not None and str(value).strip():
                metadata[key] = str(value)

        # Paragraph count gives a sense of document size
        metadata['Paragraph Count'] = str(len(doc.paragraphs))

    except Exception as e:
        metadata['Error'] = f'Could not read Word document: {str(e)}'

    return metadata