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

        fields = {
            'Author':            props.author,
            'Last Modified By':  props.last_modified_by,
            'Created':           props.created,
            'Modified':          props.modified,
            'Last Printed':      props.last_printed,
            'Company':           props.company,
            'Category':          props.category,
            'Description':       props.description,
            'Keywords':          props.keywords,
            'Subject':           props.subject,
            'Title':             props.title,
            'Revision Number':   props.revision,
            'Total Editing Time': props.total_time,  # in minutes
            'Template':          props.template,
        }

        for key, value in fields.items():
            if value is not None and str(value).strip():
                metadata[key] = str(value)

        # Paragraph count gives a sense of document size
        metadata['Paragraph Count'] = str(len(doc.paragraphs))

    except Exception as e:
        metadata['Error'] = f'Could not read Word document: {str(e)}'

    return metadata