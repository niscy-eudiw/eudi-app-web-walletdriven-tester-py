from werkzeug.utils import secure_filename
import base64, os
from app_config.config import ConfService as cfgserv

def get_base64_document(filename):
    base64_document = None
    with open(filename, 'rb') as document:
        base64_document = base64.b64encode(document.read()).decode("utf-8")
    
    return base64_document

def get_signature_format_simplified(signature_format):
    if signature_format == "PAdES":
        return 'P'
    elif signature_format == "XAdES":
        return 'X'
    elif signature_format == "JAdES":
        return 'J'
    else:
        return 'C'

def get_unique_filename(folder, filename):
    base, ext = os.path.splitext(filename)  # Split the filename into name and extension
    counter = 1
    new_filename = filename
    while os.path.exists(os.path.join(folder, new_filename)):
        new_filename = f"{base}_{counter}{ext}"
        counter += 1
    return new_filename

def save_document(document):
    filename = secure_filename(document.filename)
    filename = get_unique_filename(cfgserv.UPLOAD_FOLDER, filename)
    file_path = os.path.join(cfgserv.UPLOAD_FOLDER, filename)
    document.save(file_path)
    document.stream.seek(0)
    return file_path, filename

## Function to save a document with a given filename
## Returns the path to the saved file and the filename
## The filename returned may be different from the one given
def save_document_with_name(document, filename):
    filename = secure_filename(filename)
    filename = get_unique_filename(cfgserv.UPLOAD_FOLDER, filename)
    file_path = os.path.join(cfgserv.UPLOAD_FOLDER, filename)
    
    with open(file_path, 'wb') as file:
        file.write(document)
    
    return file_path, filename

def add_suffix_to_filename(filename, suffix="_signed"):
    name, ext = os.path.splitext(filename)
    return f"{name}{suffix}{ext}"
