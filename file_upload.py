import os
from werkzeug.utils import secure_filename
from flask import current_app
from datetime import datetime

def save_uploaded_file(file, upload_folder='uploads'):
    """
    Save an uploaded file to a designated folder.
    Returns the full path to the saved file.
    """
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    filename = secure_filename(file.filename)
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    unique_filename = f"{timestamp}_{filename}"
    file_path = os.path.join(upload_folder, unique_filename)
    file.save(file_path)
    return file_path

def delete_file(file_path):
    """
    Safely delete a file from the filesystem if it exists.
    """
    if file_path and os.path.exists(file_path):
        os.remove(file_path)
        return True
    return False

def get_file_extension(file_path):
    """
    Return the extension of a file.
    """
    return os.path.splitext(file_path)[1].lower()

def is_allowed_file(filename, allowed_extensions=None):
    """
    Check if the file extension is allowed.
    """
    if allowed_extensions is None:
        allowed_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'md'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def generate_file_identifier(user_id, original_filename):
    """
    Generate a unique file identifier for tracking embeddings or uploads.
    """
    base = secure_filename(original_filename.rsplit('.', 1)[0])
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    return f"{user_id}_{base}_{timestamp}"
