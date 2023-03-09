"""
Module to manager custom file utils functions. The functions related to working with files will be grouped in order
to encapsulate behaviors and avoid code redundancy, in addition to speeding up development.

This module contains the following functions:

- get_file_encoding
"""

import os
import chardet

from wazuh_qa_framework.generic_modules.exceptions.exceptions import ValueError, ValidationError


def get_file_encoding(file_path):
    """Detect and return the file encoding.

    Args:
        file_path (str): File path to check.

    Returns:
        str: File encoding.

    Raises:
        ValidationError: If could not find the file_path or is not a file.
        ValueError: If could not detect the file encoding.
    """
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        raise ValidationError(f"{file_path} was not found or is not a file.")

    # Read the file as bytes
    with open(file_path, 'rb') as _file:
        data = _file.read()

    # Detect the content encoding
    encoding = chardet.detect(data)['encoding']

    if len(data) == 0:
        return 'utf-8'

    if encoding is None:
        raise ValueError(f"Could not detect the {file_path} encoding")

    return encoding
