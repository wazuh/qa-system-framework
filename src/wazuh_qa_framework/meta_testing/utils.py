"""
Util functions to use in the framework testing.
"""

import re

CUSTOM_REGEX = r'.*wazuh-modulesd:aws-s3: INFO: Executing Service Analysis'


def custom_callback(line):
    """Custom callback that matches with the module CUSTOM REGEX.

    Args:
        line (str): Log line.

    Returns:
        boolean: True if log line matches with the callback, False otherwise.
    """
    match = re.match(CUSTOM_REGEX, line)
    return True if match else None


def clean_file(file):
    """Clean the content of a file.

    Args:
        file (str): File path.
    """
    with open(file, 'w') as _file:
        _file.write('')


def append_log(file, content):
    """Append a string content to the specified file.

    Args:
        file (str): File path.
        content (str): Content to add.
    """
    with open(file, 'a') as _file:
        _file.write(content)
