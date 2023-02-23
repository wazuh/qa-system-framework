"""
Util functions to use in the framework testing.
"""

import re

CUSTOM_REGEX = r'.*wazuh-modulesd:aws-s3: INFO: Executing Service Analysis'
DEFAULT_LOG_MESSAGE = '2023/02/14 09:49:47 wazuh-modulesd:aws-s3: INFO: Executing Service Analysis\n'


def custom_callback(line):
    """Custom callback that matches with the module CUSTOM REGEX.

    Args:
        line (str): Log line.

    Returns:
        boolean: True if log line matches with the callback, False otherwise.
    """
    match = re.match(DEFAULT_LOG_MESSAGE, line)
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
