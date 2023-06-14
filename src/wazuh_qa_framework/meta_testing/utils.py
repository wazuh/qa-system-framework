"""
Util functions to use in the framework testing.

This module contains the following:

- custom_callback
- clean_file
- append_log
- read_file
- write_file
- remove_file
"""

import re
import os
import sys
import logging

CUSTOM_PATTERN = 'wazuh-modulesd:aws-s3: INFO: Executing Service Analysis'
CUSTOM_REGEX = r'.*wazuh-modulesd:aws-s3: INFO: Executing Service Analysis'
DEFAULT_LOG_MESSAGE = '2023/02/14 09:49:47 wazuh-modulesd:aws-s3: INFO: Executing Service Analysis'
FREE_API_URL = 'https://jsonplaceholder.typicode.com'


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


def append_log(file, content, encoding='utf-8'):
    """Append a string content to the specified file.

    Args:
        file (str): File path.
        content (str): Content to add.
        encoding (str): Characters encoding.
    """
    with open(file, 'a', encoding=encoding) as _file:
        _file.write(content)


def read_file(file):
    """Read a file content.

    Args:
        file (str): File path.

    Returns:
        str: File content.
    """
    with open(file, 'r') as _file:
        data = _file.read()

    return data


def write_file(file, content='', encoding='utf-8'):
    """Write content to file.

    Args:
        file (str): File path.
        content (str): Content to write.
    """
    with open(file, 'w', encoding=encoding) as _file:
        _file.write(content)


def remove_file(file):
    """Remove a file if exists.

    Args:
        file (str): File path.
    """
    if os.path.exists(file) and os.path.isfile(file):
        if sys.platform == 'win32':
            # Shutdown logging. Needed because on Windows we can't remove the logging file if the file handler is set
            # and up.
            logging.shutdown()

        os.remove(file)
