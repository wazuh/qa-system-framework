"""
Module to test the BaseLogger.

Test cases:
    - Case 1: Log using different logger levels and check if the logs are written.
        - Case 1.1: Log using DEBUG level and check how many logs are written.
        - Case 1.2: same for INFO, WARNING, ERROR and CRITICAL levels.
        - ...
    - Case 2: Check if the messages are colorized according to output_color logger parameter.
        - Case 2.1: Logs are colorized if output_color is True.
        - Case 2.2: Logs are not colorized if output_color is False.
"""

import pytest
import os

from tempfile import gettempdir
from wazuh_qa_framework.generic_modules.logging.base_logger import BaseLogger
from wazuh_qa_framework.meta_testing.utils import read_file


SAMPLE_FILE = os.path.join(gettempdir(), 'file.log')


@pytest.mark.parametrize('level, expected_lines', [('debug', 5), ('info', 4), ('warning', 3), ('error', 2),
                                                   ('critical', 1)])
def test_levels(level, create_destroy_sample_file, expected_lines):
    """Check the logging levels filters the log messages appropriately.

    case: Log using different logger levels and check if the logs are written.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Create a BaseLogger with a specific level.
            - Read the log file and check how many logs have been written.
            - Check that the numbers of written logs are the expected according to the level set.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
        - expected_lines (int): Parametrized variable.
    """
    logger = BaseLogger(name=f"test_{expected_lines}", level=level, output_color=False, handlers=['file'],
                        logging_file=SAMPLE_FILE)
    log_message = 'hello world'
    levels = ['debug', 'info', 'warning', 'error', 'critical']

    # Write one log for each level
    for log_level in levels:
        logger.log(log_message, level=log_level)

    # Get file lines
    log_data = read_file(SAMPLE_FILE)
    lines_number = len(log_data.strip().split('\n'))

    # Check that only the expected lines have been written
    assert expected_lines == lines_number


@pytest.mark.parametrize('color, message, expected_message', [(True, 'hello', 'INFO — \x1b[94mhello\x1b[0m'),
                                                              (False, 'hello', 'INFO — hello')])
def test_output_color(color, message, expected_message, create_destroy_sample_file):
    """Check if the output is colorized when set.

    case: Check if the messages are colorized according to output_color logger parameter.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Create a BaseLogger with a specific output_color value.
            - Write a log.
            - Check if the log message contains the color marks if set.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - color (int): Parametrized variable.
        - message (int): Parametrized variable.
        - expected_message (int): Parametrized variable.
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    logger = BaseLogger(name='test', level='info', output_color=color, handlers=['file'], logging_file=SAMPLE_FILE)

    # Log a line and check the log file content
    logger.info(message)
    log_data = read_file(SAMPLE_FILE).strip()

    # Check if the log content has the color marks.
    assert expected_message in log_data
