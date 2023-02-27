import pytest
import os

from tempfile import gettempdir
from wazuh_qa_framework.generic_modules.logging.base_logger import BaseLogger
from wazuh_qa_framework.meta_testing.utils import read_file


SAMPLE_FILE = os.path.join(gettempdir(), 'file.log')


@pytest.mark.parametrize('level, expected_lines', [('debug', 5), ('info', 4),('warning', 3), ('error', 2),
                                                   ('critical', 1)])
def test_levels(level, create_destroy_sample_file, expected_lines):
    logger = BaseLogger(name='test', level=level, output_color=False, handlers=['file'], logging_file=SAMPLE_FILE)
    log_message = 'hello world'
    levels = ['debug', 'info', 'warning', 'error', 'critical']

    for log_level in levels:
        logger.log(log_message, level=log_level)

    log_data = read_file(SAMPLE_FILE)
    lines_number = len(log_data.strip().split('\n'))

    assert expected_lines == lines_number


@pytest.mark.parametrize('color, message, expected_message', [(True, 'hello', 'INFO — \x1b[94mhello\x1b[0m'),
                                                              (False, 'hello', 'INFO — hello')])
def test_output_color(color, message, expected_message, create_destroy_sample_file):
    logger = BaseLogger(name='test', level='info', output_color=color, handlers=['file'], logging_file=SAMPLE_FILE)
    logger.info(message)
    log_data = read_file(SAMPLE_FILE).strip()

    assert expected_message in log_data
