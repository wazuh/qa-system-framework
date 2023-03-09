"""
Module to test the get_file_encoding function from file module.

Test cases:
    - Write encoded strings and check that it detected by the function.
    - Write a non supported encoded string and check that an exception is raised.
"""

import os
import sys
import pytest
from tempfile import gettempdir

from wazuh_qa_framework.generic_modules.file.file import get_file_encoding
from wazuh_qa_framework.meta_testing.configuration import get_test_cases_data
from wazuh_qa_framework.meta_testing.utils import write_file, remove_file
from wazuh_qa_framework.generic_modules.exceptions.exceptions import ValueError


DEFAULT_SAMPLE_FILE = os.path.join(gettempdir(), 'file.log')

# Test cases data path
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'cases_get_file_encoding')

# Valid check order cases
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_valid_file_encoding.yaml')
t1_case_parameters, t1_case_names = get_test_cases_data(t1_cases_path)
# Convert it to list of tuples to be able to use the values by the fixtures
t1_case_parameters = [tuple(item.values()) for item in t1_case_parameters]

# Invalid check order cases
# Invalid case encoding is not supported by Windows, so do this trick to avoid the error
cases_file = 'cases_valid_file_encoding.yaml' if sys.platform == 'win32' else 'cases_invalid_file_encoding.yaml'
t2_cases_path = os.path.join(TEST_CASES_PATH, cases_file)
t2_case_parameters, t2_case_names = get_test_cases_data(t2_cases_path)
# Convert it to list of tuples to be able to use the values by the fixtures
t2_case_parameters = [tuple(item.values()) for item in t2_case_parameters]


@pytest.fixture
def create_ephemeral_file(encoding, text):
    """Custom fixture to create, write and remove file.

    Args:
        encoding (str): Text encoding.
        text (str): Text to write.

    Setup:
        - Create the file and write a specific encoded text.
    Teardown:
        - remove the file
    """
    write_file(DEFAULT_SAMPLE_FILE, text, encoding=encoding)
    yield
    remove_file(DEFAULT_SAMPLE_FILE)


@pytest.mark.parametrize('encoding, text', t1_case_parameters, ids=t1_case_names)
def test_get_file_encoding(encoding, text, create_ephemeral_file):
    """Write encoded strings and check that it detected by the function.

    test_phases:
        - setup:
            - Create a file and write the specificied encoded text.
        - test:
            - Check that the deteted encoded text is the expected.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - encoding (str): Parametrized variables.
        - text (str): Parametrized variables.
        - create_ephemeral_file (fixture): Create an empty file and remove it after finishing.
    """
    assert get_file_encoding(DEFAULT_SAMPLE_FILE) == encoding


@pytest.mark.skipif(sys.platform == 'win32', reason='Not supported on windows')
@pytest.mark.parametrize('encoding, text', t2_case_parameters, ids=t2_case_names)
def test_invalid_get_file_encoding(encoding, text, create_ephemeral_file):
    """Write a non supported encoded string and check that an exception is raised.

    test_phases:
        - setup:
            - Create a file and write the specificied encoded text.
        - test:
            - Check that a exception is raised.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - encoding (str): Parametrized variables.
        - text (str): Parametrized variables.
        - create_ephemeral_file (fixture): Create an empty file and remove it after finishing.
    """
    with pytest.raises(ValueError):
        get_file_encoding(DEFAULT_SAMPLE_FILE)
        pytest.fail('Function get_file_encoding did not raise an expected exception when encoding is unknown')
