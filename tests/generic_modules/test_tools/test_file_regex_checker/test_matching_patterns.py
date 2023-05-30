"""
Module to test the matching patterns of FileRegexChecker.
"""
import os
import pytest

from wazuh_qa_framework.generic_modules.tools.file_regex_checker import FileRegexChecker
from wazuh_qa_framework.generic_modules.exceptions.exceptions import ElementNotFoundError
from wazuh_qa_framework.meta_testing.configuration import get_test_cases_data
from wazuh_qa_framework.meta_testing.utils import write_file


TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'cases_multiple_patterns')

# valid patterns
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_valid_multiple_patterns.yaml')
t1_case_parameters, t1_case_names = get_test_cases_data(t1_cases_path)

# invalid patterns
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_invalid_multiple_patterns.yaml')
t2_case_parameters, t2_case_names = get_test_cases_data(t2_cases_path)


@pytest.mark.parametrize('case_parameters', t1_case_parameters, ids=t1_case_names)
def test_valid_matching_patterns(case_parameters, create_destroy_sample_file):
    """Check the FileRegexChecker expected valid cases when we set matching patterns.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Write the file content.
            - Check if patterns has been matched.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - case_parameters (list): Parametrized variables.
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    checked_file = create_destroy_sample_file

    write_file(checked_file, case_parameters['file_content'].replace('\\n', '\n'))

    FileRegexChecker(file=checked_file, patterns=case_parameters['patterns'])


@pytest.mark.parametrize('case_parameters', t2_case_parameters, ids=t2_case_names)
def test_invalid_matching_patterns(case_parameters, create_destroy_sample_file):
    """Check the FileRegexChecker expected invalid cases when we set unmatching patterns.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Write the file content.
            - Check exception caused by patterns not matched.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - case_parameters (list): Parametrized variables.
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    checked_file = create_destroy_sample_file

    write_file(checked_file, case_parameters['file_content'].replace('\\n', '\n'))

    with pytest.raises(ElementNotFoundError):
        FileRegexChecker(file=checked_file, patterns=case_parameters['patterns'])
        pytest.fail(case_parameters['error_message'])
