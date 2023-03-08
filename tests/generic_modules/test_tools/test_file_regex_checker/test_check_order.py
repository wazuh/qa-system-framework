"""
Module to test the check_order parameter of FileRegexChecker.
"""
import os
import pytest

from wazuh_qa_framework.generic_modules.tools.file_regex_checker import FileRegexChecker
from wazuh_qa_framework.generic_modules.exceptions.exceptions import ElementNotFoundError
from wazuh_qa_framework.meta_testing.configuration import get_test_cases_data
from wazuh_qa_framework.meta_testing.utils import write_file


TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'cases_check_order')

# valid check order cases
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_valid_check_order.yaml')
t1_case_parameters, t1_case_names = get_test_cases_data(t1_cases_path)

# invalid check order cases
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_invalid_check_order.yaml')
t2_case_parameters, t2_case_names = get_test_cases_data(t2_cases_path)


@pytest.mark.parametrize('case_parameters', t1_case_parameters, ids=t1_case_names)
def test_valid_check_order(case_parameters, create_destroy_sample_file):
    """Check the FileRegexChecker expected valid cases when we set the "check_order" parameter.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Write the file content.
            - Check if patterns has been found in order.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - case_parameters (list): Parametrized variables.
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    checked_file = create_destroy_sample_file

    write_file(checked_file, case_parameters['file_content'].replace('\\n', '\n'))

    FileRegexChecker(file=checked_file, patterns=case_parameters['patterns'],
                     check_order=case_parameters['check_order'])


@pytest.mark.parametrize('case_parameters', t2_case_parameters, ids=t2_case_names)
def test_invalid_check_order(case_parameters, create_destroy_sample_file):
    """Check the FileRegexChecker expected invalid cases when we set the "check_order" parameter.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Write the file content.
            - Check that the element was not found.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - case_parameters (list): Parametrized variables.
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    checked_file = create_destroy_sample_file

    write_file(checked_file, case_parameters['file_content'].replace('\\n', '\n'))

    with pytest.raises(ElementNotFoundError):
        FileRegexChecker(file=checked_file, patterns=case_parameters['patterns'],
                         check_order=case_parameters['check_order'])
        pytest.fail(case_parameters['error_message'])
