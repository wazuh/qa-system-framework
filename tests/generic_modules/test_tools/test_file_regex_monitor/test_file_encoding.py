"""
Module to test the FileRegexMonitor when monitoring files with different encondings.

Test cases:
    - Start monitoring a written log file and write a new line with specific enconding.
    - Start monitoring an empty log file and write a new line with specific encoding.
    - Start monitoring a written log file and write a new line with different encoding.
"""

import time
import os
import pytest

from wazuh_qa_framework.generic_modules.tools.file_regex_monitor import FileRegexMonitor
from wazuh_qa_framework.generic_modules.threading.thread import Thread
from wazuh_qa_framework.meta_testing.utils import append_log
from wazuh_qa_framework.meta_testing.configuration import get_test_cases_data


# Test cases data path
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'cases_file_encoding')

# Valid check order cases
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_pre_decoding.yaml')
t1_case_parameters, t1_case_names = get_test_cases_data(t1_cases_path)

# Invalid check order cases
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_post_decoding.yaml')
t2_case_parameters, t2_case_names = get_test_cases_data(t2_cases_path)


def custom_callback(line):
    """Custom callback to match with test cases.

    Args:
        line (str): Log line.

    Returns:
        boolean: True if pattern has matched, None otherwise.
    """
    if line in ['matching string', 'ЄЃЂ', 'ÿð¤¢é']:
        return True

    return None


@pytest.mark.parametrize('case_parameters', t1_case_parameters, ids=t1_case_names)
def test_pre_encoding(case_parameters, create_destroy_sample_file):
    """Start monitoring a written log file and write a new line with specific enconding.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Write a line with specific encoding
            - Start file monitoring.
            - Log a encoded line that triggers the monitoring callback.
            - Check that callback has been triggered.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - case_parameters (list): Parametrized variables.
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Write initial log line
    append_log(log_file, f"{case_parameters['pre_text']}", encoding=case_parameters['encoding'])

    # Start the file regex monitoring
    file_regex_monitor_parameters = {'monitored_file': log_file, 'callback': custom_callback, 'timeout': 1,
                                     'only_new_events': False}
    file_regex_monitor_process = Thread(target=FileRegexMonitor, parameters=file_regex_monitor_parameters)
    file_regex_monitor_process.start()

    # Waiting time for log to be written
    time.sleep(0.25)
    append_log(log_file, case_parameters['text'], encoding=case_parameters['encoding'])

    # Check that callback has been triggered
    file_regex_monitor_process.join()


@pytest.mark.parametrize('case_parameters', t2_case_parameters, ids=t2_case_names)
def test_post_encoding(case_parameters, create_destroy_sample_file):
    """Start monitoring an empty log file and write a new line with specific encoding.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Start file monitoring.
            - Log a encoded line that triggers the monitoring callback.
            - Check that callback has been triggered.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - case_parameters (list): Parametrized variables.
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Start the file regex monitoring
    file_regex_monitor_parameters = {'monitored_file': log_file, 'callback': custom_callback, 'timeout': 1,
                                     'only_new_events': False}
    file_regex_monitor_process = Thread(target=FileRegexMonitor, parameters=file_regex_monitor_parameters)
    file_regex_monitor_process.start()

    # Waiting time for log to be written
    time.sleep(0.25)
    append_log(log_file, case_parameters['text'])

    # Check that callback has been triggered
    file_regex_monitor_process.join()


def test_new_encoding(create_destroy_sample_file):
    """Start monitoring a written log file and write a new line with different encoding.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Write initial log line in ISO-8859-1 encoding.
            - Start file monitoring.
            - Log a line encoded with UTF-16 that triggers the monitoring callback.
            - Check that callback has been triggered.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - case_parameters (list): Parametrized variables.
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Write initial log line
    append_log(log_file, 'ÿð¤¢é')

    # Start the file regex monitoring
    file_regex_monitor_parameters = {'monitored_file': log_file, 'callback': custom_callback, 'timeout': 1,
                                     'only_new_events': False}
    file_regex_monitor_process = Thread(target=FileRegexMonitor, parameters=file_regex_monitor_parameters)
    file_regex_monitor_process.start()

    # Waiting time for log to be written
    time.sleep(0.25)
    append_log(log_file, 'ЄЃЂ')

    # Check that callback has been triggered
    file_regex_monitor_process.join()
