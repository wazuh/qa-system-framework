"""
Module to test the accumulations parameter of FileRegexMonitor.

Test cases:
- Case 1: Pre-logged event, log another event while monitoring and expect 2 matches.
- Case 2: Log 2 events while monitoring and expect 2 matches
- Case 3: Log one event while monitoring and expect 2 matches.
"""

import time
import pytest

from wazuh_qa_framework.meta_testing.utils import custom_callback, append_log, DEFAULT_LOG_MESSAGE
from wazuh_qa_framework.generic_modules.monitoring.file_regex_monitor import FileRegexMonitor
from wazuh_qa_framework.generic_modules.exceptions.exceptions import TimeoutError
from wazuh_qa_framework.generic_modules.threading.thread import Thread


def test_accumulations_case_1(create_destroy_sample_file):
    """Check the FileRegexMonitor behavior when we set the "accumulations" parameter.

    case: Pre-logged event, log another event while monitoring and expect 2 matches.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Log a line that triggers the monitoring callback.
            - Start file monitoring.
            - Log a line that triggers the monitoring callback.
            - Check that no TimeoutError exception has been raised.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Write the event
    append_log(log_file, DEFAULT_LOG_MESSAGE)
    time.sleep(0.25)

    # Start the file regex monitoring
    file_regex_monitor_parameters = {'monitored_file': log_file, 'callback': custom_callback, 'timeout': 5,
                                     'only_new_events': False, 'accumulations': 2}
    file_regex_monitor_process = Thread(target=FileRegexMonitor, parameters=file_regex_monitor_parameters)
    file_regex_monitor_process.start()

    # Waiting time for log to be written
    time.sleep(0.25)

    # Write the event
    append_log(log_file, DEFAULT_LOG_MESSAGE)

    # Check that the callback has been triggered and no exception has been raised
    file_regex_monitor_process.join()


def test_accumulations_case_2(create_destroy_sample_file):
    """Check the FileRegexMonitor behavior when we set the "accumulations" parameter.

    case: Log 2 events while monitoring and expect 2 matches.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Start file monitoring.
            - Log 2 lines that trigger the monitoring callback.
            - Check that no TimeoutError exception has been raised.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Start the file regex monitoring
    file_regex_monitor_parameters = {'monitored_file': log_file, 'callback': custom_callback, 'timeout': 5,
                                     'only_new_events': True, 'accumulations': 2}
    file_regex_monitor_process = Thread(target=FileRegexMonitor, parameters=file_regex_monitor_parameters)
    file_regex_monitor_process.start()

    # Waiting time for log to be written
    time.sleep(0.25)

    # Write 2 events
    for _ in range(2):
        append_log(log_file, DEFAULT_LOG_MESSAGE)
        time.sleep(0.1)

    # Check that the callback has been triggered and no exception has been raised
    file_regex_monitor_process.join()


def test_accumulations_case_3(create_destroy_sample_file):
    """Check the FileRegexMonitor behavior when we set the "accumulations" parameter.

    case: Log one event while monitoring and expect 2 matches.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Start file monitoring.
            - Log a line that triggers the monitoring callback.
            - Check that TimeoutError exception has been raised due to we expect 2 matches.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Start the file regex monitoring
    file_regex_monitor_parameters = {'monitored_file': log_file, 'callback': custom_callback, 'timeout': 1,
                                     'only_new_events': False, 'accumulations': 2}
    file_regex_monitor_process = Thread(target=FileRegexMonitor, parameters=file_regex_monitor_parameters)
    file_regex_monitor_process.start()

    # Waiting time for log to be written
    time.sleep(0.25)

    # Write the event
    append_log(log_file, DEFAULT_LOG_MESSAGE)

    # Check that the callback has been triggered and no exception has been raised
    with pytest.raises(TimeoutError):
        file_regex_monitor_process.join()
        assert False, 'A TimeoutError exception has not been generated when we write 1 event and expect 2'
