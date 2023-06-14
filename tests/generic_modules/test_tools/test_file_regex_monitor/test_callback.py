"""
Module to test the callback parameter of FileRegexMonitor.

Test cases:
    - Case 1: Log a matching event while monitoring.
    - Case 2: Log several non matching events while monitoring.
    - Case 3: Log several non matching events and an only matching event while monitoring.
"""

import time
import pytest

from wazuh_qa_framework.meta_testing.utils import custom_callback, append_log, DEFAULT_LOG_MESSAGE
from wazuh_qa_framework.generic_modules.tools.file_regex_monitor import MonitoringObject, FileRegexMonitor
from wazuh_qa_framework.generic_modules.exceptions.exceptions import TimeoutError
from wazuh_qa_framework.generic_modules.threading.thread import Thread


def test_callback_case_1(create_destroy_sample_file):
    """Check the FileRegexMonitor behavior when setting a custom callback.

    case: Log a matching event while monitoring.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Start file monitoring.
            - Log a line that triggers the monitoring callback.
            - Check that TimeoutError exception has not been raised.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Start the file regex monitoring
    monitoring = MonitoringObject(callback=custom_callback, timeout=1, monitored_file=log_file)
    file_regex_monitor_parameters = {'monitoring': monitoring}
    file_regex_monitor_process = Thread(target=FileRegexMonitor, parameters=file_regex_monitor_parameters)
    file_regex_monitor_process.start()

    # Waiting time for log to be written
    time.sleep(0.25)

    # Write the event
    append_log(log_file, DEFAULT_LOG_MESSAGE)

    # Check that the callback has been triggered and no exception has been raised
    file_regex_monitor_process.join()


def test_callback_case_2(create_destroy_sample_file):
    """Check the FileRegexMonitor behavior when setting a custom callback.

    case: Log several non matching events while monitoring.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Start file monitoring.
            - Log several lines that don't trigger the monitoring callback.
            - Check that TimeoutError exception has been raised.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Start the file regex monitoring
    monitoring = MonitoringObject(callback=custom_callback, timeout=1, monitored_file=log_file)
    file_regex_monitor_parameters = {'monitoring': monitoring}
    file_regex_monitor_process = Thread(target=FileRegexMonitor, parameters=file_regex_monitor_parameters)
    file_regex_monitor_process.start()

    # Waiting time for log to be written
    time.sleep(0.25)

    # Write multiple non matching events
    for index in range(3):
        append_log(log_file, f"Non matching event {index}\n")
        time.sleep(0.1)

    # Check that the callback has not been triggered and exception has been raised
    with pytest.raises(TimeoutError):
        file_regex_monitor_process.join()
        pytest.fail('A TimeoutError exception has not been generated with non matching events')


def test_callback_case_3(create_destroy_sample_file):
    """Check the FileRegexMonitor behavior when setting a custom callback.

    case: Log several non matching events and an only matching event while monitoring.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Start file monitoring.
            - Log several lines that don't trigger the monitoring callback and one that it does.
            - Check that TimeoutError exception has not been raised.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Start the file regex monitoring
    monitoring = MonitoringObject(callback=custom_callback, timeout=1, monitored_file=log_file)
    file_regex_monitor_parameters = {'monitoring': monitoring}
    file_regex_monitor_process = Thread(target=FileRegexMonitor, parameters=file_regex_monitor_parameters)
    file_regex_monitor_process.start()

    # Waiting time for log to be written
    time.sleep(0.25)

    # Write multiple non matching events
    for index in range(3):
        append_log(log_file, f"Non matching event {index}\n")
        time.sleep(0.1)

    # Write a matching event
    append_log(log_file, DEFAULT_LOG_MESSAGE)

    # Check that the callback has been triggered and no exception has been raised
    file_regex_monitor_process.join()
