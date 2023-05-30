"""
Module to test the only_new_events parameter of FileRegexMonitor.

Test cases:
    - Case 1: Log a new event in a empty file while monitoring.
        - case 1.1 [only_new_events enabled]
        - case 1.2 [only_new_events disabled]
    - Case 2: Pre-logged event and does not log anything while monitoring.
        - case 2.1 [only_new_events enabled]
        - case 2.2 [only_new_events disabled]
    - Case 3: Start monitoring in a empty file and does not log anything.
        - case 3.1 [only_new_events enabled]
        - case 3.2 [only_new_events disabled]
"""

import time
import pytest

from wazuh_qa_framework.meta_testing.utils import custom_callback, append_log, DEFAULT_LOG_MESSAGE
from wazuh_qa_framework.generic_modules.tools.file_regex_monitor import FileRegexMonitor
from wazuh_qa_framework.generic_modules.exceptions.exceptions import TimeoutError
from wazuh_qa_framework.generic_modules.threading.thread import Thread


EXPECTED_EXCEPTION_ERROR_MESSAGE = 'FileRegexMonitor has not raised a TimeoutError exception when it was expected'


@pytest.mark.parametrize('only_new_events, expected_exception', [(True, False), (False, False)],
                         ids=['enabled', 'disabled'])
def test_only_new_events_case_1(only_new_events, expected_exception, create_destroy_sample_file):
    """Check the FileRegexMonitor behavior when we enable/disable the setting only_new_events.

    case: Log a new event in a empty file while monitoring.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Start file monitoring and write a log line that triggers the monitoring callback.
            - Check if TimeoutError exception has been raised.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - only_new_events (boolean): Parametrized variable.
        - expected_exception (boolean): Parametrized variable.
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Start the file regex monitoring
    file_regex_monitor_parameters = {'monitored_file': log_file, 'callback': custom_callback, 'timeout': 5,
                                     'only_new_events': only_new_events}
    file_regex_monitor_process = Thread(target=FileRegexMonitor, parameters=file_regex_monitor_parameters)
    file_regex_monitor_process.start()

    # Waiting time for log to be written
    time.sleep(0.25)
    append_log(log_file, DEFAULT_LOG_MESSAGE)

    # Check if the callback has been triggered and if a timeout exception has been raised
    if expected_exception:
        with pytest.raises(TimeoutError):
            file_regex_monitor_process.join()
            pytest.fail(EXPECTED_EXCEPTION_ERROR_MESSAGE)
    else:
        file_regex_monitor_process.join()


@pytest.mark.parametrize('only_new_events, expected_exception', [(True, True), (False, False)],
                         ids=['enabled', 'disabled'])
def test_only_new_events_case_2(only_new_events, expected_exception, create_destroy_sample_file):
    """Check the FileRegexMonitor behavior when we enable/disable the setting only_new_events.

    case: Pre-logged event and does not log anything while monitoring.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Log a line that triggers the monitoring callback.
            - Start file monitoring.
            - Check if TimeoutError exception has been raised.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - only_new_events (boolean): Parametrized variable.
        - expected_exception (boolean): Parametrized variable.
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Add a log message
    append_log(log_file, DEFAULT_LOG_MESSAGE)

    # Waiting time for log to be written
    time.sleep(0.25)

    # Start the file regex monitoring
    file_regex_monitor_parameters = {'monitored_file': log_file, 'callback': custom_callback, 'timeout': 1,
                                     'only_new_events': only_new_events}
    file_regex_monitor_process = Thread(target=FileRegexMonitor, parameters=file_regex_monitor_parameters)
    file_regex_monitor_process.start()

    # Check if the callback has been triggered and if a timeout exception has been raised
    if expected_exception:
        with pytest.raises(TimeoutError):
            file_regex_monitor_process.join()
            pytest.fail(EXPECTED_EXCEPTION_ERROR_MESSAGE)
    else:
        file_regex_monitor_process.join()


@pytest.mark.parametrize('only_new_events, expected_exception', [(True, True), (False, True)],
                         ids=['enabled', 'disabled'])
def test_only_new_events_case_3(only_new_events, expected_exception, create_destroy_sample_file):
    """Check the FileRegexMonitor behavior when we enable/disable the setting only_new_events.

    case: Start monitoring in a empty file and does not log anything.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Start file monitoring.
            - Check if TimeoutError exception has been raised.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - only_new_events (boolean): Parametrized variable.
        - expected_exception (boolean): Parametrized variable.
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Start the file regex monitoring
    file_regex_monitor_parameters = {'monitored_file': log_file, 'callback': custom_callback, 'timeout': 1,
                                     'only_new_events': only_new_events}
    file_regex_monitor_process = Thread(target=FileRegexMonitor, parameters=file_regex_monitor_parameters)
    file_regex_monitor_process.start()

    # Check if the callback has been triggered and if a timeout exception has been raised
    if expected_exception:
        with pytest.raises(TimeoutError):
            file_regex_monitor_process.join()
            pytest.fail('Nothing has been logged and the FileRegexMonitor has not raised the TimeoutError exception')
    else:
        file_regex_monitor_process.join()
