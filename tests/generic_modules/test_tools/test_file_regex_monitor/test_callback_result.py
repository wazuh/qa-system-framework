"""
Module to test the callback result of FileRegexMonitor.

When monitoring is started, each file line will be processed by a callback function, that will determine if the line
meets the condition to trigger it. In the case that the callback is triggered, the result is stored in an attribute
variable. In this module we check that behavior.

Test cases:
    - Write an event that matches with callback and check the returned callback group info.
"""

import re

from wazuh_qa_framework.meta_testing.utils import DEFAULT_LOG_MESSAGE, append_log
from wazuh_qa_framework.generic_modules.tools.file_regex_monitor import MonitoringObject, FileRegexMonitor


def custom_callback(line):
    """Custom callback to check if a line matches with the expected pattern.

    Args:
        line (str): Log line.

    Returns:
        tuple(str): Log captured groups, if not matched returns None.
    """
    pattern = r'(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) wazuh-modulesd:(.*): (\w+): .*'
    match = re.match(pattern, line)

    if match:
        return match.group(1), match.group(2), match.group(3)

    return None


def test_get_callback_group_values(create_destroy_sample_file):
    """Write an event that matches with callback and check the returned callback group info.

    test_phases:
        - setup:
            - Create an empty file.
        - test:
            - Write a line that matches with callback.
            - Check that callback has been triggered.
            - Check that the callback grouped info is the expected one.
        - teardown:
            - Remove the create file in the setup phase.

    parameters:
        - create_destroy_sample_file (fixture): Create an empty file and remove it after finishing.
    """
    log_file = create_destroy_sample_file

    # Write a matching event
    append_log(log_file, DEFAULT_LOG_MESSAGE)

    # Start the file regex monitoring
    monitoring = MonitoringObject(callback=custom_callback, timeout=1, monitored_file=log_file)
    file_regex_monitor_process = FileRegexMonitor(monitoring=monitoring)

    # Check that callback results values are the expected ones.
    assert file_regex_monitor_process.callback_result == ('2023/02/14 09:49:47', 'aws-s3', 'INFO')
