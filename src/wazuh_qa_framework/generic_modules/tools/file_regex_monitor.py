"""
Module to build a tool that allow us to monitor a file content and check if the content matches with a specified
callback.

We can configure this tools to check from the beggining of file or just check new lines from monitoring time. If the
callback is not matched, a TimeoutError exception will be raised.

The monitoring will start as soon as the object is created. We don't need to do anymore.

This module contains the following:

- FileRegexMonitor
"""

import os
import re
import time

from wazuh_qa_framework.generic_modules.exceptions.exceptions import ValidationError, TimeoutError
from wazuh_qa_framework.generic_modules.file.file import get_file_encoding


class MonitoringObject:
    """Class to monitor a file and check if the content matches with the specified callback.

    Args:
        description (str): String that describes the whole metadata stack.
        pattern (str): Regex that is combined with the prefix to match with logs.
        prefix (str): Prefix string that comes before the pattern used to match logs.
        monitored_file (str): File path to monitor.
        callback (function): Callback function that will be evaluated for each log line.
        timeout (int): Max time to monitor and trigger the callback.

    Attributes:
        description (str): String that describes the whole metadata stack.
        pattern (str): Regex that is combined with the prefix to match with logs.
        prefix (str): Prefix string that comes before the pattern used to match logs.
        complete_pattern (str): Prefix and pattern join.
        regex (re): Regex created with the prefix and pattern.
        monitored_file (str): File path to monitor.
        callback (function): Callback function that will be evaluated for each log line.
        timeout (int): Max time to monitor and trigger the callback.
    """
    def __init__(self, description=None, pattern='.*', prefix='.*', timeout=1, monitored_file=None, callback=None):
        self.validate_args(description, pattern, prefix, timeout, monitored_file, callback)

        self.pattern = pattern
        self.prefix = prefix
        self.complete_pattern = pattern if prefix is None else fr'{prefix}{pattern}'
        self.regex = re.compile(self.complete_pattern)
        self.timeout = timeout
        self.monitored_file = monitored_file
        self.callback = callback if callback else self.get_default_callback()
        self.description = description if description else self.get_default_description()

    def __str__(self):
        """String representation when using str function."""
        return self.description

    def validate_args(self, description, pattern, prefix, timeout, monitored_file, callback):
        """Validate the given monitoring args.

        Args:
            description (str): String that describes the whole metadata stack.
            pattern (str): Regex that is combined with the prefix to match with logs.
            prefix (str): Prefix string that comes before the pattern used to match logs.
            monitored_file (str): File path to monitor.
            callback (function): Callback function that will be evaluated for each log line.
            timeout (int): Max time to monitor and trigger the callback.
        """
        # Validate if the specified file can be monitored.
        # Check if monitored file is given
        if not monitored_file:
            raise ValidationError('The monitored_file arg is required. Pass an existing file to be monitored.')

        # Check that the monitored file exists
        if not os.path.exists(monitored_file):
            raise ValidationError(f"File {monitored_file} does not exist")

        # Check that the monitored file is a file
        if not os.path.isfile(monitored_file):
            raise ValidationError(f"{monitored_file} is not a file")

        # Check that the program can read the content of the file
        if not os.access(monitored_file, os.R_OK):
            raise ValidationError(f"{monitored_file} is not readable")

        # Validate if timeout is a positive integer
        if timeout < 0:
            raise ValidationError('The timeout can\'t be a negative value')

        # Validate that callback is a callable function if given
        if callback and not callable(callback):
            raise ValidationError(f"The given callback {callback} is not a callable function.")

    def get_default_callback(self):
        """Get the default callback lambda function.

        The default callback checks if the given line matches with the monitored regex.
        """
        return lambda line: self.regex.match(line.decode() if isinstance(line, bytes) else line) is not None

    def get_default_description(self):
        """Get the default monitoring description.

        The default description uses the fields that represent the pattern search:
            - prefix
            - pattern
            - monitored_file
        """
        return f"MonitoringObject-{self.prefix}{self.pattern}-{self.monitored_file}"


class FileRegexMonitor:
    """Class to monitor a file and check if the content matches with the specified callback.

    Args:
        monitored_file (str): File path to monitor.
        callback (function): Callback function that will be evaluated for each log line.
        timeout (int): Max time to monitor and trigger the callback.
        accumulations (int): Number of expected times to match with the callback.
        only_new_events (boolean): True for only checking new lines, False to take into account all file lines.
        error_message (str): Error message to show if the timeout exception is raised.

    Attributes:
        monitored_file (str): File path to monitor.
        callback (function): Callback function that will be evaluated for each log line.
        timeout (int): Max time to monitor and trigger the callback.
        accumulations (int): Number of expected times to match with the callback.
        only_new_events (boolean): True for only checking new lines, False to take into account all file lines.
        error_message (str): Error message to show if the timeout exception is raised.
        callback_result (*): It will store the result returned by the callback call if it is not None.
    """

    def __init__(self, monitoring, accumulations=1, only_new_events=False, error_message=None):
        self.monitoring = monitoring
        self.accumulations = accumulations
        self.only_new_events = only_new_events
        self.error_message = error_message
        self.callback_result = None

        self.__validate_parameters()
        self.__start()

    def __validate_parameters(self):
        """Validate if the specified file can be monitored."""
        # Check that the monitored file exists
        if not os.path.exists(self.monitoring.monitored_file):
            raise ValidationError(f"File {self.monitoring.monitored_file} does not exist")

        # Check that the monitored file is a file
        if not os.path.isfile(self.monitoring.monitored_file):
            raise ValidationError(f"{self.monitoring.monitored_file} is not a file")

        # Check that the program can read the content of the file
        if not os.access(self.monitoring.monitored_file, os.R_OK):
            raise ValidationError(f"{self.monitoring.monitored_file} is not readable")

    def __start(self):
        """Start the file regex monitoring"""
        matches = 0
        encoding = get_file_encoding(self.monitoring.monitored_file)
        # Check if current file content lines triggers the callback (only when new events has False value)
        if not self.only_new_events:
            with open(self.monitoring.monitored_file, encoding=encoding) as _file:
                for line in _file:
                    callback_result = self.monitoring.callback(line)
                    self.callback_result = callback_result if callback_result is not None else self.callback_result
                    matches = matches + 1 if callback_result else matches
                    if matches >= self.accumulations:
                        return

        # Start count to set the timeout
        start_time = time.time()

        # Start the file regex monitoring from the last line
        with open(self.monitoring.monitored_file, encoding=encoding) as _file:
            # Go to the end of the file
            _file.seek(0, 2)
            while True:
                current_position = _file.tell()
                line = _file.readline()
                # If we have not new changes wait for the next try
                if not line:
                    _file.seek(current_position)
                    time.sleep(0.1)
                # If we have a new line, check if it matches with the callback
                else:
                    callback_result = self.monitoring.callback(line)
                    self.callback_result = callback_result if callback_result is not None else self.callback_result
                    matches = matches + 1 if callback_result else matches
                    # If it has triggered the callback the expected times, break and leave the loop
                    if matches >= self.accumulations:
                        break

                # Add the time processing time
                elapsed_time = time.time() - start_time

                # Raise timeout error if we have passed the timeout
                if elapsed_time > self.monitoring.timeout:
                    raise TimeoutError(f"Events from {self.monitoring.monitored_file} did not match with the callback" +
                                       f" from {self.monitoring}" if self.error_message is None else self.error_message)
