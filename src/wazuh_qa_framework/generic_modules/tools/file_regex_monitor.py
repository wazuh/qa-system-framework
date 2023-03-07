"""
Module to build a tool that allow us to monitor a file content and check if the content matches with a specified
callback.

We can configure this tools to check from the beggining of file or just check new lines from monitoring time. If the
callback is not matched, a TimeoutError exception will be raised.

The monitoring will start as soon as the object is created. We don't need to do anymore.
"""

import os
import time

from wazuh_qa_framework.generic_modules.exceptions.exceptions import ValidationError, TimeoutError


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
    """

    def __init__(self, monitored_file, callback, timeout=10, accumulations=1, only_new_events=True,
                 error_message=None):
        self.monitored_file = monitored_file
        self.callback = callback
        self.timeout = timeout
        self.accumulations = accumulations
        self.only_new_events = only_new_events
        self.error_message = error_message

        self.__validate_parameters()
        self.__start()

    def __validate_parameters(self):
        """Validate if the specified file can be monitored."""
        # Check that the monitored file exists
        if not os.path.exists(self.monitored_file):
            raise ValidationError(f"File {self.monitored_file} does not exist")

        # Check that the monitored file is a file
        if not os.path.isfile(self.monitored_file):
            raise ValidationError(f"{self.monitored_file} is not a file")

        # Check that the program can read the content of the file
        if not os.access(self.monitored_file, os.R_OK):
            raise ValidationError(f"{self.monitored_file} is not readable")

    def __start(self):
        """Start the file regex monitoring"""
        matches = 0

        # Check if current file content lines triggers the callback (only when new events has False value)
        if not self.only_new_events:
            with open(self.monitored_file) as _file:
                for line in _file:
                    matches = matches + 1 if self.callback(line) else matches
                    if matches >= self.accumulations:
                        return

        # Start count to set the timeout
        start_time = time.time()

        # Start the file regex monitoring from the last line
        with open(self.monitored_file) as _file:
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
                    matches = matches + 1 if self.callback(line) else matches
                    # If it has triggered the callback the expected times, break and leave the loop
                    if matches >= self.accumulations:
                        break

                # Add the time processing time
                elapsed_time = time.time() - start_time

                # Raise timeout error if we have passed the timeout
                if elapsed_time > self.timeout:
                    raise TimeoutError(f"Events from {self.monitored_file} did not match with the callback" if
                                       self.error_message is None else self.error_message)
