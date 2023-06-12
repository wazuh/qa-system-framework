import os
import time

from wazuh_qa_framework.generic_modules.exceptions.exceptions import ValidationError, TimeoutError
from wazuh_qa_framework.generic_modules.file.file import get_file_encoding


class FileRegexMonitorManager:

    def __init__(self, monitoring_data, logging=None):
        self.monitoring_data = monitoring_data
        self.logging = logging
        self.matches_results = []

        self.__validate_parameters()
        self.__start()

    def __validate_parameters(self):
        """Validate if the specified file can be monitored."""
        pass

    def __start(self):
        """Start the file regex monitoring"""
        matches_results = []
        matches = 0
        monitoring_iterator = iter(self.monitoring_data)

        monitoring = next(monitoring_iterator)
        monitored_file = monitoring.get("path")
        callback = monitoring.get("callback")
        timeout = monitoring.get("timeout", 60)
        accumulations = monitoring.get("accumulations", 1)
        error_message = monitoring.get("error_message", None)
        monitor_id = monitoring.get("monitor_id", None)

        callback_result = None
        encoding = get_file_encoding(monitored_file)
        # Start count to set the timeout
        start_time = time.time()

        # Start the file regex monitoring from the last line
        with open(monitored_file, encoding=encoding) as _file:
            while True:
                current_position = _file.tell()
                line = _file.readline()
                # If we have not new changes wait for the next try
                if not line:
                    _file.seek(current_position)
                    time.sleep(0.1)
                # If we have a new line, check if it matches with the callback
                else:
                    callback_result_lines = monitoring.get('callback')(line)
                    callback_result = callback_result_line if callback_result_line is not None else callback_result
                    matches = matches + 1 if callback_result_line else matches

                    # If it has triggered the callback the expected times, break and leave the loop
                    if matches >= accumulations:
                        matches_results.append(callback_result)
                        monitoring = next(monitoring_iterator, None)
                        if monitoring is None:
                            break
                        else:
                            monitored_file = monitoring.get("path")
                            callback = monitoring.get("callback")
                            timeout = monitoring.get("timeout", 60)
                            accumulations = monitoring.get("accumulations", 1)
                            error_message = monitoring.get("error_message", None)
                            monitor_id = monitoring.get("monitor_id", None)
                            callback_result = None
                            encoding = get_file_encoding(monitored_file)
                            # Start count to set the timeout
                            start_time = time.time()
                # Add the time processing time
                elapsed_time = time.time() - start_time

                # Raise timeout error if we have passed the timeout
                if elapsed_time > timeout:
                    raise TimeoutError(f"Event {callback} from {monitored_file} did not match with the callback" if
                                       error_message is None else error_message)

        self.matches_results = matches_results

"""
[
  - regex: ".*Server IP Address: MANAGER_DNS\\/MANAGER_IP"
    path: "/var/ossec/logs/ossec.log"
    timeout: 60
  - regex: ".*Requesting a key from server: MANAGER_DNS\\/MANAGER_IP"
    path: "/var/ossec/logs/ossec.log"
    timeout: 60
  - regex: ".*Connected to enrollment service at '\\[MANAGER_IP\\]:1515'.*"
    path: "/var/ossec/logs/ossec.log"
    timeout: 60
  - regex: ".*Registering agent to unverified manager"
    path: "/var/ossec/logs/ossec.log"
    timeout: 60
  - regex: ".*Using agent name as:*"
    path: "/var/ossec/logs/ossec.log"
    timeout: 60
  - regex: ".*Waiting for server reply"
    path: "/var/ossec/logs/ossec.log"
    timeout: 60
  - regex: ".*Valid key received"
    path: "/var/ossec/logs/ossec.log"
    timeout: 60
  - regex: ".*Waiting .* seconds before server connection"
    path: "/var/ossec/logs/ossec.log"
    timeout: 60
]
"""