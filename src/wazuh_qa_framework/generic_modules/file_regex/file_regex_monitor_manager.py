import os
import time
import json

from wazuh_qa_framework.generic_modules.exceptions.exceptions import ValidationError, TimeoutError
from wazuh_qa_framework.generic_modules.file.file import get_file_encoding


class FileRegexMonitorManager:

    def __init__(self, logging=None):
        self.logging = logging
        self.files_position = {}

    def start(self, monitoring_data, report_file=None, update_position=True, ignore_errors=False):
        """Start the file regex monitoring

        Args:
            monitoring_data (list): List of dictionaries with the monitoring data.
            report_file (str): File path to store the monitoring results.
            update_position (bool): True for start monitoring from the last position, False to start from the beginning.
            ignore_errors (bool): True for continue monitoring if an error is raised, False to stop monitoring.

        Returns:
            list: List of dictionaries with the monitoring results.

        Raises:
            TimeoutError: If the callback does not match with the file content.
        """

        def get_monitoring_data_values(monitoring_data):
            return [monitoring_data.get("path"), monitoring_data.get("callback"), monitoring_data.get("timeout", 60),
                    monitoring_data.get("error_message", None)]

        matches_results = []

        for monitoring_element in monitoring_data:
            monitoring_file, callback, timeout, error_message = get_monitoring_data_values(monitoring_element)
            encoding = get_file_encoding(monitoring_file)

            # Start count to set the timeout
            start_time = time.time()
            with open(file=monitoring_file, encoding=encoding) as _file:
                if update_position:
                    if monitoring_file not in self.files_position:
                        self.files_position[monitoring_file] = 0
                    else:
                        _file.seek(self.files_position[monitoring_file])
                while True:
                    current_position = _file.tell()
                    line = _file.readline()

                    # If we have not new changes wait for the next try
                    if not line:
                        _file.seek(current_position)
                        time.sleep(0.1)
                    # If we have a new line, check if it matches with the callback

                    else:
                        match = callback(line)
                        if match:
                            if match.groups():
                                result = {"file": monitoring_file, "line": line,
                                          "groups": match.groups(), "found": True}
                            else:
                                result = {"file": monitoring_file, "line": line, "found": True}

                            matches_results.append(result)
                            self.files_position[monitoring_file] = _file.tell()
                            break

                    # Add the time processing time
                    elapsed_time = time.time() - start_time

                    # Raise timeout error if we have passed the timeout
                    if elapsed_time > timeout:
                        failed_result = {"file": monitoring_file, "last_monitored_line": line,
                                         "found": False}
                        matches_results.append(failed_result)
                        break

                if not ignore_errors and matches_results[-1].get("found") is False:
                    break

        if self.report_file is not None:
            with open(self.report_file, "w") as report_file_handler:
                print(matches_results)
                json.dump(matches_results, report_file_handler)

        if not ignore_errors:
            if matches_results[-1].get("found") is False:
                raise TimeoutError(f"Event {callback} from {monitoring_file} did not match with the callback" if
                                   error_message is None else error_message)

        return matches_results
