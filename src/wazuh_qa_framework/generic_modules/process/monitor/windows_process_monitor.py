"""
Module to define a Windows process monitor.

The WindowsProcessMonitor class provides us with an interface of methods that we can use in Windows systems to obtain
information about resources and process information.

This module contains the following:

- WindowsProcessMonitor(ProcessMonitor):
    - get_memory_usage
    - get_memory_usage_percentage
    - get_total_cpu_usage
    - get_username
    - get_status
    - get_ppid
    - get_creation_time
    - get_num_threads
"""

from wazuh_qa_framework.generic_modules.exceptions.exceptions import ValidationError
from wazuh_qa_framework.generic_modules.time.time_utils import Time
from wazuh_qa_framework.generic_modules.process.monitor.process_monitor import ProcessMonitor


class WindowsProcessMonitor(ProcessMonitor):
    """Class to get data from process.

    Args:
        pid (int): Process PID.

    Attributes:
        pid (int): Process PID.
        process (psutil.Process): Process object.
    """
    def get_memory_usage(self, unit='KB'):
        """Get the memory usage of monitored process.

        Args:
            unit (str): Memory unit. Enum: [B, KB, MB].

        Returns:
            str: Process memory usage. Example: 4KB
        """
        units = {
            'B': 1,
            'KB': 1024,
            'MB': 1048576
        }

        if unit not in units:
            raise ValidationError(f"unit parameters is not valid. Accepted ones: {units.keys()}")

        return f"{int(self.process.memory_info()[0] / units[unit])}{unit}"

    def get_memory_usage_percentage(self):
        """Get the memory usage percentage of monitored process.

        Returns:
            str: Process memory usage percentage. Example: 15%
        """
        return f"{round(self.process.memory_percent(), 3)}%"

    def get_total_cpu_usage(self):
        """Get the total cpu usage percentage of monitored process.

        Returns:
            str: Process total cpu usage percentage. Example: 5%
        """
        return f"{self.process.cpu_percent(interval=0.1)}%"

    def get_username(self):
        """Get the username who launched the monitored process.

        Returns:
            str: Username who launched the process.
        """
        return self.process.username()

    def get_status(self):
        """Get the status of the monitored process.

        Returns:
            str: Process status.
        """
        return self.process.status()

    def get_ppid(self):
        """Get the PID of the parent process who launched this monitored process.

        Returns:
            int: PPID of the process.
        """
        return self.process.ppid()

    def get_creation_time(self):
        """Get the creation time of the monitored process.

        Returns:
            str: date time when the monitoried process has been created. Example: 2022-11-20 20:48:33
        """
        return Time.get_datetime_from_timestamp(self.process.create_time())

    def get_num_threads(self):
        """Get the number of threads that the monitored process is running.

        Returns:
            int: Number of used threads by the process.
        """
        return self.process.num_threads()
