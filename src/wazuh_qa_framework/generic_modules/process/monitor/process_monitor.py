"""
Module to define a process monitor.

This module defines the basis for creating methods that allow us to obtain information about resources and process
information. For this purpose, psutil.Process is used, which practically provides us with the necessary information.

This module contains the following:

- ProcessMonitor(ABC):
"""

import psutil
from abc import ABC

from wazuh_qa_framework.generic_modules.exceptions.exceptions import ValueError


class ProcessMonitor(ABC):
    """Class to get data from process.

    Args:
        pid (int): Process PID.

    Attributes:
        pid (int): Process PID.
        process (psutil.Process): Process object.
    """
    def __init__(self, pid):
        self.pid = pid

        try:
            self.process = psutil.Process(pid)
        except psutil.NoSuchProcess as exception:
            raise ValueError(f"PID {self.pid} was not found", traceback=False) from exception
