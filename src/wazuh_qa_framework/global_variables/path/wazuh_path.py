"""
Module to build the Wazuh path according to the selected operating system.

This modules contains the following:

- WazuhPath:
    - get_wazuh_path
"""

import sys
import os

from wazuh_qa_framework.global_variables.platform import WINDOWS, MACOS


class WazuhPath:
    """Class to build the wazuh paths according to the selected OS.

    Args:
        os_system (str): Operating system.

    Attributes:
        os_system (str): Operating system.
    """
    def __init__(self, os_system=sys.platform):
        self.os_system = os_system

    def get_wazuh_path(self):
        """Get the wazuh path.

        Returns:
            str: Wazuh path.
        """
        if self.os_system == WINDOWS:
            return os.path.join('C:', os.sep, 'Program Files (x86)', 'ossec-agent')
        elif self.os_system == MACOS:
            return os.path.join('/', 'Library', 'Ossec')
        else:
            return os.path.join('/var', 'ossec')
