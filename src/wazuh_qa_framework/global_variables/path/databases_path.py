"""
Module to build the Wazuh databases paths according to the selected operating system.

This modules contains the following:

- DatabasesPath(WazuhPath):
    - get_global_db_path
    - get_manager_local_db_path
    - get_agent_db_path
    - get_cve_db_path
    - get_local_fim_db_path
    - get_local_syscollector_db_path
"""

import sys
import os

from wazuh_qa_framework.global_variables.path.wazuh_path import WazuhPath


class DatabasesPath(WazuhPath):
    """Class to build the wazuh database paths according to the selected OS.

    Args:
        os_system (str): Operating system.

    Attributes:
        os_system (str): Operating system.
        databases_path (str): Wazuh databases path.
    """
    def __init__(self, os_system=sys.platform):
        super().__init__(os_system=os_system)

    def get_global_db_path(self):
        return os.path.join(self.databases_path, 'global.db')

    def get_manager_local_db_path(self):
        return os.path.join(self.databases_path, '000.db')

    def get_agent_db_path(self, agent_id='000'):
        return os.path.join(self.databases_path, f"{agent_id}.db")

    def get_cve_db_path(self):
        return os.path.join(self.get_wazuh_path(), 'queue', 'vulnerabilities', 'cve.db')

    def get_local_fim_db_path(self):
        return os.path.join(self.get_wazuh_path(), 'queue', 'fim', 'db', 'fim.db')

    def get_local_syscollector_db_path(self):
        return os.path.join(self.get_wazuh_path(), 'queue', 'syscollector', 'db', 'local.db')
