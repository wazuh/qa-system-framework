"""
Module to build the Wazuh binary paths according to the selected operating system.

This modules contains the following:

- BinaryPath(WazuhPath):
    - get_binary_path
    - get_agent_control_path
    - get_agent_groups_path
    - get_agent_upgrade_path
    - get_clear_stats_path
    - get_cluster_control_path
    - get_manage_agents_path
    - get_wazuh_control_path
    - get_wazuh_agentlessd_path
    - get_wazuh_analysisd_path
    - get_wazuh_apid_path
    - get_wazuh_authd_path
    - get_wazuh_clusterd_path
    - get_wazuh_csyslogd_path
    - get_wazuh_db_path
    - get_wazuh_dbd_path
    - get_wazuh_execd_path
    - get_wazuh_integratord_path
    - get_wazuh_logcollector_path
    - get_wazuh_logtest_path
    - get_wazuh_maild_path
    - get_wazuh_modulesd_path
    - get_wazuh_monitord_path
    - get_wazuh_regex_path
    - get_wazuh_remoted_path
    - get_wazuh_reportd_path
    - get_wazuh_syscheckd_path
    - get_agent_auth_path
    - get_wazuh_agentd_path
"""

import sys
import os

from wazuh_qa_framework.global_variables.path.wazuh_path import WazuhPath
from wazuh_qa_framework.global_variables.platform import WINDOWS


class BinaryPath(WazuhPath):
    """Class to build the wazuh binary paths according to the selected OS.

    Args:
        os_system (str): Operating system.

    Attributes:
        os_system (str): Operating system.
        binary_path (str): Wazuh binary paths.
    """
    def __init__(self, os_system=sys.platform):
        super().__init__(os_system=os_system)
        self.binary_path = os.path.join(self.get_wazuh_path()) if os_system == WINDOWS else \
            os.path.join(self.get_wazuh_path, 'bin')

    def get_binary_path(self):
        return self.binary_path

    def get_agent_control_path(self):
        return os.path.join(self.binary_path, 'agent_control')

    def get_agent_groups_path(self):
        return os.path.join(self.binary_path, 'agent_groups')

    def get_agent_upgrade_path(self):
        return os.path.join(self.binary_path, 'agent_upgrade')

    def get_clear_stats_path(self):
        return os.path.join(self.binary_path, 'clear_stats')

    def get_cluster_control_path(self):
        return os.path.join(self.binary_path, 'cluster_control')

    def get_manage_agents_path(self):
        return os.path.join(self.binary_path, 'manage_agents')

    def get_wazuh_control_path(self):
        return os.path.join(self.binary_path, 'wazuh_control')

    def get_wazuh_agentlessd_path(self):
        return os.path.join(self.binary_path, 'wazuh-agentlessd')

    def get_wazuh_analysisd_path(self):
        return os.path.join(self.binary_path, 'wazuh-analysisd')

    def get_wazuh_apid_path(self):
        return os.path.join(self.binary_path, 'wazuh-apid')

    def get_wazuh_authd_path(self):
        return os.path.join(self.binary_path, 'wazuh-authd')

    def get_wazuh_clusterd_path(self):
        return os.path.join(self.binary_path, 'wazuh-clusterd')

    def get_wazuh_csyslogd_path(self):
        return os.path.join(self.binary_path, 'wazuh-csyslogd')

    def get_wazuh_db_path(self):
        return os.path.join(self.binary_path, 'wazuh-db')

    def get_wazuh_dbd_path(self):
        return os.path.join(self.binary_path, 'wazuh-dbd')

    def get_wazuh_execd_path(self):
        return os.path.join(self.binary_path, 'wazuh-execd')

    def get_wazuh_integratord_path(self):
        return os.path.join(self.binary_path, 'wazuh-integratord')

    def get_wazuh_logcollector_path(self):
        return os.path.join(self.binary_path, 'wazuh-logcollector')

    def get_wazuh_logtest_path(self):
        return os.path.join(self.binary_path, 'wazuh-logtest')

    def get_wazuh_maild_path(self):
        return os.path.join(self.binary_path, 'wazuh-maild')

    def get_wazuh_modulesd_path(self):
        return os.path.join(self.binary_path, 'wazuh-modulesd')

    def get_wazuh_monitord_path(self):
        return os.path.join(self.binary_path, 'wazuh-monitord')

    def get_wazuh_regex_path(self):
        return os.path.join(self.binary_path, 'wazuh-regex')

    def get_wazuh_remoted_path(self):
        return os.path.join(self.binary_path, 'wazuh-remoted')

    def get_wazuh_reportd_path(self):
        return os.path.join(self.binary_path, 'wazuh-reportd')

    def get_wazuh_syscheckd_path(self):
        return os.path.join(self.binary_path, 'wazuh-syscheckd')

    def get_agent_auth_path(self):
        return os.path.join(self.binary_path, 'agent-auth')

    def get_wazuh_agentd_path(self):
        return os.path.join(self.binary_path, 'wazuh-agentd')
