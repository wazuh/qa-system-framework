"""
Module to build the Wazuh config paths according to the selected operating system.

This modules contains the following:

- ConfigPath(WazuhPath):
    - get_wazuh_config_path
    - get_wazuh_config_file_path
    - get_internal_config_file_path
    - get_local_internal_config_file_path
    - get_client_keys_file_path
    - get_ssl_manager_cert_file_path
    - get_local_decoders_file_path
    - get_local_rules_file_path
    - get_default_agent_conf_file_path
"""
import sys
import os

from wazuh_qa_framework.global_variables.path.wazuh_path import WazuhPath
from wazuh_qa_framework.global_variables.platform import WINDOWS


class ConfigPath(WazuhPath):
    """Class to build the wazuh config paths according to the selected OS.

    Args:
        os_system (str): Operating system.

    Attributes:
        os_system (str): Operating system.
        config_path (str): Wazuh config files path.
    """
    def __init__(self, os_system=sys.platform):
        super().__init__(os_system=os_system)
        self.config_path = os.path.join(self.get_wazuh_path()) if os_system == WINDOWS else \
            os.path.join(self.get_wazuh_path, 'etc')

    def get_wazuh_config_path(self):
        return self.config_path

    def get_wazuh_config_file_path(self):
        return os.path.join(self.config_path, 'ossec.conf')

    def get_internal_config_file_path(self):
        return os.path.join(self.config_path, 'internal_options.conf')

    def get_local_internal_config_file_path(self):
        return os.path.join(self.config_path, 'local_internal_options.conf')

    def get_client_keys_file_path(self):
        return os.path.join(self.config_path, 'client.keys')

    def get_ssl_manager_cert_file_path(self):
        return os.path.join(self.config_path, 'sslmanager.cert')

    def get_local_decoders_file_path(self):
        return os.path.join(self.config_path, 'decoders', 'local_decoder.xml')

    def get_local_rules_file_path(self):
        return os.path.join(self.config_path, 'rules', 'local_rules.xml')

    def get_default_agent_conf_file_path(self):
        return os.path.join(self.config_path, 'shared', 'default', 'agent.conf')
