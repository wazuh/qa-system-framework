# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import yaml
from multiprocessing.pool import ThreadPool

from wazuh_qa_framework.generic_modules.logging.base_logger import BaseLogger
from wazuh_qa_framework.generic_modules.tools.configuration import set_section_wazuh_conf
from wazuh_qa_framework.global_variables.daemons import WAZUH_ANGENT_WINDOWS_SERVICE_NAME
from wazuh_qa_framework.system.host_manager import HostManager


DEFAULT_INSTALL_PATH = {
    'linux': '/var/ossec',
    'windows': 'C:\\Program Files\\ossec-agent',
    'darwin': '/Library/Ossec'
}

DEFAULT_TEMPORAL_DIRECTORY = {
    'linux': '/tmp',
    'windows': 'C:\\Users\\qa\\AppData\Local\Temp'
}


def configure_local_internal_options(new_conf):
    local_internal_configuration_string = ''
    for option_name, option_value in new_conf.items():
        local_internal_configuration_string += f"{str(option_name)}={str(option_value)}\n"
    return local_internal_configuration_string


def configure_ossec_conf(new_conf, template):
    new_configuration = ''.join(set_section_wazuh_conf(new_conf, template))
    return new_configuration


def configure_api_yaml(new_conf):
    new_configuration = yaml.dump(new_conf)
    return new_configuration


conf_functions = {
    'local_internal_options.conf': configure_local_internal_options,
    'ossec.conf': configure_ossec_conf,
    'agent.conf': configure_ossec_conf,
    'api.yaml': configure_api_yaml
}


def get_configuration_directory_path(custom_installation_path=None, os_host='linux'):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH[os_host]
    return installation_path if os_host == 'windows' else os.path.join(installation_path, 'etc')


def get_custom_decoders_directory_path(custom_installation_path=None):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH['linux']
    return os.path.join(installation_path, 'etc', 'decoders')


def get_custom_rules_directory_path(custom_installation_path=None):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH['linux']
    return os.path.join(installation_path, 'etc', 'rules')


def get_api_directory(custom_installation_path=None):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH['linux']
    return os.path.join(installation_path, 'api')


def get_api_configuration_directory(custom_installation_path=None):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH['linux']
    return os.path.join(get_api_directory(installation_path), 'configuration')


def get_alert_directory_path(custom_installation_path=None):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH['linux']
    return os.path.join(installation_path, 'logs', 'alerts')


def get_archives_directory_path(custom_installation_path=None):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH['linux']
    return os.path.join(installation_path, 'logs', 'archives')


def get_logs_directory_path(custom_installation_path=None, os_host='linux'):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH[os_host]
    return installation_path if os_host == 'windows' else os.path.join(installation_path, 'logs')


def get_shared_directory_path(custom_installation_path=None, os_host='linux'):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH[os_host]
    return os.path.join(get_configuration_directory_path(installation_path, os_host), 'shared')


def get_group_configuration_directory(custom_installation_path=None, os_host='linux', component='manager',
                                      group='default'):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH[os_host]
    group_configuration_path = None
    if component == 'manager':
        group_configuration_path = os.path.join(get_shared_directory_path(installation_path, os_host),
                                                group)
    else:
        group_configuration_path = os.path.join(get_shared_directory_path(installation_path, os_host))

    return group_configuration_path


def get_ruleset_directory(custom_installation_path=None, os_name='linux'):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH[os_name]
    return os.path.join(installation_path, 'ruleset')


def get_wazuh_file_path(custom_installation_path=None, os_host='linux', file_name=None, component=None, **extra_params):
    """Get the Wazuh file paths

    Args:
        custom_installation_path (str): Custom installation path.
        os (str): Operating system.
    Returns:
        str: Wazuh installation path.
    """
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH[os_host]
    group = extra_params.get('group', 'default')

    wazuh_directory_files = {
        'general_configuration': {
            'files': ['ossec.conf', 'client.keys', 'local_internal_options.conf', 'internal_options.conf'],
            'path_calculator': lambda filename: os.path.join(get_configuration_directory_path(installation_path,
                                                                                              os_host),
                                                             filename)
        },
        'api_configuration': {
            'files': ['api.yaml'],
            'path_calculator': lambda filename: os.path.join(get_api_configuration_directory(installation_path),
                                                             filename)
        },
        'general_logs': {
            'files': ['ossec.log', 'active-responses.log', 'api.log', 'cluster.log', 'integrations.log'],
            'path_calculator': lambda filename: os.path.join(get_logs_directory_path(installation_path, os_host),
                                                             filename)
        },
        'alert_directory': {
            'files': ['alerts.json', 'alerts.log'],
            'path_calculator': lambda filename: os.path.join(get_alert_directory_path(installation_path), filename)
        },
        'archives_directory': {
            'files': ['archives.json', 'archives.log'],
            'path_calculator': lambda filename: os.path.join(get_archives_directory_path(installation_path), filename)
        },
        'custom_decoder_directory': {
            'files': ['local_decoders.xml'],
            'path_calculator': lambda filename: os.path.join(get_custom_decoders_directory_path(installation_path),
                                                             filename)
        },
        'custom_rule_directory': {
            'files': ['local_rules.xml'],
            'path_calculator': lambda filename: os.path.join(get_custom_rules_directory_path(installation_path),
                                                             filename)
        },
        'group_configuration': {
            'files': ['agent.conf'],
            'path_calculator': lambda filename: os.path.join(get_group_configuration_directory(installation_path,
                                                                                               os_host,
                                                                                               group=group,
                                                                                               component=component),
                                                             filename)
        }
    }
    for files in wazuh_directory_files.values():
        if file_name in files['files']:
            return files['path_calculator'](file_name)


class WazuhEnvironmentHandler(HostManager):
    def __init__(self, inventory_path, debug=False, max_workers=10):
        super().__init__(inventory_path)
        self.pool = ThreadPool(max_workers)

        # Define logger
        logger_level = 'debug' if debug else 'info'
        logger_formatter = 'verbose' if debug else 'basic'
        self.logger = BaseLogger('WazuhEnvironment', level=logger_level, output_source=True)

    def get_file_fullpath(self, host, filename, group=None):
        """Get the path of common configuration and log file in the specified host.
        Args:
            host (str): Hostname
            filename (str): File name
            group (str): Group name. Default `None`
        Returns:
            str: Path of the file
        """
        wazuh_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)

        return get_wazuh_file_path(custom_installation_path=wazuh_installation_path,
                                   os_host=self.get_ansible_host_os(host),
                                   file_name=filename, group=group, component=self.get_ansible_host_component(host))

    def get_configuration_directory_path(self, host):
        """Get the path of configuration directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the configuration directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)

        return get_configuration_directory_path(custom_installation_path=custom_installation_path,
                                                os_host=host_os)

    def get_custom_decoders_directory_path(self, host):
        """Get the path of custom decoders directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the custom decoders directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_component = self.get_ansible_host_component(host)

        if host_component == 'manager':
            custom_decoders_directory_path = get_custom_decoders_directory_path(custom_installation_path)
        else:
            custom_decoders_directory_path = None

        return custom_decoders_directory_path

    def get_custom_rules_directory_path(self, host):
        """Get the path of custom rules directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the custom rules directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_component = self.get_ansible_host_component(host)

        if host_component == 'manager':
            custom_rules_directory_path = get_custom_rules_directory_path(custom_installation_path)
        else:
            custom_rules_directory_path = None

        return custom_rules_directory_path

    def get_api_directory(self, host):
        """Get the path of API directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the API directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_component = self.get_ansible_host_component(host)

        if host_component == 'manager':
            api_directory = get_api_directory(custom_installation_path)
        else:
            api_directory = None

        return api_directory

    def get_api_configuration_directory(self, host):
        """Get the path of API configuration directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the API configuration directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_component = self.get_ansible_host_component(host)

        if host_component == 'manager':
            api_configuration_directory = get_api_configuration_directory(custom_installation_path)
        else:
            api_configuration_directory = None

        return api_configuration_directory

    def get_alerts_directory_path(self, host):
        """Get the path of alert directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the alert directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_component = self.get_ansible_host_component(host)

        if host_component == 'manager':
            alert_directory_path = get_alert_directory_path(custom_installation_path)
        else:
            alert_directory_path = None

        return alert_directory_path

    def get_archives_directory_path(self, host):
        """Get the path of archives directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the archives directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_component = self.get_ansible_host_component(host)

        if host_component == 'manager':
            archives_directory_path = get_archives_directory_path(custom_installation_path)
        else:
            archives_directory_path = None

        return archives_directory_path

    def get_logs_directory_path(self, host):
        """Get the path of logs directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the logs directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)

        logs_directory_path = get_logs_directory_path(custom_installation_path, host_os)

        return logs_directory_path

    def get_shared_directory_path(self, host):
        """Get the path of shared directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the shared directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)

        shared_directory_path = get_shared_directory_path(custom_installation_path, host_os)

        return shared_directory_path

    def get_group_configuration_directory_path(self, host, group='default'):
        """Get the path of group configuration directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the group configuration directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)
        host_component = self.get_ansible_host_component(host)

        group_configuration_directory_path = get_group_configuration_directory(custom_installation_path, host_os,
                                                                               group=group, component=host_component)

        return group_configuration_directory_path

    def get_ruleset_directory_path(self, host):
        """Get the path of ruleset directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the ruleset directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)

        ruleset_directory_path = get_ruleset_directory(custom_installation_path, host_os)

        return ruleset_directory_path

    def configure_host(self, host, configuration_file, configuration_values):
        """Configure ossec.conf, agent.conf, api.conf and local_internal_options of specified host of the environment
        Configuration should fit the format expected for each configuration file:
        - ossec and agent.conf configuration should be provided as a list of configuration sections section.
        - local_internal_options configuration should be provided as a map
        - api.yaml should be provided as a map

        Example:
            local_internal_options:
                remoted.debug: 2
                wazuh_modulesd.debug: 2
            ossec.conf:
                - 'section': 'client',
                  'elements':
                  - 'server':
                        'elements':
                            - 'address':
                                'value': 121.1.3.1
            agent.conf:
                - 'group': 'default',
                - configuration:
                    - 'section': 'client',
                      'elements':
                        - 'server':
                            'elements':
                                - 'address':
                                    'value': 121.1.3.1
        Args:
            host (str): Hostname
            configuration_file (str): File name to be configured
            configuration_values (dict): Dictionary with the new configuration
        """
        self.logger.debug(f"Configuring {configuration_file} in {host}")

        if configuration_file not in conf_functions:
            raise Exception(f"Invalid operation for {configuration_file} configuration file. Please select one \
                              of the following: {conf_functions.keys()}")

        # Get group folder and new configuration for agent.conf
        group = configuration_values.get('group', 'default') if configuration_file == 'agent.conf' else None
        configuration_values = (configuration_values['configuration'] if configuration_file == 'agent.conf'
                                else configuration_values)

        # Get configuration file path
        host_configuration_file_path = self.get_file_fullpath(host, configuration_file, group)

        parameters = {'new_conf': configuration_values}

        # Get template for ossec.conf and agent.conf
        if configuration_file == 'ossec.conf' or configuration_file == 'agent.conf':
            current_configuration = self.get_file_content(host, host_configuration_file_path, become=True)
            parameters.update({'template': current_configuration})

        # Set new configuration
        new_configuration = conf_functions[configuration_file](**parameters)
        self.modify_file_content(host, host_configuration_file_path, new_configuration,
                                 not self.is_windows(host), self.is_windows(host))

        self.logger.debug(f"{configuration_file} in {host} configured successfully")

    def configure_environment(self, configuration_hosts, parallel=True):
        """Configure multiple hosts at the same time.
        Example:
        wazuh-agent1:
            local_internal_options:
                remoted.debug: 2
                wazuh_modulesd.debug: 2
            ossec.conf:
                - 'section': 'client',
                  'elements':
                  - 'server':
                        'elements':
                            - 'address':
                                'value': 121.1.3.1
            api.yml:
                ....
        wazuh-agent2:
            ossec.conf:
                ...
        Args:
            configuration_host (Map): Map with new hosts configuration
            parallel(Boolean): Enable parallel tasks
        """
        self.logger.info('Configuring environment')
        if parallel:
            host_configuration_map = []
            for host, configuration in configuration_hosts.items():
                for configuration_file, configuration_values in configuration.items():
                    host_configuration_map.append((host, configuration_file, configuration_values))
            self.pool.starmap(self.configure_host, host_configuration_map)
        else:
            for host, configurations in configuration_hosts.items():
                for configuration_file, configuration_values in configurations.items():
                    self.configure_host(host, configuration_file, configuration_values)
        self.logger.info('Environment configured successfully')

    def change_agents_configured_manager(self, agent_list, manager, use_manager_name=True):
        """Change configured manager of specified agent

        Args:
            agent_list (list): List of agents that configuration will be changed.
            manager (str): Manager name in the environment/Manager or IP.
            use_manager_name (Boolean): Replace manager name with manager IP. Default True
        """
        self.logger.debug('Changing configured manager')
        if type(agent_list) != list:
            raise TypeError('Expected a list of agents')

        new_configuration = {}
        new_manager = manager if use_manager_name else self.get_host_ansible_ip(manager)

        server_block = {'server': {'elements': [{'address': {'value': new_manager}}]}}
        configuration = [{'section': 'client', 'elements': [server_block]}]

        for agent in agent_list:
            new_configuration[agent] = {
                'ossec.conf': configuration
            }

        self.configure_environment(new_configuration)
        self.logger.debug('Changed configured manager successfully')

    def backup_host_configuration(self, host, file, group=None):
        """Backup specified files in host

        Args:
            configuration_list (dict): Host configuration files to backup
        Returns:
            dict: Host backup filepaths
        """
        self.logger.debug(f"Creating {file} backup on {host}")
        backup_paths = {host: {}}
        host_configuration_file_path = self.get_file_fullpath(host, file, group)
        temporal_folder = DEFAULT_TEMPORAL_DIRECTORY[self.get_ansible_host_os(host)]
        backup_file = os.path.join(temporal_folder, file + '.backup',)
        backup_paths[host][host_configuration_file_path] = backup_file

        self.copy_file(host, host_configuration_file_path, backup_file, remote_src=True,
                       become=not self.is_windows(host))

        self.logger.debug(f"Created {file} backup on {host} successfully")
        return backup_paths

    def backup_environment_configuration(self, configuration_hosts, parallel=True):
        """Backup specified files in all hosts

        Args:
            configuration_list (dict): Host configuration files to backup
        Returns:
            dict: Host backup filepaths
        """
        self.logger.info('Creating backup')
        backup_configuration = []
        if parallel:
            host_configuration_map = []
            for host, configuration in configuration_hosts.items():
                for file in configuration['files']:
                    group = configuration['group'] if file == 'agent.conf' else None
                    host_configuration_map.append((host, file, group))
            backup_configuration = self.pool.starmap(self.backup_host_configuration, host_configuration_map)

        else:
            for host, configuration in configuration_hosts.items():
                for file in configuration['files']:
                    group = configuration['group'] if file == 'agent.conf' else None
                    backup_map = (self.backup_host_configuration(host, file, group))
                    backup_configuration.append(backup_map)

        final_backup_configuration = {}
        for backup_conf_host in backup_configuration:
            for host, file in backup_conf_host.items():
                if host in final_backup_configuration:
                    final_backup_configuration[host].update(file)
                else:
                    final_backup_configuration[host] = file

        self.logger.info('Created backup successfully')
        return final_backup_configuration

    def restore_host_backup_configuration(self, host, dest_file, backup_file):
        """Restore backup configuration

        Args:
            backup_configuration (dict): Backup configuration filepaths
        """
        self.logger.debug(f"Restoring {dest_file} backup on {host}")
        self.copy_file(host=host, dest_path=dest_file,
                       src_path=backup_file, remote_src=True, become=not self.is_windows(host))
        self.logger.debug(f"Restored {dest_file} backup on {host} succesfully")

    def restore_environment_backup_configuration(self, backup_configurations, parallel=False):
        """Restore environment backup configuration

        Args:
            backup_configuration (dict): Backup configuration filepaths
        """
        self.logger.info('Restoring backup')
        if parallel:
            host_configuration_map = []
            for host, files in backup_configurations.items():
                for dest_file, backup_file in files.items():
                    host_configuration_map.append((host, dest_file, backup_file))
            self.pool.starmap(self.restore_host_backup_configuration, host_configuration_map)
        else:
            for host, files in backup_configurations.items():
                for dest_file, backup_file in files.items():
                    self.restore_host_backup_configuration(host, dest_file, backup_file)
        self.logger.info('Restored backup successfully')

    def log_search(self, host, pattern, timeout, file, escape=False, output_file='log_search_output.json'):
        """Search log in specified host file

        Args:
            host (str): Hostname
            pattern (str): Pattern to search
            timeout (int): Timeout
            file (str): Filepath
            escape (bool, optional): Escape special characters. Defaults to False.
            output_file (str, optional): Match results file. Defaults to 'find.json'.

        Returns:
            dict: Match results
        """
        pass

    def log_multisearch(self, multipattern_search, file, escape=False):
        """Multihost log pattern

        Args:
            multipattern_search (dict): Multihost and multipattern  dictionary
            file (str, optional): Filepath.
            escape (bool, optional): Escape special characters. Defaults to False.
        Returns:
            srt: Search results
        """
        pass

    def get_ansible_host_os(self, host):
        """Get host os

        Args:
            host (str): Hostname

        Returns:
            str: Host os
        """
        return self.get_host_variables(host)['os_name']

    def get_ansible_host_component(self, host):
        """Get host os

        Args:
            host (str): Hostname

        Returns:
            str: Host os
        """
        agent_list = self.get_agents()
        manager_list = self.get_managers()
        return 'agent' if host in agent_list else 'manager' if host in manager_list else None

    def get_agents_info(self):
        """Get registered agents information.

        Returns:
            dict: Agent information
        """
        pass

    def get_agents_id(self, agents_list=None):
        """Get agents id

        Returns:
            List: Agents id list
        """
        pass

    def restart_agent(self, host):
        """Restart agent

        Args:
            host (str): Hostname
        """
        self.logger.debug(f"Restarting agent {host}")
        service_name = WAZUH_ANGENT_WINDOWS_SERVICE_NAME if self.is_windows(host) else 'wazuh-agent'
        if self.is_agent(host):
            self.control_service(host, service_name, 'restarted')
            self.logger.debug(f"Agent {host} restarted successfully")
        else:
            raise ValueError(f"Host {host} is not an agent")

    def restart_agents(self, agent_list=None, parallel=True):
        """Restart list of agents

        Args:
            agent_list (list, optional): Agent list. Defaults to None.
            parallel (bool, optional): Parallel execution. Defaults to True.
        """
        self.logger.info(f"Restarting agents: {agent_list}")
        if parallel:
            self.pool.map(self.restart_agent, agent_list)
        else:
            for agent in agent_list:
                self.restart_agent(agent)
        self.logger.info(f"Agents restarted successfully: {agent_list}")

    def restart_manager(self, host):
        """Restart manager

        Args:
            host (str): Hostname
        """
        self.logger.debug(f"Restarting manager {host}")
        if self.is_manager(host):
            self.control_service(host, 'wazuh-manager', 'restarted', become=True)
            self.logger.debug(f"Manager {host} restarted successfully")
        else:
            ValueError(f"Host {host} is not a manager")

    def restart_managers(self, manager_list, parallel=True):
        """Restart managers

        Args:
            manager_list (list): Managers list
            parallel (bool, optional): Parallel execution. Defaults to True.
        """
        self.logger.info(f"Restarting managers: {manager_list}")
        if parallel:
            self.pool.map(self.restart_manager, manager_list)
        else:
            for manager in manager_list:
                self.restart_manager(manager)
        self.logger.info(f"Managers restarted successfully: {manager_list}")

    def stop_agent(self, host):
        """Stop agent

        Args:
            host (str): Hostname
        """
        self.logger.debug(f"Stopping agent {host}")
        service_name = WAZUH_ANGENT_WINDOWS_SERVICE_NAME if self.is_windows(host) else 'wazuh-agent'
        if self.is_agent(host):
            self.control_service(host, service_name, 'stopped')
            self.logger.debug(f"Agent {host} stopped successfully")
        else:
            raise ValueError(f"Host {host} is not an agent")

    def stop_agents(self, agent_list=None, parallel=True):
        """Stop agents

        Args:
            agent_list(list, optional): Agents list. Defaults to None
            parallel (bool, optional): Parallel execution. Defaults to True.
        """
        self.logger.info(f"Stopping agents: {agent_list}")
        if parallel:
            self.pool.map(self.stop_agent, agent_list)
        else:
            for agent in agent_list:
                self.restart_agent(agent)
        self.logger.info(f"Agents stopped successfully: {agent_list}")

    def stop_manager(self, host):
        """Stop manager

        Args:
            host (str): Hostname
        """
        self.logger.debug(f"Stopping manager {host}")
        if self.is_manager(host):
            self.control_service(host, 'wazuh-manager', 'stopped', become=True)
            self.logger.debug(f"Manager {host} stopped successfully")
        else:
            raise ValueError(f"Host {host} is not a manager")

    def stop_managers(self, manager_list, parallel=True):
        """Stop managers

        Args:
            manager_list (list): Managers list
            parallel (bool, optional): Parallel execution. Defaults to True.
        """
        self.logger.info(f"Stopping managers: {manager_list}")
        if parallel:
            self.pool.map(self.stop_manager, manager_list)
        else:
            for manager in manager_list:
                self.restart_manager(manager)
        self.logger.info(f"Stopping managers: {manager_list}")

    def start_agent(self, host):
        """Start agent

        Args:
            host (str): Hostname
        """
        self.logger.debug(f"Starting agent {host}")
        service_name = WAZUH_ANGENT_WINDOWS_SERVICE_NAME if self.is_windows(host) else 'wazuh-agent'
        if self.is_agent(host):
            self.control_service(host, service_name, 'started')
            self.logger.debug(f"Agent {host} started successfully")
        else:
            raise ValueError(f"Host {host} is not an agent")

    def start_agents(self, agent_list, parallel=True):
        """Start agents

        Args:
            agent_list (list): Agents list
            parallel (bool, optional): Parallel execution. Defaults to True.
        """
        self.logger.info(f"Starting agents: {agent_list}")
        if parallel:
            self.pool.map(self.start_agent, agent_list)
        else:
            for agent in agent_list:
                self.start_agent(agent)
        self.logger.info(f"Agents started successfully: {agent_list}")

    def start_manager(self, host):
        """Start manager

        Args:
            host (str): Hostname
        """
        self.logger.debug(f"Starting manager {host}")
        if self.is_manager(host):
            self.control_service(host, 'wazuh-manager', 'started', become=True)
            self.logger.debug(f"Manager {host} started successfully")
        else:
            raise ValueError(f"Host {host} is not a manager")

    def start_managers(self, manager_list, parallel=True):
        """Start managers

        Args:
            manager_list (list): Managers list
            parallel (bool, optional): Parallel execution. Defaults to True.
        """
        self.logger.info(f"Starting managers: {manager_list}")
        if parallel:
            self.pool.map(self.start_manager, manager_list)
        else:
            for manager in manager_list:
                self.start_manager(manager)
        self.logger.info(f"Managers started successfully: {manager_list}")

    def restart_environment(self, parallel=True):
        """Restart all agents and manager in the environment

        Args:
            parallel (bool, optional): Parallel execution. Defaults to True.
        """
        self.logger.info('Restarting environment')
        manager_list = self.get_managers()
        agent_list = self.get_agents()

        if parallel:
            self.logger.info(message='Restarting environment: Managers')
            self.pool.map(self.restart_manager, manager_list)

            self.logger.info(message='Restarting environment: Agents')
            self.pool.map(self.restart_agent, agent_list)
        else:
            self.logger.info(message='Restarting environment: Managers')
            for manager in manager_list:
                self.restart_manager(manager)

            self.logger.info(message='Restarting environment: Agents')
            for agent in agent_list:
                self.restart_agent(agent)

        self.logger.info('Environment restarted successfully')

    def stop_environment(self, parallel=True):
        """Stop all agents and manager in the environment

        Args:
            parallel (bool, optional): Parallel execution. Defaults to True.
        """
        self.logger.info('Stopping environment')
        manager_list = self.get_managers()
        agent_list = self.get_agents()

        if parallel:
            self.logger.info(message='Stopping environment: Managers')
            self.pool.map(self.stop_manager, manager_list)

            self.logger.info(message='Stopping environment: Agents')
            self.pool.map(self.stop_agent, agent_list)
        else:
            self.logger.info(message='Stopping environment: Managers')
            for manager in self.get_managers():
                self.stop_manager(manager)

            self.logger.info(message='Stopping environment: Agents')
            for agent in self.get_agents():
                self.stop_agent(agent)

        self.logger.info('Stopping environment')

    def start_environment(self, parallel=True):
        """Start all agents and manager in the environment

        Args:
            parallel (bool, optional): Parallel execution. Defaults to True.
        """
        self.logger.info('Starting environment')
        manager_list = self.get_managers()
        agent_list = self.get_agents()

        if parallel:
            self.logger.info(message='Starting environment: Managers')
            self.pool.map(self.start_manager, manager_list)

            self.logger.info(message='Starting environment: Agents')
            self.pool.map(self.start_agent, agent_list)
        else:
            self.logger.info(message='Starting environment: Managers')
            for manager in self.get_managers():
                self.start_manager(manager)

            self.logger.info(message='Starting environment: Agents')
            for agent in self.get_agents():
                self.start_agent(agent)

        self.logger.info('Environment started successfully')

    def get_master_node(self):
        """Get master manager hostname

        Returns:
            str: Manager master node
        """
        pass

    def get_api_details(self):
        """Get api details

        Returns:
            dict: Api details
        """
        pass

    def clean_client_keys(self, hosts=None):
        """Clean client keys

        Args:
            hosts (str, optional): Hostname. Defaults to None.
        """
        pass

    def clean_agents(self, agents=None):
        """Stop agents, remove them from manager and clean their client keys

        Args:
            agents (_type_, agents_list): Agents list. Defaults to None.
        """
        pass

    def remove_agents_from_manager(self, agents=None, status='all', older_than='0s'):
        """Remove agents from manager

        Args:
            agents (list, optional): Agents list. Defaults to None.
            status (str, optional): Agents status. Defaults to 'all'.
            older_than (str, optional): Older than parameter. Defaults to '0s'.

        Returns:
            dict: API response
        """
        pass

    def get_managers(self):
        """Get environment managers names

        Returns:
            List: Managers names list
        """
        return self.get_group_hosts('manager')

    def get_agents(self):
        """Get environment agents names

        Returns:
            List: Agent names list
        """
        return self.get_group_hosts('agent')

    def is_agent(self, host):
        """Check if host is agent

        Args:
            host (str): Hostname
        Returns:
            bool: True if host is agent
        """
        return host in self.get_agents()

    def is_manager(self, host):
        """Check if host is manager

        Args:
            host (str): Hostname
        Returns:
            bool: True if host is manager
        """
        return host in self.get_managers()
