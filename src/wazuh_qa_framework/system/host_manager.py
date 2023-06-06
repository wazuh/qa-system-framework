# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import tempfile
import testinfra
import base64
import os
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader
from ansible.vars.manager import VariableManager


class HostManager:
    """Remote host management interface.

    It allows to manage remote hosts using ansible inventory and testinfra framework.

    Args:
        inventory_path (str): Ansible inventory path

    Attributes:
        inventory_path (str): Ansible inventory path
        inventory_manager (ansible.inventory.manager.InventoryManager): Ansible inventory manager
        variable_manager (ansible.vars.manager.VariableManager): Ansible variable manager
    """

    def __init__(self, inventory_path):
        self.inventory_path = inventory_path

        data_loader = DataLoader()
        self.inventory_manager = InventoryManager(loader=data_loader, sources=inventory_path)
        self.hosts_variables = {}

        variable_manager = VariableManager(loader=data_loader, inventory=self.inventory_manager)

        for host in self.inventory_manager.get_hosts():
            self.hosts_variables[host] = variable_manager.get_vars(host=self.inventory_manager.get_host(str(host)))

    def get_host(self, host):
        """Get the testinfra host.

        Args:
            host (str): Hostname

        Returns:
            testinfra.modules.base.Ansible: Host instance from hostspec
        """
        return testinfra.get_host(f"ansible://{host}?ansible_inventory={self.inventory_path}")

    def get_groups(self):
        """Get the groups of the inventory.

        Returns:
            list: Groups of the inventory
        """
        return list(self.inventory_manager.groups.keys())

    def get_group_hosts(self, pattern=None):
        """Get all hosts from inventory that belong to a group.

        Args:
            group (str): Group name

        Returns:
            list: List of hosts
        """
        if pattern:
            return [str(host) for host in self.inventory_manager.get_hosts(pattern=pattern)]
        else:
            return [str(host) for host in self.inventory_manager.get_hosts()]

    def get_host_variables(self, host):
        """Get the variables of the specified host.

        Args:
            host (str): Hostname

        Returns:
            testinfra.modules.base.Ansible: Host instance from hostspec
        """
        inventory_manager_host = self.inventory_manager.get_host(host)

        return self.hosts_variables[inventory_manager_host]

    def collect_host_ansible_facts(self, host):
        """Get the ansible facts of the specified host.

        Args:
            host (str): Hostname

        Returns:
            str: OS of the host
        """
        testinfra_host = self.get_host(host)

        return testinfra_host.ansible("setup")

    def collect_host_os(self, host):
        """Get the OS of the specified host.

        Args:
            host: Hostname

        Returns:
            tuple: Hostname, Major version, Distribution version. Example: ('CentOS', '7', '7.6.1810')
        """
        ansible_facts = self.collect_host_ansible_facts(host)

        return (ansible_facts['ansible_facts']['ansible_distribution'],
                ansible_facts['ansible_facts']['ansible_distribution_major_version'],
                ansible_facts['ansible_facts']['ansible_distribution_version'])

    def collect_host_ips(self, host):
        """Get the host IPs

        Args:
            host (str): Hostname

        Returns:
            dict: IPs of the host (ipv4 and ipv6). Example: {'ipv4': ['172.31.5.209'], 'ipv6': ['fe80::f::fef4:bb6d']}
        """
        ansible_facts = self.collect_host_ansible_facts(host)

        return {'ipv4': ansible_facts['ansible_facts']['ansible_all_ipv4_addresses'],
                'ipv6': ansible_facts['ansible_facts']['ansible_all_ipv6_addresses']}

    def collect_host_interfaces(self, host):
        """Get the interfaces of the specified host.

        Args:
            host (str): Hostname

        Returns:
            list: Interfaces of the host. Example ['lo', 'eth0']
        """
        ansible_facts = self.collect_host_ansible_facts(host)

        return ansible_facts['ansible_facts']['ansible_interfaces']

    def check_connection(self, host):
        """Check if the host is reachable.

        Args:
            host (str): Hostname

        Returns:
            bool: True if the host is reachable, False otherwise
        """
        testinfra_host = self.get_host(host)
        ansible_command = 'win_ping' if self.get_host_variables(host)['os_name'] == 'windows' else 'ping'
        return testinfra_host.ansible(ansible_command, check=False)['ping'] == 'pong'

    def copy_file(self, host, src_path, dest_path, remote_src=False, become=None, ignore_errors=False):
        """Move from src_path to the desired location dest_path for the specified host.

        Args:
            host (str): Hostname
            src_path (str): Source path
            dest_path (str): Destination path
            remote_src (bool): If True, the file is assumed to live on the remote machine, not the controller.
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool): Ignore errors

        Returns:
            dict: Result of the command execution

        Raises:
            Exception: If the command execution fails
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        testinfra_host = self.get_host(host)
        ansible_command = 'win_copy' if self.get_host_variables(host)['os_name'] == 'windows' else 'copy'
        remote_source = 'yes' if remote_src else 'no'

        command_parameters = f"src={src_path} dest={dest_path} remote_src={remote_source}"
        result = testinfra_host.ansible(ansible_command, command_parameters, check=False, become=become)

        if result.get('msg', None) and not ignore_errors:
            raise Exception(f"Error moving file from {src_path} to {dest_path} on host {host}: {result}")

        return result

    def get_file_content(self, host, path, become=None, ignore_errors=False):
        """Read a file from the specified host.

        Args:
            host (str): Hostname
            path (str): File path
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool): Ignore errors

        Returns:
            str: File content

        Raises:
            Exception: If the file cannot be read
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        testinfra_host = self.get_host(host)
        result = testinfra_host.ansible("slurp", f"src={path}", check=False, become=become)

        if result.get('msg', None) and not ignore_errors:
            raise Exception(f"Error reading file {path} on host {host}: {result}")

        return base64.b64decode(result['content']).decode('utf-8')

    def synchronize_linux_directory(self, host, dest_path, src_path=None, filesystem=None, become=None,
                                    ignore_errors=False):
        """Create a file structure on the specified host.
        Not supported on Windows.

        Args:
            host (str): Hostname
            dest_path (str): Destination path
            filesystem (dict): File structure
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool, optional): Ignore errors. Defaults to False.

        Returns:
            dict: Result of the command execution

        Raises:
            Exception: If the command execution fails
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        testinfra_host = self.get_host(host)

        ansible_command = 'synchronize'

        if filesystem:
            tmp_directory = tempfile.TemporaryDirectory()
            directory_path = os.path.join(tmp_directory.name, filesystem['directory_name'])
            os.mkdir(directory_path)
            src_path = directory_path

            for file in filesystem['files']:
                file_path = f"{directory_path}/{file['filename']}"
                with open(file_path, 'w') as file_operator:
                    file_operator.write(file['content'])

        result = testinfra_host.ansible(ansible_command, f"src={src_path} dest={dest_path}", check=False, become=become)

        if (result['rc'] != 0 or not result) and not ignore_errors:
            raise Exception(f"Error creating file structure on host {host}: {result}")

        return result

    def truncate_file(self, host, file_path, recreate=True, become=None, ignore_errors=False):
        """Truncate a file from the specified host.

        Args:
            host (str): Hostname
            file_path (str): File path
            recreate (bool, optional): Recreate file. Defaults to True.
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool, optional): Ignore errors. Defaults to False.

        Returns:
            dict: Command result

        Raises:
            Exception: If the file cannot be truncated
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        testinfra_host = self.get_host(host)
        result = None

        if recreate:
            ansible_command = 'win_copy' if self.get_host_variables(host)['os_name'] == 'windows' else 'copy'
            result = testinfra_host.ansible(ansible_command, f"dest='{file_path}' content=''", check=False,
                                            become=become)
        else:
            ansible_command = 'win_file' if self.get_host_variables(host)['os_name'] == 'windows' else 'file'
            result = testinfra_host.ansible(ansible_command, f"path={file_path} state=touch", check=False,
                                            become=become)
        if result.get('msg', None) and not ignore_errors:
            raise Exception(f"Error truncating file {file_path} on host {host}: {result}")

        return result

    def remove_file(self, host, file_path, become=None, ignore_errors=False):
        """Remove a file from the specified host.

        Args:
            host (str): Hostname
            file_path (str): File path
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool, optional): Ignore errors. Defaults to False.

        Returns:
            dict: Command result

        Raises:
            Exception: If the file cannot be removed
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        testinfra_host = self.get_host(host)
        ansible_command = 'win_file' if self.get_host_variables(host)['os_name'] == 'windows' else 'file'
        result = testinfra_host.ansible(ansible_command, f"path={file_path} state=absent", check=False, become=become)

        if result.get('msg', None) and not ignore_errors:
            raise Exception(f"Error removing file {file_path} on host {host}: {result}")

        return result

    def modify_file_content(self, host, path, content, become=None, ignore_errors=False):
        """Create a file with a specified content and copies it to a path.

        Args:
            host (str): Hostname
            path (str): path for the file to create and modify
            content (str, bytes): content to write into the file
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool, optional): Ignore errors. Defaults to False.

        Returns:
            dict: Command result

        Raises:
            Exception: If the file cannot be modified
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        tmp_file = tempfile.NamedTemporaryFile()
        with open(tmp_file.name, 'w+') as tmp:
            tmp.write(content)

        result = self.copy_file(host, src_path=tmp_file.name, dest_path=path, become=become)

        if result.get('msg', None) and not ignore_errors:
            raise Exception(f"Error modifying file {path} on host {host}: {result}")

        return result

    def create_file(self, host, path, content, directory=False, owner=None, group=None, mode=None, become=None,
                    ignore_errors=False):
        """Create a file with a specified content and copies it to a path.

        Args:
            host (str): Hostname
            path (str): path for the file to create and modify
            content (str, bytes): content to write into the file
            owner (str): owner of the file
            group (str): group of the file
            mode (str): mode of the file
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool, optional): Ignore errors. Defaults to False.

        Returns:
            dict: Command result

        Raises:
            Exception: If the file cannot be created
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        testinfra_host = self.get_host(host)
        tmp_file = tempfile.NamedTemporaryFile()
        with open(tmp_file.name, 'w+') as tmp:
            tmp.write(content)

        ansible_command = 'win_copy' if self.get_host_variables(host)['os_name'] == 'windows' else 'copy'

        ansible_parameters = f"src={tmp_file.name} dest={path}"
        ansible_parameters += f" owner={owner}" if owner else ''
        ansible_parameters += f" group={group}" if group else ''
        ansible_parameters += f" mode={mode}" if mode else ''
        ansible_parameters += f' state=directory' if directory else ''

        result = testinfra_host.ansible(ansible_command, ansible_parameters, check=False, become=become)

        if result.get('msg', None) and not ignore_errors:
            raise Exception(f"Error creating file {path} on host {host}: {result}")
        return result

    def control_service(self, host, service, state, become=None, ignore_errors=False):
        """Control a service on a host.

            Args:
                host (str): Hostname
                service (str): Service name
                state (str): Service state
                become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
                provide a value, it will default to False. Defaults None
                ignore_errors (bool, optional): Ignore errors. Defaults to False.

            Returns:
                dict: Command result

            Raises:
                Exception: If the service cannot be controlled
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        testinfra_host = self.get_host(host)
        ansible_command = 'win_service' if self.get_host_variables(host)['os_name'] == 'windows' else 'service'

        result = testinfra_host.ansible(ansible_command, f"name={service} state={state}", check=False, become=become)

        if result.get('msg', None) and not ignore_errors:
            raise Exception(f"Error controlling service {service} on host {host}: {result}")

        return result

    def run_command(self, host, cmd, become=None, ignore_errors=False):
        """Run a command on a host.

        Args:
            host (str): Hostname
            cmd (str): Command to run
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool, optional): Ignore errors. Defaults to False.

        Returns:
            dict: Command result

        Raises:
            Exception: If the command cannot be run
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        testinfra_host = self.get_host(host)
        ansible_command = 'win_command' if self.get_host_variables(host)['os_name'] == 'windows' else 'command'

        result = testinfra_host.ansible(ansible_command, f"{cmd}", check=False, become=become)
        rc, stdout = result.get('rc', 1), result.get('stdout', '')

        if rc != 0 and not ignore_errors:
            raise Exception(f"Error running command '{cmd}' on host {host}: {result}")

        return rc, stdout

    def run_shell(self, host, cmd, become=None, ignore_errors=False):
        """Run a shell command on a host.
        The difference with run_command is that here, shell symbols like &, |, etc. are interpreted.

        Args:
            host (str): Hostname
            cmd (str): Command to run
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool, optional): Ignore errors. Defaults to False.

        Returns:
            dict: Command result

        Raises:
            Exception: If the command cannot be run
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        testinfra_host = self.get_host(host)
        rc = None
        stdout = None

        ansible_command = 'win_shell' if self.get_host_variables(host)['os_name'] == 'windows' else 'shell'

        result = testinfra_host.ansible(ansible_command, f"{cmd}", check=False, become=become)

        rc, stdout = result['rc'], result['stdout']

        if rc != 0 and not ignore_errors:
            raise Exception(f"Error running command {cmd} on host {host}: {result}")

        return rc, stdout

    def find_files(self, host, path, pattern, recurse=False, use_regex=False, become=None, ignore_errors=False):
        """Search and return information of a file inside a path.

        Args:
            host (str): Hostname
            path (str): Path in which to search for the file that matches the pattern.
            pattern (str): Restrict the files to be returned to those whose basenames match the pattern specified.
            recurse (bool): If target is a directory, recursively descend into the directory looking for files.
            use_regex (bool): If no, the patterns are file globs (shell), if yes, they are python regexes.
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool, optional): Ignore errors. Defaults to False.

        Returns:
            Files (list): List of found files.

        Raises:
            Exception: If the command cannot be run
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        test_infra_host = self.get_host(host)
        ansible_command = 'win_find' if self.get_host_variables(host)['os_name'] == 'windows' else 'find'
        ansible_pattern_arguments = 'patterns' if self.get_host_variables(host)['os_name'] == 'windows' else 'pattern'

        result = test_infra_host.ansible(ansible_command, f"paths={path} {ansible_pattern_arguments}='{pattern}' \
                                         recurse={recurse} use_regex={use_regex}",
                                         become=become, check=False)

        if 'files' not in result and not ignore_errors:
            raise Exception(f"Error finding file {path} on host {host}: {result}")

        return result['files']

    def get_file_stats(self, host, path, become=None, ignore_errors=False):
        """Retrieve file or file system status.

        Args:
            host (str): Hostname.
            path (str): The full path of the file/object to get the facts of.
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool, optional): Ignore errors. Defaults to False.

        Returns:
            dict: Command result.

        Raises:
            Exception: If the command cannot be run.
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        testinfra_host = self.get_host(host)

        if self.get_host_variables(host)['os_name'] == 'windows':
            ansible_command = 'ansible.windows.win_stat'
        else:
            ansible_command = 'stat'

        result = testinfra_host.ansible(ansible_command, f"path={path}", check=False, become=become)

        if 'stat' not in result and not ignore_errors:
            raise Exception(f"Error getting stats of {path} on host {host}: {result}")

        return result

    def get_host_ansible_ip(self, host):
        """Get host used ip by ansible.

        Args:
            host (str): Hostname

        Returns:
            str: Host used IP
        """
        ansible_ip = self.get_host_variables(host).get('ansible_host', None)

        return ansible_ip

    def is_windows(self, host):
        """Check if host is windows

        Args:
            host (str): Hostname

        Returns:
            boolean: Host is a windows host
        """
        return self.get_host_variables(host)['os_name'] == 'windows'

    def is_linux(self, host):
        """Check if host is Linux

        Args:
            host (str): Hostname

        Returns:
            boolean: Host is a linux host
        """
        return self.get_host_variables(host)['os_name'] == 'linux'

    def is_macos(self, host):
        """Check if host is macos

        Args:
            host (str): Hostname

        Returns:
            boolean: Host is a macos host
        """
        return self.get_host_variables(host)['os_name'] == 'darwin'

    def is_solaris(self, host):
        """Check if host is solaris

        Args:
            host (str): Hostname

        Returns:
            boolean: Host is a solaris host
        """
        return self.get_host_variables(host)['os_name'] == 'solaris'

    def install_package(self, host, package_name, become=None, ignore_errors=False):
        """Install a package on a host.

        Args:
            host (str): Hostname
            package_name (str): Package to install
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool, optional): Ignore errors. Defaults to False.

        Returns:
            dict: Command result

        Raises:
            Exception: If the install cannot be run
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        testinfra_host = self.get_host(host)
        ansible_arguments = f"name={package_name} state=present"
        ansible_command = 'win_chocolatey' if self.get_host_variables(host)['os_name'] == 'windows' else 'package'

        result = testinfra_host.ansible(ansible_command, ansible_arguments,
                                        check=False, become=become)

        if result.get('msg', None) and not ignore_errors:
            raise Exception(f"Error installing package {package_name} on host {host}: {result}")

        return result

    def uninstall_package(self, host, package_name, become=None, ignore_errors=False):
        """Uninstall a package on a host.

        Args:
            host (str): Hostname
            package_name (str): Package to uninstall
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool, optional): Ignore errors. Defaults to False.

        Returns:
            dict: Command result

        Raises:
            Exception: If the uninstall cannot be run
        """
        become = self.get_host_variables(host).get('become', False) if become is None else become

        testinfra_host = self.get_host(host)
        ansible_arguments = f"name={package_name} state=absent"
        ansible_command = 'win_chocolatey' if self.get_host_variables(host)['os_name'] == 'windows' else 'package'

        result = testinfra_host.ansible(ansible_command, ansible_arguments,
                                        check=False, become=become)

        if result.get('msg', None) and not ignore_errors:
            raise Exception(f"Error installing package {package_name} on host {host}: {result}")

        return result

    def append_block_in_file(self, host, path, block, become=None, ignore_errors=False):
        """Append a text block in file

        Args:
            host (str): Hostname
            path (str): path for the file to insert a block
            block (str, bytes): text to append to the file
            become (bool): If no value is provided, it will be taken from the inventory. If the inventory does not
            provide a value, it will default to False. Defaults None
            ignore_errors (bool, optional): Ignore errors. Defaults to False.

        Returns:
            dict: Command result

        Raises:
            Exception: If the file cannot be modified
        """
        if self.get_host_variables(host)['os_name'] == 'windows':
            file_content = self.get_file_content(host, path)
            content = file_content + '\n' + block
            result = self.modify_file_content(host, path, content)

        else:
            become = self.get_host_variables(host).get('become', False) if become is None else become

            testinfra_host = self.get_host(host)
            ansible_arguments = f"path={path} block={block}"
            ansible_command = 'blockinfile'

            result = testinfra_host.ansible(ansible_command, ansible_arguments, check=False, become=become)

            if not result.get('msg', 'Block inserted') and not ignore_errors:
                raise Exception(f"Error inserting a block in file {path} on host {host}: {result}")

        return result
