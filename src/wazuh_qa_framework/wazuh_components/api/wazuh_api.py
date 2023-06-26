"""
Module to wrapp the main Wazuh API calls. This module contains the following:

- WazuhAPI:
    - get_token
    - set_token_expiration
    - get_api_info
    - list_agents
    - restart_agent
"""
from base64 import b64encode
from http import HTTPStatus
import requests

from wazuh_qa_framework.wazuh_components.api.wazuh_api_request import WazuhAPIRequest
from wazuh_qa_framework.generic_modules.request.request import GetRequest
from wazuh_qa_framework.generic_modules.exceptions.exceptions import ConnectionError, RuntimeError


DEFAULT_USER = 'wazuh'
DEFAULT_PASSOWRD = 'wazuh'
DEFAULT_PORT = 55000
DEFAULT_ADDRESS = 'localhost'
DEFAULT_PROTOCOL = 'https'
DEFAULT_TOKEN_EXPIRATION = 900


class WazuhAPI:
    """Class to manage the Wazuh API via requests.

    Args:
        user (str): Wazuh API user.
        password (str): Wazuh API password.
        port (int): Wazuh API port connection.
        address (str): Wazuh API address.
        protocol (str): Wazuh API protocol.
        auto_auth (boolean): True for getting the API auth token automatically, False otherwise.
        token_expiration (int): Number of seconds to set to the token expiration.

    Attributes:
        user (str): Wazuh API user.
        password (str): Wazuh API password.
        port (int): Wazuh API port connection.
        address (str): Wazuh API address.
        protocol (str): Wazuh API protocol.
        token (str): Wazuh API auth token.
        token_expiration (int): Number of seconds to set to the token expiration.
    """
    def __init__(self, user=DEFAULT_USER, password=DEFAULT_PASSOWRD, port=DEFAULT_PORT, address=DEFAULT_ADDRESS,
                 protocol=DEFAULT_PROTOCOL, auto_auth=True, token_expiration=DEFAULT_TOKEN_EXPIRATION):
        self.user = user
        self.password = password
        self.port = port
        self.address = address
        self.protocol = protocol
        self.url = f"{protocol}://{address}:{port}"
        self.token_expiration = token_expiration
        self.token = self.get_token() if auto_auth else None

        if token_expiration != DEFAULT_TOKEN_EXPIRATION:
            self.set_token_expiration(token_expiration)
            self.token = self.get_token()

    def get_token(self):
        """Get the auth API token.

        Returns:
            str: API auth token.

        Raises:
            exceptions.RuntimeError: If there are any error when obtaining the login token.
            exceptions.RuntimeError: Cannot establish connection with API.
        """
        basic_auth = f"{self.user}:{self.password}".encode()
        auth_header = {'Content-Type': 'application/json', 'Authorization': f'Basic {b64encode(basic_auth).decode()}'}

        try:
            response = GetRequest(f"{self.url}/security/user/authenticate?raw=true", headers=auth_header).send()

            if response.status_code == HTTPStatus.OK:
                return response.text

            raise RuntimeError(f"Error obtaining login token: {response.json()}")

        except requests.exceptions.ConnectionError as exception:
            raise ConnectionError(f"Cannot establish connection with {self.url}") from exception

    def set_token_expiration(self, num_seconds):
        """Set the Wazuh API token expiration.

        Returns:
            WazuhAPIResponse: Operation result (response).
        """
        response = WazuhAPIRequest(method='PUT', endpoint='/security/config',
                                   payload={'auth_token_exp_timeout': num_seconds}).send(self)
        return response

    @WazuhAPIRequest(method='GET', endpoint='/')
    def get_api_info(self, response):
        """Get the Wazuh API info.

        Returns:
            dict: Wazuh API info.
        """
        return response.data

    @WazuhAPIRequest(method='GET', endpoint='/agents')
    def list_agents(self, response):
        """List the wazuh agents.

        Returns:
            dict: Wazuh API info.
        """
        return response.data

    @WazuhAPIRequest(method='GET', endpoint='/agents?status=active')
    def get_active_agents(self, response):
        """Get active agents.

        Returns:
            dict: Wazuh API info.
        """

        return response.data

    def get_agents_in_manager(self, manager):
        """Get agents reporting to a specific manager.

        Args:
            manager (str): Manager name.

        Returns:
            dict: Wazuh API info.
        """
        response = WazuhAPIRequest(method='GET', endpoint=f"/agents/?select=id,name&q=manager={manager}").send(self)

        return response

    def restart_agent(self, agent_id):
        """Restart a wazuh-agent.

        Args:
            agent_id (str): Agent ID.

        Returns:
            dict: Wazuh API info.
        """
        response = WazuhAPIRequest(method='PUT', endpoint=f"/agents/{agent_id}/restart").send(self)

        return response

    def delete_agents(self, agents_list, status='all', older_than='0s'):
        """Delete agents.

        Args:
            agents_list (str): List of agent IDs or keyword all.
            status (str): Agent status.
            older_than (str): Time since last keep alive or register date.

        Returns:
            dict: Wazuh API info.
        """
        response = WazuhAPIRequest(method='DELETE', endpoint=f"/agents?agents_list={agents_list}&status={status}"
                                   f"&older_than={older_than}").send(self)

        return response

    def create_group(self, group_id):
        """Create group.

        Args:
            group_id (str): Group name.

        Returns:
            dict: Wazuh API info.
        """
        response = WazuhAPIRequest(method='POST', endpoint='/groups', payload={'group_id': group_id}).send(self)

        return response

    def delete_groups(self, groups_list):
        """Delete group.

        Args:
            groups_list (str): List of group IDs or keyword all.

        Returns:
            dict: Wazuh API info.
        """
        response = WazuhAPIRequest(method='DELETE', endpoint=f"/groups?groups_list={groups_list}").send(self)

        return response

    def assign_agent_to_group(self, agent_id, group_id):
        """Assign an agent to a specified group.

        Args:
            agent_id (str): Agent ID.
            group_id (str): Group name.

        Returns:
            dict: Wazuh API info.
        """
        response = WazuhAPIRequest(method='PUT', endpoint=f"/agents/{agent_id}/group/{group_id}").send(self)

        return response

    def remove_agent_from_group(self, agent_id, group_id):
        """Remove an agent from a specified group.

        Args:
            agent_id (str): Agent ID.
            group_id (str): Group name.

        Returns:
            dict: Wazuh API info.
        """
        response = WazuhAPIRequest(method='DELETE', endpoint=f"/agents/{agent_id}/group/{group_id}").send(self)

        return response

    @WazuhAPIRequest(method='GET', endpoint='/cluster/ruleset/synchronization')
    def get_ruleset_sync_status(self, response):
        """Return ruleset synchronization status for all nodes.

        Returns:
            dict: Wazuh API info.
        """

        return response.data

    def add_api_user(self, username, password):
        """Add a new API user to the system.

        Args:
            username (str): Username.
            password (str): Password.

        Returns:
            dict: Wazuh API info.
        """
        response = WazuhAPIRequest(method='POST', endpoint='/security/users',
                                   payload={'username': username, 'password': password}).send(self)

        return response

    def remove_api_user(self, user_ids):
        """Delete a list of users by specifying their IDs.

        Args:
            user_ids (str): List of user IDs or keyword all.

        Returns:
            dict: Wazuh API info.
        """
        response = WazuhAPIRequest(method='DELETE', endpoint=f"/security/users?user_ids={user_ids}").send(self)

        return response

    @WazuhAPIRequest(method='GET', endpoint='/security/users')
    def get_api_users(self, response):
        """Get the information of API users.

        Returns:
            dict: Wazuh API info.
        """
        return response.data

    @WazuhAPIRequest(method='GET', endpoint='/security/users')
    def get_api_user_id(self, response, username):
        """Get the ID of a specified user.

        Returns:
            dict: Wazuh API info.
        """
        for user in response.data['affected_items']:
            if user['username'] == username:
                return user['id']

    def modify_user_allow_run_as(self, user_id, allow_run_as):
        """Modify a user's allow_run_as flag.

        Args:
            user_id (str): User ID.
            allow_run_as (bool): Value for the allow_run_as flag.

        Returns:
            dict: Wazuh API info.
        """
        response = WazuhAPIRequest(method='PUT',
                                   endpoint=f'/security/users/{user_id}/run_as?allow_run_as={allow_run_as}').send(self)

        return response

    @WazuhAPIRequest(method='GET', endpoint='/security/roles')
    def get_roles(self, response):
        """Get roles information.

        Returns:
            dict: Wazuh API info.
        """
        return response.data

    @WazuhAPIRequest(method='GET', endpoint='/security/roles')
    def get_role_id(self, response, role):
        """Get the ID of a specified role.

        Returns:
            dict: Wazuh API info.
        """
        for role in response.data['affected_items']:
            if role['name'] == role:
                return role['id']

    def add_api_user_role(self, user_id, role_ids):
        """Add roles to user.

        Args:
            user_id (str): User ID.
            role_ids (str): List of role IDs.

        Returns:
            dict: Wazuh API info.
        """
        response = WazuhAPIRequest(method='POST',
                                   endpoint=f"/security/users/{user_id}/roles?role_ids={role_ids}").send(self)

        return response

    @WazuhAPIRequest(method='GET', endpoint='/security/policies')
    def get_policies(self, response):
        """Get policies information.

        Returns:
            dict: Wazuh API info.
        """
        return response.data

    @WazuhAPIRequest(method='GET', endpoint='/security/policies')
    def get_policy_id(self, response, policy_name):
        """Get the ID of a specified policy.

        Returns:
            dict: Wazuh API info.
        """
        for policy in response.data['affected_items']:
            if policy['name'] == policy_name:
                return policy['id']

    def create_policy(self, name, policy):
        """Add a new policy.

        Args:
            name (str): Policy name.
            policy (dict): Policy definition.

        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='POST', endpoint='/security/policies',
                                   payload={'name': name, 'policy': policy}).send(self)

        return response

    def create_role(self, name):
        """Add a new role.

        Args:
            name (str): Role name.

        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='POST', endpoint='/security/roles', payload={'name': name}).send(self)

        return response

    def create_security_rule(self, name, rule):
        """Add a new security rule.

        Args:
            name (str): Rule name.
            rule (dict): Rule definition.

        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='POST', endpoint='/security/rules',
                                   payload={'name': name, 'rule': rule}).send(self)

        return response

    def add_policy_to_role(self, role_id, policy_ids):
        """Create a specified relation role-policy.

        Args:
            role_id (str): Role ID.
            policy_ids (str): List of policy IDs.

        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='POST',
                                   endpoint=f"/security/roles/{role_id}/policies?policy_ids={policy_ids}").send(self)

        return response

    def add_security_rule_to_role(self, role_id, rule_ids):
        """Create a specified relation role-rule.

        Args:
            role_id (str): Role ID.
            rule_ids (str): List of rule IDs.

        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='POST',
                                   endpoint=f"/security/roles/{role_id}/rules?rule_ids={rule_ids}").send(self)

        return response

    def remove_policy(self, policy_ids):
        """Delete a list of policies.

        Args:
            policy_ids (str): List of policy IDs or keyword all.

        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='DELETE',
                                   endpoint=f"/security/policies?policy_ids={policy_ids}").send(self)

        return response

    def remove_rule(self, rule_ids):
        """Delete a list of security rules.

        Args:
            rule_ids (str): List of rule IDs or keyword all.

        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='DELETE',
                                   endpoint=f"/security/rules?rule_ids={rule_ids}").send(self)

        return response

    def remove_role(self, role_ids):
        """Delete a list of roles.

        Args:
            role_ids (str): List of role IDs or keyword all.

        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='DELETE',
                                   endpoint=f"/security/roles?role_ids={role_ids}").send(self)

        return response

    @WazuhAPIRequest(method='DELETE', endpoint='/security/config')
    def restore_default_security_config(self, response):
        """Replaces the security configuration with the original one.

        Returns:
            dict: Wazuh API info.
        """

        return response.data

    @WazuhAPIRequest(method='GET', endpoint='/security/config')
    def get_security_config(self, response):
        """Get the security configuration.

        Returns:
            dict: Wazuh API info.
        """

        return response.data

    def modify_security_config(self, rbac_mode, auth_token_exp_timeout=900):
        """Modify the security configuration.

        Args:
            rbac_mode (str): RBAC mode (white/black).
            auth_token_exp_timeout (int): Time in seconds until the token expires.
        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='PUT', endpoint='/security/config',
                                   payload={'auth_token_exp_timeout': auth_token_exp_timeout,
                                            'rbac_mode': rbac_mode}).send(self)

        return response

    def add_role_to_user(self, user_id, role_ids):
        """Set role to user.

        Args:
            user_id (str): User ID.
            role_ids (str): List of role IDs.
        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='POST',
                                   endpoint=f"/security/users/{user_id}/roles?role_ids={role_ids}").send(self)

        return response

    def modify_policy(self, policy_id, name, policy):
        """Modify a policy.

        Args:
            policy_id (str): Policy ID.
            name (str): Policy name.
            policy (dict): New policy definition.
        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='PUT', endpoint=f"/security/policies/{policy_id}",
                                   payload={'name': name, 'policy': policy}).send(self)

        return response

    def modify_role(self, role_id, name):
        """Modify a role.

        Args:
            role_id (str): Role ID.
            name (str): Role name.
        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='PUT', endpoint=f"/security/policies/{role_id}",
                                   payload={'name': name}).send(self)

        return response

    def modify_security_rule(self, rule_id, name, rule):
        """Modify a security_rule.

        Args:
            rule_id (str): Rule ID.
            name (str): Rule name.
            rule (dict): New rule definition.
        Returns:
            dict: Wazuh API info.
        """

        response = WazuhAPIRequest(method='PUT', endpoint=f"/security/rules/{rule_id}",
                                   payload={'name': name, 'rule': rule}).send(self)

        return response
