"""
Module to wrapp the main Wazuh API calls. This module contains the following:

Classes
-------

- WazuhAPI:
    - get_token()
    - set_token_expiration(num_seconds)
    - get_api_info()
    - list_agents()
    - restart_agent(agent_id)
"""
from base64 import b64encode
from http import HTTPStatus
import requests

from wazuh_qa_framework.wazuh_components.api.wazuh_api_request import WazuhAPIRequest
from wazuh_qa_framework.generic_modules.request.request import GetRequest
from wazuh_qa_framework.generic_modules.exceptions import exceptions


DEFAULT_USER = 'wazuh'
DEFAULT_PASSOWRD = 'wazuh'
DEFAULT_PORT = 55000
DEFAULT_ADDRESS = 'localhost'
DEFAULT_PROTOCOL = 'https'
DEFAULT_TOKEN_EXPIRATION = 900


class WazuhAPI():
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

            raise exceptions.RuntimeError(f"Error obtaining login token: {response.json()}")

        except requests.exceptions.ConnectionError as exception:
            raise exceptions.ConnectionError(f"Cannot establish connection with {self.url}") from exception

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

    def restart_agent(self, agent_id):
        """Restart a wazuh-agent.

        Returns:
            dict: Wazuh API info.
        """
        response = WazuhAPIRequest(method='PUT', endpoint=f"/agents/{agent_id}/restart").send(self)

        return response
