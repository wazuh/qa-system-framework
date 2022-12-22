"""
Module to wrapp the Wazuh API requests. Normally, the developers should not use this class but WazuhAPI one. This class
is used by WazuhAPI to make and send the API requests. This module contains the following:

Classes
-------

- WazuhAPIRequest():
    - send(wazuh_api_object)
"""
import json
import requests

from wazuh_qa_framework.generic_modules.request.request import Request
from wazuh_qa_framework.generic_modules.exceptions import exceptions
from wazuh_qa_framework.wazuh_components.api.wazuh_api_response import WazuhAPIResponse


class WazuhAPIRequest:
    """Wrapper class to manage requests to the Wazuh API.

    Args:
        endpoint (str): Target API endpoint.
        method (str): Request method (GET, POST, PUT, DELETE).
        payload (dict): Request data.
        headers (dict): Request headers.
        verify (boolean): False for ignore making insecure requests, False otherwise.

    Attributes:
        endpoint (str): Target API endpoint.
        method (str): Request method (GET, POST, PUT, DELETE).
        payload (dict): Request data.
        headers (dict): Request headers.
        verify (boolean): False for ignore making insecure requests, False otherwise.
    """
    def __init__(self, endpoint, method, payload=None, headers=None, verify=False):
        self.endpoint = endpoint
        self.method = method.upper()
        self.payload = payload
        self.headers = headers
        self.verify = verify

    def __get_request_parameters(self, wazuh_api_object):
        """Build the request parameters.

        Args:
            wazuh_api_object (WazuhAPI): Wazuh API object.
        """
        # Get the token if we have not got it before.
        if wazuh_api_object.token is None:
            wazuh_api_object.token = wazuh_api_object.get_token()

        self.headers = {} if self.headers is None else self.headers
        self.headers.update({
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {wazuh_api_object.token}'
        })

        request_args = {
            'method': self.method,
            'url': f"{wazuh_api_object.url}{self.endpoint}",
            'headers': self.headers,
            'verify': self.verify
        }

        if self.payload is not None:
            request_args['payload'] = self.payload

        return request_args

    def __call__(self, func):
        """Perform directly the Wazuh API call and add the response object to the function parameters. Useful to run
        the request using only a python decorator.

        Args:
            func (function): Function object.
        """
        def wrapper(obj, *args, **kwargs):
            kwargs['response'] = self.send(obj)

            return func(obj, *args, **kwargs)

        return wrapper

    def __str__(self):
        """Overwrite the print object representation"""
        return json.dumps(self.__dict__)

    def send(self, wazuh_api_object):
        """Send the API request.

        Args:
            wazuh_api_object (WazuhAPI): Wazuh API object.

        Returns:
            WazuhAPIResponse: Wazuh API response object.

        Raises:
            exceptions.RuntimeError: Cannot establish connection with the API.
        """
        request_parameters = self.__get_request_parameters(wazuh_api_object)

        try:
            return WazuhAPIResponse(Request(**request_parameters).send())
        except requests.exceptions.ConnectionError as exception:
            raise exceptions.RuntimeError(f"Cannot establish connection with {wazuh_api_object.url}") from exception
