"""
Module to wrapp the Wazuh API responses. This modules contains the following:

- WazuhAPIResponse
"""
from http import HTTPStatus
from json import JSONDecodeError


class WazuhAPIResponse:
    """Wrapper class to handle Wazuh API responses.

    Args:
        request_response (requests.Response): Response object.

    Attributes:
        request_response (requests.Response): Response object.
        status_code (int): Response status code.
        error (int): Wazuh API response error.
        data (dict|str): Wazuh API response data in dict format if possible else string.
    """
    def __init__(self, request_response):
        self.request_response = request_response
        self.status_code = request_response.status_code
        self.error = 0
        self.data = self.__get_data()

    def __get_data(self):
        """Set and get the custom class object data

        Returns:
            (dict|str):  Wazuh API response data in dict format if possible else string.
        """
        if self.status_code == HTTPStatus.METHOD_NOT_ALLOWED or self.status_code == HTTPStatus.UNAUTHORIZED:
            self.error = 1
            return self.request_response.json()['title']

        if self.status_code == HTTPStatus.OK:
            try:
                data_container = self.request_response.json()

                if 'data' in data_container:
                    self.error = data_container['error'] if 'error' in data_container else 0
                    return data_container['data']
                else:
                    self.error = 0
                    return data_container

            except JSONDecodeError:
                return self.request_response.text

    def __str__(self):
        """Overwrite the print object representation."""
        return '{' + f"'status_code': {self.status_code}, 'data': '{self.data}', error: {self.error}" + '}'
