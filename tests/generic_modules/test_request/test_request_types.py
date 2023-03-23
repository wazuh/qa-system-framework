"""
Module to test the different custom requests.

Test cases:
    - Case 1: Send a request and check the response.
        - Case 1.1: Send a GET request and check the response.
        - Case 1.2: Send a PUT request and check the response.
        - Case 1.3: Send a POST request and check the response.
        - Case 1.4: Send a DELETE request and check the response.

Note: Higher coverage rate needed (time requirements I could not add more)
"""

import pytest

from wazuh_qa_framework.generic_modules.request.request import GetRequest, PostRequest, PutRequest, DeleteRequest
from wazuh_qa_framework.meta_testing.utils import FREE_API_URL


parameters = [
    (GetRequest(url=f"{FREE_API_URL}/posts/1", verify=True), 200),
    (PutRequest(url=f"{FREE_API_URL}/posts/1", verify=True), 200),
    (PostRequest(url=f"{FREE_API_URL}/posts", verify=True), 201),
    (DeleteRequest(url=f"{FREE_API_URL}/posts/1", verify=True), 200),
]


@pytest.mark.parametrize('request_object, status_code', parameters, ids=['GET', 'PUT', 'POST', 'DELETE'])
def test_request(request_object, status_code):
    """Check that custom requests are sent.

    case: Send a request and check the response.

    test_phases:
        - test:
            - Send a custom request to a test API.
            - Check that request was sent and check the response status code.

    parameters:
        - request_object (Request): Parametrized variable.
        - status_code (int): Parametrized variable.
    """
    response = request_object.send()
    assert response.status_code == status_code
