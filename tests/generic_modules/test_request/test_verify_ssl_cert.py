"""
Module to check the verify request parameter.

Test cases:
    - Case 1: Check the behavior when activating/deactivating the verify parameter.
        - Case 1.1: Activate verify and check that no warning is generated.
        - Case 1.2: Deactivate verify and check that a warning is generated.
"""

import warnings
import pytest

from wazuh_qa_framework.generic_modules.request.request import Request
from wazuh_qa_framework.meta_testing.utils import FREE_API_URL


@pytest.mark.parametrize('verify', [True, False])
def test_verify_ssl_cert(verify):
    """Check the verify parameter.

    case: Check the behavior when activating/deactivating the verify parameter.

    test_phases:
        - test:
            - Send a custom request updating the verify parameter value.
            - Check if a insecure warning is raised when sending the request.
            - Check that the request was sent and the response status is OK.

    parameters:
        - verify (boolean): Parametrized variable.
    """
    request_object = Request(url=f"{FREE_API_URL}/posts/1", method='GET', verify=verify)

    if not verify:
        with warnings.catch_warnings(record=True) as catched_warnings:
            response = request_object.send()
            assert len(catched_warnings) == 1 and 'Unverified HTTPS request' in str(catched_warnings[0].message), \
                'Unverified HTTPS request warning was not raised'
    else:
        response = request_object.send()

    assert response.status_code == 200
