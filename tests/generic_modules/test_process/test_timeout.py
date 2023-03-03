"""
Module to test the timeout parameter of Process class.

Test cases:
    - Case 1: Run a extended command and check if the process raise a timeout exception.
        - Case 1.1: Run a extended command setting a timeout lower than command time execution.
        - Case 1.2: Run a extended command setting a timeout greater than command time execution.
"""

import pytest
import subprocess

from wazuh_qa_framework.generic_modules.process.process import Process


@pytest.mark.parametrize('timeout, sleep_time, expected_exception', [(1, 1.1, True), (1, 0.1, False)])
def test_timeout(timeout, sleep_time, expected_exception):
    """Check that timeout parameter of Process works as expected.

    case: Run a extended command and check if the process raises a timeout exception.

    test_phases:
        - test:
            - Create a process object with the specific command.
            - Check if a timeout exception has been generated according to the timeout value set.

    parameters:
        - wait (str): Parametrized variable.
    """
    process = Process(command=f"sleep {sleep_time}; echo hello", wait=True, capture_stdout=True, capture_stderr=True,
                      timeout=timeout)

    if expected_exception:
        with pytest.raises(subprocess.TimeoutExpired):
            process.run()
    else:
        process.run()
