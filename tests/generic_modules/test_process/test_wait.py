"""
Module to test the wait parameter of Process class.

Test cases:
    - Case 1: Run a extended command and check if the main process waits until it is finished.
        - Case 1.1: Run a extended command setting wait parameter to True.
        - Case 1.2: Run a extended command setting wait parameter to False.
"""

import pytest
import time

from wazuh_qa_framework.generic_modules.process.process import Process


@pytest.mark.parametrize('wait', [True, False])
def test_wait(wait):
    """Check that wait parameter of Process works as expected.

    case: Run a extended command and check if the main process waits until it is finished.

    test_phases:
        - test:
            - Create a process object with the specific command.
            - Measure the time from the start of the process to the continuation of the next flow line.
            - Check that the time taken is the expected one according to the wait value.

    parameters:
        - wait (str): Parametrized variable.
    """
    process = Process(command='sleep 1.1; echo hello', wait=wait, capture_stdout=False, capture_stderr=False)

    # Run the process, measuring the time taken
    start_time = time.time()
    process.run()
    end_time = time.time()
    total_time = end_time - start_time

    assert total_time > 1 if wait else total_time < 1
