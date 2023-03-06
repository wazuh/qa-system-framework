"""
Module to test the wait parameter of Process class.

Test cases:
    - Case 1: Run a extended command and check if the main process waits until it is finished.
        - Case 1.1: Run a extended command setting wait parameter to True.
        - Case 1.2: Run a extended command setting wait parameter to False.
"""

import sys
import time
import pytest


from wazuh_qa_framework.generic_modules.process.windows_process import WindowsProcess
from wazuh_qa_framework.generic_modules.process.linux_process import LinuxProcess


@pytest.mark.skipif(sys.platform != 'linux', reason='Requires Linux')
@pytest.mark.parametrize('wait', [True, False])
def test_linux_wait(wait):
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
    process = LinuxProcess(command='sleep 1.1; echo hello', wait=wait, capture_stdout=False, capture_stderr=False)

    # Run the process, measuring the time taken
    start_time = time.time()
    process.run()
    end_time = time.time()
    total_time = end_time - start_time

    assert total_time > 1 if wait else total_time < 1


@pytest.mark.skipif(sys.platform != 'win32', reason='Requires Windows')
@pytest.mark.parametrize('wait', [True, False])
def test_windows_wait(wait):
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
    process = WindowsProcess(command='sleep 1.1; echo hello', wait=wait, capture_stdout=False, capture_stderr=False)

    # Run the process, measuring the time taken
    start_time = time.time()
    process.run()
    end_time = time.time()
    total_time = end_time - start_time

    assert total_time > 1 if wait else total_time < 1
