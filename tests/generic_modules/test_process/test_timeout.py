"""
Module to test the timeout parameter of Process class.

Test cases:
    - Case 1: Run a extended command and check if the process raise a timeout exception.
        - Case 1.1: Run a extended command setting a timeout lower than command time execution.
        - Case 1.2: Run a extended command setting a timeout greater than command time execution.
"""

import sys
import subprocess
import pytest


from wazuh_qa_framework.generic_modules.process.windows_process import WindowsProcess
from wazuh_qa_framework.generic_modules.process.linux_process import LinuxProcess


@pytest.mark.skipif(sys.platform != 'linux', reason='Requires Linux')
@pytest.mark.parametrize('timeout, sleep_time, expected_exception', [(1, 1.1, True), (1, 0.1, False)])
def test_linux_timeout(timeout, sleep_time, expected_exception):
    """Check that timeout parameter of Process works as expected.

    case: Run a extended command and check if the process raises a timeout exception.

    test_phases:
        - test:
            - Create a process object with the specific command.
            - Check if a timeout exception has been generated according to the timeout value set.

    parameters:
        - wait (str): Parametrized variable.
    """
    process = LinuxProcess(command=f"sleep {sleep_time}; echo hello", wait=True, capture_stdout=True,
                           capture_stderr=True, timeout=timeout)

    if expected_exception:
        with pytest.raises(subprocess.TimeoutExpired):
            process.run()
    else:
        process.run()


@pytest.mark.skipif(sys.platform != 'win32', reason='Requires Windows')
@pytest.mark.parametrize('timeout, sleep_time, expected_exception', [(1, 1.1, True), (1, 0.1, False)])
def test_windows_timeout(timeout, sleep_time, expected_exception):
    """Check that timeout parameter of Process works as expected.

    case: Run a extended command and check if the process raises a timeout exception.

    test_phases:
        - test:
            - Create a process object with the specific command.
            - Check if a timeout exception has been generated according to the timeout value set.

    parameters:
        - wait (str): Parametrized variable.
    """
    process = WindowsProcess(command=f"sleep {sleep_time}; echo hello", wait=True, capture_stdout=True,
                             capture_stderr=True, timeout=timeout)

    if expected_exception:
        with pytest.raises(subprocess.TimeoutExpired):
            process.run()
    else:
        process.run()
