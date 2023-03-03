"""
Module to test the run method of Process class.

Test cases:
    - Case 1: Run command and check the return code.
        - Case 1.1: Run a command that will return RC=0 and check that is has been run.
        - Case 1.2: Run a command that will return RC!=0 and check that is has returned the correct RC.
"""

import sys
import pytest

from wazuh_qa_framework.generic_modules.process.windows_process import WindowsProcess
from wazuh_qa_framework.generic_modules.process.linux_process import LinuxProcess


@pytest.mark.skipif(sys.platform != 'win32', reason='Requires Windows')
@pytest.mark.parametrize('command, expected_result_code', [('ls /', 0), ('ls /fail', 1)])
def test_windows_process_run(command, expected_result_code):
    """Check that run method of Process works as expected.

    case: Run a windows command and check the return code.

    test_phases:
        - test:
            - Create a process object with the specific command
            - Check that the return code is the expected one.

    parameters:
        - command (str): Parametrized variable.
        - expected_result_code (int): Parametrized variable.
    """
    process = WindowsProcess(command=command, wait=True, capture_stdout=True, capture_stderr=True)
    process.run()

    assert process.return_code == expected_result_code


@pytest.mark.skipif(sys.platform != 'linux', reason='Requires Linux')
@pytest.mark.parametrize('command, expected_result_code', [('ls /', 0), ('ls /fail', 2)])
def test_linux_process_run(command, expected_result_code):
    """Check that run method of Process works as expected.

    case: Run a linux command and check the return code.

    test_phases:
        - test:
            - Create a process object with the specific command
            - Check that the return code is the expected one.

    parameters:
        - command (str): Parametrized variable.
        - expected_result_code (int): Parametrized variable.
    """
    process = LinuxProcess(command=command, wait=True, capture_stdout=True, capture_stderr=True)
    process.run()

    assert process.return_code == expected_result_code
