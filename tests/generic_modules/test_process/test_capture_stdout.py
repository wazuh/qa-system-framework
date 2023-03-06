"""
Module to test the capture_stdout parameter of Process class.

Test cases:
    - Case 1: Run command and check the if the output is saved in the variable or not:
        - Case 1.1: Run a command capturing the output in a variable.
        - Case 1.2: Run a command without capturing the output.
"""

import sys
import pytest

from wazuh_qa_framework.generic_modules.process.windows_process import WindowsProcess
from wazuh_qa_framework.generic_modules.process.linux_process import LinuxProcess


@pytest.mark.skipif(sys.platform != 'linux', reason='Requires Linux')
@pytest.mark.parametrize('capture_stdout', [True, False])
def test_linux_capture_stdout(capture_stdout):
    """Check that run method of Process works as expected.

    case: Run command and check the captured stdout.

    test_phases:
        - test:
            - Create a process object with the specific command.
            - Check if the output has been captured according to the parameter set.

    parameters:
        - capture_stdout (int): Parametrized variable.
    """
    process = LinuxProcess(command='ls /', wait=True, capture_stdout=capture_stdout, capture_stderr=True)
    process.run()

    assert len(process.stdout) > 0 if capture_stdout else process.stdout is None


@pytest.mark.skipif(sys.platform != 'win32', reason='Requires Windows')
@pytest.mark.parametrize('capture_stdout', [True, False])
def test_windows_capture_stdout(capture_stdout):
    """Check that run method of Process works as expected.

    case: Run command and check the captured stdout.

    test_phases:
        - test:
            - Create a process object with the specific command.
            - Check if the output has been captured according to the parameter set.

    parameters:
        - capture_stdout (int): Parametrized variable.
    """
    process = WindowsProcess(command='ls /', wait=True, capture_stdout=capture_stdout, capture_stderr=True)
    process.run()

    assert len(process.stdout) > 0 if capture_stdout else process.stdout is None
