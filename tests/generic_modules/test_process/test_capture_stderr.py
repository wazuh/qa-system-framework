"""
Module to test the capture_stderr parameter of Process class.

Test cases:
    - Case 1: Run command and check the if the output is saved in the variable or not:
        - Case 1.1: Run a command capturing the output in a variable.
        - Case 1.2: Run a command without capturing the output.
"""

import pytest

from wazuh_qa_framework.generic_modules.process.process import Process


@pytest.mark.parametrize('capture_stderr', [True, False])
def test_capture_stderr(capture_stderr):
    """Check that run method of Process works as expected.

    case: Run command and check the captured stderr.

    test_phases:
        - test:
            - Create a process object with the specific command.
            - Check if the output has been captured according to the parameter set.

    parameters:
        - capture_stderr (int): Parametrized variable.
    """
    process = Process(command='ls /fail', wait=True, capture_stdout=True, capture_stderr=capture_stderr)
    process.run()

    assert len(process.stderr) > 0 if capture_stderr else process.stderr is None
