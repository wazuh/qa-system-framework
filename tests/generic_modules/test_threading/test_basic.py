"""
Module to test the custom Thread class from the wazuh-qa-framework

Test cases:
    - Case 1: Run a sample function in the thread and get its result.
    - Case 2: Run a sample function in the thread that raises an exception to check if its propagated to the parent
              process.
"""
import pytest
import time

from wazuh_qa_framework.generic_modules.threading.thread import Thread


def test_target_runner():
    """Check that the thread target function is run.

    case: Run a sample function in the thread and get its result.

    test_phases:
        - test:
            - Create the thread with the custom function
            - Wait until the thread has run the function and check the result
    """
    def default_function(param_1, param_2):
        """Sample function"""
        time.sleep(1)
        return param_1 + param_2

    # Create and start the thread calling the function with parameters
    thread = Thread(target=default_function, parameters={'param_1': 1, 'param_2': 2})
    thread.start()

    # Wait until the thread tasks has finished and get the result
    returned_value = thread.join()

    # Check that the thread tasks has been completed and check the result
    assert returned_value == 3


def test_raise_exception():
    """Check that the thread exception is propagated to the parent process

    case: Run a sample function in the thread that raises an exception to check if its propagated to the parent process.

    test_phases:
        - test:
            - Create the thread with the custom function
            - Wait until the thread has run the function and check if the thread exception has been propagated to the
              parent process.
    """
    def raise_exception():
        """Sample function that raises an exception"""
        raise RuntimeError('This is a triggered exception')

    # Create and start the thread calling the exception function
    thread = Thread(target=raise_exception)
    thread.start()

    # Check that the thread exception has been propagated to the parent process
    with pytest.raises(RuntimeError):
        thread.join()
        pytest.fail('The thread exception has not been propagated to the parent process')
