"""
Module to test the custom Thead class from the wazuh-qa-framework
"""
import pytest
import time

from wazuh_qa_framework.generic_modules.threading.thread import Thread


def test_target_runner():
    """Check that the thread target function is run."""
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
    """Check that the thread exception is propagated to the parent process"""
    def raise_exception():
        """Sample function that raises an exception"""
        raise RuntimeError('This is a triggered exception')

    # Create and start the thread calling the exception function
    thread = Thread(target=raise_exception)
    thread.start()

    # Check that the thread exception has been propagated to the parent process
    with pytest.raises(RuntimeError):
        thread.join()
        assert False, 'The thread exception has not been propagated to the parent process'
