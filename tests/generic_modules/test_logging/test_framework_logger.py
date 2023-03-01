"""
Module to test the BaseLogger.

Test cases:
    - Case 1: Check that if we define multiple framework loggers, they are the same object (singleton).
"""

from wazuh_qa_framework.generic_modules.logging.framework_logger import FrameworkLogger


def test_singleton():
    """Check that if we define multiple framework loggers, they are the same object (singleton).

    test_phases:
        - test:
            - Create two framework loggers with different name.
            - Check that they have the same memory address.
    """
    # Create two framework loggers with different name
    logger_obj_1 = FrameworkLogger(name='example_1')
    logger_obj_2 = FrameworkLogger(name='example_2')

    # Check that they have the same memory address
    assert hex(id(logger_obj_1)) == hex(id(logger_obj_2))
