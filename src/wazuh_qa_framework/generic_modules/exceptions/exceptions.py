"""
Module to manage custom exceptions. This module contains the following:

- QAFrameworkException(Exception)
- ValueError(QAFrameworkException)
- RuntimeError(QAFrameworkException)
- ConnectionError(QAFrameworkException)
- ValidationError(QAFrameworkException)
- FileRegexMonitorError(QAFrameworkException)
- TimeoutError(QAFrameworkException)
- ElementNotFoundError(QAFrameworkException)
"""

import sys


class QAFrameworkException(Exception):
    """Generic class to create and handle custom exceptions.

    Args:
        - message (str): Exception message.
        - color (boolean): True for printing the exception message in red color, False otherwise.
        - traceback (boolean): True for showing the exception traceback, False otherwise.

    Attributes:
        - message (str): Exception message.
        - color (boolean): Allow to print the exception message in a colorized way.
        - traceback (boolean): Allow to enable or disable the exception traceback.
    """
    def __init__(self, message, color=True, traceback=True):
        self.message = message
        self.color = color
        self.traceback = traceback
        sys.tracebacklimit = 1 if traceback else 0
        super().__init__()

    def __str__(self):
        """Overwrite how the exception message will be printed.

        Returns:
            str: Exception message
        """
        exception_message = f"\033[91m{self.message}\033[0m" if self.color else self.message
        return exception_message


class ValueError(QAFrameworkException):
    """Class to manage value error cases."""

    def __init__(self, message, color=True, traceback=True):
        super().__init__(message, color, traceback)


class RuntimeError(QAFrameworkException):
    """Class to manage Runtime error cases."""
    def __init__(self, message, color=True, traceback=True):
        super().__init__(message, color, traceback)


class ConnectionError(QAFrameworkException):
    """Class to manage Connection error cases."""
    def __init__(self, message, color=True, traceback=False):
        super().__init__(message, color, traceback)


class ValidationError(QAFrameworkException):
    """Class to manage validation error cases."""
    def __init__(self, message, color=True, traceback=True):
        super().__init__(message, color, traceback)


class ProcessError(QAFrameworkException):
    """Class to manage process error cases."""
    def __init__(self, message, color=True, traceback=True):
        super().__init__(message, color, traceback)


class TimeoutError(QAFrameworkException):
    """Class to manage timeout error cases."""
    def __init__(self, message, color=True, traceback=True):
        super().__init__(message, color, traceback)


class ElementNotFoundError(QAFrameworkException):
    """Class to manage elements not found cases."""
    def __init__(self, message, color=True, traceback=True):
        super().__init__(message, color, traceback)
