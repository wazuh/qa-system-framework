"""
Module to manage custom exceptions. This module contains the following:

- QAException(Exception)
- ValueError(QAException)
- RuntimeError(QAException)
- ConnectionError(QAException)
- ValidationError(QAException)
"""
import sys


class QAException(Exception):
    """Generic class to create and handle custom exceptions.

    Args:
        - message (str): Exception message.
        - color (boolean): True for printing the exception message in red color, False otherwise.

    Attributes:
        - message (str): Exception message.
        - color (boolean): Allow to print the exception message in a colorized way.
    """
    def __init__(self, message, color=True, traceback=True, class_exception_name=None):
        self.message = message
        self.color = color
        self.traceback = traceback
        self.class_exception = class_exception_name
        sys.tracebacklimit = 1 if traceback else 0
        super().__init__()

    def __str__(self):
        """Overwrite how the exception message will be printed.

        Returns:
            str: Exception message
        """
        exception_message = f"\033[91m{self.message}\033[0m" if self.color else self.message
        return exception_message


class ValueError(QAException):
    """Class to manage value error cases."""

    def __init__(self, message, color=True, traceback=True):
        super().__init__(message, color, traceback, self.__class__)


class RuntimeError(QAException):
    """Class to manage Runtime error cases."""
    def __init__(self, message, color=True, traceback=True):
        super().__init__(message, color, traceback, self.__class__)


class ConnectionError(QAException):
    """Class to manage Connection error cases."""
    def __init__(self, message, color=True, traceback=False):
        super().__init__(message, color, traceback, self.__class__)


class ValidationError(QAException):
    """Class to manage validation error cases."""
    def __init__(self, message, color=True, traceback=True):
        super().__init__(message, color, traceback, self.__class__)
