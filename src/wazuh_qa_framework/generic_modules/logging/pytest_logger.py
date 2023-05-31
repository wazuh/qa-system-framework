"""Custom logging module to log pytest messages.

This module contains the following:

- PytestLogger(BaseLogger):
    - log
    - debug
    - info
    - warning
    - error
    - critical
"""

from wazuh_qa_framework.generic_modules.logging.base_logger import BaseLogger


class PytestLogger(BaseLogger):
    """Singleton logger class to manage pytest logging.

    Args:
        name (str): Logger name.
        level (str): Logging level.
        formatter (str): Formatter group.
        handlers (list(str)): Logging handlers.
        logging_file (str): File path were save the logging if the file handler has been specified.
        output_color (boolean): True for logging with output colors, False otherwise.

    Attributes:
        name (str): Logger name.
        logger (logging.Logger): Logger object.
        level (str): Logging level.
        formatter (str): Formatter group.
        handlers (list(str)): Logging handlers.
        logging_file (str): File path were save the logging if the file handler has been specified.
        output_color (boolean): True for logging with output colors, False otherwise.
    """
    __instance = None

    def __init__(self, name, level='info', formatter='basic', handlers=None, logging_file=None,
                 output_color=True):
        super().__init__(name=name, level=level, formatter=formatter, handlers=handlers, logging_file=logging_file,
                         output_color=output_color)
