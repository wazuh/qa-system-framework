"""Custom logging module to log framework messages. This module contains the following:

- FrameworkLogger(BaseLogger)
"""

from wazuh_qa_framework.generic_modules.logging.base_logger import BaseLogger


class FrameworkLogger(BaseLogger):
    """Logger singleton class to manage framework logging.

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

    def __new__(self, *args, **kwargs):
        if self.__instance is None:
            self.__instance = super().__init__(self, *args, **kwargs)

        return self.__instance
