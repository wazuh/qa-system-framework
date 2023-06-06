"""Custom logging module.

It adds an extra layer on top of the python logging module, in which the logger is auto-configured based on the class
attributes, and simplifies its use.

This module contains the following:

- BaseLogger
    - log
    - debug
    - info
    - warning
    - error
    - critical
"""
import logging
import sys
import inspect
import os

from wazuh_qa_framework.generic_modules.exceptions.exceptions import ValidationError


LOGGERS = {}
HANDLERS = ['sys_output', 'file']

LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

COLORS = {
    'CLEAR': '\033[0m',
    'BLUE': '\033[94m',
    'CYAN': '\033[96m',
    'YELLOW': '\033[93m',
    'RED': '\033[91m'
}

LOG_COLORS = {
    'debug': COLORS['CYAN'],
    'info': COLORS['BLUE'],
    'warning': COLORS['YELLOW'],
    'error': COLORS['RED'],
    'critical': COLORS['RED']
}

FORMATERS = {
    'basic': logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
}


class SystemLogger:
    """Logger class to manage modules logging.

    This class defines the main behavior of the loggers and will be used as a base class for the rest of the loggers
    to be defined. It is recommended that it is only used to define new loggers (as if it were an abstract class, but
    for now it does not have any abstract method).

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
        output_source (boolean): True for logging with the source of the message, False otherwise.
    """
    def __init__(self, name, level='info', formatter='basic', handlers=None, logging_file=None, output_source=True,
                 output_color=True):
        self.name = name
        self.__logger = logging.getLogger(name)
        self.level = level
        self.formatter = formatter
        self.logging_file = logging_file
        self.handlers = handlers
        self.output_color = output_color
        self.output_source = output_source

    @property
    def name(self):
        """Getter to obtain name attribute.

        Returns:
            str: Logger name.
        """
        return self.__name

    @name.setter
    def name(self, new_name):
        """Setter of name attribute.

        Args:
            new_name (str): Logger new name.
        """
        self.__name = new_name

    @property
    def logger(self):
        """Getter to obtain logger attribute.

        Returns:
            logging.Logger: Logger object.
        """
        return self.__logger

    @property
    def level(self):
        """Getter to obtain level attribute.

        Returns:
            str: Logger level.
        """
        return self.__level

    @level.setter
    def level(self, new_level):
        """Setter of level attribute.

        Args:
            new_level (str): New logger level.

        Raises:
            ValidationError: If new level is wrong.
        """
        if new_level.lower() in LEVELS.keys():
            self.__level = LEVELS[new_level.lower()]
            self.__logger.level = self.__level
        else:
            raise ValidationError(f"{new_level} is not an accepted level. Expected one of {list(LEVELS.keys())}")

    @property
    def formatter(self):
        """Getter to obtain formatter attribute.

        Returns:
            str: Logger formatter.
        """
        return self.__formatter

    @formatter.setter
    def formatter(self, new_formatter):
        """Setter of level attribute.

        Args:
            new_formatter (str): New logger formatter.

        Raises:
            ValidationError: If new formatter is wrong.
        """
        if new_formatter in FORMATERS.keys():
            self.__formatter = FORMATERS[new_formatter]
        else:
            self.__formatter = FORMATERS['basic']
            raise ValidationError(f"{new_formatter} is not an accepted formatter. Expected one of"
                                  f" {list(FORMATERS.keys())}")

    @property
    def logging_file(self):
        """Getter to obtain logging_file attribute.

        Returns:
            str: Logging file path.
        """
        return self.__logging_file

    @logging_file.setter
    def logging_file(self, new_logging_file):
        """Setter of logging_file attribute.

        Args:
            new_logging_file (str): New logging file.

        Raises:
            ValidationError: If logging file does not exist, is not a file or is not readable.
        """
        if new_logging_file:
            if not os.path.exists(new_logging_file):
                raise ValidationError(f"File {new_logging_file} does not exist")

            # Check that the monitored file is a "file"
            if not os.path.isfile(new_logging_file):
                raise ValidationError(f"{new_logging_file} is not a file")

            # Check that the program can read or write in the file.
            if not os.access(new_logging_file, os.R_OK) or not os.access(new_logging_file, os.W_OK):
                raise ValidationError(f"{new_logging_file} is not readable")

        self.__logging_file = new_logging_file

    @property
    def handlers(self):
        """Getter to obtain handlers attribute.

        Returns:
            list(str): Logger handlers.
        """
        return self.__handlers

    @handlers.setter
    def handlers(self, new_handlers):
        """Setter of handlers attribute.

        Args:
            new_handlers (list(str)): New logger handlers.

        Raises:
            ValidationError: If the handlers are not expected/correct.
        """
        handlers = new_handlers if new_handlers is not None else ['sys_output']

        if type(handlers) != list:
            ValidationError(f"It was expected to receive a list of allowed handlers: f{HANDLERS}")

        # Set logger handlers
        for handler in handlers:
            if handler in HANDLERS:
                if handler == 'sys_output':
                    stream_handler = logging.StreamHandler(sys.stdout)
                    stream_handler.setFormatter(self.__formatter)
                    stream_handler.setLevel(self.__level)
                    self.__logger.addHandler(stream_handler)
                elif handler == 'file':
                    file_handler = logging.FileHandler(self.__logging_file)
                    file_handler.setFormatter(self.__formatter)
                    file_handler.setLevel(self.__level)
                    self.__logger.addHandler(file_handler)
                else:
                    ValidationError(f"{handler} not found")
            else:
                # Avoid default duplicated handlers.
                if not any(isinstance(_handler, logging.StreamHandler) for _handler in self.__logger.handlers):
                    stream_handler = logging.StreamHandler(sys.stdout)
                    stream_handler.setFormatter(self.__formatter)
                    stream_handler.setLevel(self.__level)
                    self.__logger.addHandler(stream_handler)
                    ValidationError(f"{handler} handler is not allowed")

        self.__handlers = handlers

    @property
    def output_color(self):
        """Getter to obtain output_color attribute.

        Returns:
            boolean: True if output color is enabled, False otherwise.
        """
        return self.__output_color

    @property
    def output_source(self):
        """Getter to obtain output_source attribute.

        Returns:
            boolean: True if output source is enabled, False otherwise.
        """
        return self.__output_source

    @output_source.setter
    def output_source(self, new_output_source):
        """Setter of output_source attribute.

        Args:
            new_output_source (boolean): New output source value.
        """
        self.__output_source = new_output_source

    @output_color.setter
    def output_color(self, new_output_color):
        """Setter of output_color attribute.

        Args:
            new_output_color (boolean): New output color value.
        """
        self.__output_color = new_output_color

    def generate_logging_message(self, message, level='info'):
        final_message = message
        if self.output_source:
            curframe = inspect.currentframe()
            calframe = inspect.getouterframes(curframe, 2)
            class_name = calframe[2][0].f_locals['self'].__class__.__name__
            method = calframe[2][3]
            line = calframe[2][2]
            message = message + f" [{class_name} {method}:{line}]"
        if self.output_color:
            color = LOG_COLORS[level]
            final_message = f"{color}{message}{COLORS['CLEAR']}"

        return final_message

    def log(self, message, level='info'):
        """Log a specific level message.

        Args:
            message (str): Logging message.
            level (str): Log level.

        Raises:
            ValidationError: If log level is wrong.
        """
        custom_message = f"{LOG_COLORS[level]}{message}{COLORS['CLEAR']}" if self.output_color else message

        if level == 'debug':
            self.logger.debug(custom_message)
        elif level == 'info':
            self.logger.info(custom_message)
        elif level == 'warning':
            self.logger.warning(custom_message)
        elif level == 'error':
            self.logger.error(custom_message)
        elif level == 'critical':
            self.logger.critical(custom_message)
        else:
            raise ValidationError(f"{level} is not a valid level. Allowed ones: {list(LEVELS.keys())}")

    def debug(self, message):
        """DEBUG logging.

        Args:
            message (str): Logging message.
        """
        self.logger.debug(self.generate_logging_message(message, level='debug'))

    def info(self, message):
        """INFO logging.

        Args:
            message (str): Logging message.
        """
        self.logger.info(self.generate_logging_message(message, level='info'))

    def warning(self, message):
        """WARNING logging.

        Args:
            message (str): Logging message.
        """
        self.logger.warning(self.generate_logging_message(message, level='warning'))

    def error(self, message):
        """ERROR logging.

        Args:
            message (str): Logging message.
        """
        self.logger.error(self.generate_logging_message(message, level='error'))

    def critical(self, message):
        """CRITICAL logging.

        Args:
            message (str): Logging message.
        """
        self.logger.critical(self.generate_logging_message(message, level='critical'))

    def __str__(self):
        """Redefine the logger object representation.

        Returns:
            str: Logger object representation.
        """
        return '{' + f"name: {self.name}, level={self.level}, formatter={self.formatter}, handlers={self.handlers}, " \
                     f" logging_file={self.logging_file}, output_color={self.output_color}" + '}'
