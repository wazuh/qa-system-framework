"""
Module to build a tool that allow us to check if a file contains a sequence of searched patterns in order.

For example, if we want to check that a file contains first line 1 and then line 2, this tool is useful, because if
line 2 appears first and then line 1, or either of them does not appear, an exception will be generated.

>Note: It is important to note that this tool does not monitor, but has to be launched once the logs have been produced.

This module contains the following:

- FileRegexChecker
"""

import re
import os
from collections import deque

from wazuh_qa_framework.generic_modules.exceptions.exceptions import ElementNotFoundError, ValidationError


class FileRegexChecker:
    """Class to check if a file contains the specified patterns.

    Args:
        patterns (str): File path to check.
        patterns (list(str)): List of patterns in string format to search.
        check_order (boolean): True to take into account the patterns list order, False otherwise.

    Attributes:
        patterns (str): File path to check.
        patterns (list(str)): List of patterns in string format to search.
        check_order (boolean): True to take into account the patterns list order, False otherwise.
    """

    def __init__(self, file, patterns, check_order=True):
        self.file = file
        self.patterns = patterns
        self.check_order = check_order

        self.__validate_parameters()
        self.__start()

    def __validate_parameters(self):
        """Validate the input parameters"""
        # Check that patterns is a list
        if type(self.patterns) != list:
            raise ValidationError('Patterns parameter must be a list')

        # Check that patterns list is not empty
        if len(self.patterns) == 0:
            raise ValidationError('Patterns parameter list cannot be empty')

        if not os.path.exists(self.file):
            raise ValidationError(f"File {self.file} does not exist")

        # Check that the monitored file is a file
        if not os.path.isfile(self.file):
            raise ValidationError(f"{self.file} is not a file")

        # Check that the program can read the content of the file
        if not os.access(self.file, os.R_OK):
            raise ValidationError(f"{self.file} is not readable")

    def __start(self):
        """Start the search process.

        Raises:
            ElementNotFoundError: If the pattern was not found in file or was not in order (if selected).
        """
        queue_data = deque()

        # Read the file content and save every line into a queue data structure
        with open(self.file) as _file:
            for line in _file.readlines():
                queue_data.append(line)

        if self.check_order:
            # Check that every pattern is found in the file content in order.
            for pattern in self.patterns:
                pattern_found = False
                while len(queue_data) > 0:
                    line = queue_data.popleft()

                    if re.match(rf"{pattern}", line):
                        pattern_found = True
                        break

                if len(queue_data) == 0 and not pattern_found:
                    raise ElementNotFoundError(f"The pattern {pattern} was not found in {self.file}")
        else:
            # Check that every pattern is found in the file content.
            for pattern in self.patterns:
                for line in queue_data:
                    if re.match(rf"{pattern}", line):
                        break
                else:
                    raise ElementNotFoundError(f"The pattern {pattern} was not found in {self.file}")
