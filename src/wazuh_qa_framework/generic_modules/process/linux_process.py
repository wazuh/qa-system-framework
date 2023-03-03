"""
Module to build a tool that allow us to run local Linux commands using bash and process the output in a custom way.
It contains the following:

- LinuxProcess(Process):
    - run
    - get_stdout
    - get_stderr
    - get_status
    - get_pid
    - kill
    - get_return_code
"""

from wazuh_qa_framework.generic_modules.process.process import Process
from wazuh_qa_framework.generic_modules.exceptions.exceptions import ValidationError


class LinuxProcess(Process):
    """Class to run processes.

    Args:
        command (str or list(str)): Command (string or splitted in list) to run.
        capture_stdout (boolean): True for capturing the process stdout, False otherwise.
        capture_stderr (boolean): True for capturing the process stderr, False otherwise.
        wait (boolean): True for waiting until the process is finished, False otherwise. Important note: If we capture
                        the stdout or stderr the process will act as wait=True.
        timeout (int): Num seconds to wait until the process is finished. If it's exceeded, exception will be generated.

    Attributes:
        command (str or list(str)): Command (string or splitted in list) to run.
        capture_stdout (boolean): True for capturing the process stdout, False otherwise.
        capture_stderr (boolean): True for capturing the process stderr, False otherwise.
        stdout (str): Process stdout if captured with capture_stdout=True.
        stderr (str): Process stderr if captured with capture_stderr=True.
        wait (boolean): True for waiting until the process is finished, False otherwise.
        timeout (int): Num seconds to wait until the process is finished. If it's exceeded, exception will be generated.
        process (psutil.Process): Process object.
    """
    def __init__(self, command, capture_stdout=False, capture_stderr=False, wait=False, timeout=None):
        if type(command) is list:
            linux_command = ['/bin/bash', '-c'] + command
        elif type(command) is str:
            linux_command = f"/bin/bash -c \"{command}\""
        else:
            raise ValidationError('The type of command variable is not the expected one. Allowed list or string')

        super().__init__(command=linux_command, capture_stdout=capture_stdout, capture_stderr=capture_stderr, wait=wait,
                         timeout=timeout)
