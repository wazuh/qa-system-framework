"""
Module to build a tool that allow us to run local commands and process the output in a custom way.

This module contains the following:

- Process:
    - run
    - get_stdout
    - get_stderr
    - get_status
    - get_pid
    - kill
    - get_return_code
"""

import subprocess
import json
import psutil


class Process:
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
        self.command = command
        self.shell = True if isinstance(command, str) else False
        self.capture_stdout = capture_stdout
        self.capture_stderr = capture_stderr
        self.stdout = None
        self.stderr = None
        self.wait = wait
        self.timeout = timeout
        self.process = None
        self.return_code = None

    def __str__(self):
        """Redefine the process object representation.

        Returns:
            str: Process object representation.
        """
        attributes = self.__dict__
        del(attributes['process'])
        return json.dumps(attributes)

    def run(self):
        """Run the process

        Raises:
            subprocess.TimeoutExpired: If the process time taken is grater than the timeout set.
        """
        args = {
            'args': self.command,
            'shell': self.shell,
        }

        if self.capture_stdout:
            args['stdout'] = subprocess.PIPE

        if self.capture_stderr:
            args['stderr'] = subprocess.PIPE

        # Run the process
        self.process = psutil.Popen(**args)

        # If we capture the stdout or stderr, we have to wait until process is finished and save it into attributes.
        if self.capture_stdout or self.capture_stderr:
            output = self.process.communicate(timeout=self.timeout)
            self.stdout = output[0].decode() if type(output[0]) is bytes else output[0]
            self.stderr = output[1].decode() if type(output[1]) is bytes else output[1]
            self.return_code = self.process.returncode

        # If we set wait=True, we can set the return code.
        if not(self.capture_stdout or self.capture_stderr) and self.wait:
            self.return_code = self.process.wait(timeout=self.timeout)

    def get_stdout(self):
        """Get process stdout.

        Returns:
            str: Process stdout.
        """
        return self.stdout

    def get_stderr(self):
        """Get process stderr.

        Returns:
            str: Process stderr.
        """
        return self.stderr

    def get_status(self):
        """Get process status.

        Returns:
            str: Process status.
        """
        try:
            return self.process.status()
        except psutil.NoSuchProcess:
            return psutil.STATUS_DEAD

    def get_pid(self):
        """Get process PID.

        Returns:
            int: Process PID.
        """
        return self.process.pid

    def kill(self):
        """Kill the process if it exists"""
        try:
            self.process.kill()
        except psutil.NoSuchProcess:
            pass

    def get_return_code(self):
        """Get the process return code.

        Returns:
            int: Process return code.
        """
        return self.return_code
