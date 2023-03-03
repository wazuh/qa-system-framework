"""
Custom threading module for wrapping threading.Thread module and allowing to raise the thread exception to the parent
process.

- Thread(threading.Thread):
    - run
    - start
    - join
"""

import threading


class Thread(threading.Thread):
    """Class which allows us to upload the thread exception to the parent process.

    Args:
        target (callable): Function to run in the thread.
        parameters (dict): Function parameters. Used as kwargs in the callable function.
        throw_exception (boolean): Flag to active/deactivate the exception raising from the thread.

    Attributes:
        target (callable): Function to run in the thread.
        parameters (dict): Function parameters. Used as kwargs in the callable function.
        exception (Exception): Thread exception in case it has occurred.
        throw_exception (boolean): Flag to active/deactivate the exception raising from the thread.
    """
    def __init__(self, target, parameters=None, throw_exception=True):
        super().__init__()
        self.target = target
        self.exception = None
        self.parameters = {} if parameters is None else parameters
        self.throw_exception = throw_exception
        self._return = None

    def _run(self):
        """Run the target function with its parameters in the thread"""
        self._return = self.target(**self.parameters)

    def run(self):
        """Overwrite run function of threading Thread module.

        Launch the target function and catch the exception in case it occurs.
        """
        try:
            self._run()
        except Exception as exception:
            self.exception = exception

    def start(self):
        """Overwrite run function of threading Thread module.

        Launch the target function and catch the exception in case it occurs.
        """
        super().start()

    def join(self):
        """Overwrite join function of threading Thread module.

        Raises the exception to the parent in case it was raised when executing the target function.

        Raises:
            Exception: Target function exception if ocurrs
        """
        super().join()
        if self.exception and self.throw_exception:
            raise self.exception

        return self._return
