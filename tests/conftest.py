import pytest
import os
import sys
import logging
from tempfile import gettempdir

DEFAULT_SAMPLE_FILE = os.path.join(gettempdir(), 'file.log')


@pytest.fixture
def create_destroy_sample_file(request):
    """Create and destroy a sample file"""
    file = getattr(request.module, 'SAMPLE_FILE') if hasattr(request.module, 'SAMPLE_FILE') else DEFAULT_SAMPLE_FILE

    # Create an empty file
    with open(file, 'a'):
        pass

    yield file

    # Remove the file
    if os.path.exists(file):
        if sys.platform == 'win32':
            # Shutdown logging. Needed because on Windows we can't remove the logging file if the file handler is set
            # and up.
            logging.shutdown()

        os.remove(file)
