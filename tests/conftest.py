import pytest
import os
from tempfile import gettempdir

DEFAULT_SAMPLE_FILE =  os.path.join(gettempdir(), 'file.log')

@pytest.fixture
def create_destroy_sample_file(request):
    file = request.module['SAMPLE_FILE'] if hasattr(request.module, 'SAMPLE_FILE') else DEFAULT_SAMPLE_FILE

    with open(file, 'a'):
        pass

    yield file

    if os.path.exists(file):
        os.remove(file)
