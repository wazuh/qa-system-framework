import pytest
import os
from tempfile import gettempdir

from wazuh_qa_framework.meta_testing.utils import write_file, remove_file

DEFAULT_SAMPLE_FILE = os.path.join(gettempdir(), 'file.log')


@pytest.fixture
def create_destroy_sample_file(request):
    """Create and destroy a sample file"""
    file = getattr(request.module, 'SAMPLE_FILE') if hasattr(request.module, 'SAMPLE_FILE') else DEFAULT_SAMPLE_FILE
    write_file(file)

    yield file

    remove_file(file)


@pytest.fixture
def create_destroy_sample_file_with_content(request, file_content):
    """Create and destroy a sample file with specified content"""
    file = getattr(request.module, 'SAMPLE_FILE') if hasattr(request.module, 'SAMPLE_FILE') else DEFAULT_SAMPLE_FILE
    write_file(file, content=file_content)

    yield file

    remove_file(file)
