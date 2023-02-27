from wazuh_qa_framework.generic_modules.logging.framework_logger import FrameworkLogger



def test_singleton():
    logger_obj_1 = FrameworkLogger(name='example_1')
    logger_obj_2 = FrameworkLogger(name='example_2')

    assert hex(id(logger_obj_1)) == hex(id(logger_obj_2))
