from wazuh_qa_framework.generic_modules.logging.base_logger import BaseLogger


class FrameworkLogger(BaseLogger):
    __instance = None

    def __init__(self, name, level='info', formatter='basic', handlers=None, logging_file=None,
                 output_color=True):
        super().__init__(name=name, level=level, formatter=formatter, handlers=handlers, logging_file=logging_file,
                         output_color=output_color)

    def __new__(self, *args, **kwargs):
        if self.__instance is None:
            self.__instance = super().__init__(self, *args, **kwargs)

        return self.__instance
