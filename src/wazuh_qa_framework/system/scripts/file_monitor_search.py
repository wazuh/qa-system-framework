import argparse
import json
import re

from wazuh_qa_framework.generic_modules.file_regex.file_regex_monitor_manager import FileRegexMonitorManager


def make_callback(pattern, prefix="", escape=False):
    """
    Creates a callback function from a text pattern.

    Args:
        pattern (str): String to match on the log
        prefix  (str): String prefix (modulesd, remoted, ...)
        escape (bool): Flag to escape special characters in the pattern
    Returns:
        lambda function with the callback
    """
    if escape:
        pattern = re.escape(pattern)
    else:
        pattern = r'\s+'.join(pattern.split())

    full_pattern = pattern if prefix is None else fr'{prefix}{pattern}'
    regex = re.compile(full_pattern)

    return lambda line: regex.match(line.decode() if isinstance(line, bytes) else line)


def validate_parameters(args):
    pass


def parse_parameters():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-m', '--monitoring-data', metavar='<monitoring-json-data>', type=str, required=True,
                            help='Monitoring JSON data', dest='monitoring_data_file')
    arg_parser.add_argument('-u', '--update-position', action='store_false', required=False, dest='update_position')
    arg_parser.add_argument('-i', '--ignore-errors', action='store_true', required=False, dest='ignore_errors')
    arg_parser.add_argument('-l', '--logging', action='store_true', required=False, dest='logging')
    arg_parser.add_argument('-r', '--report-file', type=str, required=True, dest='report_file')

    args = arg_parser.parse_args()

    return args


def main():
    arguments = parse_parameters()
    validate_parameters(arguments)

    file_monitor = FileRegexMonitorManager(arguments.logging)
    monitoring_data = []

    with open(file=arguments.monitoring_data_file) as monitoring_file:
        monitoring_data = json.load(monitoring_file)

    for monitoring_object in monitoring_data:
        monitoring_file = monitoring_object.get('path')
        callback = make_callback(monitoring_object.get('regex'), monitoring_object.get('prefix'),
                                 monitoring_object.get('escape'))
        monitoring_object['callback'] = callback

    file_monitor.start(monitoring_data, arguments.report_file, arguments.update_position, arguments.ignore_errors)


if __name__ == '__main__':
    main()
