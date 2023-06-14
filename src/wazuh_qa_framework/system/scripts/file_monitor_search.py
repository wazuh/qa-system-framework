import argparse
import os
import json
import re

from wazuh_qa_framework.generic_modules.file_regex.file_regex_monitor_manager import FileRegexMonitorManager
from wazuh_qa_framework.generic_modules.logging.base_logger import BaseLogger


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
    """Validate the parameters for file_monitor_search.py

    Args:
        args (argparse.Namespace): Arguments from the command line
    """
    DEBUG_LEVELS = ['debug', 'info', 'warning', 'error', 'critical']

    if args.debug not in DEBUG_LEVELS:
        raise ValueError(f'Invalid debug level {args.debug}. Valid values are {DEBUG_LEVELS}')
    if not os.path.isfile(args.monitoring_data_file):
        raise ValueError(f'Invalid monitoring data file {args.monitoring_data_file}')
    if not os.path.isfile(args.report_file):
        raise ValueError(f'Invalid report file {args.report_file}')
    if args.report_file and not os.access(args.report_file, os.W_OK):
        raise ValueError(f'Invalid report file {args.report_file}. '
                         f'You do not have write permissions')
    if args.monitoring_data_file and not os.access(args.monitoring_data_file, os.R_OK):
        raise ValueError(f'Invalid monitoring data file {args.monitoring_data_file}. '
                         f'You do not have read permissions')

    with open(args.monitoring_data_file, 'r') as monitoring_data_json_file:
        try:
            json.load(monitoring_data_json_file)
        except json.JSONDecodeError as json_error:
            raise ValueError(f'Invalid monitoring data file {args.monitoring_data_file}. '
                             f'Invalid JSON format: {json_error}')


def parse_parameters():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-m', '--monitoring-data', metavar='<monitoring-json-data>', type=str, required=True,
                            help='Monitoring JSON data', dest='monitoring_data_file')
    arg_parser.add_argument('-u', '--update-position', action='store_false', required=False, dest='update_position')
    arg_parser.add_argument('-i', '--ignore-errors', action='store_true', required=False, dest='ignore_errors')
    arg_parser.add_argument('-d', '--debug', type=str, required=False, dest='debug')
    arg_parser.add_argument('-r', '--report-file', type=str, required=True, dest='report_file')

    args = arg_parser.parse_args()

    return args


def main():
    arguments = parse_parameters()

    logging = BaseLogger(name='file_monitor_search', level=arguments.debug, output_color=True, output_source=True)
    logging.info('Validating parameters for file_monitor_search.py')
    validate_parameters(arguments)

    file_monitor = FileRegexMonitorManager(arguments.debug)
    monitoring_data = []

    logging.info(f'Loading monitoring data from file {arguments.monitoring_data_file}')
    with open(file=arguments.monitoring_data_file) as monitoring_file:
        monitoring_data = json.load(monitoring_file)

    for monitoring_object in monitoring_data:
        monitoring_file = monitoring_object.get('path')
        callback = make_callback(monitoring_object.get('regex'), monitoring_object.get('prefix'),
                                 monitoring_object.get('escape'))
        monitoring_object['callback'] = callback

    logging.info(f'Starting file monitoring')
    file_monitor.start(monitoring_data, arguments.report_file, arguments.update_position, arguments.ignore_errors)
    logging.info(f'File monitoring finished')


if __name__ == '__main__':
    main()
