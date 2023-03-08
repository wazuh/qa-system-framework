"""
Configuration functions used by tests
"""

import yaml


def get_test_cases_data(data_file_path):
    """Read the generic template cases data and extract the info.

    Args:
        data_file_path (str): Template file path.

    Returns:
        list(), list(): Test cases parameters list and tests cases names
    """
    with open(data_file_path) as _file:
        test_cases_data = yaml.safe_load(_file)

    parameters = []
    cases_ids = []

    for test_case in test_cases_data:
        parameters.append(test_case['parameters'])
        cases_ids.append(test_case['name'])

    return parameters, cases_ids
