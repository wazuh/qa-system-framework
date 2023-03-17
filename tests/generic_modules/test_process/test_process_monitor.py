"""
Module to test the Process Monitor class.

Test cases:
    - Case 1: Run process monitor with invalid PID.
    - Case 2: Run a process and check that all methods run without errors.

Note: It is tested in a general way, without taking into account the exact values returned, due to the difficulty of
creating processes with exact values of resources ... and that are independent of the environment.
"""

import os
import sys
import signal
import time
import multiprocessing
import pytest

from wazuh_qa_framework.generic_modules.process.monitor.process_monitor import ProcessMonitor
from wazuh_qa_framework.generic_modules.process.monitor.linux_process_monitor import LinuxProcessMonitor
from wazuh_qa_framework.generic_modules.process.monitor.windows_process_monitor import WindowsProcessMonitor
from wazuh_qa_framework.generic_modules.exceptions.exceptions import ValueError


def loop():
    """Dummy function"""
    while True:
        time.sleep(1)


@pytest.fixture(scope='module')
def run_dummy_process():
    """Run a dummy process and kill it in the teardown."""
    process = multiprocessing.Process(target=loop)
    process.start()

    # Waiting time to start the process
    time.sleep(0.1)

    yield process.pid

    os.kill(process.pid, signal.SIGTERM)


def test_invalid_pid():
    """Check that custom exception is raised when monitoring with invalid PID number.

    case: Run process monitor with invalid PID.

    test_phases:
        - test:
            - Create a process monitor object and check the exception raised.
    """
    non_existing_pid = 99999999

    with pytest.raises(ValueError):
        ProcessMonitor(non_existing_pid)


@pytest.mark.skipif(sys.platform != 'linux', reason='Requires Linux')
def test_linux_process_monitor(run_dummy_process):
    """Monitor a Linux process and check that there are no errors.

    case: Run a process and check that all methods run without errors.

    test_phases:
        - setup:
            - Run a dummy process
        - test:
            - Create a process monitor object for the dummy process.
            - Check that every method is run without errors.
        - teardown:
            - Kill the dummy process

    parameters:
        - run_dummy_process (fixture): Fixture to run a dummy process.
    """
    pid = run_dummy_process
    linux_process = LinuxProcessMonitor(pid)

    # Check that every method is run without errors
    assert linux_process.get_memory_usage()
    assert linux_process.get_memory_usage_percentage
    assert linux_process.get_total_cpu_usage
    assert linux_process.get_total_cpu_usage
    assert linux_process.get_num_file_descriptors()
    assert linux_process.get_username()
    assert linux_process.get_status()
    assert linux_process.get_ppid()
    assert linux_process.get_creation_time()
    assert linux_process.get_num_threads()


@pytest.mark.skipif(sys.platform != 'win32', reason='Requires Windows')
def test_windows_process_monitor(run_dummy_process):
    """Monitor a Windows process and check that there are no errors.

    case: Run a process and check that all methods run without errors.

    test_phases:
        - setup:
            - Run a dummy process
        - test:
            - Create a process monitor object for the dummy process.
            - Check that every method is run without errors.
        - teardown:
            - Kill the dummy process

    parameters:
        - run_dummy_process (fixture): Fixture to run a dummy process.
    """
    pid = run_dummy_process
    windows_process = WindowsProcessMonitor(pid)

    # Check that every method is run without errors
    assert windows_process.get_memory_usage()
    assert windows_process.get_memory_usage_percentage()
    assert windows_process.get_total_cpu_usage()
    assert windows_process.get_total_cpu_usage()
    assert windows_process.get_username()
    assert windows_process.get_status()
    assert windows_process.get_ppid()
    assert windows_process.get_creation_time()
    assert windows_process.get_num_threads()
