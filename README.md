[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)
[![Twitter](https://img.shields.io/twitter/follow/wazuh?style=social)](https://twitter.com/wazuh)
[![YouTube](https://img.shields.io/youtube/views/peTSzcAueEc?style=social)](https://www.youtube.com/watch?v=peTSzcAueEc)


# Wazuh QA framework

This repository contains a generic framework for the different QA processes.

## How to install

### Preconditions

QA system framework require a python version >=3.7.1

### VirtualEnvironment

It is highly recommended to use a virtual environment when installing the QA framework. Follow the steps below to create and activate a virtual environment:

- Create a virtual environment named "qa-system-env" by running the following command
```
python -m venv qa-system-env
```
- Activate the virtual environment by executing the following command

**Windows**
```
qa-system-env\Scripts\activate
```

**Linux/macOS**
```
source qa-system-env/bin/activate
```

By using a virtual environment, you can isolate the dependencies and ensure a clean installation of the QA framework without affecting your system's global Python environment.

### Install

To install the base Wazuh QA Framework package, you can use the following pip command:
```
pip install .
```
> **Note**:
> The base framework is designed exclusively for in-host operations.

If you need to install the dependencies to launch system tests with the node executor, you should specify it during the framework installation:
```
pip install .[system_executor_node]
```
> **Warning**:
> Please note that only Linux systems can act as executor nodes.

> **Note**:
> Optional dependencies also include the base requirements.


To install the dependencies for running unit tests, use the following command:
```
pip install .[unit_testing]
```

By executing this command, you will install the necessary dependencies for unit testing.

## How to use

Once you have installed the `wazuh-qa-framework`, you can use and import it into your python scripts or tests modules.

```
from wazuh_qa_framework.x import y
```
