
"""Custom time module for wrapping datetime utils methods.

Classes:

- Time(object):
    Methods:
    - static:
        - get_datetime_from_timestamp(timestamp, datetime_format)
"""

from datetime import datetime as date
import pytz


class Time(object):
    """Class to manage datetimes with useful related methods.

    Args:
        datetime (str): Custom datetime. By default is the current datetime (in the moment of object creation).
        timezone (str): Datetime timezone.

    Attributes:
        datetime (str): Custom datetime. By default is the current datetime (in the moment of object creation).
        timezone (str): Datetime timezone.
    """
    DAYS = 'day'
    HOURS = 'hour'
    MINUTES = 'minute'
    SECONDS = 'second'
    TODAY = 'today'
    WEEK = 'week'
    MONTH = 'month'

    def __init__(self, datetime=None, timezone='Europe/Berlin'):
        self.timezone = timezone
        self.datetime = datetime if datetime else date.now(pytz.timezone(timezone)).strftime("%Y-%m-%d %H:%M:%S")

    def __str__(self):
        return self.datetime

    @staticmethod
    def get_datetime_from_timestamp(timestamp, datetime_format='%Y-%m-%d %H:%M:%S'):
        """Get the datetime from specific timestamp.
        Args:
            timestamp (float): Timestamp data.
            datetime_format (str): Date time format.
        Returns
            str: Date time from specified timestamp.
        """
        return date.fromtimestamp(timestamp).strftime(datetime_format)

    @staticmethod
    def get_datetime(datetime_format='%Y-%m-%d %H:%M:%S', timezone='Europe/Berlin'):
        """Get the current datetime according to the specified format and timezone.

        Args:
            datetime_format (str): Date time format.
            timezone (str): Datetime timezone.

        Returns:
            str: Current datetime.
        """
        return date.now(pytz.timezone(timezone)).strftime(datetime_format)
