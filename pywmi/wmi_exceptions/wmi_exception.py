"""
This file provides **WMIException** class which is the parent for
all wmi exception classes

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-10
"""
import logging
from abc import ABCMeta


class WMIException(Exception, metaclass=ABCMeta):
    """
    Abstract base class. Parent for WMI exceptions
    """
    message: str = 'Unknown error! The message was not set!'  #: configuration error message string
    logger: logging.Logger = logging.getLogger('wmi')  #: all of WMI Exceptions will user this logger

    def _get_log_message(self) -> str:
        """
        Creates a message for logging
        :return: a message for logging
        :rtype: str
        """
        return f'{self.__class__.__name__}. {self.message}'
