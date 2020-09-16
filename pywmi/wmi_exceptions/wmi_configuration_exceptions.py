"""
WMI configuration exceptions

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-10
"""
from pywmi.wmi_exceptions.wmi_exception import WMIException


class WMIConfigurationException(WMIException):
    """
    Parent for WMI configuration exceptions
    """
    def __init__(self):
        # a WMI configuration exception needed to be written to log as error
        self.logger.error(self._get_log_message())
        super().__init__(f"{self._get_log_message()}. Please create needed environment and try again.")


class WMIConfigurationUsernameException(WMIConfigurationException):
    """
    The **AD_USERNAME** environment variable does not set
    """
    message: str = 'An environment variable AD_USERNAME does not exist'


class WMIConfigurationPasswordException(WMIConfigurationException):
    """
    The **AD_PASSWORD** environment variable does not set
    """
    message: str = 'An environment variable AD_PASSWORD does not exist'


class WMIConfigurationDomainException(WMIConfigurationException):
    """
    The **AD_DOMAIN** environment variable does not set
    """
    message: str = 'An environment variable AD_DOMAIN does not exist'


class WMIConfigurationAddressException(WMIConfigurationException):
    """
    The **WMI_ADDRESS** environment variable does not set
    """
    message: str = 'An environment variable WMI_ADDRESS does not exist'
