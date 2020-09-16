"""
Settings of an Active Directory account to connect to remote PC
under Windows and to perform WMI requests.

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-05
"""
from typing import Optional, Dict, Any
import os
# wmi configuration exceptions
from pywmi.wmi_exceptions.wmi_configuration_exceptions import WMIConfigurationUsernameException, \
    WMIConfigurationPasswordException, \
    WMIConfigurationDomainException, \
    WMIConfigurationAddressException
#
from pywmi.kwargs import KwargsObject


class ADSettings(KwargsObject):
    """
    Settings of Active Directory

    :param username: The active directory account name to perform WMI requests
    :type username: str
    :param password: The active directory account password
    :type password: str
    :param domain: The name of the active directory realm
    :type domain: str
    """

    def __init__(self, username: str = None, password: str = None, domain: str = None):
        """
        Initialises settings using arguments,
        if arguments are not presented using environment variables.
        If never arguments nor environment variables are present raises exception.
        """
        # active directory username
        if username:
            self.username: str = username
        else:
            self.username: str = os.environ.get('AD_USERNAME')
        if not self.username:
            raise WMIConfigurationUsernameException()
        # active directory password
        if password:
            self.password: str = password
        else:
            self.password: str = os.environ.get('AD_PASSWORD')
        if not self.password:
            raise WMIConfigurationPasswordException()
        # active directory domain
        if domain:
            self.domain: str = domain
        else:
            self.domain: str = os.environ.get('AD_DOMAIN')
        if not self.domain:
            raise WMIConfigurationDomainException()

    def __str__(self):
        return f'{self.__class__.__name__}(ad_username="{self.username}"' \
               f', ad_password="{self.password}", ad_domain="{self.domain}")'

    def __repr__(self):
        return str(self)


class WMIConnectionSettings(KwargsObject):
    """
    Settings of a WMI Connection

    :param target: An ip address of the target computer
    :type target: str
    :param ad_settings: An instance of ADSettings, provides Active Directory authentication
    :type ad_settings: ADSettings
    """
    lmhash: str = ''
    nthash: str = ''
    aesKey: Optional[str] = None
    oxidResolver: bool = True
    doKerberos: bool = False
    kdcHost: Optional[str] = None

    def __init__(self, ad_settings: ADSettings, target: str = None):
        self.ad_settings: ADSettings = ad_settings
        if target:
            self.target: str = target
        else:
            self.target: str = os.environ.get('WMI_ADDRESS')
        if not self.target:
            raise WMIConfigurationAddressException()

    def __str__(self):
        return f'{self.__class__.__name__}(ad_settings={str(self.ad_settings)}, target="{self.target}")'

    def __repr__(self):
        return f'{self.__class__.__name__}(ad_settings={repr(self.ad_settings)}, target="{self.target}")'

    def get_connection_settings_kwargs(self):
        """
        Returns the dict of key word arguments for impacket.dcerpc.v5.dcomrt.DCOMConnection.__init__.
        Using this dict makes you able to run DCOMConnection(**wmi_connection_settings.get_connection_settings_list)

        :return: the dict of key word of arguments for DCOMConnection.__init__
        :rtype: Dict[Any]
        """
        self_kwargs: Dict[str, Any] = self.kwargs()
        ad_settings_kwargs: Dict[str, Any] = self_kwargs.pop('ad_settings').kwargs()
        return {**self_kwargs, **ad_settings_kwargs}
