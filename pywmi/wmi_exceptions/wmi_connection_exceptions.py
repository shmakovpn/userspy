"""
WMI Connection exceptions

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-10
"""
from pywmi.wmi_exceptions.wmi_exception import WMIException
from pywmi.wmi_settings import WMIConnectionSettings


class WMIConnectionException(WMIException):
    """
    Parent for WMI connection exceptions
    """
    def __init__(self, wmi_connection_settings: WMIConnectionSettings):
        self.wmi_connection_settings: WMIConnectionSettings = wmi_connection_settings
        self.message = f'{self.message}. target={self.wmi_connection_settings.target}'
        # a WMI connection exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')


class WMIConnectionDCOMConnectionException(WMIConnectionException):
    """
    Parent for WMI connection exceptions raises when DCOMConnection() is failed.
    """
    pass


class WMIConnectionNoRouteToHostException(WMIConnectionDCOMConnectionException):
    """
    DCOMConnection() was failed for a reason: *Could not connect: [Errno 113] No route to host*
    """
    message = "Could not connect: [Errno 113] No route to host"


class WMIConnectionTimedOutException(WMIConnectionDCOMConnectionException):
    """
    DCOMConnection() was failed for a reason: *Could not connect: Timed out*
    """
    message = "Could not connect: Timed out"


class WMIConnectionNetworkUnreachableException(WMIConnectionDCOMConnectionException):
    """
    DCOMConnection() was failed for a reason: *Could not connect: [Errno 101] Network is unreachable*
    """
    message = "Could not connect: [Errno 101] Network is unreachable"


class WMIConnectionNoAnswerException(WMIConnectionDCOMConnectionException):
    """
    DCOMConnection() was failed for a reason:
    *Could not connect: [WinError 10060]
    Попытка установить соединение была безуспешной,
    т.к. от другого компьютера за требуемое время не получен нужный отклик,
    или было разорвано уже установленное соединение из-за неверного отклика уже подключенного компьютера*
    """
    message = "Could not connect: [WinError 10060] host answer timeout"


class WMIConnectionRefusedException(WMIConnectionDCOMConnectionException):
    """
    DCOMConnection() was failed for a reason: *"Could not connect: [Errno 111] Connection refused*
    """
    message = "Could not connect: [Errno 111] Connection refused"


class WMIConnectionDCOMConnectionUnknownException(WMIConnectionDCOMConnectionException):
    """
    DCOMConnection() was failed for an unknown exception
    """
    message = "Could not connect: an unknown exception"

    def __init__(self, wmi_connection_settings: WMIConnectionSettings, e: Exception):
        self.e: Exception = e
        self.message = f'{self.message}. "{e}"'
        super().__init__(wmi_connection_settings)


class WMICoCreateInstanceException(WMIException):
    """
    Parent for WMI create instance exceptions raises when CoCreateInstanceEx() is failed.
    """
    pass


class WMICoCreateInstanceAccessDeniedException(WMICoCreateInstanceException):
    """
    Could not auth to the target host for a reason: access denied
    """
    message = 'CoCreateInstanceEx() failed. Access Denied'

    def __init__(self, wmi_connection_settings: WMIConnectionSettings):
        self.wmi_connection_settings: WMIConnectionSettings = wmi_connection_settings
        self.message = f'{self.message}. target={self.wmi_connection_settings.target}. ' \
            f'username={self.wmi_connection_settings.ad_settings.username} ' \
            f'password={self.wmi_connection_settings.ad_settings.password} ' \
            f'domain={self.wmi_connection_settings.ad_settings.domain}'
        # a WMI CoCreateInstance exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')


class WMICoCreateInstanceUnknownException(WMICoCreateInstanceException):
    """
    CoCreateInstanceEx() was failed for an unknown exception
    """
    message = "CoCreateInstanceEx() failed: an unknown exception"

    def __init__(self, wmi_connection_settings: WMIConnectionSettings, e: Exception):
        self.wmi_connection_settings: WMIConnectionSettings = wmi_connection_settings
        self.e: Exception = e
        self.message = f'{self.message}. "{e}"'
        # a WMI CoCreateInstance exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')


class WMICoCreateInstanceSocketTimeoutException(WMICoCreateInstanceException):
    """
    CoCreateInstanceEx() was failed for an socket timeout exception
    """
    message = "CoCreateInstanceEx() failed: socket timeout"

    def __init__(self, wmi_connection_settings: WMIConnectionSettings):
        self.wmi_connection_settings: WMIConnectionSettings = wmi_connection_settings
        self.message = f'{self.message}. target={self.wmi_connection_settings.target}. '
        # a WMI CoCreateInstance exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')


class WMIIWbemLevel1LoginException(WMIException):
    """
    Parent class for IWbemLevel1Login exceptions
    """
    pass


class WMIIWbemLevel1LoginInitException(WMIIWbemLevel1LoginException):
    """
    Parent for __init___ method of IWbemLevel1Login exceptions
    """
    pass


class WMIIWbemLevel1LoginInitUnknownException(WMIIWbemLevel1LoginInitException):
    """
    An unknown exception has occurred when IWbemLevel1Login.__init__
    """
    message = "An unknown exception has occurred when IWbemLevel1Login.__init__"

    def __init__(self, wmi_connection_settings: WMIConnectionSettings, e: Exception):
        self.wmi_connection_settings: WMIConnectionSettings = wmi_connection_settings
        self.e: Exception = e
        self.message = f'{self.message}. "{e}"'
        # a WMI IWbemLevel1Login exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')


class WMINTLMLoginException(WMIIWbemLevel1LoginException):
    """
    Parent for IWbemLevel1Login.NTLMLogin() exceptions
    """
    pass


class WMINTLMLoginNoAnswerException(WMINTLMLoginException):
    """
    IWbemLevel1Login.NTLMLogin() failed. host answer timeout
    *Could not connect: [WinError 10060]
    Попытка установить соединение была безуспешной,
    т.к. от другого компьютера за требуемое время не получен нужный отклик,
    или было разорвано уже установленное соединение из-за неверного отклика уже подключенного компьютера*
    """
    message = "Could not connect: [WinError 10060] host answer timeout"

    def __init__(self, wmi_connection_settings: WMIConnectionSettings):
        self.wmi_connection_settings: WMIConnectionSettings = wmi_connection_settings
        self.message = f'{self.message}. target={self.wmi_connection_settings.target}. '
        # a WMI NTLMLogin exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')


class WMINTLMLoginTimeoutException(WMINTLMLoginException):
    """
    IWbemLevel1Login.NTLMLogin() failed. Connection timeout
    """
    message = "Could not connect: [Errno 110] Connection timed out"

    def __init__(self, wmi_connection_settings: WMIConnectionSettings):
        self.wmi_connection_settings: WMIConnectionSettings = wmi_connection_settings
        self.message = f'{self.message}. target={self.wmi_connection_settings.target}. '
        # a WMI NTLMLogin exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')


class WMINTLMLoginWbemAccessDenied(WMINTLMLoginException):
    """
    IWbemLevel1Login.NTLMLogin() faled. WMI Session Error: code: 0x80041003 - WBEM_E_ACCESS_DENIED
    """
    message = "WMI Session Error: code: 0x80041003 - WBEM_E_ACCESS_DENIED"

    def __init__(self, wmi_connection_settings: WMIConnectionSettings):
        self.wmi_connection_settings: WMIConnectionSettings = wmi_connection_settings
        self.message = f'{self.message}. target={self.wmi_connection_settings.target}. '
        # a WMI NTLMLogin exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')


class WMINTLMLoginUnknownException(WMINTLMLoginException):
    """
    An unknown exception has occurred when IWbemLevel1Login.NTLMLogin()
    """
    message = "An unknown exception has occurred when IWbemLevel1Login.NTLMLogin()"

    def __init__(self, wmi_connection_settings: WMIConnectionSettings, e: Exception):
        self.wmi_connection_settings: WMIConnectionSettings = wmi_connection_settings
        self.e: Exception = e
        self.message = f'{self.message}. "{e}"'
        # a WMI IWbemLevel1Login.NTLMLogin exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')


class WMIQueryException(WMIException):
    """
    Parent for WMI query exceptions
    """
    pass


class WMIQueryInvalidClassException(WMIQueryException):
    """
    WMI query *0x80041010 - WBEM_E_INVALID_CLASS* error
    """
    message = "WMI query 0x80041010 - WBEM_E_INVALID_CLASS error"

    def __init__(self, wmi_query_string: str):
        self.wmi_query_string: str = wmi_query_string
        self.message = f'{self.message}. "{self.wmi_query_string}"'
        # a WMI query exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')


class WMIQueryInvalidQueryException(WMIQueryException):
    """
    WMI query *0x80041017 - WBEM_E_INVALID_QUERY* error
    """
    message = "WMI query 0x80041017 - WBEM_E_INVALID_QUERY error"

    def __init__(self, wmi_query_string: str):
        self.wmi_query_string: str = wmi_query_string
        self.message = f'{self.message}. "{self.wmi_query_string}"'
        # a WMI query exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')


class WMIQueryUnknownException(WMIQueryException):
    """
    WMI query unknown error
    """
    message = "WMI query unknown error"

    def __init__(self, wmi_query_string: str, e: Exception):
        self.wmi_query_string: str = wmi_query_string
        self.e: Exception = e
        self.message = f'{self.message}. "{self.wmi_query_string}". "{e}"'
        # a WMI query exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')


class WMIEnumNextUnknownException(WMIException):
    """
    WMI *iEnumWbemClassObject.Next(0xffffffff, 1)[0]* failed via unknown exception
    """
    message = "iEnumWbemClassObject.Next(0xffffffff, 1)[0] failed via unknown exception"

    def __init__(self, e: Exception):
        self.e: Exception = e
        self.message = f'{self.message}. "{e}"'
        # a WMI enum next unknown exception needed to be written to log as warning
        self.logger.warning(self._get_log_message())
        super().__init__(f'{self._get_log_message()}')
