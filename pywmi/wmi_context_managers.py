"""
WMI context managers

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-11
"""
from typing import Optional, ContextManager
from contextlib import contextmanager
import socket
# impacket
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcom.wmi import IWbemLevel1Login, \
    IWbemServices, \
    IEnumWbemClassObject, \
    DCERPCSessionError, \
    IWbemClassObject
from impacket.dcerpc.v5.dcomrt import DCOMConnection, IRemUnknown2
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dcom.wmi import DCERPCSessionError
# settings
from pywmi.wmi_settings import ADSettings, WMIConnectionSettings
# exceptions
from pywmi.wmi_exceptions.wmi_connection_exceptions import WMIConnectionNoRouteToHostException, \
    WMIConnectionTimedOutException, \
    WMIConnectionNetworkUnreachableException, \
    WMIConnectionNoAnswerException, \
    WMIConnectionRefusedException, \
    WMIConnectionDCOMConnectionUnknownException, \
    WMICoCreateInstanceAccessDeniedException, \
    WMICoCreateInstanceUnknownException, \
    WMICoCreateInstanceSocketTimeoutException, \
    WMIIWbemLevel1LoginInitUnknownException, \
    WMINTLMLoginNoAnswerException, \
    WMINTLMLoginTimeoutException, \
    WMINTLMLoginUnknownException, \
    WMINTLMLoginWbemAccessDenied, \
    WMIQueryInvalidClassException, \
    WMIQueryInvalidQueryException, \
    WMIQueryUnknownException


@contextmanager
def wmi_connection(wmi_connection_settings: WMIConnectionSettings) -> ContextManager[DCOMConnection]:
    """
    Creates a DCOM connection context manager that establish a new connection and
    is guaranteed to close the connection when an exception is thrown or when a block of code **with** ends.

    :param wmi_connection_settings: settings needed to establish a new DCOM connection
    :type wmi_connection_settings: WMIConnectionSettings
    :return: A context manager for a DCOM connection
    :rtype: ContextManager[DCOMConnection]
    """
    dcom_connection: Optional[DCOMConnection] = None
    try:
        try:
            dcom_connection = DCOMConnection(
                **wmi_connection_settings.get_connection_settings_kwargs()
            )
        except DCERPCException as e:
            if e.error_string == 'Could not connect: [Errno 113] No route to host':
                raise WMIConnectionNoRouteToHostException(wmi_connection_settings)
            elif e.error_string == 'Could not connect: timed out':
                raise WMIConnectionTimedOutException(wmi_connection_settings)
            elif e.error_string == 'Could not connect: [Errno 101] Network is unreachable':
                raise WMIConnectionNetworkUnreachableException(wmi_connection_settings)
            elif e.error_string.startswith('Could not connect: [WinError 10060]'):
                raise WMIConnectionNoAnswerException(wmi_connection_settings)
            elif e.error_string == 'Could not connect: [Errno 111] Connection refused':
                raise WMIConnectionRefusedException(wmi_connection_settings)
            else:
                raise WMIConnectionDCOMConnectionUnknownException(wmi_connection_settings, e)
        except Exception as e:
            raise WMIConnectionDCOMConnectionUnknownException(wmi_connection_settings, e)
        yield dcom_connection
    finally:
        if dcom_connection:
            try:
                dcom_connection.disconnect()
            except KeyError as e:
                if wmi_connection_settings.target in str(e):
                    pass
                else:
                    raise WMIConnectionDCOMConnectionUnknownException(wmi_connection_settings, e)


@contextmanager
def wmi_interface(
        dcom_connection: DCOMConnection, wmi_connection_settings: WMIConnectionSettings
) -> ContextManager[IRemUnknown2]:
    """
    Creates IRemUnknown2 context manager by performing DCOMConnection.CoCreateInstanceEx()

    :param dcom_connection:
    :type dcom_connection: DCOMConnection
    :param wmi_connection_settings: settings of wmi connection for logging and exceptions
    :type wmi_connection_settings: WMIConnectionSettings
    :return: A context manager for an IRemUnknown2
    :rtype: ContextManager[IRemUnknown2]
    """
    try:
        iInterface: IRemUnknown2 = dcom_connection.CoCreateInstanceEx(
            wmi.CLSID_WbemLevel1Login,
            wmi.IID_IWbemLevel1Login
        )
    except DCERPCException as e:
        if e.error_string == 'rpc_s_access_denied':
            raise WMICoCreateInstanceAccessDeniedException(wmi_connection_settings)
        else:
            raise WMICoCreateInstanceUnknownException(wmi_connection_settings, e)
    except socket.timeout as e:
        raise WMICoCreateInstanceSocketTimeoutException(wmi_connection_settings)
    except Exception as e:
        raise WMICoCreateInstanceUnknownException(wmi_connection_settings, e)
    yield iInterface


@contextmanager
def wbem_level1_login(
        iInterface: IRemUnknown2, wmi_connection_settings: WMIConnectionSettings
) -> ContextManager[IWbemLevel1Login]:
    """
    Creates IWbemLevel1Login context manager

    :param iInterface: wmi unknown interface
    :type iInterface: IRemUnknown2
    :param wmi_connection_settings: settings of wmi connection for logging and exceptions
    :type wmi_connection_settings: WMIConnectionSettings
    :return: A context manager for an IWbemLevel1Login
    :rtype: ContextManager[IWbemLevel1Login]
    """
    try:
        iWbemLevel1Login: IWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
    except Exception as e:
        raise WMIIWbemLevel1LoginInitUnknownException(wmi_connection_settings, e)
    yield iWbemLevel1Login


@contextmanager
def wbem_services(
        iWbemLevel1Login: IWbemLevel1Login, wmi_connection_settings: WMIConnectionSettings
) -> ContextManager[IWbemServices]:
    """
    Creates IWbemServices context manager

    :param iWbemLevel1Login: wmi wbem level 1 login interface
    :type iWbemLevel1Login: IWbemLevel1Login
    :param wmi_connection_settings: settings of wmi connection for logging and exceptions
    :type wmi_connection_settings: WMIConnectionSettings
    :return: A context manager for an IWbemServices
    :rtype: ContextManager[IWbemServices]
    """
    try:
        iWbemServices: IWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
    except DCERPCSessionError as e:
        if 'WMI Session Error: code: 0x80041003 - WBEM_E_ACCESS_DENIED' in str(e):
            raise WMINTLMLoginWbemAccessDenied(wmi_connection_settings)
        else:
            raise WMINTLMLoginUnknownException(wmi_connection_settings, e)
    except DCERPCException as e:
        if e.error_string.startswith('Could not connect: [WinError 10060]'):
            raise WMINTLMLoginNoAnswerException(wmi_connection_settings)
        elif e.error_string == 'Could not connect: [Errno 110] Connection timed out':
            raise WMINTLMLoginTimeoutException(wmi_connection_settings)
        else:
            raise WMINTLMLoginUnknownException(wmi_connection_settings, e)
    except Exception as e:
        raise WMINTLMLoginUnknownException(wmi_connection_settings, e)
    yield iWbemServices


@contextmanager
def enum_wbem_class_object(
        iWbemServices: IWbemServices, wmi_query_string: str
) -> ContextManager[IEnumWbemClassObject]:
    """
    Creates IEnumWbemClassObject context manager

    :param iWbemServices: wmi wbem services interface
    :type iWbemServices: IWbemServices
    :param wmi_query_string: wmi query string
    :type wmi_query_string: str
    :return: A context manager for an IEnumWbemClassObject
    :rtype: ContextManager[IEnumWbemClassObject]
    """
    try:
        iEnumWbemClassObject: IEnumWbemClassObject = iWbemServices.ExecQuery(wmi_query_string)
    except DCERPCSessionError as e:
        if '0x80041010 - WBEM_E_INVALID_CLASS' in str(e):
            raise WMIQueryInvalidClassException(wmi_query_string)
        elif '0x80041017 - WBEM_E_INVALID_QUERY' in str(e):
            raise WMIQueryInvalidQueryException(wmi_query_string)
        else:
            raise WMIQueryUnknownException(wmi_query_string, e)
    except Exception as e:
        raise WMIQueryUnknownException(wmi_query_string, e)
    yield iEnumWbemClassObject
    try:
        iEnumWbemClassObject.RemRelease()
    except Exception as e:
        raise WMIQueryUnknownException(wmi_query_string, e)
