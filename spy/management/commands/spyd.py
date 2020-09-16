"""
userspy project spy/management/commands/spyd.py
runs userspy monitoring daemon

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-18
"""
# type hints
from typing import Set, Dict
from collections import OrderedDict
from impacket.dcerpc.v5.dcom.wmi import IWbemClassObject
# django
from django.core.management.base import BaseCommand
from django.utils.timezone import now
from django.conf import settings
from spy.models import UserTask, TaskLog, IpStatus, HeartBeat
# time
from time import sleep
# queues
from spy.growque import GrowDeque
# threaing
from threading import Thread
# wmi settings
from pywmi.wmi_settings import ADSettings, WMIConnectionSettings
# exceptions
from pywmi.wmi_exceptions.wmi_exception import WMIException
from pywmi.wmi_exceptions.wmi_connection_exceptions import WMIConnectionNoRouteToHostException, \
        WMIConnectionTimedOutException
from pywmi.wmi_exceptions.wmi_connection_exceptions import WMIEnumNextUnknownException
# wmi context managers
from pywmi.wmi_context_managers import wmi_connection, \
        wmi_interface, \
        wbem_level1_login, \
        wbem_services, \
        enum_wbem_class_object


class Command(BaseCommand):
    """
    Starts userspy monitoring daemon
    """
    help = """Starts userpsy monitoring daemon"""

    def handle(self, *args, **kwargs):
        ad_settings: ADSettings = ADSettings(
            username=settings.ADTOOLS_USER,
            password=settings.ADTOOLS_PASSWORD,
            domain=settings.ADTOOLS_DOMAIN,
        )
        threads: Dict[str, Thread] = {}
        wmi_query_string: str = 'SELECT ReadOperationCount FROM Win32_process WHERE name="csrss.exe"'

        def worker(ip):
            wmi_connection_settings: WMIConnectionSettings = WMIConnectionSettings(
                target=ip,
                ad_settings=ad_settings,
            )
            grow_deque = GrowDeque(maxlen=settings.USERSPY_ANALYSIS_DEEPNESS)
            thread_id: int = TaskLog.next_thread_id(ip)
            ip_status: IpStatus = IpStatus.objects.get_or_create(ip=ip)[0]
            while ip in threads:
                try:
                    with wmi_connection(
                        wmi_connection_settings
                    ) as dcom_connection:
                        with wmi_interface(
                            dcom_connection,
                            wmi_connection_settings
                        ) as iInterface:
                            with wbem_level1_login(
                                iInterface,
                                wmi_connection_settings
                            ) as iWbemLevel1Login:
                                with wbem_services(
                                    iWbemLevel1Login,
                                    wmi_connection_settings
                                ) as iWbemServices:
                                    last_sum_read_operation_count: int = 0
                                    while ip in threads:
                                        with enum_wbem_class_object(
                                            iWbemServices,
                                            wmi_query_string
                                        ) as iEnumWbemClassObject:
                                            sum_read_operation_count: int = 0  # sum of read operation count for all sessions
                                            while True:
                                                try:
                                                    pEnum: iWbemClassObject = iEnumWbemClassObject.Next(0xffffffff, 1)[0]
                                                except Exception as e:
                                                    if 'S_FALSE' not in str(e):
                                                        raise WMIEnumNextUnknownException(e)
                                                    else:
                                                        break
                                                record: OrderedDict = pEnum.getProperties()
                                                sum_read_operation_count += record['ReadOperationCount']['value']
                                            TaskLog.log_counter(ip, thread_id, sum_read_operation_count)  # write counter to the log
                                            grow_deque.append(sum_read_operation_count)
                                            if grow_deque.is_full_grow():
                                                ip_status.save_activity()
                                            else:
                                                ip_status.save_no_activity()
                                            sleep(settings.USERSPY_TIMEOUT)
                except (WMIConnectionNoRouteToHostException, WMIConnectionTimedOutException) as e:
                    TaskLog.log_no_ping(ip, thread_id)
                    ip_status.save_no_ping()
                except WMIException as e:
                    TaskLog.log_error(ip, thread_id, str(e))
                    ip_status.save_error(str(e))
                grow_deque.clear()
                sleep(settings.USERSPY_TIMEOUT)

        while True:
            ip_set: Set[str] = set(
                map(
                    lambda values: values[0],
                    UserTask.objects.filter(
                        created__lt=now(),
                        deadline__gt=now(),
                        removed=False
                    ).values_list('ip').distinct()
                )
            )
            thread_ip_set: Set[str] = set(threads.keys())
            new_ip_set: Set[str] = ip_set - thread_ip_set  # threads to start
            old_ip_set: Set[str] = thread_ip_set - ip_set  # threads to stop
            for ip in old_ip_set:
                del threads[ip]
            for ip in new_ip_set:
                threads[ip] = Thread(target=worker, args=(ip,))
                threads[ip].start()
            HeartBeat.update()
            sleep(settings.USERSPY_TIMEOUT)
