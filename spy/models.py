"""
userspy project spy/models.py

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-13
"""
from datetime import timedelta
from django.utils.timezone import now
from django.conf import settings
from django.db import models
from django.contrib.auth.models import User
from django.core.validators import validate_ipv4_address
from django.core.exceptions import ValidationError


def get_task_default_deadline():
    default_period: timedelta = getattr(settings, 'USERSPY_DEFAULT_PERIOD', timedelta(weeks=1))
    return now() + default_period


class UserTask(models.Model):
    user = models.ForeignKey(to=User, on_delete=models.CASCADE, null=False, blank=False)
    ip = models.CharField(validators=[validate_ipv4_address], null=False, max_length=15, blank=False)
    desc = models.TextField(null=False, default='', blank=True)
    created = models.DateTimeField(auto_now_add=True, null=False, blank=True)
    deadline = models.DateTimeField(null=False, default=get_task_default_deadline, blank=True)
    removed = models.BooleanField(null=False, default=False, blank=True)

    def __str__(self):
        return f"UserTask(user='{self.user.username}', ip='{self.ip}', deadline='{self.deadline}', " \
            f"created='{self.created}', removed={self.removed}, desc='{self.desc}'"


class TaskLog(models.Model):
    ip = models.CharField(validators=[validate_ipv4_address], null=False, max_length=15, blank=False)
    created = models.DateTimeField(auto_now_add=True, null=False, blank=True)
    thread_id = models.IntegerField(null=False, blank=False)
    counter = models.IntegerField(null=True, blank=True)
    no_ping = models.BooleanField(null=True, blank=True)
    error = models.BooleanField(null=True, blank=True)
    error_msg = models.TextField(null=True, blank=True)

    def clean(self):
        if not self.counter and not self.no_ping and not self.error:
            raise ValidationError(f"counter='{self.counter}', no_ping='{self.no_ping}', error='{self.error}'")
        if self.counter and self.no_ping:
            raise ValidationError(f"counter='{self.counter}', no_ping='{self.no_ping}'")
        if self.counter and self.error:
            raise ValidationError(f"counter='{self.counter}', error='{self.error}'")
        if self.no_ping and self.error:
            raise ValidationError(f"no_ping='{self.no_ping}', error='{self.error}'")
        if self.error and not self.error_msg:
            raise ValidationError(f"error='{self.error}', error_msg='{self.error_msg}'")

    @staticmethod
    def next_thread_id(ip: str) -> int:
        max_ip_thread_id: int = TaskLog.objects.filter(ip=ip).aggregate(models.Max('thread_id'))['thread_id__max']
        if max_ip_thread_id:
            return max_ip_thread_id+1
        return 1

    @staticmethod
    def log_counter(ip: str, thread_id: int, counter: int) -> None:
        task_log_record: TaskLog = TaskLog(
            ip=ip,
            thread_id=thread_id,
            counter=counter,
            no_ping=False,
            error=False,
            error_msg=None
        )
        task_log_record.full_clean()
        task_log_record.save()

    @staticmethod
    def log_no_ping(ip: str, thread_id: int) -> None:
        task_log_record: TaskLog = TaskLog(
            ip=ip,
            thread_id=thread_id,
            counter=None,
            no_ping=True,
            error=False,
            error_msg=None
        )
        task_log_record.full_clean()
        task_log_record.save()

    @staticmethod
    def log_error(ip: str, thread_id: int, error_msg: str) -> None:
        task_log_record: TaskLog = TaskLog(
            ip=ip,
            thread_id=thread_id,
            counter=None,
            no_ping=False,
            error=True,
            error_msg=error_msg
        )
        task_log_record.full_clean()
        task_log_record.save()


class IpStatus(models.Model):
    ip = models.CharField(validators=[validate_ipv4_address], null=False, max_length=15, blank=False)
    activity = models.BooleanField(null=True, blank=True)
    activity_dt = models.DateTimeField(null=True, blank=True)  # last activity datetime
    ping = models.BooleanField(null=True, blank=True)
    ping_dt = models.DateTimeField(null=True, blank=True)  # last success ping datetime
    no_ping_dt = models.DateTimeField(null=True, blank=True)  # last no ping datetime
    error = models.BooleanField(null=True, blank=True)
    error_dt = models.DateTimeField(null=True, blank=True)  # last error datetime
    no_error_dt = models.DateTimeField(null=True, blank=True)  # last no error datetime
    error_msg = models.TextField(null=True, blank=True)  # last error message

    def save_activity(self) -> None:
        self.activity = True
        self.activity_dt = now()
        self.ping = True
        self.ping_dt = now()
        self.error = False
        self.no_error_dt = now()
        self.save()

    def save_no_activity(self) -> None:
        self.activity = False
        self.ping = True
        self.ping_dt = now()
        self.error = False
        self.no_error_dt = now()
        self.save()

    def save_no_ping(self) -> None:
        self.activity = False
        self.ping = False
        self.no_ping_dt = now()
        self.error = False
        self.no_error_dt = now()
        self.save()

    def save_error(self, error_msg: str) -> None:
        self.activity = False
        self.ping = True
        self.ping_dt = now()
        self.error = True
        self.error_dt = now()
        self.error_msg = error_msg
        self.save()


class HeartBeat(models.Model):
    updated = models.DateTimeField(auto_now=True)
    counter = models.BigIntegerField(null=False, blank=True, default=0)
    started = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        self.counter += 1
        super().save(*args, **kwargs)

    @staticmethod
    def get():
        return HeartBeat.objects.get_or_create(id=1)[0]

    @staticmethod
    def start() -> None:
        heart_beat = HeartBeat.get()
        heart_beat.started = now()
        heart_beat.save()
        return heart_beat

    @staticmethod
    def update() -> None:
        heart_beat = HeartBeat.get()
        heart_beat.save()
        return heart_beat

    def __str__(self):
        return f'{self.__class__.__name__}: id={self.id}, updated="{self.updated}", started="{self.started}", counter={self.counter}'
