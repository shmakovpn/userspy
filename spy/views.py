"""
usespy project spy/views.py

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-12
"""
import os
import json
from django.conf import settings
from django.shortcuts import render
from django.views import View
from django.urls import reverse, reverse_lazy
from django.http import HttpResponse, HttpResponseBadRequest
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.timezone import now
from datetime import timedelta
from django.db.models.query import QuerySet  # type hints
from django.db.models import Max
from django.core.exceptions import ValidationError
from spy.models import UserTask, TaskLog, IpStatus, HeartBeat


class Index(LoginRequiredMixin, View):
    login_url = reverse_lazy('login-gssapi')

    def get(self, request):
        context = {
            'package': __package__,
        }
        return render(request, f'{__package__}/index.html', context)


def get_ip_status(ip: str) -> str:
    try:
        ip_status = IpStatus.objects.get(ip=ip)
        if not ip_status.ping:
            return 'No ping'
        if ip_status.error:
            return 'Error'
        if ip_status.activity:
            return 'Green'
        if ip_status.activity_dt and ((now() - ip_status.activity_dt) < timedelta(minutes=settings.USERSPY_GREEN_PERIOD)):
            return 'Green'
        if ip_status.activity_dt and ((now() - ip_status.activity_dt) < timedelta(minutes=settings.USERSPY_YELLOW_PERIOD)):
            return 'Yellow'
        return 'Red'
    except IpStatus.DoesNotExist:
        return 'Unknown'


class ActiveTasks(View):
    def get(self, request):
        if not request.user.is_authenticated:
            return HttpResponse(json.dumps({
                'success': False,
                'message': 'Unauthorized',
            }), status=401)
        active_tasks: QuerySet = UserTask.objects.filter(
            user=request.user,
            created__lt=now(),
            deadline__gt=now(),
            removed=False,
        )  # todo active_tasks not sorted
        if (now() - HeartBeat.get().updated) < timedelta(minutes=settings.USERSPY_HEARTBEAT_INTERVAL):
            return HttpResponse(
                json.dumps({
                    'success': True,
                    'active_tasks' : list(
                        map(
                            lambda task: {
                                'id': task.id,
                                'ip': task.ip,
                                'desc': task.desc,
                                'created': str(task.created),
                                'deadline': str(task.deadline),
                                'status': get_ip_status(task.ip),
                            },
                            active_tasks
                        )
                    )
                }),
                status=200
            )
        else:
            return HttpResponse(
                json.dumps({
                    'success': False,
                    'heartbeat': False,
                }),
                status=200
            )


class AddTask(View):
    def post(self, request):
        if not request.user.is_authenticated:
            return HttpResponse(json.dumps({
                'success': False,
                'message': 'Unauthorized',
            }), status=401)
        body_str: str = request.body.decode('utf8')
        try:
            body = json.loads(body_str)
        except json.decoder.JSONDecodeError as e:
            response = {
                'success': False,
                'message': f'Request body JSON decode error: "{e}"',
            }
            return HttpResponseBadRequest(json.dumps(response))
        ip: str = body['ip']
        desc: str = body['desc']
        task: UserTask = UserTask(
            user=request.user,
            ip=ip,
            desc=desc,
        )
        try:
            task.full_clean()
        except ValidationError as e:
            response = {
                'success': False,
                'message': f'ValidationError: {e}',
            }
            return HttpResponseBadRequest(json.dumps(response))
        task.save()
        return HttpResponse(
            json.dumps({
                'success': True,
            }),
            status=201
        )


class DeleteTask(View):
    def post(self, request):
        if not request.user.is_authenticated:
            return HttpResponse(json.dumps({
                'success': False,
                'message': 'Unauthorized',
            }), status=401)
        body_str: str = request.body.decode('utf8')
        try:
            body = json.loads(body_str)
        except json.decoder.JSONDecodeError as e:
            response = {
                'success': False,
                'message': f'Request body JSON decode error: "{e}"',
            }
            return HttpResponseBadRequest(json.dumps(response))
        try:
            user_task = UserTask.objects.get(id=body['id'])
        except UserTask.DoesNotExist as e:
            return HttpResponseBadRequest({
                'success': False,
                'message': f'The id="{body["id"]}" does not exist',
            })
        user_task.removed = True
        user_task.save()
        return HttpResponse(
            json.dumps({
                'success': True,
            }),
            status=200
        )


