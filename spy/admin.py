"""
userspy project spy/admin.py

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-13
"""
from django.contrib import admin
from spy.models import UserTask


class UserTaskAdmin(admin.ModelAdmin):
    pass


admin.site.register(UserTask, UserTaskAdmin)
