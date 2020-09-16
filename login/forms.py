"""
userspy project login/forms.py

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-11
"""
from django import forms


class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

