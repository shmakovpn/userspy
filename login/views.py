"""
userspy project login/views.py

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-11
"""
from typing import List
import os
from ldap.ldapobject import SimpleLDAPObject
from django.shortcuts import render, redirect
from django.views import View
from django.http import HttpResponse
from django.urls import reverse, reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin
from .forms import LoginForm
from django_adtools.models import DomainController
from django_adtools.ad_tools import ad_login, ad_clear_username, ldap_connect, user_dn, dn_groups
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
import logging


logger = logging.getLogger('userspy.login.views')
# logger.setLevel(logging.DEBUG)


class Login(View):
    def get(self, request):
        logger.warning(f'GET login form')
        form = LoginForm()
        context = {'package': __package__, 'form': form}
        return render(request, f'{__package__}/login.html', context)

    def post(self, request):
        logger.warning(f'POST login form')
        form = LoginForm(request.POST)
        if form.is_valid():
            logger.warning(f'POST login form is_valid=True')
            dc: str = DomainController.get()  # ip address of DomainController
            domain: str = settings.ADTOOLS_DOMAIN
            group: str = settings.ADTOOLS_GROUP
            username: str = form.cleaned_data['username']
            password: str = form.cleaned_data['password']
            if ad_login(
                dc=dc,
                username=username,
                password=password,
                domain=domain,
                group=group,
            ):
                logger.warning(f'POST login form ad_login=True dc={dc}, domain={domain}, group={group}, username={username}')
                username_without_domain = ad_clear_username(form.cleaned_data['username'])
                username = f'{username_without_domain}@{settings.ADTOOLS_DOMAIN}'
                try:
                    user = User.objects.get(username__iexact=username)
                except User.DoesNotExist:
                    user = User(username=username.lower())
                    user.save()
                login(request=request, user=user)
                return redirect(request.GET.get('next') or reverse('index'))
            else:
                logger.warning(f'POST login form ad_login=False dc={dc}, domain={domain}, group={group}, username={username}')
        else:
            logger.warning(f'POST login form, is_valid=False')
        context = {'package': __package__, 'form': form, 'login_failed': True}
        return render(request, f'{__package__}/login.html', context)


class Logout(View):
    def get(self, request):
        logger.warning(f'GET logout. username={request.user.username}')
        logout(request)
        return redirect(reverse('login'))



class LoginGssapi(View):
    def get(self, request):
        logger.warning(f'GET LoginGssapi. request.META["GSSNAME"]={request.META["GSS_NAME"]}. request.META["REMOTE_USER"]={request.META["REMOTE_USER"]}.')
        if 'GSS_NAME' in request.META:  # try login via SSO
            username: str = request.META['GSS_NAME'].lower()  # username@domain in lower case
            logger.warning(f'GET LoginGssapi username={username}')
            ldap_connection: SimpleLDAPObject  = ldap_connect(
                dc=DomainController.get(),
                username=settings.ADTOOLS_USER,
                password=settings.ADTOOLS_PASSWORD
            )
            dn: str = user_dn(ldap_connection, username, settings.ADTOOLS_DOMAIN)
            logger.warning(f'GET LoginGssapi username={username}, dn={dn}')
            groups: List[str] = dn_groups(ldap_connection, dn, settings.ADTOOLS_DOMAIN)
            logger.warning(f'GET LoginGssapi username={username}, groups={groups}')
            if not getattr(settings, 'ADTOOLS_GROUP', None) or settings.ADTOOLS_GROUP in groups:
                logger.warning(f'GET LoginGssapi usrename={username} authenticated')
                try:
                    user = User.objects.get(username__iexact=username)
                except User.DoesNotExist:
                    user = User(username=username.lower())
                    user.save()
                login(request=request, user=user)
                return redirect(request.GET.get('next') or reverse('index'))
            logger.warning(f'GET LoginGssapi username={username}, groups check failed, login failed')
        return redirect(reverse('login'))  # redirect to login page using username and password


class RedirectToLogin(View):
    def get(self, request):
        return redirect(reverse('login'))  # redirect to login page using username and password
