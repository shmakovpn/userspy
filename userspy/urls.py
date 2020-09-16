"""
userspy project userspy/urls.py
"""
from django.contrib import admin
from django.urls import path

from login.views import Login, Logout, LoginGssapi
from spy.views import Index, ActiveTasks, AddTask, DeleteTask

urlpatterns = [
    path('', Index.as_view(), name='index'),
    path('login/', Login.as_view(), name='login'),
    path('logout/', Logout.as_view(), name='logout'),
    path('login/gssapi/', LoginGssapi.as_view(), name='login-gssapi'),
    path('tasks/', ActiveTasks.as_view(), name='active-tasks'),
    path('add/', AddTask.as_view(), name='add-task'),
    path('delete/', DeleteTask.as_view(), name='delete-task'),
    path('admin/', admin.site.urls),
    # path('debug/', Debug.as_view(), name='debug'),
]
