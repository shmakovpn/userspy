"""
PROJECT_PATH/wsgi_test_script.py
This script is intended to check out that the WSGI is working.

Using
=====
uwsgi under Ubunto example
--------------------------
uwsgi --http :9090 --wsgi-file PROJECT_PATH/wsgi_test_script.py


Apache under Ubuntu example
---------------------------
Apache config file: /etc/apache2/sites-enabled/userspy.conf
1. Using VirtualHost and WSGIScriptAlias
WSGIPythonPath /var/www/userspy_site/  # path to project
WSGIPythonHome /home/shmakovpn/.virtualenvs/us36  # path to virtualenv
<VirtualHost *.80>
    ...
    WSGIScriptAlias /test_wsgi /var/www/userspy_site/wsgi_test_script.py  # path to this script
    WSGIScriptAlias / /var/www/userspy_site/userspy_site/wsgi.py  # path to the project wsgi.py
    <Directory /var/www/userspy_site/userspy_site>  # path to the project
        <Files wsgi.py>
            Require all granted
        </Files>
    </Directory>
    ...
</VirtualHost>
"""
__author__ = 'shmakovpn <shmakovpn@yandex.ru>'
__date__ = '2019-09-18'


import os
import stat
import sys
from subprocess import Popen, PIPE


def isfile(path):
    """Test whether a path is a regular file"""
    try:
        st = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode)



def application(environ, start_response):
    status = '200 OK'
    environ_str = ''
    for key, val in environ.items():
        environ_str += '<div>environ['+str(key)+']='+str(val)+'</div>\n'

    script_str = ''
    try:
        script_str += '<div>Проверка доступа к файлам названным по-русски</div>'
        fl = './тестовый_файл.txt'
        if isfile(fl):
            script_str += '<div>Тестовый файл \'' + fl + '\' существует</div>'
        else:
            script_str += '<div>Тестовый файл \'' + fl + '\' <b>не существует, а должен</b></div>'
    except Exception as e:
        script_str += '<div>Файлы названные по русски не поддерживаются: ' + str(e) + '</div>\n'
        script_str += '<div>Надо закоментировать строку LANG=C в \'/etc/sysconfig/httpd\'</div>\n'
    script_str += '<div><br /></div>'
    script_str += '<div>sys.getfilesystemencoding()=' + sys.getfilesystemencoding() + '</div>\n'
    script_str += '<div>os LANG=' + str(getattr(os.environ, 'LANG', 'undefined')) + '</div>\n'
    script_str += '<div><br /></div>'
    script_str += '<div>__file__=' + os.path.abspath(__file__) + '</div>\n'
    script_str += '<div><br /></div>'
    script_str += '<div>current working directory of the python process os.getcwd()=' + os.getcwd() + '</div>\n'
    script_str += '<div>os PWD=' + str(getattr(os.environ, 'PWD', 'undefined')) + '</div>\n'
    output = Popen(["/bin/bash", "-c","echo $PWD"], stdout=PIPE)
    response = output.communicate()
    script_str += '<div>os PWD (using `echo $PWD`)=' + str(response[0].decode()) + '</div>\n'
    script_str += '<div><br /></div>'
    script_str += '<div>python path=' + str(sys.path) + '</div>\n'
    script_str += '<div>os PATH=' + str(getattr(os.environ, 'PATH', 'undefined')) + '</div>\n'
    output = Popen(["/bin/bash", "-c","echo $PATH"], stdout=PIPE)
    response = output.communicate()
    script_str += '<div>os PATH (using `echo $PATH`)=' + str(response[0].decode()) + '</div>\n'
    #script_str += '<div><br /></div>'
    #script_str += '<div>Selinux test os.listxattr</div>'
    #src = '/var/www/ocr_server/django_ocr_server/upload'

    html = '<html>\n' \
           ' <head>\n' \
           '   <meta http-equiv="content-type" content="text/html; charset=utf-8" />\n' \
           ' </head>\n' \
           '<body>\n' \
           ' Userspy, mod_wsgi is working\n' \
           '<p>\n' \
           + script_str + \
           '</p>\n' \
           ' <p>\n' \
           + environ_str + \
           ' </p>\n' \
           '</body>\n' \
           '</html>\n'
    response_header = [('Content-type', 'text/html')]
    start_response(status, response_header)
    return [str.encode(html)]
