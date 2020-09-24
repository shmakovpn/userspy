# The folder with secret data

## .gitignore configuration

Put into **.gitingore** rules to exclude from the repository
all files in **secret/** folder besides **README.md**

```
secret/*
!secret/README.md
```

## Usage example

Create a file *secret/secret_settings.py*

```python
"""
secret settings for userspy project
"""
import socket

if 'test' in socket.gethostname():
    # develop server
    def get_DATABASES():
        """returns DATABASES dict for settings of django"""
        return  {
            'default': {
                'ENGINE': 'django.db.backends.postgresql_psycopg2',
                'NAME': 'test',
                'USER': 'tester',
                'PASSWORD': 'tester',
                'HOST': 'localhost',
                'PORT': '',
            }
        }

    def get_ADTOOLS_DOMAIN():
        return 'test.com'

    def get_ADTOOLS_GROUP():
        return 'testers'

    def get_ADTOOLS_USER():
        return 'tester'

    def get_ADTOOLS_PASSWORD():
        return 'test-P@ssw0rd'

else:
    # production server
    def get_DATABASES():
        """returns DATABASES dict for settings of django"""
        return  {
            'default': {
                'ENGINE': 'django.db.backends.postgresql_psycopg2',
                'NAME': 'my_db',
                'USER': 'my_name',
                'PASSWORD': 'my_P@ssw0rd',
                'HOST': 'localhost',
                'PORT': '',
            }
        }

    def get_ADTOOLS_DOMAIN():
        return 'my.domain.com'

    def get_ADTOOLS_GROUP():
        return 'my_users'

    def get_ADTOOLS_USER():
        return 'my_user'

    def get_ADTOOLS_PASSWORD():
        return 'my_ad_P@ssw0rd'
```

Your_project/settings.py

```python
import secret.secret_settings  # Create secret/secret_setting.py file
# add in secret/secret_settings.py
# def get_DATABASES(): which will return a DATABASES dict for the Django project
# def get_ADTOOLS_DOMAIN(): which will return a name of a domain for the Django project
# def get_ADTOOLS_GROUP(): which will return a name of a domain group or None for the Django project
# def get_ADTOOLS_USER(): which will return an username of a domain for the Django project
# def get_ADTOOLS_PASSWORD(): which will return a password of a domain user for the Django project

# ...

DATABASES = secret.secret_settings.get_DATABASES()

# ...

# DJANGO_ADTOOLS
ADTOOLS_DOMAIN: str = secret.secret_settings.get_ADTOOLS_DOMAIN()
ADTOOLS_GROUP: str = secret.secret_settings.get_ADTOOLS_GROUP()
ADTOOLS_USER: str = secret.secret_settings.get_ADTOOLS_USER()
ADTOOLS_PASSWORD: str = secret.secret_settings.get_ADTOOLS_PASSWORD()
```
