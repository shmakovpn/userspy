"""
This script provides KwargsObject class
"""
# type hints
from typing import Dict, Any
#
import re
from abc import ABCMeta


class KwargsObject(metaclass=ABCMeta):
    """
    Abstract base class provides **kwargs** method
    returns a dict of key words arguments contains
    names of members of **self** and its values.
    Not public members (members which named starts with **_**)
    will be skipped.
    """

    def kwargs(self) -> Dict[str, Any]:
        """
        Creates a dict of key words arguments contains
        names of members of **self** and its values.

        Not public members (members which named starts with **_**) will be skipped.

        :return: A dict of key words arguments
        :rtype: Dict[str, Any]
        """
        public_members_names: Dict[str, Any] = {
            name: (getattr(self, name)) for name in dir(self) if
            not name.startswith('_')
            and 'method' not in getattr(type(getattr(self, name)), '__name__')
        }
        return public_members_names
