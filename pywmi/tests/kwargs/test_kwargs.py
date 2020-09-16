"""
Tests for class KwargsObject from kwargs.py

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2019-08-06
"""
from unittest import TestCase
from kwargs import KwargsObject


class TestKwargs(TestCase):
    """
    Testing KwargsObject class
    """
    def test_kwargs(self):
        class Foo(KwargsObject):
            class_member: str = 'class member value'
            __hidden_class_member: str = 'hidden class member value'

            def __init__(self):
                self.instance_member: str = 'instance member value'
                self.__hidden_instance_member: str = 'hidden instance member value'
        foo: Foo = Foo()
        self.assertEqual(
            foo.kwargs(), {'class_member': 'class member value', 'instance_member': 'instance member value'}
        )

        class Bar(Foo):
            bar_class_member: str = 'bar class member value'
            __bar_hidden_class_member: str = 'bar class hidden class member value'

            def __init__(self):
                self.bar_instance_member: str = 'bar instance member value'
                self.__bar_hidden_instance_member: str = 'bar hidden instance member value'
                super().__init__()
        bar: Bar = Bar()
        self.assertEqual(
            bar.kwargs(), {
                'bar_class_member': 'bar class member value',
                'bar_instance_member': 'bar instance member value',
                'class_member': 'class member value',
                'instance_member': 'instance member value'
            },
        )
