"""
Extends collections.deque:

 - provides **is_grow** method returning True if the queue is growing,
 and False otherwise

 - provides **is_full** method returning True if the length of self is
 equal to its maxlen

 - provides **is_full_grow** method returning True if the queue is growing
 and it is fulll

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-26
"""
from collections import deque


class GrowDeque(deque):
    """
    Extends collections.deque
    """
    def is_full(self) -> bool:
        """
        Returns True if the queue is full, the length of self is equal to its maxlen
        """
        return self.maxlen is not None and len(self)==self.maxlen

    def is_grow(self) -> bool:
        """
        Returns True if the queue is growing
        """
        return len(self)>1 and all( (self[i]<self[i+1] for i in range(len(self)-1)) )

    def is_full_grow(self) -> bool:
        """
        Returns True if the queue is growing and it is full
        """
        return self.is_full() and self.is_grow()
