"""Ограниченный кэш с вытеснением по давности использования и времени жизни и
тревогой при заполнении. Пригоден, например, для кэша базовой линии анализатора,
чтобы не запрашивать хранилище логов на каждый разбор. Часы инъектируемы для
детерминированной проверки.
"""
from __future__ import annotations

import time
from collections import OrderedDict


class BoundedCache:
    def __init__(self, capacity: int, ttl_seconds: float, on_alarm=None,
                 alarm_ratio: float = 0.8, clock=time.monotonic):
        self.capacity = max(1, int(capacity))
        self.ttl = float(ttl_seconds)
        self.on_alarm = on_alarm
        self.alarm_ratio = alarm_ratio
        self._clock = clock
        self.store: OrderedDict = OrderedDict()   # key -> (value, expires_at)
        self._alarmed = False

    def get(self, key):
        item = self.store.get(key)
        if item is None:
            return None
        value, exp = item
        if self._clock() >= exp:
            del self.store[key]
            return None
        self.store.move_to_end(key)   # обновляем давность использования
        return value

    def set(self, key, value) -> None:
        exp = self._clock() + self.ttl
        self.store[key] = (value, exp)
        self.store.move_to_end(key)
        # Вытеснение по времени жизни (ленивое) и по давности при переполнении.
        while len(self.store) > self.capacity:
            self.store.popitem(last=False)   # наименее недавно использованный
        self._check_alarm()

    def _check_alarm(self) -> None:
        ratio = len(self.store) / self.capacity
        if ratio >= self.alarm_ratio and not self._alarmed:
            self._alarmed = True
            if self.on_alarm:
                self.on_alarm(len(self.store), self.capacity)
        elif ratio < self.alarm_ratio:
            self._alarmed = False

    def __len__(self) -> int:
        return len(self.store)
