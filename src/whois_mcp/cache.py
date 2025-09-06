from collections import OrderedDict
from typing import TypeVar, Optional, Generic
import time

K = TypeVar("K")
V = TypeVar("V")


class TTLCache(Generic[K, V]):
    """A Least Recently Used (LRU) cache with Time-To-Live (TTL) expiration."""

    def __init__(self, max_items: int = 512, ttl_seconds: float = 60.0) -> None:
        """Initialize the cache with max items and TTL in seconds."""
        self._max_items: int = max_items
        self._ttl: float = ttl_seconds
        self._data: OrderedDict[K, tuple[float, V]] = OrderedDict()

    def get(self, key: K) -> Optional[V]:
        """Retrieve a value from the cache by key."""
        item = self._data.get(key)
        if item is None:
            return None

        timestamp, value = item
        if time.perf_counter() - timestamp > self._ttl:
            self._data.pop(key, None)
            return None

        self._data.move_to_end(key)
        return value

    def set(self, key: K, value: V) -> None:
        """Store a key-value pair in the cache."""
        self._data[key] = (time.perf_counter(), value)
        self._data.move_to_end(key)
        if len(self._data) > self._max_items:
            self._data.popitem(last=False)

    def clear(self) -> None:
        """Remove all items from the cache."""
        self._data.clear()

    def __len__(self) -> int:
        """Return the current number of items in the cache."""
        return len(self._data)

    def __contains__(self, key: K) -> bool:
        """Check if a key exists in the cache and is not expired."""
        return self.get(key) is not None
