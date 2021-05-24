from datetime import timedelta
from typing import Union, Optional, Any

import redis
from flask import Flask


class RedisClient:
    CONFIG_NAME = "REDIS_URL"

    def __init__(self):
        self._redis_client: redis.Redis = redis.Redis
        self.keys = None
        self.copied_keys = []

    def init_app(self, app: Flask, url=None):
        redis_url = url if url else app.config.get(RedisClient.CONFIG_NAME)
        self._redis_client = self._redis_client.from_url(redis_url)

    def scan_pattern(self, pattern: str) -> None:
        self.keys = self._redis_client.scan_iter(pattern)

    def get_after_scan(self) -> Optional[dict]:
        try:
            key = next(self.keys)
            value = self._redis_client.get(key)
            self.copied_keys.append(key)
            return {"key": key, "value": value}
        except StopIteration as e:
            return None

    def set(self, key: Any, value: Any, ex: Union[int, timedelta] = None, ) -> None:
        self._redis_client.set(name=key, value=value, ex=ex)

    def clear_cache(self) -> None:
        for key in self.copied_keys:
            self._redis_client.delete(key)
        self.keys = None
        self.copied_keys = []

    def get_by_key(self, key: any) -> str:
        return self._redis_client.get(name=key)

    def flushall(self) -> None:
        self._redis_client.flushall()

    def disconnect(self) -> None:
        self._redis_client.connection_pool.disconnect()
