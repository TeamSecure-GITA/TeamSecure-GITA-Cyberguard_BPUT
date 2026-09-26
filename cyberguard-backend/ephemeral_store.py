"""Expiring one-time state with optional Redis-backed multi-instance sharing."""
import base64
import hashlib
import json
import math
import os
import threading
import time
import uuid
from typing import Any


_INCREMENT_FIELD_SCRIPT = """
local raw = redis.call('GET', KEYS[1])
if not raw then return nil end
local value = cjson.decode(raw)
value[ARGV[1]] = (tonumber(value[ARGV[1]]) or 0) + 1
local ttl = redis.call('TTL', KEYS[1])
if ttl > 0 then
  redis.call('SET', KEYS[1], cjson.encode(value), 'EX', ttl)
else
  redis.call('SET', KEYS[1], cjson.encode(value))
end
return value[ARGV[1]]
"""

_POP_IF_FIELD_SCRIPT = """
local raw = redis.call('GET', KEYS[1])
if not raw then return nil end
local value = cjson.decode(raw)
if tostring(value[ARGV[1]]) ~= ARGV[2] then return nil end
redis.call('DEL', KEYS[1])
return raw
"""

_POP_SCRIPT = """
local raw = redis.call('GET', KEYS[1])
if raw then redis.call('DEL', KEYS[1]) end
return raw
"""

_RECORD_WINDOW_SCRIPT = """
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('EXPIRE', KEYS[1], math.ceil(window))
return redis.call('ZCARD', KEYS[1])
"""


def _json_default(value):
    if isinstance(value, bytes):
        return {"__cyberguard_bytes__": base64.b64encode(value).decode("ascii")}
    raise TypeError(f"Unsupported transient state value: {type(value).__name__}")


def _json_object_hook(value):
    if set(value) == {"__cyberguard_bytes__"}:
        return base64.b64decode(value["__cyberguard_bytes__"])
    return value


class EphemeralStore:
    def __init__(self, redis_client=None, clock=time.time, default_ttl_seconds: int = 300):
        self._redis = redis_client
        self._clock = clock
        self._default_ttl_seconds = default_ttl_seconds
        self._values: dict[str, tuple[float, str]] = {}
        self._windows: dict[str, list[float]] = {}
        self._lock = threading.RLock()

    @classmethod
    def from_environment(cls):
        redis_url = os.getenv("CYBERGUARD_REDIS_URL", "").strip()
        if not redis_url:
            if os.getenv("CYBERGUARD_ENV", "development").lower() == "production":
                raise RuntimeError("CYBERGUARD_REDIS_URL is required in production for shared OTP, passkey, and rate-limit state")
            return cls()
        try:
            import redis
        except ImportError as error:
            raise RuntimeError("CYBERGUARD_REDIS_URL requires redis>=5.0 in backend requirements") from error
        client = redis.Redis.from_url(redis_url, decode_responses=False, socket_connect_timeout=2, socket_timeout=2)
        try:
            client.ping()
        except redis.RedisError as error:
            raise RuntimeError("CYBERGUARD_REDIS_URL is configured but Redis is unavailable") from error
        return cls(redis_client=client)

    @property
    def backend(self) -> str:
        return "redis" if self._redis is not None else "process-local-memory"

    def _encode(self, value: Any) -> str:
        return json.dumps(value, default=_json_default, separators=(",", ":"))

    def _decode(self, value: bytes | str) -> Any:
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        return json.loads(value, object_hook=_json_object_hook)

    def _ttl(self, value: Any, ttl_seconds: float | None) -> int:
        if isinstance(value, dict) and value.get("expires_at") is not None:
            until_expiry = float(value["expires_at"]) - self._clock()
            ttl_seconds = until_expiry if ttl_seconds is None else min(ttl_seconds, until_expiry)
        if ttl_seconds is None:
            ttl_seconds = self._default_ttl_seconds
        return max(0, math.ceil(ttl_seconds))

    def set(self, key: str, value: Any, ttl_seconds: float | None = None) -> None:
        ttl = self._ttl(value, ttl_seconds)
        if ttl <= 0:
            self.pop(key)
            return
        encoded = self._encode(value)
        if self._redis is not None:
            self._redis.set(key, encoded, ex=ttl)
            return
        with self._lock:
            self._values[key] = (self._clock() + ttl, encoded)

    def get(self, key: str, default=None):
        if self._redis is not None:
            value = self._redis.get(key)
            return default if value is None else self._decode(value)
        with self._lock:
            entry = self._values.get(key)
            if entry is None:
                return default
            expires_at, encoded = entry
            if expires_at <= self._clock():
                self._values.pop(key, None)
                return default
            return self._decode(encoded)

    def pop(self, key: str, default=None):
        if self._redis is not None:
            value = self._redis.eval(_POP_SCRIPT, 1, key)
            return default if value is None else self._decode(value)
        with self._lock:
            entry = self._values.pop(key, None)
            if entry is None or entry[0] <= self._clock():
                return default
            return self._decode(entry[1])

    def pop_if(self, key: str, field: str, expected_value: Any) -> Any | None:
        if self._redis is not None:
            value = self._redis.eval(_POP_IF_FIELD_SCRIPT, 1, key, field, str(expected_value))
            return None if value is None else self._decode(value)
        with self._lock:
            entry = self._values.get(key)
            if entry is None or entry[0] <= self._clock():
                self._values.pop(key, None)
                return None
            value = self._decode(entry[1])
            if str(value.get(field)) != str(expected_value):
                return None
            self._values.pop(key, None)
            return value

    def increment_field(self, key: str, field: str) -> int | None:
        if self._redis is not None:
            value = self._redis.eval(_INCREMENT_FIELD_SCRIPT, 1, key, field)
            return None if value is None else int(value)
        with self._lock:
            entry = self._values.get(key)
            if entry is None or entry[0] <= self._clock():
                self._values.pop(key, None)
                return None
            expires_at, encoded = entry
            value = self._decode(encoded)
            value[field] = int(value.get(field, 0)) + 1
            self._values[key] = (expires_at, self._encode(value))
            return value[field]

    def record_window_event(self, key: str, now: float | None = None, window_seconds: int = 60) -> int:
        now = self._clock() if now is None else float(now)
        if self._redis is not None:
            digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
            count = self._redis.eval(_RECORD_WINDOW_SCRIPT, 1, f"window:{digest}", now, window_seconds, uuid.uuid4().hex)
            return int(count)
        with self._lock:
            events = [stamp for stamp in self._windows.get(key, []) if now - stamp < window_seconds]
            events.append(now)
            self._windows[key] = events
            return len(events)