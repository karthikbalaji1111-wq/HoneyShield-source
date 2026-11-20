"""In-process event broadcaster for real-time detection event delivery.

Design
------
Each connected WebSocket/SSE client registers a subscriber with a
tenant_id and an ``asyncio.Queue``.  When a detection event is
persisted and committed, the service layer calls ``publish()`` which
enqueues the event into every tenant-matched subscriber queue.

Thread Safety
-------------
``publish()`` is called from **synchronous** service methods that run
in the ASGI thread-pool.  ``subscribe()`` and ``unsubscribe()`` are
called from **async** WebSocket/SSE handlers running in the event-loop
thread.  A ``threading.Lock`` protects the subscriber registry.  When
publishing from a sync thread, ``call_soon_threadsafe`` is used to
safely enqueue into the async queues.

Several replicas (HONEY-026)
----------------------------
With REDIS_URL set, ``publish()`` delivers to this process's clients first and then publishes
the event on the Redis channel ``hs:events``. A relay thread in every replica subscribes to
that channel and delivers messages from other replicas to its own clients (tenant filtering
happens at delivery, exactly as for local events). If Redis is unavailable, events still
reach clients on the replica that recorded them; the relay reconnects with backoff. The live
stream is best-effort by design: durable alerting uses the database outbox.
"""
from __future__ import annotations


import asyncio
import json
import logging
import threading
import uuid
from typing import Any

logger = logging.getLogger(__name__)


class _Subscriber:
    """Internal per-client subscriber state."""

    __slots__ = ("tenant_id", "queue", "loop")

    def __init__(
        self,
        tenant_id: int | None,
        queue: asyncio.Queue[dict[str, Any]],
        loop: asyncio.AbstractEventLoop | None,
    ) -> None:
        self.tenant_id = tenant_id
        self.queue = queue
        self.loop = loop


#: Process-local counters exposed on /metrics (HONEY-025/027).
STATS: dict[str, int] = {"dropped_events": 0, "rejected_subscriptions": 0, "published_events": 0,
                         "relayed_in": 0, "relay_publish_errors": 0}
CHANNEL = "hs:events"


class SubscriptionLimitError(RuntimeError):
    """Raised when the global or per-tenant live-stream connection cap is reached."""


def _safe_put(queue: asyncio.Queue[dict[str, Any]], event_data: dict[str, Any], tenant_id: int | None) -> None:
    """Enqueue an event safely, dropping the oldest item if the queue is full.

    This ensures that slow consumers never block the event pipeline and that
    the newest, most critical security threat signals are always retained.
    """
    try:
        queue.put_nowait(event_data)
    except asyncio.QueueFull:
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            queue.put_nowait(event_data)
        except asyncio.QueueFull:
            pass
        STATS["dropped_events"] += 1
        logger.warning(
            "Event queue overflow for subscriber (tenant_id=%s); dropped oldest event to retain newest threat signal",
            tenant_id,
        )


class EventBroadcaster:
    """Thread-safe, in-process event broadcaster.

    Tenant isolation: each subscriber declares a ``tenant_id``.  Events
    are delivered **only** to subscribers whose ``tenant_id`` matches the
    event's ``event_tenant_id``.  Subscribers with ``tenant_id=None``
    (SYSTEM_ADMIN) receive events from **all** tenants.
    """

    MAX_QUEUE_SIZE: int = 256
    #: Bounded live connections per process (HONEY-025). Durable alerting never depends on these.
    MAX_SUBSCRIBERS: int = 500
    MAX_SUBSCRIBERS_PER_TENANT: int = 25

    def __init__(self) -> None:
        self._subscribers: dict[int, _Subscriber] = {}
        self._next_id: int = 0
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._is_shutting_down: bool = False
        self.instance_id = uuid.uuid4().hex
        self._relay_thread: threading.Thread | None = None
        self._relay_stop = threading.Event()

    # ------------------------------------------------------------------
    # Subscriber management (called from async context)
    # ------------------------------------------------------------------

    def subscribe(self, tenant_id: int | None, queue: asyncio.Queue[dict[str, Any]]) -> int:
        """Register a subscriber and return its unique ID.

        Must be called from the event-loop thread (async context).
        Captures the event loop reference for this subscriber so that
        ``publish()`` can safely enqueue from sync threads to the correct loop.

        Args:
            tenant_id: The subscriber's tenant scope.  ``None`` means
                the subscriber receives events for all tenants
                (SYSTEM_ADMIN semantics).
            queue: An asyncio queue that will receive event dicts.

        Returns:
            A unique subscriber identifier used for ``unsubscribe()``.
        """
        running_loop = None
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        with self._lock:
            if len(self._subscribers) >= self.MAX_SUBSCRIBERS or (
                sum(1 for sub in self._subscribers.values() if sub.tenant_id == tenant_id)
                >= self.MAX_SUBSCRIBERS_PER_TENANT
            ):
                STATS["rejected_subscriptions"] += 1
                raise SubscriptionLimitError("Live stream connection limit reached")
            sub_id = self._next_id
            self._next_id += 1
            self._subscribers[sub_id] = _Subscriber(
                tenant_id=tenant_id, queue=queue, loop=running_loop
            )
            if running_loop is not None:
                self._loop = running_loop
            logger.debug(
                "Subscriber %d registered (tenant_id=%s, total=%d)",
                sub_id, tenant_id, len(self._subscribers),
            )
            return sub_id

    def unsubscribe(self, sub_id: int) -> None:
        """Remove a subscriber.  Thread-safe; idempotent."""
        with self._lock:
            removed = self._subscribers.pop(sub_id, None)
            if removed is not None:
                logger.debug(
                    "Subscriber %d removed (tenant_id=%s, remaining=%d)",
                    sub_id, removed.tenant_id, len(self._subscribers),
                )

    # ------------------------------------------------------------------
    # Publishing (called from sync service threads)
    # ------------------------------------------------------------------

    def publish(self, event_data: dict[str, Any], event_tenant_id: int) -> None:
        """Publish an event to all tenant-matched subscribers.

        Thread-safe.  Can be called from synchronous code running in a
        thread pool.  When called from outside the event-loop thread,
        ``call_soon_threadsafe`` is used on each subscriber's target loop
        with ``_safe_put`` to safely enqueue items without raising
        unhandled QueueFull in the loop.

        A publish failure for one subscriber never affects other
        subscribers or the caller.  Failures are logged, never raised.

        Args:
            event_data: Serialised event payload (dict).
            event_tenant_id: The tenant that owns the detection event.
        """
        if self._is_shutting_down:
            return
        self._deliver_local(event_data, event_tenant_id)
        self._publish_remote(event_data, event_tenant_id)

    def _publish_remote(self, event_data: dict[str, Any], event_tenant_id: int) -> None:
        from app.core import shared_state

        r = shared_state.client()
        if r is None:
            return
        try:
            r.publish(CHANNEL, json.dumps({"o": self.instance_id, "t": event_tenant_id, "e": event_data},
                                          default=str, separators=(",", ":")))
        except Exception as exc:  # noqa: BLE001 - never affects detection
            STATS["relay_publish_errors"] += 1
            shared_state.failed(exc)

    def handle_relay_message(self, raw: str | bytes) -> bool:
        """Deliver a message received from the cluster channel. Returns True if delivered."""
        try:
            msg = json.loads(raw)
            if msg.get("o") == self.instance_id:
                return False  # our own publish; already delivered locally
            tenant_id, event = msg["t"], msg["e"]
            if not isinstance(event, dict) or not isinstance(tenant_id, int):
                return False
        except (ValueError, KeyError, TypeError):
            logger.warning("Ignoring malformed live-stream relay message")
            return False
        STATS["relayed_in"] += 1
        self._deliver_local(event, tenant_id)
        return True

    # ------------------------------------------------------------------
    # Cluster relay (one thread per process, only when REDIS_URL is set)
    # ------------------------------------------------------------------

    def start_relay(self) -> bool:
        from app.core import shared_state

        if not shared_state.configured() or (self._relay_thread and self._relay_thread.is_alive()):
            return False
        self._relay_stop.clear()
        self._relay_thread = threading.Thread(target=self._relay_loop, name="hs-stream-relay", daemon=True)
        self._relay_thread.start()
        return True

    def stop_relay(self, timeout: float = 3.0) -> None:
        self._relay_stop.set()
        if self._relay_thread is not None:
            self._relay_thread.join(timeout)
            self._relay_thread = None

    def _relay_loop(self) -> None:
        import redis

        from app.core import shared_state
        from app.core.config import get_settings

        backoff = 1.0
        while not self._relay_stop.is_set():
            pubsub = None
            try:
                conn = redis.Redis.from_url(get_settings().redis_url, socket_connect_timeout=2, socket_timeout=5,
                                            health_check_interval=15, decode_responses=True)
                pubsub = conn.pubsub(ignore_subscribe_messages=True)
                pubsub.subscribe(CHANNEL)
                backoff = 1.0
                while not self._relay_stop.is_set():
                    message = pubsub.get_message(timeout=1.0)
                    if message and message.get("type") == "message":
                        self.handle_relay_message(message["data"])
            except Exception as exc:  # noqa: BLE001 - reconnect with backoff
                shared_state.failed(exc)
                self._relay_stop.wait(backoff)
                backoff = min(backoff * 2, 10.0)
            finally:
                if pubsub is not None:
                    try:
                        pubsub.close()
                    except Exception:  # noqa: BLE001
                        pass

    def _deliver_local(self, event_data: dict[str, Any], event_tenant_id: int) -> None:
        with self._lock:
            subs = list(self._subscribers.values())

        if not subs:
            return

        current_loop = None
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        for sub in subs:
            # Tenant isolation: skip subscribers from other tenants.
            # tenant_id=None means SYSTEM_ADMIN → receives all events.
            if sub.tenant_id is not None and sub.tenant_id != event_tenant_id:
                continue

            target_loop = sub.loop
            if target_loop is None or not target_loop.is_running():
                target_loop = getattr(sub.queue, "_loop", None) or self._loop

            try:
                if current_loop is not None and current_loop == target_loop:
                    _safe_put(sub.queue, event_data, sub.tenant_id)
                elif target_loop is not None and target_loop.is_running():
                    target_loop.call_soon_threadsafe(
                        _safe_put, sub.queue, event_data, sub.tenant_id
                    )
                else:
                    logger.debug("No active event loop available for subscriber %s", sub.tenant_id)
            except Exception:
                logger.warning(
                    "Failed to deliver event to subscriber", exc_info=True,
                )

    # ------------------------------------------------------------------
    # Lifecycle & Graceful Shutdown
    # ------------------------------------------------------------------

    def shutdown(self) -> None:
        """Signal all subscribers to shut down and clear all subscriptions."""
        self._is_shutting_down = True
        self.stop_relay()
        with self._lock:
            subs = list(self._subscribers.values())
            self._subscribers.clear()

        shutdown_event = {"type": "shutdown", "message": "Server shutting down"}
        for sub in subs:
            target_loop = sub.loop or getattr(sub.queue, "_loop", None) or self._loop
            try:
                if target_loop is not None and target_loop.is_running():
                    target_loop.call_soon_threadsafe(
                        _safe_put, sub.queue, shutdown_event, sub.tenant_id
                    )
                else:
                    _safe_put(sub.queue, shutdown_event, sub.tenant_id)
            except Exception:
                pass

    def reset(self) -> None:
        """Reset broadcaster state (primarily for test isolation)."""
        with self._lock:
            self._subscribers.clear()
            self._next_id = 0
            self._loop = None
            self._is_shutting_down = False

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def is_shutting_down(self) -> bool:
        """Return whether the broadcaster is currently shutting down."""
        return self._is_shutting_down

    @property
    def subscriber_count(self) -> int:
        """Return the current number of active subscribers."""
        with self._lock:
            return len(self._subscribers)


# ------------------------------------------------------------------
# Module-level singleton
# ------------------------------------------------------------------

_broadcaster: EventBroadcaster | None = None
_broadcaster_lock = threading.Lock()


def get_broadcaster() -> EventBroadcaster:
    """Return the process-wide ``EventBroadcaster`` singleton."""
    global _broadcaster
    if _broadcaster is None:
        with _broadcaster_lock:
            if _broadcaster is None:
                _broadcaster = EventBroadcaster()
    return _broadcaster
