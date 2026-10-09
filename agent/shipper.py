import queue
import time
from typing import List, Dict, Any, Optional
import httpx


class EventShipper:
    def __init__(
        self,
        server_url: str,
        api_key: str,
        batch_size: int = 50,
        flush_interval_seconds: float = 5.0,
        max_queue_size: int = 1000,
        timeout_seconds: float = 10.0,
        client: Optional[httpx.Client] = None
    ):
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.batch_size = batch_size
        self.flush_interval = flush_interval_seconds
        self.max_queue_size = max_queue_size
        self.timeout = timeout_seconds

        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._last_flush_time = time.time()
        self._client = client or httpx.Client(timeout=timeout_seconds)

    def enqueue(self, event: Dict[str, Any]) -> bool:
        """Add an event to the outbound shipping buffer."""
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            return False

    def enqueue_batch(self, events: List[Dict[str, Any]]) -> int:
        """Add multiple events to the outbound shipping buffer."""
        count = 0
        for ev in events:
            if self.enqueue(ev):
                count += 1
        return count

    def should_flush(self) -> bool:
        """Check if buffer reached batch size or flush interval expired."""
        q_size = self._queue.qsize()
        if q_size >= self.batch_size:
            return True
        if q_size > 0 and (time.time() - self._last_flush_time) >= self.flush_interval:
            return True
        return False

    def flush(self) -> List[Dict[str, Any]]:
        """
        Extract pending batch from queue and post to SentinelX backend.
        Returns list of newly generated alerts from backend response.
        """
        batch = []
        while not self._queue.empty() and len(batch) < self.batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break

        if not batch:
            return []

        self._last_flush_time = time.time()
        endpoint = f"{self.server_url}/api/v1/events/batch"
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key
        }

        try:
            resp = self._client.post(endpoint, json={"events": batch}, headers=headers)
            if resp.status_code == 201:
                # Mark queue tasks as done
                for _ in range(len(batch)):
                    self._queue.task_done()
                return resp.json()
            else:
                # If server returns error, re-enqueue events if space permits
                self._re_enqueue(batch)
                return []
        except Exception:
            # Network error - requeue
            self._re_enqueue(batch)
            return []

    def _re_enqueue(self, batch: List[Dict[str, Any]]):
        for item in batch:
            try:
                self._queue.put_nowait(item)
            except queue.Full:
                break

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    def close(self):
        self._client.close()

