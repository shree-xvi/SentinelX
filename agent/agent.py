import logging
import time
from typing import List, Dict, Any, Optional
from agent.config_loader import load_agent_config
from agent.shipper import EventShipper
from agent.collectors.base import BaseCollector
from agent.collectors.auth_collector import AuthCollector
from agent.collectors.file_collector import FileCollector
from agent.collectors.usb_collector import USBCollector
from agent.collectors.process_collector import ProcessCollector
from agent.collectors.network_collector import NetworkCollector

logger = logging.getLogger("SentinelXAgent")


class SentinelXAgent:
    def __init__(self, config: Dict[str, Any] = None, shipper: Optional[EventShipper] = None):
        self.config = config or load_agent_config()
        server_cfg = self.config.get("server", {})
        shipping_cfg = self.config.get("shipping", {})
        collector_cfgs = self.config.get("collectors", {})

        self.server_url = server_cfg.get("url", "http://127.0.0.1:8000")
        self.api_key = server_cfg.get("api_key", "")

        self.shipper = shipper or EventShipper(
            server_url=self.server_url,
            api_key=self.api_key,
            batch_size=shipping_cfg.get("batch_size", 50),
            flush_interval_seconds=shipping_cfg.get("flush_interval_seconds", 5),
            max_queue_size=shipping_cfg.get("max_queue_size", 1000),
            timeout_seconds=server_cfg.get("timeout_seconds", 10)
        )

        self.collectors: List[BaseCollector] = [
            AuthCollector(collector_cfgs.get("auth")),
            FileCollector(collector_cfgs.get("file")),
            USBCollector(collector_cfgs.get("usb")),
            ProcessCollector(collector_cfgs.get("process")),
            NetworkCollector(collector_cfgs.get("network")),
        ]

    def run_cycle(self) -> int:
        """
        Execute one poll cycle across all enabled collectors.
        Enqueues discovered events and flushes if conditions are met.
        Returns total number of events collected in this cycle.
        """
        total_collected = 0

        for collector in self.collectors:
            if collector.enabled:
                try:
                    events = collector.collect()
                    if events:
                        enqueued = self.shipper.enqueue_batch(events)
                        total_collected += enqueued
                except Exception as e:
                    logger.warning(f"Collector {collector.name} error: {e}")

        if self.shipper.should_flush():
            alerts = self.shipper.flush()
            if alerts:
                logger.info(f"[!] Threat alerts generated from agent events: {len(alerts)}")

        return total_collected

    def run_loop(self, poll_interval_seconds: float = 2.0, max_iterations: Optional[int] = None):
        """Continuously run agent collection cycles."""
        logger.info(f"SentinelX Endpoint Agent started. Target: {self.server_url}")
        iterations = 0

        try:
            while True:
                self.run_cycle()
                iterations += 1
                if max_iterations and iterations >= max_iterations:
                    break
                time.sleep(poll_interval_seconds)
        except KeyboardInterrupt:
            logger.info("Agent stopped by user.")
        finally:
            # Final flush on exit
            if self.shipper.queue_size > 0:
                self.shipper.flush()
            self.shipper.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    agent = SentinelXAgent()
    agent.run_loop()

