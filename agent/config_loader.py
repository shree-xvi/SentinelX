import os
from pathlib import Path
from typing import Dict, Any
import yaml


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"


def load_agent_config(config_path: Path = None) -> Dict[str, Any]:
    path = config_path or DEFAULT_CONFIG_PATH
    config: Dict[str, Any] = {}

    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    config = loaded
        except Exception:
            pass

    # Ensure defaults
    server = config.setdefault("server", {})
    shipping = config.setdefault("shipping", {})
    collectors = config.setdefault("collectors", {})

    server.setdefault("url", "http://127.0.0.1:8000")
    server.setdefault("api_key", "")
    server.setdefault("timeout_seconds", 10)

    shipping.setdefault("batch_size", 50)
    shipping.setdefault("flush_interval_seconds", 5)
    shipping.setdefault("max_queue_size", 1000)

    # Environment overrides
    if os.getenv("SENTINELX_SERVER_URL"):
        server["url"] = os.getenv("SENTINELX_SERVER_URL")
    if os.getenv("SENTINELX_API_KEY"):
        server["api_key"] = os.getenv("SENTINELX_API_KEY")

    return config

