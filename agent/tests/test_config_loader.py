import os
from pathlib import Path
from agent.config_loader import load_agent_config


def test_load_default_agent_config():
    config = load_agent_config()
    assert "server" in config
    assert "shipping" in config
    assert "collectors" in config
    assert config["server"]["url"] == "http://127.0.0.1:8000"


def test_environment_variable_overrides(monkeypatch):
    monkeypatch.setenv("SENTINELX_SERVER_URL", "https://sentinelx.cloud.internal")
    monkeypatch.setenv("SENTINELX_API_KEY", "snx_live_env_test_key_123")

    config = load_agent_config()
    assert config["server"]["url"] == "https://sentinelx.cloud.internal"
    assert config["server"]["api_key"] == "snx_live_env_test_key_123"

