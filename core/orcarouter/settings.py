"""Agent provider/model settings shared by the settings panel and the chat page."""

from __future__ import annotations

import os
import threading
from pathlib import Path

from .catalog import ModelInfo
from .config import DEFAULT_MODEL
from .envfile import read_env_values, write_env_values
from .providers import get_provider

ENV_PROVIDER = "HALBERD_AGENT_PROVIDER"
ENV_MODEL = "HALBERD_AGENT_MODEL"


class AgentSettings:
    def __init__(self, env_path: str | os.PathLike | None = None, environ=None):
        self._path = Path(env_path) if env_path is not None else Path(".env")
        self._environ = os.environ if environ is None else environ
        self._lock = threading.RLock()
        self._provider = self._env_value(ENV_PROVIDER) or "anthropic"
        self._model = self._env_value(ENV_MODEL) or ""

    def _env_value(self, name: str) -> str:
        value = (self._environ.get(name) or "").strip()
        if value:
            return value
        return (read_env_values(self._path).get(name) or "").strip()

    # ------------------------------------------------------------------ read
    def provider(self) -> str:
        with self._lock:
            return self._provider

    def model(self) -> str:
        with self._lock:
            if self._provider == "orcarouter":
                return self._model or DEFAULT_MODEL
            return self._model

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "provider": self._provider,
                "provider_label": get_provider(self._provider).label,
                "model": self.model(),
            }

    # ----------------------------------------------------------------- write
    def _store(self, **updates: str) -> None:
        write_env_values(self._path, {name: (value or None) for name, value in updates.items()})
        for name, value in updates.items():
            if value:
                self._environ[name] = value
            else:
                self._environ.pop(name, None)

    def set_provider(self, provider_id: str) -> dict:
        with self._lock:
            spec = get_provider(provider_id)
            self._provider = spec.id
            if spec.id == "orcarouter" and not self._model:
                self._model = DEFAULT_MODEL
            self._store(**{ENV_PROVIDER: self._provider, ENV_MODEL: self._model})
            return self.snapshot()

    def set_model(self, model_id: str, options: list[ModelInfo] | None = None) -> dict:
        """Persist a model choice, rejecting values the current list lacks."""
        with self._lock:
            if options is not None and model_id:
                allowed = {model.id for model in options}
                if model_id not in allowed:
                    raise ValueError(f'Model "{model_id}" is not available for this provider and input.')
            self._model = (model_id or "").strip()
            self._store(**{ENV_MODEL: self._model})
            return self.snapshot()


_SETTINGS = AgentSettings()


def get_agent_settings() -> AgentSettings:
    return _SETTINGS
