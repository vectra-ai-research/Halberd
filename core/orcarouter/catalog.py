"""Live model catalog and capability filtering for OrcaRouter.

The single source of truth is ``GET {api_base}/models`` on the configured
inference origin. Live results are authoritative; when discovery fails the
service keeps the last known-good catalog, or a small verified seed, and
reports ``degraded`` so the UI can say so. A selector is never replaced by a
free-text field.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .config import DEFAULT_MODEL, FALLBACK_MODEL

MAX_ITEMS = 500
MAX_BYTES = 512 * 1024
DEFAULT_TIMEOUT = 8.0

#: Endpoint types that can serve an OpenAI-style chat completion.
TEXT_ENDPOINTS = frozenset({"openai", "openai-response", "openai-responses", "anthropic", "gemini"})
#: Endpoint types that are not text chat, even if a model also lists a text type.
NON_CHAT_ENDPOINTS = frozenset({"image-generation", "openai-video", "jina-rerank", "embeddings", "embedding"})

CAPABILITY_ENDPOINTS = {
    "embedding": frozenset({"embeddings", "embedding"}),
    "image": frozenset({"image-generation"}),
    "video": frozenset({"openai-video"}),
    "rerank": frozenset({"jina-rerank"}),
}
KNOWN_MODALITIES = frozenset({"text", "image", "audio", "video"})


@dataclass(frozen=True)
class ModelInfo:
    id: str
    name: str | None = None
    context_length: int | None = None
    input_modalities: tuple[str, ...] = ()
    output_modalities: tuple[str, ...] = ()
    endpoint_types: tuple[str, ...] = ()
    reasoning_efforts: tuple[str, ...] = ()
    description: str | None = None

    def option(self) -> dict:
        label = self.id
        if self.context_length:
            label = f"{self.id}  ·  {_human_context(self.context_length)} ctx"
        return {"label": label, "value": self.id}

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "context_length": self.context_length,
            "input_modalities": list(self.input_modalities),
            "output_modalities": list(self.output_modalities),
            "endpoint_types": list(self.endpoint_types),
            "reasoning_efforts": list(self.reasoning_efforts),
            "description": self.description,
        }


def _human_context(value: int) -> str:
    if value >= 1_000_000:
        return f"{value // 1000}k"
    return str(value)


def _str_tuple(value) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(item) for item in value if isinstance(item, str) and item)


def parse_catalog(payload) -> list[ModelInfo]:
    """Parse a bounded, shape-checked catalog response."""
    if isinstance(payload, dict):
        items = payload.get("data")
    else:
        items = payload
    if not isinstance(items, list):
        return []
    models: list[ModelInfo] = []
    seen: set[str] = set()
    for raw in items[:MAX_ITEMS]:
        if not isinstance(raw, dict):
            continue
        model_id = raw.get("id")
        if not isinstance(model_id, str) or not model_id.strip():
            continue
        model_id = model_id.strip()
        if model_id in seen:
            continue
        seen.add(model_id)
        architecture = raw.get("architecture") if isinstance(raw.get("architecture"), dict) else {}
        raw_types = raw.get("supported_endpoint_types", raw.get("endpoint_types"))
        if raw_types is not None and not isinstance(raw_types, (list, tuple)):
            continue  # malformed declaration: do not guess a route from the name
        endpoints = _str_tuple(raw_types)
        reasoning = _reasoning_efforts(raw)
        context_length = raw.get("context_length")
        if not isinstance(context_length, int) or context_length <= 0:
            context_length = None
        models.append(
            ModelInfo(
                id=model_id,
                name=raw.get("name") if isinstance(raw.get("name"), str) else None,
                context_length=context_length,
                input_modalities=_str_tuple(architecture.get("input_modalities")),
                output_modalities=_str_tuple(architecture.get("output_modalities")),
                endpoint_types=endpoints,
                reasoning_efforts=reasoning,
                description=(raw.get("description") if isinstance(raw.get("description"), str) else None),
            )
        )
    return models


def _reasoning_efforts(raw: dict) -> tuple[str, ...]:
    for container in (raw.get("supported_parameters"), raw.get("architecture")):
        if isinstance(container, dict):
            ladder = container.get("reasoning_efforts") or container.get("reasoning_effort")
            found = _str_tuple(ladder)
            if found:
                return found
    return ()


def is_chat_model(model: ModelInfo) -> bool:
    """Text chat eligibility, from declared endpoint types only."""
    types = set(model.endpoint_types)
    if not types:
        # No declaration means we cannot prove the route exists: fail closed.
        return False
    if not types & TEXT_ENDPOINTS:
        return False
    if types <= NON_CHAT_ENDPOINTS:
        return False
    return True


def supports_modalities(model: ModelInfo, modalities=()) -> bool:
    """Fail closed: an undeclared modality never matches."""
    required = {m for m in modalities if m and m != "text"}
    if not required:
        return True
    declared = set(model.input_modalities)
    if not declared:
        return False
    return required <= declared


def is_compatible(model: ModelInfo, capability: str = "chat", modalities=()) -> bool:
    capability = (capability or "chat").lower()
    if capability == "chat":
        return is_chat_model(model) and supports_modalities(model, modalities)
    wanted = CAPABILITY_ENDPOINTS.get(capability)
    if wanted is None:
        return False
    types = set(model.endpoint_types)
    return bool(types & wanted)


def filter_models(models, capability: str = "chat", modalities=()) -> list[ModelInfo]:
    return [model for model in models if is_compatible(model, capability, modalities)]


def sort_for_display(models) -> list[ModelInfo]:
    def key(indexed):
        index, model = indexed
        if model.id == DEFAULT_MODEL:
            return (0, "", index)
        if model.id == FALLBACK_MODEL:
            return (1, "", index)
        if model.id.startswith("orca/orcacyber-"):
            return (2, model.id, index)
        return (3, model.id, index)

    return [model for _, model in sorted(enumerate(models), key=key)]


# --------------------------------------------------------------- verified seed
def _seed(
    model_id: str,
    context_length: int | None = None,
    modalities=("text",),
    endpoints=("openai", "openai-response", "anthropic"),
    reasoning=(),
) -> ModelInfo:
    return ModelInfo(
        id=model_id,
        context_length=context_length,
        input_modalities=tuple(modalities),
        output_modalities=("text",),
        endpoint_types=tuple(endpoints),
        reasoning_efforts=tuple(reasoning),
    )


#: Small, verified cold-start catalog used only when live discovery is
#: unavailable. Metadata is retained verbatim for every entry.
VERIFIED_SEED: tuple[ModelInfo, ...] = (
    _seed("orcarouter/auto", None, ("text",), ("openai", "openai-response", "anthropic", "gemini")),
    _seed("orcarouter/fusion", 1_000_000, ("text",), ("openai", "openai-response", "anthropic", "gemini")),
    _seed("orca/orcacyber-ultra-1.0", 1_048_576, ("text",), ("openai",)),
    _seed("orca/orcacyber-zero-1.5", 1_000_000, ("text",), ("openai",)),
    _seed("openai/gpt-5.5", 400_000, ("text", "image"),
          ("openai", "openai-response"), ("low", "medium", "high", "xhigh")),
    _seed("anthropic/claude-opus-4.8", 200_000, ("text", "image"), ("anthropic",)),
    _seed("google/gemini-3.5-flash", 1_000_000, ("text", "image"), ("gemini",)),
    _seed("deepseek/deepseek-v4-pro", 1_048_576, ("text",), ("openai", "openai-response")),
)


class CatalogError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def fetch_catalog(
    api_base: str, api_key: str, timeout: float = DEFAULT_TIMEOUT, opener=None
) -> list[ModelInfo]:
    """Bounded ``GET {api_base}/models`` with Bearer authentication."""
    if not api_key:
        raise CatalogError("missing_key", "An OrcaRouter API key is required to load the model catalog.")
    request = urllib.request.Request(
        api_base.rstrip("/") + "/models?capability=chat",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        method="GET",
    )
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(request, timeout=timeout) as response:
            raw = response.read(MAX_BYTES + 1)
            status = getattr(response, "status", 200)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise CatalogError("auth_error", "OrcaRouter rejected the API key.") from None
        if exc.code == 429:
            raise CatalogError("rate_limited", "OrcaRouter is rate limiting catalog requests.") from None
        raise CatalogError("http_error", f"Model catalog request failed ({exc.code}).") from None
    except urllib.error.URLError as exc:
        raise CatalogError("network_error", f"Could not reach the OrcaRouter catalog: {exc.reason}") from None
    except TimeoutError:
        raise CatalogError("network_error", "The OrcaRouter catalog request timed out.") from None
    if status >= 400:
        raise CatalogError("http_error", f"Model catalog request failed ({status}).")
    if len(raw) > MAX_BYTES:
        raise CatalogError("oversized", "The OrcaRouter catalog response was too large.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise CatalogError("invalid_response", "The OrcaRouter catalog was not valid JSON.") from None
    models = parse_catalog(payload)
    if not models:
        raise CatalogError("empty", "The OrcaRouter catalog returned no usable models.")
    return models


@dataclass
class CatalogResult:
    models: list[ModelInfo] = field(default_factory=list)
    source: str = "seed"  # live | last-known-good | seed
    degraded: bool = False
    error: str | None = None
    fetched_at: float | None = None
    total: int = 0

    def options(self) -> list[dict]:
        return [model.option() for model in self.models]

    def ids(self) -> list[str]:
        return [model.id for model in self.models]


class CatalogService:
    """Cache + fallback wrapper around live discovery. Thread-safe."""

    def __init__(self, api_base: str, ttl: float = 300.0, fetcher=fetch_catalog, clock=time.time):
        self._api_base = api_base
        self._ttl = ttl
        self._fetch = fetcher
        self._clock = clock
        self._lock = threading.RLock()
        self._live: list[ModelInfo] | None = None
        self._live_at: float = 0.0
        self._last_error: str | None = None

    def set_api_base(self, api_base: str) -> None:
        with self._lock:
            self._api_base = api_base
            self._live = None
            self._live_at = 0.0

    def invalidate(self) -> None:
        with self._lock:
            self._live = None
            self._live_at = 0.0

    def _ensure(self, api_key: str, refresh: bool, force_seed: bool = False) -> tuple[list[ModelInfo], str, str | None]:
        with self._lock:
            now = self._clock()
            fresh = self._live is not None and (now - self._live_at) < self._ttl
            if fresh and not refresh:
                return self._live, "live", None
            if force_seed:
                return list(VERIFIED_SEED), "seed", "forced seed"
            try:
                models = self._fetch(self._api_base, api_key)
            except CatalogError as exc:
                self._last_error = exc.message
                if self._live is not None:
                    return self._live, "last-known-good", exc.message
                return list(VERIFIED_SEED), "seed", exc.message
            self._live = models
            self._live_at = now
            self._last_error = None
            return models, "live", None

    def result(
        self,
        capability: str = "chat",
        modalities=(),
        api_key: str | None = None,
        refresh: bool = False,
        force_seed: bool = False,
    ) -> CatalogResult:
        models, source, error = self._ensure(api_key or "", refresh, force_seed)
        filtered = sort_for_display(filter_models(models, capability, modalities))
        return CatalogResult(
            models=filtered,
            source=source,
            degraded=source != "live",
            error=error,
            fetched_at=self._live_at or None,
            total=len(filtered),
        )

    def find(self, model_id: str, capability: str = "chat", modalities=(), api_key: str | None = None) -> ModelInfo | None:
        models = self.result(capability, modalities, api_key).models
        for model in models:
            if model.id == model_id:
                return model
        return None
