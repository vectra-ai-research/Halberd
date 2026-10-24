"""Model-selector decision logic, shared by the chat page and its tests.

The selector is always driven by catalog options: a model that is not in the
filtered list can never be chosen, and a previously chosen model that stops
being compatible is cleared rather than silently kept.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .catalog import CatalogResult


@dataclass
class SelectorState:
    options: list[dict] = field(default_factory=list)
    value: str | None = None
    disabled: bool = True
    visible: bool = False
    notices: list[tuple[str, str]] = field(default_factory=list)  # (severity, text)
    count: int = 0
    source: str = "seed"
    degraded: bool = True
    error: str | None = None

    @property
    def ids(self) -> list[str]:
        return [option["value"] for option in self.options]


def build_model_options(
    provider: str,
    result: CatalogResult,
    current_value: str | None,
    preferred_model: str | None,
    modalities=(),
) -> SelectorState:
    """Filter catalog options for the current provider and input modalities."""
    if provider != "orcarouter":
        # The Anthropic provider keeps its existing single-model behaviour.
        return SelectorState()

    options = result.options()
    available = [option["value"] for option in options]

    if current_value and current_value in available:
        value = current_value
    elif preferred_model and preferred_model in available:
        value = preferred_model
    elif available:
        value = available[0]
    else:
        value = None

    notices: list[tuple[str, str]] = []
    if current_value and current_value not in available:
        notices.append(
            ("warning", "The previous model does not accept this attachment; choose another.")
        )
    if result.degraded:
        notices.append(("warning", f"{len(options)} models · {result.source} catalog"))
    else:
        notices.append(("success", f"{len(options)} models · live catalog"))
    if result.error:
        notices.append(("muted", f" ({result.error})"))
    if "document" in (modalities or []):
        notices.append(("warning", " PDF attachments require the Anthropic provider."))

    return SelectorState(
        options=options,
        value=value,
        disabled=not options,
        visible=True,
        notices=notices,
        count=len(options),
        source=result.source,
        degraded=result.degraded,
        error=result.error,
    )
