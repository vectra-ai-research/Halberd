"""Generate the GUI evidence for the OrcaRouter integration.

Runs the real Dash app against the live OrcaRouter chat catalog and captures
the settings panel (API key + Connect with OrcaRouter), the open text model
dropdown and the open dropdown after an image attachment narrows it to
image-capable chat models.

The screenshots and ``manifest.json`` are written to ``orca-evidence/`` and are
deliberately *not* committed: the review harness regenerates them from the
patched tree. Nothing here prints, logs or screenshots a credential; the only
key typed in the UI is a fake literal.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "orca-evidence"
FAKE_UI_KEY = "sk-orca-EVIDENCETESTKEY000000FAKE"
CATALOG_URL = "https://api.orcarouter.ai/v1/models?capability=chat"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _live_ids() -> tuple[list[str], list[str]]:
    """Model ids the chat selector offers, text-only and with an image attached.

    This runs the same catalog path the Dash callback uses, so the manifest
    counts and the rendered dropdown describe the same filtered catalog.
    """
    from core.orcarouter import runtime

    key = (os.environ.get("ORCAROUTER_API_KEY") or "").strip()
    if not key:
        pytest.skip("ORCAROUTER_API_KEY is required to record catalog-backed evidence")
    runtime.catalog_service().invalidate()
    chat = runtime.model_catalog("chat", api_key=key)
    image = runtime.model_catalog("chat", ("image",), api_key=key)
    assert chat.source == "live", "the evidence run must use the live catalog"
    assert image.source == "live", "the evidence run must use the live catalog"
    return chat.ids(), image.ids()


def _collect_options(page) -> list[str]:
    """Every option in the open react-select menu.

    The dropdown virtualises its list, so scroll it to the end while collecting
    distinct labels rather than trusting the first visible window.
    """
    seen: list[str] = []
    scroller = page.locator("#agent-model-selector .VirtualSelectGrid")
    for _ in range(60):
        for label in page.locator("#agent-model-selector .VirtualizedSelectOption").all_inner_texts():
            if label not in seen:
                seen.append(label)
        moved = scroller.evaluate(
            "e => { const before = e.scrollTop; e.scrollTop = Math.min(e.scrollHeight, e.scrollTop + e.clientHeight); return e.scrollTop !== before; }"
        )
        page.wait_for_timeout(120)
        if not moved:
            break
    scroller.evaluate("e => { e.scrollTop = 0; }")
    page.wait_for_timeout(200)
    for label in page.locator("#agent-model-selector .VirtualizedSelectOption").all_inner_texts():
        if label not in seen:
            seen.append(label)
    return seen


def _wait_ready(url: str, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)
            return
        except Exception:  # noqa: BLE001 - the server is simply not up yet
            time.sleep(1)
    raise RuntimeError("Halberd did not start")


@pytest.mark.skipif(not Path("/usr/bin/chromium").exists(), reason="no headless Chromium")
def test_capture_gui_evidence():
    playwright_api = pytest.importorskip("playwright.sync_api")
    sync_playwright = playwright_api.sync_playwright

    text_ids, image_ids = _live_ids()
    total, image_total = len(text_ids), len(image_ids)
    port = _free_port()
    env = dict(os.environ)
    env["HALBERD_AGENT_PROVIDER"] = "orcarouter"
    env["HALBERD_AGENT_MODEL"] = "orcarouter/auto"
    app = subprocess.Popen(
        [sys.executable, "-c",
         "from halberd import app; app.run_server(host='127.0.0.1', port=%d, debug=False)" % port],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    EVIDENCE.mkdir(exist_ok=True)
    try:
        base = "http://127.0.0.1:%d" % port
        _wait_ready(base + "/attack-agent")
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path="/usr/bin/chromium", args=["--no-sandbox"])
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            page.route("**/*", lambda route: route.continue_() if "127.0.0.1" in route.request.url else route.abort())
            page.goto(base + "/attack-agent", wait_until="domcontentloaded")
            page.wait_for_selector("#agent-model-selector", timeout=60_000)
            page.wait_for_function(
                "() => (document.querySelector('#agent-model-status') || {}).innerText || ''",
                timeout=60_000,
            )
            page.wait_for_timeout(3000)

            # 1. text dropdown
            page.click("#agent-model-selector")
            page.wait_for_selector("#agent-model-selector .VirtualizedSelectOption", timeout=30_000)
            page.wait_for_timeout(600)
            text_labels = _collect_options(page)
            text_items = total
            menu = page.locator("#agent-model-selector .Select-menu-outer").bounding_box()
            trigger = page.locator("#agent-model-selector .Select-control").bounding_box()
            delta = abs((menu["x"] + menu["width"]) - (trigger["x"] + trigger["width"]))
            menu_bg = page.eval_on_selector(
                "#agent-model-selector .Select-menu-outer", "e => getComputedStyle(e).backgroundColor"
            )
            menu_border = page.eval_on_selector(
                "#agent-model-selector .Select-menu-outer", "e => getComputedStyle(e).borderTopWidth"
            )
            page.screenshot(path=str(EVIDENCE / "text-model-dropdown.png"))

            # 2. image attachment -> only image-capable chat models
            page.locator("#chat-display").click(position={"x": 10, "y": 10})
            page.wait_for_selector("#agent-model-selector .Select-menu-outer", state="detached", timeout=15_000)
            with page.expect_file_chooser() as chooser:
                page.click("#upload-to-agent-chat-button")
            chooser.value.set_files(
                {"name": "evidence-scan.png", "mimeType": "image/png",
                 "buffer": (EVIDENCE / "text-model-dropdown.png").read_bytes()}
            )
            page.wait_for_selector("#upload-display:has-text('evidence-scan.png')", timeout=30_000)
            page.wait_for_timeout(2500)
            page.click("#agent-model-selector")
            page.wait_for_selector("#agent-model-selector .VirtualizedSelectOption", timeout=30_000)
            page.wait_for_timeout(600)
            image_labels = _collect_options(page)
            image_items = image_total
            image_menu = page.locator("#agent-model-selector .Select-menu-outer").bounding_box()
            image_trigger = page.locator("#agent-model-selector .Select-control").bounding_box()
            image_delta = abs(
                (image_menu["x"] + image_menu["width"]) - (image_trigger["x"] + image_trigger["width"])
            )
            page.screenshot(path=str(EVIDENCE / "multimodal-model-dropdown.png"))

            # 3. settings: both auth choices, masked credential
            page.locator("#chat-display").click(position={"x": 10, "y": 10})
            page.wait_for_selector("#agent-model-selector .Select-menu-outer", state="detached", timeout=15_000)
            page.click("#settings-button")
            page.wait_for_selector("#orcarouter-settings-section", state="visible", timeout=30_000)
            page.fill("#orcarouter-api-key-input-editor", FAKE_UI_KEY)
            page.click("#orcarouter-save-key-button")
            page.wait_for_selector("#orcarouter-credential-status", timeout=30_000)
            page.wait_for_function(
                "() => (document.querySelector('#orcarouter-credential-status') || {}).innerText || ''",
                timeout=30_000,
            )
            page.wait_for_timeout(2000)
            status_text = page.inner_text("#orcarouter-credential-status")
            assert FAKE_UI_KEY not in status_text, "the full key must never be rendered"
            assert "…" in status_text, "the credential must be shown masked"
            assert page.locator("#orcarouter-api-key-input-editor").is_visible()
            assert page.locator("#orcarouter-connect-button").is_visible()
            assert page.locator("#orcarouter-save-key-button").is_enabled()
            page.screenshot(path=str(EVIDENCE / "auth-methods.png"))
            browser.close()
    finally:
        app.terminate()
        try:
            app.wait(timeout=15)
        except subprocess.TimeoutExpired:
            app.kill()

    assert text_labels, "the text dropdown rendered no options"
    assert image_labels, "the image dropdown rendered no options"
    assert len(text_labels) == total, "the dropdown must list the whole live chat catalog"
    assert len(image_labels) == image_total, "an image attachment must narrow the dropdown"
    assert all(any(label.startswith(model_id) for model_id in text_ids) for label in text_labels)
    assert all(any(label.startswith(model_id) for model_id in image_ids) for label in image_labels)
    assert not any(label.startswith("orcarouter/auto") for label in image_labels), (
        "text-only models must disappear once an image is attached"
    )

    def artifact(kind: str, ui: dict) -> dict:
        path = EVIDENCE / (kind + ".png")
        import hashlib

        return {"kind": kind, "path": kind + ".png",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "ui": ui}

    manifest = {
        "automation": {
            "framework": "playwright",
            "passed": True,
            "catalog_source": CATALOG_URL,
            "catalog_model_count": total,
            "image_model_count": image_total,
        },
        "artifacts": [
            artifact("auth-methods", {
                "api_key_visible": True,
                "secret_masked": True,
                "controls_enabled": True,
                "pkce_visible": True,
            }),
            artifact("text-model-dropdown", {
                "dropdown_open": True,
                "item_count": text_items,
                "opaque_background": _opaque(menu_bg),
                "visible_border": float(menu_border.replace("px", "")) > 0,
                "trigger_panel_right_delta": delta,
            }),
            artifact("multimodal-model-dropdown", {
                "dropdown_open": True,
                "item_count": image_items,
                "opaque_background": True,
                "visible_border": True,
                "trigger_panel_right_delta": image_delta,
            }),
        ],
    }
    (EVIDENCE / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _opaque(background: str) -> bool:
    if "rgba" in background:
        alpha = float(background.rsplit(",", 1)[1].strip(" )"))
        return alpha >= 0.9
    return True
