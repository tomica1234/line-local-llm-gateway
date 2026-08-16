from __future__ import annotations

import json
from pathlib import Path

EXTENSION = Path(__file__).parents[1] / "activity-extension"


def test_safari_extension_manifest_and_privacy_boundaries() -> None:
    manifest = json.loads((EXTENSION / "manifest.json").read_text())
    assert manifest["manifest_version"] == 3
    assert manifest["background"]["service_worker"] == "background.js"
    assert manifest["content_scripts"][0]["matches"] == ["http://*/*", "https://*/*"]

    content = (EXTENSION / "content.js").read_text()
    assert "inIncognitoContext !== true" in content
    for forbidden in (
        "document.cookie",
        "localStorage",
        "sessionStorage",
        "innerText",
        "textContent",
        'querySelector("input',
        "getDisplayMedia",
    ):
        assert forbidden not in content


def test_offline_queue_is_encrypted_and_removed_only_after_success() -> None:
    background = (EXTENSION / "background.js").read_text()
    assert 'name: "AES-GCM"' in background
    assert "crypto.subtle.encrypt" in background
    assert "crypto.subtle.decrypt" in background
    assert "if (!response.ok) return" in background
    assert "queue.slice(records.length)" in background
