"""Manifest-bound context assembly that denies hidden references."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DiscoveryContext:
    allowed_paths: tuple[str, ...]
    denied_paths: tuple[str, ...]
    input_digest: str
    content: dict[str, str]


def canonical_digest(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_discovery_context(root: Path) -> DiscoveryContext:
    root = root.resolve()
    corpus_path = root / "fixtures/corpus/cases.json"
    corpus = json.loads(corpus_path.read_text())
    allowed = tuple(sorted(corpus["discovery_inputs"]))
    denied = tuple(sorted(corpus["denied_discovery_paths"]))
    content: dict[str, str] = {}
    for relative in allowed:
        if any(relative == prefix.rstrip("/") or relative.startswith(prefix) for prefix in denied):
            raise ValueError(f"discovery input enters denied path: {relative}")
        candidate = (root / relative).resolve()
        if not candidate.is_relative_to(root):
            raise ValueError(f"discovery input leaves repository root: {relative}")
        content[relative] = candidate.read_text()
    digest = canonical_digest({"allowed_paths": allowed, "content": content})
    return DiscoveryContext(allowed, denied, digest, content)
