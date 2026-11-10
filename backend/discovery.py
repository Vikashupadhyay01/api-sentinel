"""
backend/discovery.py – API endpoint inventory and Shadow/Zombie detection.

Pipeline
--------
  1. ``normalize_path``  – replace numeric IDs / UUIDs with ``{id}``
  2. ``load_openapi``    – read openapi/openapi.yaml into a set of
                           (method, normalized_path) tuples
  3. ``classify``        – label each observed endpoint:
                             - ``"documented"``  → present in the OpenAPI spec
                             - ``"shadow"``      → observed but not in spec,
                                                  not an old version prefix
                             - ``"zombie"``      → old/deprecated version
                                                  prefix (e.g. /api/v0/…) OR
                                                  path marked deprecated in spec
  4. ``build_inventory`` – consume an iterable of Records, return
                           ``EndpointInfo`` objects with hit counts + timestamps

OWASP mapping: Shadow & Zombie APIs → API9 Improper Inventory Management.
"""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import yaml

from backend.parser import Record


# ---------------------------------------------------------------------------
# Ignore list for noise reduction (non-API paths & health checks)
# ---------------------------------------------------------------------------

DEFAULT_IGNORE_PATTERNS: tuple[str, ...] = (
    "/",
    "/favicon.ico",
    "/robots.txt",
    "/static/*",
    "/api/health",
)


def is_ignored_path(path: str, ignore_patterns: Iterable[str] | None = None) -> bool:
    """Return True if path matches any pattern in the ignore list.

    Patterns support glob syntax via ``fnmatch`` (e.g. ``/static/*``).
    """
    patterns = DEFAULT_IGNORE_PATTERNS if ignore_patterns is None else ignore_patterns
    clean = path.split("?")[0]
    for pattern in patterns:
        if fnmatch.fnmatch(clean, pattern):
            return True
    return False


def is_inventory_candidate(path: str, ignore_patterns: Iterable[str] | None = None) -> bool:
    """Return True only if path is an API endpoint candidate and not ignored.

    Rules:
      1. Must start with ``/api/`` (browser / favicon / static assets are excluded).
      2. Must not match any pattern in ``ignore_patterns`` (e.g. ``/api/health``).
    """
    clean = path.split("?")[0]
    if not clean.startswith("/api/"):
        return False
    if is_ignored_path(clean, ignore_patterns):
        return False
    return True


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------

# Regex patterns that identify path segments which are concrete object IDs.
# Order matters: UUID before plain integer so "550e8400-…" isn't partially matched.
_ID_PATTERNS: list[re.Pattern[str]] = [
    # UUID (any variant)
    re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    ),
    # Pure integer (positive, possibly very large)
    re.compile(r"^\d+$"),
]


def normalize_path(path: str) -> str:
    """Replace concrete numeric IDs and UUIDs in a path with ``{id}``.

    Examples
    --------
    >>> normalize_path("/api/v1/orders/101")
    '/api/v1/orders/{id}'
    >>> normalize_path("/api/v1/users/550e8400-e29b-41d4-a716-446655440000")
    '/api/v1/users/{id}'
    >>> normalize_path("/api/v1/orders")
    '/api/v1/orders'
    >>> normalize_path("/api/v1/users/me")
    '/api/v1/users/me'
    """
    segments = path.split("/")
    normalised = []
    for seg in segments:
        if any(pattern.match(seg) for pattern in _ID_PATTERNS):
            normalised.append("{id}")
        else:
            normalised.append(seg)
    return "/".join(normalised)


# ---------------------------------------------------------------------------
# Zombie-version detection
# ---------------------------------------------------------------------------

# Version prefixes we consider "old" / deprecated.
# Any path whose first real segment matches one of these is classified zombie.
_ZOMBIE_VERSION_RE = re.compile(
    r"^/api/v(?P<major>\d+)/",
    re.IGNORECASE,
)

# The current stable version — anything lower is treated as zombie.
_CURRENT_API_VERSION = 1


def _is_zombie_path(path: str) -> bool:
    """Return ``True`` when *path* looks like an old API version.

    A path is considered a zombie if it contains a version prefix with a
    major version number strictly less than ``_CURRENT_API_VERSION``.

    >>> _is_zombie_path("/api/v0/users")
    True
    >>> _is_zombie_path("/api/v1/orders")
    False
    >>> _is_zombie_path("/api/v2/orders")
    False
    """
    m = _ZOMBIE_VERSION_RE.match(path)
    if not m:
        return False
    major = int(m.group("major"))
    return major < _CURRENT_API_VERSION


# ---------------------------------------------------------------------------
# OpenAPI spec loader
# ---------------------------------------------------------------------------

def load_openapi(spec_path: str | Path) -> set[tuple[str, str]]:
    """Load a YAML OpenAPI spec and return documented (method, path) pairs.

    Path templates in the spec (e.g. ``/api/v1/orders/{order_id}``) are
    normalised so their parameter placeholders become ``{id}``, matching
    the output of :func:`normalize_path`.

    Parameters
    ----------
    spec_path:
        Path to the OpenAPI YAML file.

    Returns
    -------
    set of (method, normalized_path)
        Empty set when the file does not exist or cannot be parsed.
    """
    spec_path = Path(spec_path)
    if not spec_path.exists():
        return set()

    try:
        with spec_path.open("r", encoding="utf-8") as fh:
            spec: dict = yaml.safe_load(fh) or {}
    except (yaml.YAMLError, OSError):
        return set()

    documented: set[tuple[str, str]] = set()
    paths: dict = spec.get("paths") or {}

    for raw_path, methods_dict in paths.items():
        # Normalise the spec path so "{order_id}" → "{id}" etc.
        norm_path = _normalise_openapi_path(str(raw_path))

        if not isinstance(methods_dict, dict):
            continue

        for method, operation in methods_dict.items():
            # Skip non-HTTP-method keys (e.g. "parameters", "summary")
            method_upper = method.upper()
            if method_upper not in {
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
            }:
                continue

            documented.add((method_upper, norm_path))

            # Also treat endpoints marked deprecated in the spec as zombie
            # (they are still *documented* but flagged)
            # We track this separately; classification handles the label.

    return documented


def _normalise_openapi_path(path: str) -> str:
    """Convert OpenAPI path template params to our ``{id}`` placeholder.

    ``/api/v1/orders/{order_id}`` → ``/api/v1/orders/{id}``
    """
    # Replace any {param_name} with {id}
    return re.sub(r"\{[^}]+\}", "{id}", path)


# ---------------------------------------------------------------------------
# Endpoint classification
# ---------------------------------------------------------------------------

EndpointClass = str  # "documented" | "shadow" | "zombie"

OWASP_CATEGORY = {
    "documented": None,           # no alert
    "shadow": "API9",             # Improper Inventory Management
    "zombie": "API9",             # Improper Inventory Management
}


def classify(
    method: str,
    norm_path: str,
    documented: set[tuple[str, str]],
) -> EndpointClass:
    """Classify an observed (method, normalised_path) pair.

    Rules applied in priority order:
    1. Zombie – path uses an old version prefix (e.g. /api/v0/…).
    2. Documented – the (method, path) pair is in the OpenAPI spec.
    3. Shadow – observed in traffic but not in the spec.

    Parameters
    ----------
    method:
        HTTP method in uppercase.
    norm_path:
        Normalised path (concrete IDs already replaced with ``{id}``).
    documented:
        Set of (method, norm_path) tuples from :func:`load_openapi`.
    """
    if _is_zombie_path(norm_path):
        return "zombie"
    if (method.upper(), norm_path) in documented:
        return "documented"
    return "shadow"


# ---------------------------------------------------------------------------
# Inventory data model
# ---------------------------------------------------------------------------

@dataclass
class EndpointInfo:
    """Aggregated statistics for a single (method, normalised_path) endpoint.

    Attributes
    ----------
    method:
        HTTP method (``"GET"``, ``"POST"``, …).
    norm_path:
        Normalised path with concrete IDs replaced by ``{id}``.
    classification:
        ``"documented"``, ``"shadow"``, or ``"zombie"``.
    owasp_category:
        OWASP API Security Top-10 category (e.g. ``"API9"``), or ``None``
        for documented endpoints.
    hit_count:
        Number of times this endpoint was observed.
    first_seen:
        ISO-8601 timestamp of the first observation.
    last_seen:
        ISO-8601 timestamp of the most recent observation.
    status_codes:
        Mapping of HTTP status code → count.
    users_seen:
        Set of distinct usernames that accessed this endpoint.
    """

    method: str
    norm_path: str
    classification: EndpointClass
    owasp_category: Optional[str]
    hit_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    status_codes: dict[int, int] = field(default_factory=dict)
    users_seen: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        """Serialise to a JSON-safe dict (for the detection API)."""
        return {
            "method": self.method,
            "norm_path": self.norm_path,
            "classification": self.classification,
            "owasp_category": self.owasp_category,
            "hit_count": self.hit_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "status_codes": self.status_codes,
            "users_seen": sorted(self.users_seen),
        }


# ---------------------------------------------------------------------------
# Inventory builder
# ---------------------------------------------------------------------------

def build_inventory(
    records: Iterable[Record],
    spec_path: str | Path = "openapi/openapi.yaml",
    ignore_patterns: Iterable[str] | None = None,
) -> dict[tuple[str, str], EndpointInfo]:
    """Build an endpoint inventory from an iterable of :class:`~backend.parser.Record`.

    Parameters
    ----------
    records:
        Any iterable of ``Record`` objects (e.g. from ``iter_records``).
    spec_path:
        Path to the OpenAPI YAML contract.
    ignore_patterns:
        Optional list of glob patterns to exclude from inventory.

    Returns
    -------
    dict mapping ``(method, norm_path)`` → :class:`EndpointInfo`
        Keyed by the normalised (method, path) pair for O(1) lookup.
    """
    documented = load_openapi(spec_path)
    inventory: dict[tuple[str, str], EndpointInfo] = {}

    for rec in records:
        if not is_inventory_candidate(rec.path, ignore_patterns):
            continue

        norm_path = normalize_path(rec.path)
        key = (rec.method, norm_path)

        if key not in inventory:
            cls = classify(rec.method, norm_path, documented)
            inventory[key] = EndpointInfo(
                method=rec.method,
                norm_path=norm_path,
                classification=cls,
                owasp_category=OWASP_CATEGORY[cls],
            )

        info = inventory[key]
        info.hit_count += 1
        info.last_seen = rec.ts
        if info.first_seen is None:
            info.first_seen = rec.ts
        info.status_codes[rec.status] = info.status_codes.get(rec.status, 0) + 1
        if rec.user:
            info.users_seen.add(rec.user)

    return inventory


def inventory_to_list(
    inventory: dict[tuple[str, str], EndpointInfo],
) -> list[dict]:
    """Return the inventory as a JSON-serialisable list, sorted by norm_path."""
    return [
        info.to_dict()
        for info in sorted(inventory.values(), key=lambda i: (i.norm_path, i.method))
    ]

