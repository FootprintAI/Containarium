"""Auto-instrumentation registration via OTel entry points.

Used by the direct-API path: when a user calls
`containarium_telemetry.init(instrumentations="auto")`, we iterate every
package that registered an opentelemetry_instrumentor entry point and
call its `.instrument()` method. Failures from individual instrumentors
are logged at WARN and skipped — one broken integration doesn't abort
init().

The auto-instrument shim path (containarium-instrument / opentelemetry-
instrument) does NOT go through here — the upstream runtime registers
instrumentors itself.
"""
from __future__ import annotations

import logging
import sys
from importlib.metadata import entry_points
from typing import List, Union

logger = logging.getLogger("containarium_telemetry")

InstrumentationsArg = Union[str, List[str]]


def _entry_points_for_group(group: str):
    """Cross-version wrapper for importlib.metadata.entry_points.

    Python 3.10+ takes a `group=` kwarg directly. On 3.9 the kwarg is
    silently ignored (entry_points() returns a dict-like of all groups)
    so `entry_points(group="x")` returns the whole dict and our
    instrumentor enumeration drops to zero — exactly the bug the
    matrix CI caught on first run.
    """
    if sys.version_info >= (3, 10):
        return list(entry_points(group=group))
    return list(entry_points().get(group, []))


def register_instrumentations(instrumentations: InstrumentationsArg) -> List[str]:
    """Register OTel instrumentors per the user's choice.

    Args:
        instrumentations: One of:
            - "auto": register every installed instrumentor
            - "off": register nothing
            - list[str]: register only instrumentors whose entry-point
              name appears in the list (e.g. ["flask", "requests"])

    Returns:
        The list of instrumentor names that were successfully registered.
        Failures don't raise — they go to logger.warning.
    """
    if instrumentations == "off":
        return []

    try:
        all_entries = _entry_points_for_group("opentelemetry_instrumentor")
    except Exception as e:  # noqa: BLE001 — entry_points API has changed across versions
        logger.warning(
            "containarium_telemetry: failed to enumerate instrumentor "
            "entry points: %s",
            e,
        )
        return []

    if instrumentations == "auto":
        entries = all_entries
    elif isinstance(instrumentations, list):
        wanted = set(instrumentations)
        entries = [e for e in all_entries if e.name in wanted]
    else:
        logger.warning(
            "containarium_telemetry: unrecognized instrumentations arg %r; "
            "treating as 'off'",
            instrumentations,
        )
        return []

    instrumented: List[str] = []
    for entry in entries:
        try:
            instrumentor_class = entry.load()
            instrumentor_class().instrument()
            instrumented.append(entry.name)
        except Exception as e:  # noqa: BLE001 — never crash app on broken instrumentor
            logger.warning(
                "containarium_telemetry: failed to register instrumentation "
                "%s: %s",
                entry.name,
                e,
            )
    return instrumented
