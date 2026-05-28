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
from importlib.metadata import entry_points
from typing import List, Union

logger = logging.getLogger("containarium_telemetry")

InstrumentationsArg = Union[str, List[str]]


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
        all_entries = list(entry_points(group="opentelemetry_instrumentor"))
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
