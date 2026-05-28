from unittest import mock

from containarium_telemetry._instrumentations import register_instrumentations


def _make_entry(name: str, instrumentor_mock=None, load_raises=None):
    ep = mock.MagicMock()
    ep.name = name
    if load_raises is not None:
        ep.load.side_effect = load_raises
    else:
        # entry.load() returns the instrumentor *class*. instrumentor() is
        # the call to instantiate, .instrument() registers it.
        instrumentor_class = mock.MagicMock(return_value=instrumentor_mock)
        ep.load.return_value = instrumentor_class
    return ep


def test_off_returns_empty():
    assert register_instrumentations("off") == []


def test_unrecognized_returns_empty():
    assert register_instrumentations("garbage") == []


def test_auto_loads_all_entries():
    instr = mock.MagicMock()
    ep = _make_entry("flask", instrumentor_mock=instr)
    with mock.patch(
        "containarium_telemetry._instrumentations._entry_points_for_group",
        return_value=[ep],
    ):
        result = register_instrumentations("auto")
    assert result == ["flask"]
    instr.instrument.assert_called_once()


def test_failed_entry_skipped_others_continue():
    failing = _make_entry("broken", load_raises=ImportError("missing dep"))
    working_instr = mock.MagicMock()
    working = _make_entry("flask", instrumentor_mock=working_instr)
    with mock.patch(
        "containarium_telemetry._instrumentations._entry_points_for_group",
        return_value=[failing, working],
    ):
        result = register_instrumentations("auto")
    assert result == ["flask"]
    working_instr.instrument.assert_called_once()


def test_list_filter():
    flask_instr = mock.MagicMock()
    fastapi_instr = mock.MagicMock()
    entries = [
        _make_entry("flask", instrumentor_mock=flask_instr),
        _make_entry("fastapi", instrumentor_mock=fastapi_instr),
    ]
    with mock.patch(
        "containarium_telemetry._instrumentations._entry_points_for_group",
        return_value=entries,
    ):
        result = register_instrumentations(["flask"])
    assert result == ["flask"]
    flask_instr.instrument.assert_called_once()
    fastapi_instr.instrument.assert_not_called()


def test_instrument_method_failure_logged_not_raised():
    bad_instr = mock.MagicMock()
    bad_instr.instrument.side_effect = RuntimeError("boom")
    ep = _make_entry("flask", instrumentor_mock=bad_instr)
    with mock.patch(
        "containarium_telemetry._instrumentations._entry_points_for_group",
        return_value=[ep],
    ):
        result = register_instrumentations("auto")
    # Failed instrumentor is excluded from the success list, but no raise.
    assert result == []
