- **`BUILD_TOOLS` runs can install a Python repository's dependencies** (#3788).
  `agent-python setup`, `agent-python test` and `agent-python venv` (each with an
  optional directory) are now allowed at `BUILD_TOOLS` and `FULL_SUDO`; the
  helper's `-- CMD` passthrough form is denied by rule at every level (including
  quoted or tab-separated spellings of `--`), and plain
  `pip` / `python3 -m pip` stay refused. Nothing changes at `NONE`. The helper
  is present on agent-runtime boxes deployed with `toolchains=python`.
