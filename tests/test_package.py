"""Package-level tests for the SolGuard project scaffold."""

import solguard


def test_package_version_is_exposed() -> None:
    """The installed package exposes the expected initial version."""
    assert solguard.__version__ == "0.1.0"
