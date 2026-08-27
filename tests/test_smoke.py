from appsec_harness import __version__


def test_package_version() -> None:
    assert __version__ == "0.1.0-dev"
