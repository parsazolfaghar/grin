def test_package_imports_and_has_version():
    import grin
    assert isinstance(grin.__version__, str)
    assert grin.__version__
