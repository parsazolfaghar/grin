def test_package_imports_and_has_version():
    import ronin
    assert isinstance(ronin.__version__, str)
    assert ronin.__version__
