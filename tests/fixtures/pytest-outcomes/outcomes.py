import pytest


def test_pass():
    print("SKIPPED ERROR XFAIL")


def test_assertion_failure():
    print("SKIPPED XFAIL")
    assert False


def test_runtime_skip():
    pytest.skip("runtime reason")


@pytest.fixture
def skipped_fixture():
    pytest.skip("fixture reason")


def test_fixture_skip(skipped_fixture):
    pass


@pytest.mark.xfail(reason="expected reason")
def test_expected_failure():
    assert False


@pytest.mark.xfail(False, reason="inactive")
def test_inactive_xfail():
    pass


@pytest.mark.xfail(True, reason="active")
def test_active_xfail():
    assert False


@pytest.mark.xfail(reason="unexpected")
def test_unexpected_pass():
    pass


@pytest.mark.xfail(strict=True, reason="strict unexpected")
def test_strict_unexpected_pass():
    pass


@pytest.fixture
def broken_setup():
    raise RuntimeError("setup failure")


def test_setup_error(broken_setup):
    pass


@pytest.fixture
def broken_teardown():
    yield
    raise RuntimeError("teardown failure")


def test_teardown_error(broken_teardown):
    pass


def test_runtime_xfail():
    pytest.xfail("runtime expected")
