import pytest


@pytest.fixture(scope="session")
def console(target):
    serial = target.get_driver("ConsoleProtocol")
    target.activate(serial)
    return serial
