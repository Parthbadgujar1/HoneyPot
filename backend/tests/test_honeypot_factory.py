import pytest

from app.honeypot.base import FileBasedAdapter
from app.honeypot.cowrie import CowrieAdapter
from app.honeypot.factory import default_adapter, get_adapter
from app.honeypot.local import LocalSimulatedHoneypot


def test_default_adapter_is_local_simulated():
    adapter = default_adapter()
    assert isinstance(adapter, LocalSimulatedHoneypot)


def test_get_adapter_local_simulated():
    adapter = get_adapter("local_simulated")
    assert isinstance(adapter, LocalSimulatedHoneypot)


def test_get_adapter_cowrie_instantiates_and_polls():
    adapter = get_adapter("cowrie")
    assert isinstance(adapter, CowrieAdapter)
    assert isinstance(adapter, FileBasedAdapter)
    # read-only file poller start/stop are safe no-ops
    adapter.start()
    adapter.stop()


def test_get_adapter_unknown_raises():
    with pytest.raises(ValueError):
        get_adapter("does_not_exist")
