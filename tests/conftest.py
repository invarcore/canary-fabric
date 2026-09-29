"""Shared test fixtures for CanaryFabric test suite."""

import pytest

from canary_fabric.breaker.circuit import BreakerAction, CircuitBreaker
from canary_fabric.core.honeytoken import HoneytokenGenerator, HoneytokenRegistry
from canary_fabric.forensics.vault import IncidentVault


@pytest.fixture
def secret_key():
    """Standard test secret key."""
    return "test_secret_key"


@pytest.fixture
def vault():
    """In-memory incident vault for testing."""
    return IncidentVault(":memory:")


@pytest.fixture
def breaker(secret_key, vault):
    """Circuit breaker with in-memory vault."""
    return CircuitBreaker(
        secret_key=secret_key,
        default_action=BreakerAction.BLOCK_AND_SEVER,
        vault=vault,
    )


@pytest.fixture
def honeytoken_registry():
    """Empty honeytoken registry."""
    return HoneytokenRegistry()


@pytest.fixture
def honeytoken_generator(honeytoken_registry):
    """Honeytoken generator with shared registry."""
    return HoneytokenGenerator(registry=honeytoken_registry)