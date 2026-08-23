"""No test may reach a paid API, and none may read an ambient credential.

The development shell for this project genuinely has an OPENAI_API_KEY exported
for unrelated tooling. Without this file, any test touching the advisor or the
agent narratives would pick it up the moment someone set
NEXTATTACK_LLM_PROVIDER, billing a real account and sending incident-derived
text to a third party from a test run. It would also make the suite
non-deterministic and dependent on a network the offline guarantee says we do
not need.

So the whole suite runs with the language-model layer forced off. Tests that
exercise a provider set their own environment through monkeypatch and stub the
transport, so they never open a socket either.
"""
import pytest


@pytest.fixture(autouse=True, scope="function")
def _no_ambient_llm(monkeypatch):
    monkeypatch.setenv("NEXTATTACK_LLM_PROVIDER", "off")
    # A configured key must not change capability/status assertions or leak a
    # paid provider into integration tests. Provider tests install their own
    # fake keys after this fixture and stub the outbound transport.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)


def pytest_configure(config):
    """Belt and braces for collection-time imports, before fixtures run."""
    import os
    os.environ.setdefault("NEXTATTACK_LLM_PROVIDER", "off")
