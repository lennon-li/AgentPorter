"""Explicit sandbox selection for portable native integration tests."""
import os

BWRAP = os.environ.get('AGENTPORTER_TEST_BWRAP', '/opt/agentporter/bin/bwrap')
