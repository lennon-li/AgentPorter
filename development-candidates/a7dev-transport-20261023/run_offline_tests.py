"""Run against the active development dependencies, not the older canonical tree."""
from pathlib import Path
import importlib.util
import pytest

root=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('transport_candidate_tests', root/'tests/test_transport.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
raise SystemExit(pytest.main(['-q','-p','no:cacheprovider',str(root/'tests/test_transport.py'),
    '/tmp/agentporter-cranary-hardened-v19-harness/tests/security/test_provider_origin_broker.py']))
