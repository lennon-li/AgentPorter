"""Combined overlay tests, pinned active dependencies, no real provider workers."""
from pathlib import Path
import importlib.util
import sys
import pytest

ROOT=Path(__file__).resolve().parent
for name in ('test_provenance_wiring','test_transport'):
    spec=importlib.util.spec_from_file_location(name,ROOT/'tests'/f'{name}.py')
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
raise SystemExit(pytest.main(['-q','--import-mode=importlib','-p','no:cacheprovider',str(ROOT/'tests'),
 '/tmp/agentporter-cranary-hardened-v19-harness/tests/security/test_provider_origin_broker.py']))
