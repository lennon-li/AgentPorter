"""The MCP idempotency-key constraint matches the REST hexadecimal contract."""
from pydantic import TypeAdapter,ValidationError
import pytest
from agentporter.interface_catalog import DispatchRequestId

@pytest.mark.parametrize('value', ['A'*32,'a'*31,'a'*33,'not-an-id'])
def test_dispatch_id_rejects_invalid_keys(value):
    with pytest.raises(ValidationError):TypeAdapter(DispatchRequestId).validate_python(value)

@pytest.mark.parametrize('value',[None,'a'*32])
def test_dispatch_id_accepts_nullable_or_exact_lowercase_hex(value):
    assert TypeAdapter(DispatchRequestId).validate_python(value)==value
