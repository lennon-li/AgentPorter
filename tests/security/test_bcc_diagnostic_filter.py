import importlib.util
import json
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[2]/'scripts/filter-bcc-provider-diagnostics.py'
spec=importlib.util.spec_from_file_location('bcc_diagnostic_filter',SCRIPT)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_diagnostics_omit_credentials_queries_bodies_and_arbitrary_labels():
    poison='SYNTHETIC-PRIVATE-CREDENTIAL'
    record={'event':'provider_egress_failure','agent':'phil','phase':'request',
            'origin':'api.github.com','operation':'GET /copilot_internal/v2/token',
            'reason':'operation_scope','headers':poison,'body':poison,'error':poison}
    result=module.filtered(json.dumps({'time':poison,'event':record}))
    assert result=={key:value for key,value in record.items() if key not in {'headers','body','error'}}
    for field in ('agent','phase','origin','operation','reason'):
        record[field]=poison
    assert poison not in json.dumps(module.filtered(json.dumps(record)))


def test_only_valid_provider_status_records_are_exposed():
    assert module.filtered('{invalid') is None
    assert module.filtered(json.dumps({'event':'unrelated','token':'private'})) is None
    assert module.filtered('x'*65537) is None
    record={'event':'provider_upstream_status','agent':'argie','origin':'cloudcode-pa.googleapis.com',
            'operation':'POST /v1internal:loadCodeAssist','status':403}
    assert module.filtered(json.dumps(record))==record
    record['status']=True
    assert module.filtered(json.dumps(record))['status'] is None
