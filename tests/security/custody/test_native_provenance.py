import hashlib
import json
from pathlib import Path

import pytest

from agentporter.sandbox import native_git_provenance as bridge


def test_frozen_bridge_loader_verifies_source_and_library_before_exposure(tmp_path):
    compiled=tmp_path/'compiled';compiled.mkdir(mode=0o700)
    record=bridge.build(compiled)
    manifest=tmp_path/'manifest.json'
    manifest.write_text(json.dumps({'schema':1,**{key:record[key] for key in ('source_sha256','library_sha256')}}))
    destination=tmp_path/'installed';destination.mkdir(mode=0o700)
    result=bridge.load_prebuilt(destination,compiled/'native-git-provenance.so',manifest,
                               source_sha256=record['source_sha256'])
    assert result['prototype_compile_used'] is False
    assert hashlib.sha256((destination/'native-git-provenance.so').read_bytes()).hexdigest()==record['library_sha256']
    manifest.write_text(json.dumps({'schema':1,'source_sha256':record['source_sha256'],'library_sha256':'0'*64}))
    refused=tmp_path/'refused';refused.mkdir(mode=0o700)
    with pytest.raises(PermissionError):
        bridge.load_prebuilt(refused,compiled/'native-git-provenance.so',manifest,source_sha256=record['source_sha256'])
    assert not list(refused.iterdir())
