import copy, importlib.util, os, stat
from pathlib import Path
import pytest
import yaml

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/enroll-bcc-acceptance-fixture.py'
spec = importlib.util.spec_from_file_location('fixture_enroller', SCRIPT)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def documents():
    return {
        'config.yaml': {'sandbox': {'workspace_transactions': True}},
        'workspaces.yaml': {'workspaces': {'bcc-staging': {'path': '/fixture/staging', 'writable': True}}},
        'public-client-policy.yaml': {'workspaces': {}},
        'development-runtime.yaml': {'public_client_policy_required': True,
            'egress_policy': 'provider_origin', 'allowed_workspace_roots': [],
            'workers': {'fixture': {'executable': '/fixture/worker'}}},
    }


def test_plan_preserves_existing_workspace_and_input_documents():
    before = documents()
    original = copy.deepcopy(before)
    view = Path('/var/lib/agentporter-bcc/publication-views/fixture')
    after = helper.prepare_documents(before,view)
    assert before == original
    assert after['config.yaml']['sandbox']['workspace_transactions'] is True
    assert after['workspaces.yaml']['workspaces']['bcc-staging'] == before['workspaces.yaml']['workspaces']['bcc-staging']
    assert after['workspaces.yaml']['workspaces']['bcc-owner-fixture']['path'] == str(view)
    operations = after['public-client-policy.yaml']['workspaces']['bcc-owner-fixture']['operations']
    assert 'dispatch_write' in operations
    assert 'git_commit' not in operations and 'git_push' not in operations
    assert after['development-runtime.yaml']['workers'] == before['development-runtime.yaml']['workers']


def test_duplicate_fixture_is_refused():
    before = documents()
    view = Path('/var/lib/agentporter-bcc/publication-views/fixture')
    after = helper.prepare_documents(before,view)
    with pytest.raises(PermissionError,match='already enrolled'):
        helper.prepare_documents(after,view)


def test_unconfined_egress_is_refused():
    before = documents()
    before['development-runtime.yaml']['egress_policy'] = 'unrestricted'
    with pytest.raises(PermissionError,match='provider-origin'):
        helper.prepare_documents(before,Path('/fixture'))


def test_atomic_config_replacement_stays_on_pinned_directory_after_rename(tmp_path,monkeypatch):
    root = tmp_path/'config'; root.mkdir()
    (root/'config.yaml').write_text('original')
    outside = tmp_path/'outside'; outside.mkdir()
    (outside/'config.yaml').write_text('preserve')
    fd = os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    monkeypatch.setattr(helper,'CONFIG_FD',fd)
    root.rename(tmp_path/'pinned')
    root.symlink_to(outside)
    try:
        helper.atomic(helper.configuration_path('config.yaml'),b'updated',
            {'uid':os.getuid(),'gid':os.getgid(),'mode':0o600})
        assert (outside/'config.yaml').read_text() == 'preserve'
        assert (tmp_path/'pinned/config.yaml').read_text() == 'updated'
    finally: os.close(fd)


def test_symlink_config_is_never_read(tmp_path,monkeypatch):
    (tmp_path/'outside').write_text('synthetic secret')
    (tmp_path/'config.yaml').symlink_to(tmp_path/'outside')
    fd = os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
    monkeypatch.setattr(helper,'CONFIG_FD',fd)
    try:
        with pytest.raises(OSError): helper.configuration_bytes('config.yaml')
    finally: os.close(fd)


@pytest.mark.parametrize('body', ['version: 1\nversion: 2\n', 'one: &ref {value: 1}\ntwo: *ref\n'])
def test_config_duplicate_keys_and_aliases_are_refused(body):
    with pytest.raises(ValueError): yaml.load(body,Loader=helper.StrictLoader)
