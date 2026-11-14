"""Narrow authorization seams for low-level custody mechanics tests.

These helpers exercise publication/recovery mechanics beneath authorization.
They do not represent owner approval and must not be used by integration or
job-contract tests; those tests must use the public approval backends.
"""
from pathlib import Path


def allow_one_history_publication_for_recovery(monkeypatch, workspace):
    """Stub one constructed transaction's history validator for this workspace."""
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction

    expected = Path(workspace).resolve(strict=True)
    original_init = WorkspaceTransaction.__init__
    installed = []

    def init(self, candidate, *args, **kwargs):
        original_init(self, candidate, *args, **kwargs)
        if not installed and Path(candidate).resolve(strict=True) == expected:
            assert len(self.git_histories) == 1, 'Recovery seam requires one exact history'
            selected = next(iter(self.git_histories.values()))
            original_validate = self._validate_history_publication_authority
            def validate(history):
                if history is selected:
                    return
                return original_validate(history)
            monkeypatch.setattr(self, '_validate_history_publication_authority', validate)
            installed.append(self)

    monkeypatch.setattr(WorkspaceTransaction, '__init__', init)
    return installed


def allow_birth_for_recovery(monkeypatch, transaction):
    """Stub only this transaction's clone-authority validator in custody tests."""
    from agentporter.sandbox import repository_birth

    original = repository_birth._validate_birth_authority

    def validate(candidate, repository):
        if candidate is transaction:
            return None, None
        return original(candidate, repository)

    monkeypatch.setattr(repository_birth, '_validate_birth_authority', validate)
