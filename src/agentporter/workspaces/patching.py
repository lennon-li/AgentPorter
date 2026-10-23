"""Stage unified patches privately, then publish files through the ACL writer."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

from agentporter.workspaces.bounded import read_regular
from agentporter.workspaces.paths import validate_workspace_path
from agentporter.workspaces.shared_access import atomic_write, parent_directory


def targets(patch):
    lines = patch.splitlines()
    index = 0
    paths = []
    strip = None
    while index < len(lines):
        line = lines[index]
        if line.startswith(('diff --git ', 'index ')) or not line:
            index += 1
            continue
        if not line.startswith('--- ') or index + 1 >= len(lines) or not lines[index + 1].startswith('+++ '):
            raise ValueError('Only unified file patches are supported')
        names = [value[4:].split('\t', 1)[0] for value in lines[index:index + 2]]
        cleaned = []
        for name in names:
            if name == '/dev/null':
                cleaned.append(None)
                continue
            prefixed = name.startswith(('a/', 'b/'))
            if strip is not None and strip != prefixed:
                raise ValueError('Mixed patch path prefixes')
            strip = prefixed
            cleaned.append(name[2:] if prefixed else name)
        old, new = cleaned
        if not (old or new) or (old and new and old != new):
            raise ValueError('Patch renames are not supported')
        path = old or new
        if path in [item[0] for item in paths] or len(paths) >= 256:
            raise ValueError('Duplicate or excessive patch targets')
        paths.append((path, old is None, new is None))
        index += 2
        hunks = 0
        while index < len(lines) and lines[index].startswith('@@ '):
            match = re.fullmatch(r'@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@.*', lines[index])
            if not match:
                raise ValueError('Invalid unified hunk')
            remaining = [int(value) if value is not None else 1 for value in match.groups()]
            index += 1
            hunks += 1
            while any(remaining):
                if index >= len(lines) or not lines[index]:
                    raise ValueError('Truncated unified hunk')
                marker = lines[index][0]
                if marker == '\\':
                    if lines[index] != '\\ No newline at end of file':
                        raise ValueError('Invalid patch marker')
                elif marker in ' +-':
                    remaining[0] -= marker != '+'
                    remaining[1] -= marker != '-'
                else:
                    raise ValueError('Invalid hunk line')
                if min(remaining) < 0:
                    raise ValueError('Invalid hunk counts')
                index += 1
            if index < len(lines) and lines[index] == '\\ No newline at end of file':
                index += 1
        if not hunks:
            raise ValueError('Patch has no hunks')
    if not paths:
        raise ValueError('Patch has no targets')
    return paths, bool(strip)


def apply_workspace_patch(root, patch, limit):
    paths, strip = targets(patch)
    before = {}
    with tempfile.TemporaryDirectory(prefix='agentporter-patch-') as staging:
        for path, create, delete in paths:
            full = validate_workspace_path(root, path)
            if create:
                if os.path.lexists(full):
                    raise ValueError('Patch creation target already exists')
                before[path] = None
            else:
                data = read_regular(root, path, limit)
                before[path] = hashlib.sha256(data).hexdigest()
                target = Path(validate_workspace_path(staging, path))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        proc = subprocess.run(
            ['patch', '-p1' if strip else '-p0', '--batch', '--forward',
             '--no-backup-if-mismatch', '--reject-file=-'],
            input=patch, cwd=staging, capture_output=True, text=True, timeout=15,
        )
        if proc.returncode:
            return proc
        # Validate every output before publishing any file. Each replacement is atomic.
        outputs = {path: None if delete else read_regular(staging, path, limit)
                   for path, create, delete in paths}
        for path, create, delete in paths:
            if before[path] is not None:
                if hashlib.sha256(read_regular(root, path, limit)).hexdigest() != before[path]:
                    raise ValueError('Stale file protection: patch target changed')
            elif os.path.lexists(validate_workspace_path(root, path)):
                raise ValueError('Patch creation target already exists')
        for path, create, delete in paths:
            if delete:
                with parent_directory(root, path) as (parent, name, _):
                    os.unlink(name, dir_fd=parent)
            else:
                atomic_write(root, path, outputs[path], before[path])
        return proc
