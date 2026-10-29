"""Explicit owner-installed production controls, independent of worker runtimes."""
from __future__ import annotations

import os
import re
from pathlib import Path
import stat

import yaml

from agentporter.resources import validate_job_resource_settings
from agentporter.action_policy import DEFAULT_ACTION_MODES, VALID_MODES
from agentporter.client_policy import PRODUCTION_SCINET_SCOPES

_ERROR = "Production profile controls are unavailable or invalid"
_REQUIRED = ("production-runtime.yaml", "config.yaml", "workspaces.yaml",
             "public-client-policy.yaml", "action-policy.yaml")
_FORBIDDEN = ("development-runtime.yaml", "internal-client.key", "relay-secrets.env",
              "delegation-relay-scope.yaml", "public-https.yaml")
_PROTECTED = {"agentporter", "AgentPorter", "repos", "obsidian", "shiny", "asgard-hermes-review"}


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError(_ERROR)
        result[key] = loader.construct_object(value_node)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _directory(path):
    """Pin no-follow ancestors, allowing only root-owned sticky temp parents."""
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise PermissionError(_ERROR)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            info = os.fstat(descriptor)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not sticky_root):
                raise PermissionError(_ERROR)
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise PermissionError(_ERROR)
        result, descriptor = descriptor, -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _private_file(directory, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or not 0 < info.st_size <= 65536):
            raise PermissionError(_ERROR)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _document(directory, name):
    descriptor = _private_file(directory, name)
    try:
        before = os.fstat(descriptor)
        body = os.read(descriptor, 65537)
        after = os.fstat(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns)
        if len(body) != before.st_size or identity(before) != identity(after):
            raise PermissionError(_ERROR)
    finally:
        os.close(descriptor)
    if any(isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken))
           for token in yaml.scan(body)):
        raise ValueError(_ERROR)
    value = yaml.load(body, Loader=_UniqueLoader)
    if not isinstance(value, dict):
        raise ValueError(_ERROR)
    return value


def _shared_controls(config, documents, relay):
    """Resolve shared consumers independently and compare effective bindings."""
    from agentporter.workspace_policy import shared_policy_reference
    from agentporter.workspaces.registry import WorkspaceRegistry

    inputs = [documents["workspaces.yaml"], documents["public-client-policy.yaml"]]
    if relay is not None:
        inputs.append(relay)
    shared = any(doc.get("version") == 2 for doc in inputs)
    if not shared:
        return False, relay, ()
    policies = [shared_policy_reference(doc) for doc in inputs]
    policy = policies[0]
    configured = getattr(config, "workspace_policy", None)
    if (policy is None or configured is None
            or any(other is None or vars(other) != vars(policy) for other in policies)
            or vars(configured) != vars(policy)
            or config.workspaces != policy.workspaces):
        raise PermissionError(_ERROR)
    registry = WorkspaceRegistry(policy.workspaces, workspace_policy=policy)
    scopes = policy.public_scopes(registry)
    documents["workspaces.yaml"] = {"workspaces": policy.workspaces}
    documents["public-client-policy.yaml"] = {
        "version": 1, "workspaces": {
            name: {"path": row["path"], "operations": sorted(scopes[name])}
            for name, row in policy.workspaces.items()}}
    if relay is not None:
        relay = {"version": 1, "host": "127.0.0.1", "port": 8876,
                 "workspaces": sorted(name for name, row in policy.workspaces.items()
                                      if row["allow_agent_dispatch"])}
    return True, relay, policy.protected_paths


def _shared_protected_paths():
    from agentporter.workspace_policy import SHARED_POLICY_PATH
    return [SHARED_POLICY_PATH, Path("/etc/agentporter"),
            Path("/usr/local/libexec/agentporter"), Path("/opt/agentporter-worker"),
            Path("/var/lib/agentporter-worker"), Path.home() / ".ssh",
            Path.home() / ".local/share/agentporter",
            Path.home() / ".local/libexec/agentporter-production-20261028"]


def load_production_profile(config):
    """Return controls only for the exact unit-selected production profile.

    No selector preserves existing development/legacy startup behavior. An
    explicitly selected profile may never silently fall back to that behavior.
    All failures use fixed messages rather than YAML or protected path text.
    """
    selector = os.environ.get("AGENTPORTER_PROFILE", "")
    if selector not in ("", "production"):
        raise PermissionError("Unknown AgentPorter profile selector")
    if not selector:
        return None
    directory = None
    try:
        if os.getuid() == 0 or os.geteuid() != os.getuid():
            raise PermissionError(_ERROR)
        if 'AGENTPORTER_API_KEY' in os.environ:
            raise PermissionError(_ERROR)
        directory = _directory(config.config_dir)
        # Retain the existing file credential. Never parse it as YAML or create
        # an internal/provider key. The production unit prevents missing-key
        # auto-generation before Config is constructed.
        descriptor = _private_file(directory, "secrets.env")
        os.close(descriptor)
        for name in _FORBIDDEN:
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise PermissionError(_ERROR)
        documents = {name: _document(directory, name) for name in _REQUIRED}
        try:
            os.stat("delegation-upstream.yaml", dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            relay = None
        else:
            relay = _document(directory, "delegation-upstream.yaml")
        shared, relay, protected_paths = _shared_controls(config, documents, relay)
        if relay is not None:
            if (set(relay) != {"version", "host", "port", "workspaces"}
                    or type(relay["version"]) is not int or relay["version"] != 1
                    or relay["host"] != "127.0.0.1" or type(relay["port"]) is not int
                    or relay["port"] != 8876 or not isinstance(relay["workspaces"], list)
                    or not 1 <= len(relay["workspaces"]) <= 32
                    or not all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name)
                               for name in relay["workspaces"])
                    or len(set(relay["workspaces"])) != len(relay["workspaces"])):
                raise ValueError(_ERROR)
            descriptor = _private_file(directory, "delegation-relay.key")
            try:
                token = os.read(descriptor, 129).decode("ascii")
                if not re.fullmatch(r"[A-Za-z0-9_-]{43,96}\n?", token):
                    raise ValueError(_ERROR)
            finally:
                os.close(descriptor)
        # Existing optional identity metadata must also be protected; it does
        # not confer worker execution or cause credential creation.
        try:
            os.stat("agents.yaml", dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _document(directory, "agents.yaml")
        profile = documents["production-runtime.yaml"]
        if (set(profile) != {"version", "profile", "public_client_policy_required", "service_unit", "job_resources"}
                or type(profile["version"]) is not int or profile["version"] != 1
                or profile["profile"] != "production"
                or profile["public_client_policy_required"] is not True
                or profile["service_unit"] != "agentporter.service"):
            raise ValueError(_ERROR)
        validate_job_resource_settings(profile["job_resources"])
        registry = documents["workspaces.yaml"]
        if set(registry) != {"workspaces"} or registry["workspaces"] != config.workspaces:
            raise ValueError(_ERROR)
        workspaces = registry["workspaces"]
        if not isinstance(workspaces, dict) or not workspaces:
            raise ValueError(_ERROR)
        if relay is not None and not set(relay["workspaces"]) <= set(workspaces):
            raise PermissionError(_ERROR)
        public = documents["public-client-policy.yaml"]
        if (set(public) != {"version", "workspaces"} or type(public["version"]) is not int
                or public["version"] != 1 or not isinstance(public["workspaces"], dict)
                or set(public["workspaces"]) != set(workspaces)):
            raise ValueError(_ERROR)
        actions = documents["action-policy.yaml"]
        if (set(actions) != {"version", "action_modes"} or type(actions["version"]) is not int
                or actions["version"] != 1 or not isinstance(actions["action_modes"], dict)
                or actions["action_modes"].get("dispatch_agent") != ("SCOPE" if relay else "LOCKED")
                or any(name not in DEFAULT_ACTION_MODES or not isinstance(mode, str) or mode not in VALID_MODES
                       for name, mode in actions["action_modes"].items())):
            raise ValueError(_ERROR)
        if shared and any(actions["action_modes"].get(name, DEFAULT_ACTION_MODES[name])
                          != "LOCKED" for name in ("git_commit", "git_push")):
            raise PermissionError(_ERROR)
        roots = {}
        for name, row in workspaces.items():
            if (not isinstance(row, dict) or not isinstance(row.get("path"), str)
                    or not Path(row["path"]).is_absolute()
                    or row.get("auto_discover", False) is not False
                    or row.get("allow_agent_dispatch", False) is not (name in relay["workspaces"] if relay else False)):
                raise ValueError(_ERROR)
            root = Path(row["path"]).resolve(strict=True)
            if str(root) != row["path"]:
                raise ValueError(_ERROR)
            roots[name] = root
            scope = public["workspaces"][name]
            if (not isinstance(scope, dict) or set(scope) != {"path", "operations"}
                    or scope["path"] != str(root) or not isinstance(scope["operations"], list)
                    or not all(isinstance(op, str) for op in scope["operations"])
                    or len(scope["operations"]) != len(set(scope["operations"]))
                    or not set(scope["operations"]) <= {"read", "git_read", "git_write", "write", "exec", "dispatch"} | PRODUCTION_SCINET_SCOPES | ({"git_fetch", "dispatch_write"} if shared else set())):
                raise ValueError(_ERROR)
            if ("dispatch" in scope["operations"]) != (name in relay["workspaces"] if relay else False):
                raise PermissionError(_ERROR)
            if "dispatch" in scope["operations"] and row.get("allow_execute", False) is not True:
                raise PermissionError(_ERROR)
            if "dispatch_write" in scope["operations"] and (
                    not shared or not {"write", "dispatch", "exec"} <= set(scope["operations"])
                    or any(row.get(flag, False) is not True for flag in
                           ("writable", "allow_agent_dispatch", "allow_execute"))):
                raise PermissionError(_ERROR)
            if "git_write" in scope["operations"] and (
                row.get("writable", True) is not True or row.get("allow_git", True) is not True
            ):
                raise PermissionError(_ERROR)
            for operation in PRODUCTION_SCINET_SCOPES.intersection(scope["operations"]):
                if (name != "cranary" or row.get("allow_execute", False) is not True
                        or row.get("allow_" + operation, False) is not True):
                    raise PermissionError(_ERROR)
        targets = [Path(config.config_dir), Path(config.state_dir), Path(config.cache_dir),
                   Path(__file__).resolve().parent]
        if shared:
            targets.extend(_shared_protected_paths())
            targets.extend(protected_paths)
        targets = [target.resolve(strict=False) for target in targets]
        for name, root in roots.items():
            if any(root == target or root in target.parents or target in root.parents for target in targets):
                raise PermissionError(_ERROR)
            parent = any(other != root and root in other.parents for other in roots.values())
            if not shared and (name in _PROTECTED or parent):
                row = workspaces[name]
                if (row.get("writable", True) is not False or row.get("allow_execute", True) is not False
                        or not set(public["workspaces"][name]["operations"]) <= {"read", "git_read"}):
                    raise PermissionError(_ERROR)
        for path in (config.state_dir, config.cache_dir):
            descriptor = _directory(path)
            os.close(descriptor)
        return profile
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError, RecursionError):
        raise PermissionError(_ERROR) from None
    finally:
        if directory is not None:
            os.close(directory)
