"""Central execution policy for delegated agent workers.

Every adapter translates this one policy into its own CLI flags so the
trusted-workspace boundary is defined in a single place. Enforcement is only
as fine-grained as each underlying CLI allows; the shell deny list is
prefix-matched by the agent CLI, not a sandbox.
"""

from dataclasses import asdict, dataclass

# Shell command prefixes that are never routine. Each entry is a command
# prefix; adapters render it in their CLI's own pattern syntax.
SENSITIVE_COMMANDS: tuple[str, ...] = (
    "git push --force",
    "git push -f",
    "git push --force-with-lease",
    "git push --delete",
    "git push --mirror",
    "git remote",
    "git branch -D",
    "git branch -d",
    "git branch --delete",
    "git reset --hard",
    "git clean",
    "git filter-branch",
    "gh repo delete",
    "gh release",
    "gh pr merge",
    "gh auth",
    "rm -rf",
    "rm -fr",
    "sudo",
    "su",
    "systemctl",
    "apt",
    "apt-get",
    "dnf",
    "snap",
    "npm publish",
    "twine upload",
    "docker push",
    "ssh",
    "scp",
)

# Commit and push are blocked unless the dispatcher explicitly confirms them.
COMMIT_COMMANDS: tuple[str, ...] = ("git commit",)
PUSH_COMMANDS: tuple[str, ...] = ("git push",)


@dataclass(frozen=True)
class ExecutionPolicy:
    """Trusted local workspace autonomy, not host autonomy."""

    workspace_write: bool = True
    shell: bool = True
    tests: bool = True
    git_read: bool = True
    git_commit: bool = False
    git_push: bool = False
    destructive: bool = False
    credentials: bool = False
    external_deploy: bool = False

    @classmethod
    def for_workspace(
        cls, writable: bool, allow_commit: bool = False, allow_push: bool = False
    ) -> "ExecutionPolicy":
        """Commit/push need writable workspace plus explicit human confirmation."""
        if not writable:
            return cls(workspace_write=False)
        return cls(git_commit=allow_commit, git_push=allow_push)

    def denied_commands(self) -> list[str]:
        denied = list(SENSITIVE_COMMANDS)
        if not self.git_commit:
            denied.extend(COMMIT_COMMANDS)
        if not self.git_push:
            denied.extend(PUSH_COMMANDS)
        return denied

    def as_dict(self) -> dict:
        return asdict(self)

    def packet_text(self) -> str:
        """Human-readable policy block embedded in the worker control packet."""
        return (
            "Execution Policy:\n"
            f"- Workspace edits: {'allowed' if self.workspace_write else 'NOT allowed (read-only)'}\n"
            "- Shell, tests, builds, git status/diff/log/show: allowed inside Project Root\n"
            f"- git commit: {'allowed (confirmed by dispatcher)' if self.git_commit else 'NOT allowed without human confirmation'}\n"
            f"- git push: {'allowed to existing remotes (confirmed by dispatcher)' if self.git_push else 'NOT allowed without human confirmation'}\n"
            "- Force push, remote changes, branch deletion: NOT allowed\n"
            "- Destructive deletes, credential/secret changes, system config, "
            "package installs, deploys, publishing, external messages: NOT allowed\n"
            "- Do not write outside Project Root.\n"
        )
