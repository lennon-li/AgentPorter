"""Offline security-check runner for the staged public HTTPS proof of concept.

Uses stdlib and installed PyYAML only. This is not a substitute for full
pytest (CI will run that after explicit owner authorization to publish).
"""
from __future__ import annotations
import contextlib, re, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

class FakePytest:
    class mark:
        @staticmethod
        def parametrize(*args):
            return lambda f: f

    @staticmethod
    @contextlib.contextmanager
    def raises(cls, match=None):
        try:
            yield
        except cls as exc:
            if match and not re.search(match, str(exc)):
                raise AssertionError(f"Wrong error: {exc}")
        else:
            raise AssertionError(f"Expected error: {cls}")

sys.modules["pytest"] = FakePytest

testfile = Path(__file__).with_name("unit") / "test_scoped_https.py"
source = testfile.read_text().replace(
    "from agentporter.tools.execution import create_execution_tools", ""
)
ns = {"__name__": "offline_scoped_https_tests"}
exec(compile(source, str(testfile), "exec"), ns)

ran = []

def run(name, *params):
    with tempfile.TemporaryDirectory(prefix="offline_public_https_") as temp:
        ns[name](Path(temp), *params)
    ran.append(name)

run("test_no_operator_approval_blocks_everything")
for host in ns["PROPOSED_CRANARY_HOSTS"]:
    run("test_exact_four_hosts_get_and_head_are_scoped", host)
for url in (
    "http://api.github.com/",
    "https://evil.example/",
    "https://api.github.com.evil.example/",
    "https://api.github.com:444/",
    "https://api.github.com@evil.example/",
    "https://evil.example@api.github.com/",
    "https://127.0.0.1/",
    "https://[::1]/",
    "https://api.github.com./",
    "https://api.github.com/#anchor",
    "https://api.github.com/?token=abc",
    "https://api.github.com/\nEvil: 1",
    "https://api.github.com\\@evil.example/",
    "file:///etc/passwd",
):
    run("test_url_abuse_denied", url)
for argv in (
    ["bash", "-c", "curl https://api.github.com"],
    ["python3", "-c", "import requests"],
    ["curl", "-L", "https://api.github.com/"],
    ["curl", "--resolve", "api.github.com:443:127.0.0.1", "https://api.github.com/"],
    ["curl", "-fsS", "https://api.github.com/", "--output", ".env"],
    ["curl", "-X", "POST", "https://api.github.com/"],
    ["curl", "-fsS", "https://api.github.com/", "https://evil.example/"],
):
    ns["test_broker_cannot_spawn_arbitrary_network_commands"](argv)
    ran.append("test_broker_cannot_spawn_arbitrary_network_commands")
for addr in ("127.0.0.1", "10.2.3.4", "169.254.169.254", "::1", "fc00::1", "192.0.2.1"):
    ns["test_non_public_dns_answers_denied"](addr)
    ran.append("test_non_public_dns_answers_denied")
ns["test_mixed_public_private_dns_answers_denied"]()
ran.append("test_mixed_public_private_dns_answers_denied")
for invalid_port in (22, 80, 444, 8080):
    ns["test_resolver_result_cannot_override_https_port"](invalid_port)
    ran.append("test_resolver_result_cannot_override_https_port")
for mapped_ip in ("::ffff:8.8.8.8", "2002:0808:0808::",
                  "64:ff9b::808:808", "64:ff9b::a00:1", "64:ff9b:1::1"):
    ns["test_translated_or_embedded_dns_addresses_denied"](mapped_ip)
    ran.append("test_translated_or_embedded_dns_addresses_denied")
for content in (
    "version: 1\nworkspaces:\n  cranary:\n    hosts: [evil.example]\n    methods: [GET]\n    max_response_bytes: 1024\n    timeout_seconds: 5\n",
    ns["APPROVED"].replace("cranary:", "repos:"),
    ns["APPROVED"].replace("[GET, HEAD]", "[GET, POST]"),
    ns["APPROVED"].replace("262144", "100000000"),
    ns["APPROVED"].replace("timeout_seconds: 15", "timeout_seconds: 900"),
    ns["APPROVED"].replace("version: 1", "version: 2"),
):
    run("test_invalid_owner_policy_refuses_startup", content)
for name in (
    "test_owner_policy_must_be_private_regular_file",
    "test_untrusted_symlink_policy_refused",
    "test_config_may_not_live_inside_registered_workspace",
    "test_approved_api_get_uses_no_creds_and_no_redirects",
    "test_redirect_rejected_without_connecting_to_location",
    "test_oversized_get_denied",
    "test_non_utf8_response_replacement_cannot_exceed_output_budget",
    "test_head_returns_only_selected_metadata",
    "test_duplicate_operator_policy_keys_fail_closed",
):
    run(name)
for unsafe_policy in (
    """version: 1
workspaces: &scope
  cranary:
    hosts: [api.github.com]
    methods: [GET]
    max_response_bytes: 4096
    timeout_seconds: 5
extra: *scope
""",
    ns["APPROVED"].replace(
        "    hosts:", "    aliases: &hosts [api.github.com]\n    hosts:",
    ).replace("- api.github.com", "*hosts", 1),
    ns["APPROVED"].replace("      - api.github.com", "      - [api.github.com]"),
    ns["APPROVED"].replace("methods: [GET, HEAD]", "methods: [GET, [HEAD]]"),
    ns["APPROVED"].replace("methods: [GET, HEAD]", "methods: [GET, GET]"),
    ns["APPROVED"].replace("hosts:", "hosts: []\n    hosts:", 1),
):
    run("test_malformed_policy_stays_denied", unsafe_policy)
class _OfflineMonkeyPatch:
    def __init__(self):
        self.items = []
    def setattr(self, target, name, replacement):
        original = getattr(target, name)
        self.items.append((target, name, original))
        setattr(target, name, replacement)
    def undo(self):
        for target, name, value in reversed(self.items):
            setattr(target, name, value)


for testname in (
    "test_pinned_https_uses_vetted_ip_and_original_tls_hostname",
    "test_private_dns_rejected_before_any_tcp_connect",
):
    mp = _OfflineMonkeyPatch()
    try:
        ns[testname](mp)
        ran.append(testname)
    finally:
        mp.undo()

print(f"PASS: {len(ran)} offline HTTPS security cases; no outbound connections")
