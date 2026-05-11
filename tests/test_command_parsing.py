"""Tests for cron and systemd command parsing.

The parser in ``ExecutionIngester._extract_executables`` is responsible
for pulling the actual binary being invoked out of a cron line or
systemd ``ExecStart=`` directive. Getting this wrong floods the graph
with bogus FILE nodes (for example, by treating ``/etc`` in
``find /etc -name foo`` as an executable). These tests pin down the
expected behavior and prevent regressions.
"""
from privmap.ingestion.execution import ExecutionIngester


def _extract(cmd):
    """Convenience wrapper. _extract_executables takes self, but is pure
    on its argument, so a fresh ingester works fine for testing."""
    return ExecutionIngester(root_path="/")._extract_executables(cmd)


class TestSinglePathExtraction:
    def test_absolute_binary_with_no_args(self):
        assert _extract("/usr/bin/foo") == ["/usr/bin/foo"]

    def test_absolute_binary_with_args(self):
        # /etc is an argument, not a binary. Must not be emitted.
        assert _extract("/usr/bin/find /etc -name foo") == ["/usr/bin/find"]

    def test_path_argument_is_not_an_executable(self):
        # This is the key regression: a path-looking argument like /var/log
        # should never become an EXECUTES target.
        assert _extract("/bin/tar czf /tmp/out.tgz /var/log") == ["/bin/tar"]

    def test_relative_binary_is_skipped(self):
        # Relative names depend on $PATH and would create ambiguous
        # FILE nodes. The parser deliberately drops them.
        assert _extract("foo --bar") == []

    def test_empty_command(self):
        assert _extract("") == []

    def test_whitespace_only_command(self):
        assert _extract("   \t  ") == []


class TestEnvVarStripping:
    def test_single_env_var_prefix(self):
        assert _extract("HOME=/root /usr/bin/foo") == ["/usr/bin/foo"]

    def test_multiple_env_var_prefix(self):
        assert _extract("HOME=/root PATH=/usr/bin /usr/bin/foo") == ["/usr/bin/foo"]

    def test_env_var_with_no_binary(self):
        # Just an env-var assignment with no subsequent command should
        # produce nothing, not crash.
        assert _extract("HOME=/root") == []


class TestShellSeparators:
    def test_double_ampersand_chain(self):
        assert _extract("/bin/foo && /bin/bar") == ["/bin/foo", "/bin/bar"]

    def test_double_pipe_chain(self):
        assert _extract("/bin/foo || /bin/bar") == ["/bin/foo", "/bin/bar"]

    def test_semicolon_chain(self):
        assert _extract("/bin/foo; /bin/bar") == ["/bin/foo", "/bin/bar"]

    def test_pipe_chain(self):
        assert _extract("/bin/foo | /bin/bar") == ["/bin/foo", "/bin/bar"]

    def test_mixed_separators(self):
        # A typical cron job: do X, and if it works do Y, otherwise do Z.
        assert _extract("/bin/foo && /bin/bar || /bin/baz") == [
            "/bin/foo", "/bin/bar", "/bin/baz",
        ]

    def test_each_segment_gets_env_stripping(self):
        # Both halves of a chain should have their own env-var prefix
        # stripped independently.
        assert _extract("FOO=1 /bin/a && BAR=2 /bin/b") == ["/bin/a", "/bin/b"]


class TestDirectoryHandling:
    def test_trailing_slash_path_is_dropped(self):
        # A path ending in / is a directory, not a binary. Don't emit
        # an EXECUTES edge against it.
        assert _extract("/usr/bin/") == []

    def test_directory_in_chain_does_not_pollute(self):
        # The trailing-slash check filters the bogus first segment,
        # but the real binary in the second segment must still surface.
        assert _extract("/usr/bin/ && /bin/foo") == ["/bin/foo"]


class TestRealWorldCronCommands:
    """End-to-end on the kinds of commands cron actually emits."""

    def test_logrotate(self):
        cmd = "/usr/sbin/logrotate /etc/logrotate.conf"
        assert _extract(cmd) == ["/usr/sbin/logrotate"]

    def test_find_with_exec(self):
        # /usr/bin/find should be the only emitted binary, NOT /tmp or
        # the various paths inside the -exec clause.
        cmd = "/usr/bin/find /tmp -type f -mtime +7 -exec rm {} \\;"
        # rm is relative so it's dropped; find is the only absolute.
        assert _extract(cmd) == ["/usr/bin/find"]

    def test_man_db_update(self):
        cmd = "test -e /usr/bin/mandb && /usr/bin/mandb --quiet"
        # `test` is relative (not absolute), but /usr/bin/mandb in the
        # second segment must come through cleanly.
        assert _extract(cmd) == ["/usr/bin/mandb"]

    def test_apt_daily(self):
        cmd = (
            "/usr/lib/apt/apt.systemd.daily update "
            "&& /usr/lib/apt/apt.systemd.daily install"
        )
        assert _extract(cmd) == [
            "/usr/lib/apt/apt.systemd.daily",
            "/usr/lib/apt/apt.systemd.daily",
        ]


class TestSystemdExecCompatibility:
    """ExecStart= directives are routed through the same extractor.

    The systemd-side wrapper just calls the cron one; verifying it here
    locks in that contract so a future refactor cannot silently diverge
    the two parsers.
    """

    def test_systemd_uses_same_logic(self):
        ing = ExecutionIngester(root_path="/")
        cmd = "/usr/bin/nginx -g 'daemon off;'"
        assert ing._extract_executables(cmd) == ing._extract_executables_from_cmd(cmd)

    def test_systemd_simple_service(self):
        cmd = "/usr/bin/nginx -g 'daemon off;'"
        assert _extract(cmd) == ["/usr/bin/nginx"]
