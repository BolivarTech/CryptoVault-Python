"""Tests for the header sweep.

Maintained copy
---------------
This file and ``scripts/check_headers.py`` are the maintained copies of the header
sweep and its tests. Fixes land here, versioned, and change together: the
tests cover the project-specific pieces (the ``.py`` comment map, the
version read from ``pyproject.toml``, the shebang and the PEP 263 encoding
cookie kept above the header) as well as the language-agnostic ones.


The property under test is not "does it print something" but "does it look at
the right files, and does writing stay safe to repeat". Both halves fail
silently in production if wrong: a sweep that enumerates the wrong set reports
a confident green over files it never opened, and a write that is not
idempotent stacks a second header nobody notices until the diff is read.

Every fixture lives in a temporary git repository built by
``HeaderSweepTestCase.setUp``; the
real tree is never touched, and no test depends on the checkout it runs from.
"""

import contextlib
import io
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import check_headers

PROJECT_VERSION = "0.17.0"
RELEASE_DATE = "2026-08-27"
STALE_VERSION = "0.16.0"

PYPROJECT_TOML = f"""[project]
name = "fixture"
version = "{PROJECT_VERSION}"
"""


def _git(root: pathlib.Path, *args: str) -> None:
    """Run a git command in a fixture repository, failing loudly.

    Args:
        root: Repository the command runs in.
        *args: Arguments after ``git``.

    Raises:
        subprocess.CalledProcessError: If git exits non-zero.
    """
    subprocess.run(("git", *args), cwd=str(root), check=True, capture_output=True)


def _write(
    root: pathlib.Path, relative: str, text: str, newline: str = "\n"
) -> pathlib.Path:
    """Create a fixture file with explicit line endings.

    Args:
        root: Repository root.
        relative: Path relative to ``root``.
        text: File contents written with ``\\n`` separators.
        newline: Line ending actually stored on disk.

    Returns:
        pathlib.Path: The absolute path written.
    """
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text.replace("\n", newline))
    return path


def _header(comment: str, version: str, date: str = RELEASE_DATE) -> str:
    """Build a conforming three-line header.

    Args:
        comment: Comment marker, ``"#"``.
        version: Version to place in the header.
        date: Date to place in the header.

    Returns:
        str: The header block, newline-terminated.
    """
    return (
        f"{comment} Author: Julian Bolivar\n"
        f"{comment} Version: {version}\n"
        f"{comment} Date: {date}\n"
    )


class HeaderSweepTestCase(unittest.TestCase):
    """Base case that builds a throwaway git repository per test."""

    def setUp(self) -> None:
        """Create a repository on ``main`` with one commit as the base ref."""
        self.root = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, str(self.root), True)
        _git(self.root, "init", "-b", "main")
        _git(self.root, "config", "user.email", "fixture@example.invalid")
        _git(self.root, "config", "user.name", "Fixture")
        # Keep the working tree byte-identical to what the fixtures wrote, so
        # the line-ending assertions test the script and not git's filters.
        _git(self.root, "config", "core.autocrlf", "false")
        _write(self.root, "pyproject.toml", PYPROJECT_TOML)
        _git(self.root, "add", "-A")
        _git(self.root, "commit", "-m", "base")

    def change(self, relative: str, text: str, newline: str = "\n") -> pathlib.Path:
        """Write a file and stage it, so ``git diff main`` can see it.

        An untracked file is invisible to ``git diff``, so a fixture that only
        writes would leave the sweep with nothing to enumerate and every
        assertion vacuously green.

        Args:
            relative: Path relative to the repository root.
            text: File contents written with ``\\n`` separators.
            newline: Line ending actually stored on disk.

        Returns:
            pathlib.Path: The absolute path written.
        """
        path = _write(self.root, relative, text, newline)
        _git(self.root, "add", "--", relative)
        return path

    def check(self) -> tuple[list[str], list[pathlib.Path]]:
        """Run a check-mode sweep over the fixture repository.

        Returns:
            tuple[list[str], list[pathlib.Path]]: Offenders and (empty)
            modified paths, as returned by :func:`check_headers.sweep`.
        """
        return check_headers.sweep(
            self.root, "main", PROJECT_VERSION, RELEASE_DATE, write=False
        )

    def stamp(self) -> list[pathlib.Path]:
        """Run a write-mode sweep over the fixture repository.

        Returns:
            list[pathlib.Path]: The paths the sweep modified.
        """
        _, modified = check_headers.sweep(
            self.root, "main", PROJECT_VERSION, RELEASE_DATE, write=True
        )
        return modified

    def enumerated(self) -> list[str]:
        """List the paths the sweep would visit, as POSIX strings.

        Returns:
            list[str]: Repository-relative paths in scope.
        """
        return [
            p.as_posix() for p in check_headers.changed_source_files(self.root, "main")
        ]

    def contents(self, relative: str) -> str:
        """Read a fixture file back without newline translation.

        Args:
            relative: Path relative to the repository root.

        Returns:
            str: The file's exact contents.
        """
        return check_headers.read_text(self.root / relative)


class EnumerationTests(HeaderSweepTestCase):
    """What the sweep looks at -- the half that fails silently when wrong."""

    def test_a_deleted_file_is_not_reported_as_a_missing_header(self) -> None:
        """A file removed by the milestone must not enter the sweep.

        A deletion has no header left to stamp, and enumerating its path
        aborts the whole sweep on a read of a file that is no longer there.
        """
        self.change("src/gone.py", _header("#", PROJECT_VERSION) + "x = 1\n")
        _git(self.root, "add", "-A")
        _git(self.root, "commit", "-m", "add")
        _git(self.root, "rm", "src/gone.py")

        self.assertNotIn("src/gone.py", self.enumerated())
        offenders, _ = self.check()
        self.assertEqual([], offenders)

    def test_a_renamed_file_is_checked_at_its_new_path(self) -> None:
        """A rename must be reported at the destination, never the source.

        The old path no longer exists on disk, so checking it either crashes
        or -- worse -- silently skips the file that actually needs stamping.
        """
        self.change("src/old_name.py", _header("#", STALE_VERSION) + "x = 1\n")
        _git(self.root, "add", "-A")
        _git(self.root, "commit", "-m", "add")
        _git(self.root, "mv", "src/old_name.py", "src/new_name.py")

        enumerated = self.enumerated()
        self.assertIn("src/new_name.py", enumerated)
        self.assertNotIn("src/old_name.py", enumerated)

        offenders, _ = self.check()
        self.assertEqual(1, len(offenders))
        self.assertIn("src/new_name.py", offenders[0])

    def test_a_changed_toml_is_not_treated_as_a_source_file(self) -> None:
        """Only extensions that carry the header are in scope.

        A changed ``.toml``, ``.md``, ``.yml`` or ``.lock`` has no header, so
        reporting one as missing turns the sweep into noise operators learn to
        ignore.
        """
        self.change("config.toml", "key = 1\n")
        self.change("README.md", "# title\n")
        self.change("ci.yml", "on: push\n")
        self.change("uv.lock", "# lock\n")
        self.change("src/real.py", _header("#", PROJECT_VERSION))

        self.assertEqual(["src/real.py"], self.enumerated())
        offenders, _ = self.check()
        self.assertEqual([], offenders)


class CheckModeTests(HeaderSweepTestCase):
    """Check mode's verdicts."""

    def test_a_stale_version_fails_the_check(self) -> None:
        """A header left on the previous release's version must fail.

        This is the decay the script exists to catch: a stale header breaks no
        build and fails no other test.
        """
        self.change("src/stale.py", _header("#", STALE_VERSION) + "x = 1\n")

        offenders, _ = self.check()
        self.assertEqual(1, len(offenders))
        self.assertIn("src/stale.py", offenders[0])
        self.assertIn(STALE_VERSION, offenders[0])

    def test_a_malformed_date_fails_the_check(self) -> None:
        """A Date that is not ``YYYY-MM-DD`` must fail, version notwithstanding.

        The two fields decay independently; passing on the version alone would
        let a hand-typed "27-08-2026" through unnoticed.
        """
        self.change("src/dated.py", _header("#", PROJECT_VERSION, "27/08/2026"))

        offenders, _ = self.check()
        self.assertEqual(1, len(offenders))
        self.assertIn("YYYY-MM-DD", offenders[0])

    def test_a_file_with_no_header_at_all_fails_the_check(self) -> None:
        """A brand-new source file with no header must be named, not skipped.

        A file added by the milestone is the likeliest one to be missing the
        header entirely.
        """
        self.change("src/bare.py", "x = 1\n")

        offenders, _ = self.check()
        self.assertEqual(1, len(offenders))
        self.assertIn("src/bare.py", offenders[0])

    def test_a_header_below_an_encoding_cookie_is_recognised(self) -> None:
        """A header under a PEP 263 encoding cookie must count as present.

        The cookie only works on line 1 or 2, so a file that declares one
        legitimately carries its header below it. Reporting that as "no
        header" is a false positive, and a sweep that cries wolf is a sweep
        people stop reading.
        """
        self.change(
            "src/main.py",
            "#!/usr/bin/env python3\n"
            "# -*- coding: utf-8 -*-\n" + _header("#", PROJECT_VERSION) + "\nx = 1\n",
        )

        offenders, _ = self.check()
        self.assertEqual([], offenders)

    def test_a_stale_header_below_an_encoding_cookie_still_fails(self) -> None:
        """Tolerating the cookie must not blind the check to a stale version.

        The skip exists to find the header, not to excuse it.
        """
        self.change(
            "src/main.py",
            "# -*- coding: utf-8 -*-\n" + _header("#", STALE_VERSION) + "\nx = 1\n",
        )

        offenders, _ = self.check()
        self.assertEqual(1, len(offenders))
        self.assertIn(STALE_VERSION, offenders[0])

    def test_a_conforming_tree_exits_zero_through_main(self) -> None:
        """The CLI must exit 0 when every changed source file conforms.

        Exercised through ``main`` so the exit code contract itself is covered,
        not only the function beneath it.
        """
        self.change("src/ok.py", _header("#", PROJECT_VERSION))
        self.change("scripts/ok.py", _header("#", PROJECT_VERSION))

        with contextlib.redirect_stdout(io.StringIO()):
            code = check_headers.main(
                ["--repo-root", str(self.root), "--base-ref", "main"]
            )
        self.assertEqual(0, code)

    def test_the_cli_exits_non_zero_when_a_header_is_stale(self) -> None:
        """The CLI must exit non-zero on an offender, so a gate can fail on it.

        A sweep that reports offenders on stdout while exiting 0 is a gate that
        cannot fail.
        """
        self.change("src/stale.py", _header("#", STALE_VERSION))

        with contextlib.redirect_stdout(io.StringIO()) as captured:
            code = check_headers.main(
                ["--repo-root", str(self.root), "--base-ref", "main"]
            )
        self.assertEqual(check_headers.EXIT_OFFENDERS, code)
        self.assertIn("src/stale.py", captured.getvalue())


class WriteModeTests(HeaderSweepTestCase):
    """Write mode: stamping, repeating, and creating."""

    def test_write_stamps_the_release_version_and_date(self) -> None:
        """Write mode must replace both decayed fields in place.

        The surrounding code and the Author line must survive untouched -- the
        stamp is a two-field edit, not a header rewrite.
        """
        self.change(
            "src/stale.py", _header("#", STALE_VERSION, "2026-01-01") + "x = 1\n"
        )

        modified = self.stamp()
        self.assertEqual(["src/stale.py"], [p.as_posix() for p in modified])
        self.assertEqual(
            _header("#", PROJECT_VERSION, RELEASE_DATE) + "x = 1\n",
            self.contents("src/stale.py"),
        )

        offenders, _ = self.check()
        self.assertEqual([], offenders)

    def test_write_is_idempotent_and_stacks_no_second_header(self) -> None:
        """Running write twice must leave exactly one header.

        Re-detecting the header it just wrote is the whole guard: a writer that
        blindly prepends turns every release into another header block, and
        nothing but a human reading the diff would notice.
        """
        self.change("src/stale.py", _header("#", STALE_VERSION) + "x = 1\n")

        first = self.stamp()
        after_first = self.contents("src/stale.py")
        second = self.stamp()
        after_second = self.contents("src/stale.py")

        self.assertEqual(["src/stale.py"], [p.as_posix() for p in first])
        self.assertEqual([], second, "a conforming header was rewritten")
        self.assertEqual(after_first, after_second)
        self.assertEqual(1, after_second.count("Author: Julian Bolivar"))
        self.assertEqual(1, after_second.count("Version:"))

    def test_write_creates_a_header_on_a_file_that_has_none(self) -> None:
        """A file with no header must get one, above its existing first line.

        Without this, every newly added file would have to be stamped by hand,
        which is the manual chore the script replaces.
        """
        self.change("src/bare.py", "x = 1\n")

        self.stamp()

        self.assertEqual(
            _header("#", PROJECT_VERSION, RELEASE_DATE) + "\nx = 1\n",
            self.contents("src/bare.py"),
        )
        offenders, _ = self.check()
        self.assertEqual([], offenders)

    def test_write_keeps_a_python_shebang_on_the_first_line(self) -> None:
        """A shebang must stay on line 1, with the header inserted beneath it.

        A header pushed above ``#!`` silently stops the file being executable
        as a script, and nothing in the header check itself would report it.
        """
        self.change("scripts/tool.py", "#!/usr/bin/env python3\nprint(1)\n")

        self.stamp()

        text = self.contents("scripts/tool.py")
        self.assertTrue(text.startswith("#!/usr/bin/env python3\n"))
        self.assertEqual(
            "#!/usr/bin/env python3\n"
            + _header("#", PROJECT_VERSION, RELEASE_DATE)
            + "\nprint(1)\n",
            text,
        )
        offenders, _ = self.check()
        self.assertEqual([], offenders)

    def test_write_creates_a_header_below_an_encoding_cookie(self) -> None:
        """A created header must go under the encoding cookie, not over it.

        PEP 263 only honours the cookie on line 1 or 2, so a header written
        above it silently drops the declared encoding -- a break the header
        check itself would never report.
        """
        self.change("src/main.py", "# -*- coding: latin-1 -*-\nx = 1\n")

        self.stamp()

        self.assertEqual(
            "# -*- coding: latin-1 -*-\n"
            + _header("#", PROJECT_VERSION, RELEASE_DATE)
            + "\nx = 1\n",
            self.contents("src/main.py"),
        )

    def test_write_preserves_crlf_line_endings(self) -> None:
        """A CRLF file must come back CRLF, everywhere.

        This tree is mixed. Rewriting a CRLF file with LF marks every line as
        changed, which buries the one line that actually moved.
        """
        self.change(
            "src/crlf.py", _header("#", STALE_VERSION) + "x = 1\n", newline="\r\n"
        )

        self.stamp()

        raw = (self.root / "src/crlf.py").read_bytes()
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))
        self.assertIn(b"# Version: " + PROJECT_VERSION.encode() + b"\r\n", raw)

    def test_write_gives_a_created_header_the_files_own_line_ending(self) -> None:
        """A header created in a CRLF file must itself be CRLF.

        Mixing the two inside one file is the same diff noise as rewriting it,
        only harder to spot because most of the file still looks right.
        """
        self.change("src/crlf_bare.py", "x = 1\n", newline="\r\n")

        self.stamp()

        raw = (self.root / "src/crlf_bare.py").read_bytes()
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))
        self.assertTrue(raw.startswith(b"# Author: Julian Bolivar\r\n"))


class VersionSourceTests(HeaderSweepTestCase):
    """Where the release version comes from."""

    def test_the_release_version_is_read_from_pyproject_toml(self) -> None:
        """The expected version must come from ``[project] version``.

        Deriving it removes the second place a release number could go stale.
        """
        self.assertEqual(PROJECT_VERSION, check_headers.project_version(self.root))

    def test_a_missing_pyproject_toml_is_an_error_not_a_pass(self) -> None:
        """An unreadable manifest must fail the sweep, never default to green.

        Failing open here would report success over a version nobody supplied.
        """
        (self.root / "pyproject.toml").unlink()
        with self.assertRaises(check_headers.HeaderSweepError):
            check_headers.project_version(self.root)


if __name__ == "__main__":
    unittest.main()
