# Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The pull request title gate rejects the titles it is there to reject.

Why this exists: the gate is one `cz check` invocation in a workflow file, and two of that
command's defaults let a title through without its format being checked at all. `cz check`
skips the Conventional Commits regex outright for a message beginning with one of its default
allowed prefixes -- Merge, Revert, Pull request, fixup!, squash!, amend! -- and `--allow-abort`
accepts an empty message, which is what `# invalid title` reduces to once git comment lines are
stripped.

Both were measured against the command as first written, `cz check --allow-abort
--commit-msg-file F`: seven of the eight titles below passed it, everything except the plain
unconventional control. The two fixes are independent, and each closes only its own half.
Emptying the prefix list closes the six prefix titles and does nothing for `# invalid title`;
dropping `--allow-abort` closes `# invalid title` and does nothing for the six. Both flags are
therefore load-bearing, which is why each bypass has its own case here.

Since the title becomes the squash commit on main, a flag quietly dropped from that command
reopens the bypass with nothing failing. These tests are what fail instead.

The command is read out of the workflow rather than restated here. A copy would keep passing
after the workflow changed, which is the failure mode being guarded against -- the point is to
pin what CI actually runs, not what this file remembers it running.
"""

from __future__ import annotations

import os.path
import re
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "commit-message.yml")

# Titles that must be rejected, each with the specific bypass it exercises.
REJECTED = [
    # The `Merge` and `Revert` default prefixes. Those exist for messages git itself writes
    # during a merge or a rebase, which a pull request title is not.
    ("Merge pull request #1 from nonsense", "Merge default prefix"),
    # The `Revert` case uses the shape GitHub's revert button actually produces, because that is
    # the one closed bypass whose closure costs a contributor anything: they get a red check and
    # have to retitle. Two commits reached main this way -- `Revert "Bumping up clap-rs (#294)"
    # (#299)` and `Revert "Filter as skips (#38)" (#39)` -- against 641 commits of history, with
    # no conventional `revert:` commit at all.
    #
    # Rejecting it is still right, and not for tidiness. `--allowed-prefixes Revert` cannot be
    # narrowed to that shape: commitizen matches with `commit_msg.startswith(prefix)`, so such an
    # allowance also exempts `Reverted the thing, no type at all` from the regex entirely. Both
    # were measured. `revert:` is an accepted type here and is in ACCEPTED below, so the fix for
    # a revert-button title is one retitle.
    ('Revert "fix: keep the digits above i64::MAX"', "Revert default prefix"),
    ("Pull request: nothing conventional here", "Pull request default prefix"),
    ("fixup! not a real type", "fixup! default prefix"),
    ("squash! not a real type", "squash! default prefix"),
    ("amend! not a real type", "amend! default prefix"),
    # Every git comment line is stripped before the regex runs, so this reduces to an empty
    # message -- which `--allow-abort` accepts.
    ("# invalid title", "comment-only title reducing to empty via --allow-abort"),
    # A plain unconventional title, which is the case the gate is obviously for. Included so a
    # command that rejected everything, including valid titles, is still distinguishable from
    # one that works: the accepted cases below are the other half of that.
    ("just some words", "no Conventional Commits type"),
]

# Titles that must be accepted, so a gate that rejects everything fails too. Without these the
# suite would pass for a `cz check` that had been broken into rejecting its own repository's
# commit style.
ACCEPTED = [
    "ci: enforce Conventional Commits with commitizen",
    "fix(values): keep the digits above i64::MAX",
    "feat!: a breaking change",
    "docs: a note",
    # The conventional form of a revert. CONTRIBUTING.md tells contributors to retitle a
    # revert-button pull request to this, so it has to keep working -- otherwise that advice goes
    # stale with nothing failing.
    "revert: keep the digits above i64::MAX",
]


def workflow_cz_check_command() -> list[str]:
    """The `cz check` argv the workflow runs, with the message-file placeholder removed.

    Read from the workflow so the assertion follows the command CI runs. The message file is
    substituted per case by the caller, since each title needs its own.
    """
    with open(WORKFLOW, encoding="utf-8") as handle:
        workflow = handle.read()

    lines = [line.strip() for line in workflow.splitlines() if re.match(r"^\s*cz check\b", line)]
    assert len(lines) == 1, (
        f"expected exactly one `cz check` line in {WORKFLOW}, found {len(lines)}: {lines}. "
        "These tests pin that command, so more than one means the wrong thing would be checked."
    )

    argv = lines[0].split()

    # The workflow points --commit-msg-file at $RUNNER_TEMP; each case below supplies its own
    # path instead. Dropping the flag and its value here keeps everything else -- notably the
    # presence or absence of --allow-abort and --allowed-prefixes -- exactly as CI has it.
    try:
        index = argv.index("--commit-msg-file")
    except ValueError:  # pragma: no cover - the flag is the point of the command
        pytest.fail(f"the `cz check` line in {WORKFLOW} has no --commit-msg-file: {argv}")
    del argv[index : index + 2]

    return argv


def run_cz_check(title: str, tmp_path) -> subprocess.CompletedProcess:
    if shutil.which("cz") is None:
        pytest.skip("commitizen is not installed; `pip install -r requirements-dev.txt`")

    message_file = tmp_path / "pr-title.txt"
    # printf '%s\n', matching the workflow: cz check reads a file, and a title with no trailing
    # newline is not what CI hands it.
    message_file.write_text(title + "\n", encoding="utf-8")

    argv = workflow_cz_check_command() + ["--commit-msg-file", str(message_file)]
    return subprocess.run(
        argv,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(("title", "bypass"), REJECTED, ids=[b for _, b in REJECTED])
def test_malformed_titles_are_rejected(title, bypass, tmp_path):
    result = run_cz_check(title, tmp_path)
    assert result.returncode != 0, (
        f"`{title}` was accepted, so the {bypass} is open. The pull request title becomes the "
        f"squash commit on main, so this lands unconventional. Check that the `cz check` line in "
        f"{WORKFLOW} still passes --allowed-prefixes and still omits --allow-abort.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    # 14 is cz check's rejection code specifically. Asserting on it rather than on "nonzero"
    # alone keeps a crash -- a missing config file, an unparsable pyproject -- from reading as a
    # correctly rejected title.
    assert result.returncode == 14, (
        f"`{title}` failed with exit {result.returncode} rather than 14, which is the code "
        f"cz check uses for a rejected message. Another code means the command did not run to a "
        f"verdict.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


@pytest.mark.parametrize("title", ACCEPTED)
def test_conventional_titles_are_accepted(title, tmp_path):
    result = run_cz_check(title, tmp_path)
    assert result.returncode == 0, (
        f"`{title}` is a well-formed Conventional Commits title and was rejected, so the gate "
        f"would block correct work.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_the_gate_pins_commitizen_to_the_pre_commit_hook_version():
    """CI and the pre-commit hook must validate with the same commitizen.

    `cz check`'s behavior is the thing under test, and its defaults have changed between
    releases -- the allowed-prefix list is a default, and so is the exit code above. An
    unpinned CI install resolves to whatever is newest, so a local pass would stop predicting
    a CI pass without either file changing.
    """
    with open(os.path.join(REPO_ROOT, "requirements-dev.txt"), encoding="utf-8") as handle:
        requirements = handle.read()
    with open(os.path.join(REPO_ROOT, ".pre-commit-config.yaml"), encoding="utf-8") as handle:
        pre_commit = handle.read()

    pinned = re.search(r"^commitizen==(\S+)\s*$", requirements, re.MULTILINE)
    assert pinned, (
        "requirements-dev.txt does not pin commitizen to an exact version. CI installs from "
        "this file, so an unpinned entry lets CI and local pre-commit run different versions."
    )

    hook_versions = re.findall(r"commitizen-tools/commitizen\s*\n\s*rev:\s*v?(\S+)", pre_commit)
    assert hook_versions, (
        "no commitizen rev found in .pre-commit-config.yaml; this test needs it to compare "
        "against the requirements-dev.txt pin."
    )
    for hook_version in hook_versions:
        assert hook_version == pinned.group(1), (
            f"the pre-commit hook uses commitizen {hook_version} but requirements-dev.txt pins "
            f"{pinned.group(1)}. Local and CI validation would differ."
        )


def test_commitizen_under_test_matches_the_pin():
    """The installed cz is the pinned one, so the cases above measure what CI measures."""
    if shutil.which("cz") is None:
        pytest.skip("commitizen is not installed; `pip install -r requirements-dev.txt`")

    with open(os.path.join(REPO_ROOT, "requirements-dev.txt"), encoding="utf-8") as handle:
        pinned = re.search(r"^commitizen==(\S+)\s*$", handle.read(), re.MULTILINE)
    assert pinned, "requirements-dev.txt does not pin commitizen"

    result = subprocess.run(
        [sys.executable, "-m", "commitizen", "version"],
        capture_output=True,
        text=True,
        check=False,
    )
    installed = result.stdout.strip()
    assert installed == pinned.group(1), (
        f"commitizen {installed} is installed but requirements-dev.txt pins "
        f"{pinned.group(1)}, so the assertions above are not measuring the version CI uses."
    )
