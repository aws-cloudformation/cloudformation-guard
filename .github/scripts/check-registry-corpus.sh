#!/usr/bin/env bash
#
# Asserts that `cfn-guard test -d` over the pinned aws-guard-rules-registry corpus is in the state
# this repository last measured it in. That state is a *failing* one: the run exits 1 because 30
# expectations in rules/aws/aws_cloudformation name rules their .guard file never declares, so those
# expectations get no verdict, and an expectation that could not be evaluated is the error code by
# design. See the pin comment in .github/workflows/pr.yml, and
# aws-cloudformation/aws-guard-rules-registry#288 for the fix that releases the pin.
#
# So this is not "the corpus passes". Asserting exit 0 would be asserting something untrue and the
# job would be red forever; asserting nothing but "exit 1" would let a genuine regression through,
# because a run that fails an expectation for real also exits 1 -- `get_exit_code` in
# guard/src/commands/test.rs makes the error code sticky, so once anything is unchecked the number
# the process exits with can no longer tell you whether anything else went wrong. Hence the four
# further conditions below, which read the report rather than the exit status.
#
# Where each datum comes from, because they are not all in the same place:
#
#   - the exit code                      -> the process exit status  (condition 1)
#   - unchecked expectations             -> the JSON report on STDOUT (condition 2)
#   - failed rules                       -> the JSON report on STDOUT (condition 3)
#   - unreadable files, unrunnable cases -> the JSON report on STDOUT (condition 4)
#   - orphaned test files                -> the diagnostics on STDERR (condition 5)
#
# Condition 5 has to read stderr because orphaned test files are not in the report at all; they are
# only ever written as diagnostics. Condition 2 reads stdout rather than the equivalent stderr
# diagnostics because the report carries one entry per (case, expectation) -- 30 of them -- while the
# diagnostics are a set and collapse to the 11 distinct names, so only the report can tell you that a
# name lost some of its expectations but not all.
#
# Usage: check-registry-corpus.sh <path-to-cfn-guard> <path-to-registry-rules-dir>
#
# One script for all three integration jobs (ubuntu, macos, windows) rather than a bash copy and a
# pwsh copy. Two copies of this are two chances to get the exit-code handling wrong, and that has
# already happened once in this workflow: the Windows job's `if (<command>)` read the command's stdout
# as the verdict instead of its status, so it logged "have passed" for a run that had exited non-zero.
# The Windows job therefore declares `shell: bash` and calls this file.
#
# Written for bash 3.2 and BSD userland, because macos-latest ships bash 3.2.57 and no GNU coreutils.
# Three things are avoided for that reason and are not stylistic: failures accumulate in a file rather
# than an array, because `${#array[@]}` on an empty array is an unbound-variable error under `set -u`
# before bash 4.4; `mktemp -d` is given an explicit template, which BSD mktemp requires; and `diff` is
# given self-describing filenames rather than `--label`, which BSD diff does not reliably accept.

set -euo pipefail

readonly EXPECTED_EXIT_CODE=1

if [[ $# -ne 2 ]]; then
    printf 'usage: %s <path-to-cfn-guard> <path-to-registry-rules-dir>\n' "$0" >&2
    exit 2
fi

guard_bin=$1
rules_dir=$2

state_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../registry-corpus-state" && pwd)"
readonly state_dir
readonly expected_unchecked="$state_dir/unchecked-expectations.txt"
readonly expected_orphans="$state_dir/orphaned-test-files.txt"

# The Windows runner builds cfn-guard.exe, and the callers pass one path for all three platforms. Git
# bash appends .exe when it *executes* a name, but `-x` does not, so the suffix is resolved here.
if [[ ! -x $guard_bin && -x "$guard_bin.exe" ]]; then
    guard_bin="$guard_bin.exe"
fi

if [[ ! -x $guard_bin ]]; then
    printf 'no cfn-guard binary at %s (or %s.exe)\n' "$guard_bin" "$guard_bin" >&2
    exit 2
fi

for expected_file in "$expected_unchecked" "$expected_orphans"; do
    if [[ ! -f $expected_file ]]; then
        printf 'missing expected-state file %s\n' "$expected_file" >&2
        exit 2
    fi
done

# `TMPDIR` is not necessarily a path this shell can use. On a Windows runner Git bash can inherit a value
# carrying a drive letter and backslashes, which is not a directory from bash's point of view, and `mktemp`
# then fails on the template prefix rather than on anything to do with the corpus. Fall back instead of
# dying, because that failure mode is the worst kind to debug from a log: a bare `mktemp:` line, before any
# condition has run, with no `FAIL: condition` to say which check was unhappy -- it reads as the checker
# being broken rather than as the environment being unusual.
#
# Decided by trying `mktemp` and not by testing the path first. `[[ -d $tmproot ]]` predicts whether the
# call will work, and it predicts wrong in the direction that matters: a `TMPDIR` naming a real directory
# this process cannot write to passes the test and then fails the call, which is the same bare `mktemp:`
# line the test was added to prevent. Measured with `TMPDIR=/proc`, where `-d` is true, `-w` is false, and
# the run died before condition 1. Adding `-w` would close that one case and still be a prediction; the
# call itself is the only thing that knows, and on MSYS the reason can be the template's backslashes
# rather than anything a test on the prefix could see.
#
# The explicit template stays: BSD mktemp on macos-latest requires one, and `-t` differs between the two.
work=""
for tmproot in "${TMPDIR:-/tmp}" /tmp; do
    if work=$(mktemp -d "$tmproot/cfn-guard-registry-check.XXXXXX" 2>/dev/null); then
        if [[ $tmproot != "${TMPDIR:-/tmp}" ]]; then
            printf 'TMPDIR=%s is not usable here; using %s instead\n' "${TMPDIR-}" "$tmproot" >&2
        fi
        break
    fi
    work=""
done

# `mktemp`'s own message is suppressed above and replaced here, because a recovered run must not leave an
# error line in the log for a step that succeeded -- and a run that recovers nowhere needs to say what to
# do, which `mktemp` does not.
if [[ -z $work ]]; then
    tried=/tmp
    if [[ ${TMPDIR:-/tmp} != /tmp ]]; then
        tried="$TMPDIR or /tmp"
    fi
    printf 'could not create a temporary directory under %s\n' "$tried" >&2
    printf 'set TMPDIR to a writable directory, or clear it to use /tmp\n' >&2
    exit 2
fi
readonly work
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/expected" "$work/actual"

readonly report="$work/report.json"
readonly diagnostics="$work/diagnostics.txt"

# The failures of every condition, not just the first, so one run tells you everything that moved.
# A file and not an array: see the bash 3.2 note in the header.
readonly failures="$work/failures.txt"
: >"$failures"

fail() {
    printf 'FAIL: %s\n\n' "$1" >>"$failures"
}

# Strips the comment and blank lines from an expected-state file, and any CR a checkout might have
# left. This repository's .gitattributes pins eol=lf, so the CR strip is belt and braces -- but the
# alternative is a Windows-only failure that nothing outside CI would ever reproduce.
strip_comments() {
    tr -d '\r' <"$1" | sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d'
}

# `tr` and not `paste -sd' '`: BSD paste is stricter about the combined form.
one_line() {
    tr '\n' ' ' | sed -e 's/ *$//'
}

# `|| actual_exit=$?` rather than letting `set -e` take it: exiting non-zero is the expected outcome
# here, and the code is the thing being measured.
actual_exit=0
"$guard_bin" test -d "$rules_dir" --output-format json \
    >"$report" 2>"$diagnostics" || actual_exit=$?

# ---- condition 1: the exit code is the one the contract owes for this corpus --------------------

if [[ $actual_exit -ne $EXPECTED_EXIT_CODE ]]; then
    fail "condition 1 (exit code): expected $EXPECTED_EXIT_CODE, got $actual_exit.
  $EXPECTED_EXIT_CODE is TEST_ERROR_STATUS_CODE -- an expectation that could not be evaluated.
  7 is TEST_FAILURE_STATUS_CODE, an expectation that was not met; 0 is a clean run, which would
  mean the corpus was fixed and this check plus the pin in pr.yml should both be updated."
fi

# ---- condition 2: the unchecked expectations are exactly the known ones -------------------------

# `<name> <count>` with the name first so a plain sort orders by name, and with the count present so
# that a name losing some -- but not all -- of its expectations is a mismatch rather than a match.
jq -r '[.[] | .test_cases[]? | .unchecked_expectations[]? .name]
       | group_by(.) | map("\(.[0]) \(length)") | .[]' "$report" \
    | LC_ALL=C sort >"$work/actual/unchecked-expectations.txt"

strip_comments "$expected_unchecked" \
    | LC_ALL=C sort >"$work/expected/unchecked-expectations.txt"

if ! cmp -s "$work/expected/unchecked-expectations.txt" \
    "$work/actual/unchecked-expectations.txt"; then

    cut -d' ' -f1 <"$work/expected/unchecked-expectations.txt" >"$work/expected/names.txt"
    cut -d' ' -f1 <"$work/actual/unchecked-expectations.txt" >"$work/actual/names.txt"

    appeared=$(LC_ALL=C comm -13 "$work/expected/names.txt" "$work/actual/names.txt" | one_line)
    disappeared=$(LC_ALL=C comm -23 "$work/expected/names.txt" "$work/actual/names.txt" | one_line)

    detail=""
    if [[ -n $appeared ]]; then
        detail="$detail
  appeared (a rule name whose expectations now go unchecked, and did not before): $appeared"
    fi
    if [[ -n $disappeared ]]; then
        detail="$detail
  disappeared (expected to go unchecked, and no longer does): $disappeared"
    fi
    if [[ -z $appeared && -z $disappeared ]]; then
        detail="$detail
  the same rule names, but at least one changed how many expectations it carries"
    fi

    fail "condition 2 (unchecked-expectation set): does not match
  .github/registry-corpus-state/unchecked-expectations.txt$detail

$(diff -u "$work/expected/unchecked-expectations.txt" \
        "$work/actual/unchecked-expectations.txt" || true)"
fi

# ---- condition 3: nothing actually failed -------------------------------------------------------

# The condition the exit code cannot carry. The corpus already has unchecked expectations, which pin
# the code at 1, so a rule that runs and fails its expectation moves the exit code not at all.
jq -r '[.[] | .test_cases[]?
        | . as $case
        | .failed_rules[]?
        | "  \($case.name // "<unnamed case>"): rule \(.name), expected \(.expected), evaluated \(.evaluated | join(", "))"]
       | .[]' "$report" >"$work/failed-rules.txt"

if [[ -s $work/failed-rules.txt ]]; then
    fail "condition 3 (no failed rules): $(wc -l <"$work/failed-rules.txt" | tr -d ' ') rule(s) ran and did not meet their expectation:
$(cat "$work/failed-rules.txt")"
fi

# ---- condition 4: nothing else went wrong -------------------------------------------------------

# Without this, a rules file that stopped parsing would pass all three conditions above: it exits 1,
# adds no unchecked expectation, and reports no failed rule. Condition 3 only means "nothing failed"
# if the things that were supposed to run actually ran.
jq -r '[.[] | select(has("test_cases") | not)
        | "  \(.rule_file): \(.error)"] | .[]' "$report" >"$work/unreadable-files.txt"
jq -r '[.[] | .test_cases[]? | select(has("error"))
        | "  \(.name // "<unnamed case>"): \(.error)"] | .[]' "$report" >"$work/unrunnable-cases.txt"

if [[ -s $work/unreadable-files.txt ]]; then
    fail "condition 4 (nothing else went wrong): rules file(s) that could not be read or parsed:
$(cat "$work/unreadable-files.txt")"
fi

if [[ -s $work/unrunnable-cases.txt ]]; then
    fail "condition 4 (nothing else went wrong): test case(s) that could not be run:
$(cat "$work/unrunnable-cases.txt")"
fi

# ---- condition 5: the orphaned test files are exactly the known ones ----------------------------

# A test file no rules file claimed is never run and moves no verdict and no exit code, so nothing
# else here would notice one appearing.
readonly suffix=' did not match any rules file, so it was not run'

# Backslash to forward slash, so one expected list holds for the Windows job too, where WalkDir joins
# with a backslash. `${x//\\//}` and not `tr '\\' /`: shellcheck reads a `\\` inside single quotes as
# a mis-escaped quote (SC1003), and the Shellcheck job treats that as a finding and goes red.
prefix=${rules_dir//\\//}
prefix=${prefix%/}/
readonly prefix

# `IFS=` and `-r` because one of these filenames begins with a space, which is exactly the kind of
# name that goes unnoticed until something strips it.
: >"$work/actual/orphaned-test-files.unsorted"
while IFS= read -r line; do
    case $line in
    *"$suffix")
        path=${line%"$suffix"}
        path=${path//\\//}
        printf '%s\n' "${path#"$prefix"}" >>"$work/actual/orphaned-test-files.unsorted"
        ;;
    esac
done < <(tr -d '\r' <"$diagnostics")

LC_ALL=C sort <"$work/actual/orphaned-test-files.unsorted" \
    >"$work/actual/orphaned-test-files.txt"
strip_comments "$expected_orphans" | LC_ALL=C sort >"$work/expected/orphaned-test-files.txt"

if ! cmp -s "$work/expected/orphaned-test-files.txt" \
    "$work/actual/orphaned-test-files.txt"; then

    detail=""
    LC_ALL=C comm -13 "$work/expected/orphaned-test-files.txt" \
        "$work/actual/orphaned-test-files.txt" | sed -e 's/^/    /' >"$work/appeared.txt"
    if [[ -s $work/appeared.txt ]]; then
        detail="$detail
  appeared (a test file no rules file claims, and nothing runs):
$(cat "$work/appeared.txt")"
    fi

    LC_ALL=C comm -23 "$work/expected/orphaned-test-files.txt" \
        "$work/actual/orphaned-test-files.txt" | sed -e 's/^/    /' >"$work/disappeared.txt"
    if [[ -s $work/disappeared.txt ]]; then
        detail="$detail
  disappeared (expected to be orphaned, and no longer is):
$(cat "$work/disappeared.txt")"
    fi

    # This is the one condition that reads a sentence rather than a field, so it is the one that can
    # fail for a reason that has nothing to do with the corpus. Rewording
    # `unmatched_test_file_message` in guard/src/commands/reporters/test/mod.rs makes every orphan
    # invisible here at once, and the failure would otherwise read as "somebody fixed all three".
    if [[ ! -s $work/actual/orphaned-test-files.txt ]]; then
        detail="$detail

  Nothing at all matched, which is worth ruling out before you go looking in the corpus: this
  condition finds orphans by matching stderr lines ending \"$suffix\". If
  unmatched_test_file_message in guard/src/commands/reporters/test/mod.rs was reworded, the
  orphans are still there and this check simply stopped seeing them."
    fi

    fail "condition 5 (orphaned-test-file set): does not match
  .github/registry-corpus-state/orphaned-test-files.txt$detail"
fi

# ---- verdict ------------------------------------------------------------------------------------

if [[ -s $failures ]]; then
    printf 'The pinned aws-guard-rules-registry corpus is NOT in its known state.\n\n' >&2
    cat "$failures" >&2
    printf 'A green here means the corpus is in its known-bad state, not that it passes. If this\n' >&2
    printf 'failure is a corpus change you intended, update the file(s) named above in the same\n' >&2
    printf 'commit that moves the pin in .github/workflows/pr.yml.\n' >&2
    exit 1
fi

unchecked_total=$(jq '[.[] | .test_cases[]? | .unchecked_expectations[]?] | length' "$report")
unchecked_names=$(wc -l <"$work/actual/unchecked-expectations.txt" | tr -d ' ')
orphan_count=$(wc -l <"$work/actual/orphaned-test-files.txt" | tr -d ' ')

printf 'The pinned aws-guard-rules-registry corpus is in its known state:\n'
printf '  exit code %d (an expectation could not be evaluated)\n' "$actual_exit"
printf '  %s unchecked expectations across %s rule names, all of them expected\n' \
    "$unchecked_total" "$unchecked_names"
printf '  0 failed rules, 0 unreadable rules files, 0 unrunnable test cases\n'
printf '  %s orphaned test files, all of them expected\n' "$orphan_count"
printf '\nThis is not a pass. See aws-cloudformation/aws-guard-rules-registry#288.\n'
