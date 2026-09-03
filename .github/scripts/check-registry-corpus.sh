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

# The state files sit beside this script, so they are found relative to where this file really lives
# rather than to whatever name it was invoked under. Two measured failures in the previous shape,
# `state_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../registry-corpus-state" && pwd)"`:
#
# Reached through a symlink to the script, `dirname` gave the link's directory, so the walk looked for
# the state files beside the link and found nothing. And the `cd` failing took the whole run with it --
# a command substitution in an assignment carries its own exit status, so `set -e` fires at that line,
# which is *above* the `-f` checks that would have named the missing file. What reached the log was a
# bare `cd:` line and no verdict: the same unreadable shape as the temp-root failure this script
# already had once, and the reason both are now `exit 2` with a sentence instead.
#
# `readlink` without `-f`, because `-f` is a GNU extension and macos-latest ships no GNU coreutils. One
# link per iteration, a relative target resolved against the link's own directory, and a bound on the
# chain so a symlink cycle is an error rather than a hang.
script_path=${BASH_SOURCE[0]}
links_followed=0
while [[ -L $script_path ]]; do
    if ((links_followed++ >= 16)); then
        printf 'gave up following symlinks to %s after %d hops\n' "${BASH_SOURCE[0]}" "$links_followed" >&2
        exit 2
    fi
    link_target=$(readlink "$script_path")
    case $link_target in
    /*) script_path=$link_target ;;
    *) script_path=$(dirname "$script_path")/$link_target ;;
    esac
done

# `|| { ...; exit 2; }` and not a bare assignment: see above.
state_dir=$(cd "$(dirname "$script_path")/../registry-corpus-state" 2>/dev/null && pwd) || {
    printf 'no registry-corpus-state directory beside %s\n' "$script_path" >&2
    printf 'this script reads its expected state from a sibling directory of its own\n' >&2
    exit 2
}
readonly state_dir
readonly expected_unchecked="$state_dir/unchecked-expectations.txt"
readonly expected_orphans="$state_dir/orphaned-test-files.txt"

# The Windows runner builds cfn-guard.exe, and the callers pass one path for all three platforms, so the
# suffix is resolved here rather than in three call sites.
#
# Kept as belt and braces, not as a known necessity, and the distinction is worth recording because the
# earlier note here got it backwards. It said `-x` does not append `.exe` where execution does. Cygwin's
# documentation says the opposite -- `ls filename` and `stat("filename",..)` both report on
# `filename.exe` when only that exists -- so on Git bash `-x` is most likely already true for the bare
# name and this branch never fires on the one platform it was added for.
#
# It stays because that is an inference, not a measurement: the page documents Cygwin rather than MSYS2,
# and names `stat()` rather than the `access()` that `-x` may use. If the resolution does not happen,
# this branch is the difference between the check working and the run exiting 2 at "no cfn-guard binary
# at". Exercised on Linux, where `-x` genuinely does not resolve the suffix, so the fallback is reachable
# and tested there even if it is dead code on Windows.
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

# What two files differ by, in bytes, for a set comparison that has already failed.
#
# `diff` compares lines and prints them; it never says what they are made of. So a difference in a byte
# that renders as nothing, or as the same thing -- a trailing space, a doubled separator, a tab, a
# non-breaking space, a CR -- produces a hunk whose two sides read identically. That is not
# hypothetical: condition 2 failed on windows-latest with all eleven lines in the hunk and the two
# sides indistinguishable in the log, and the log itself may normalize whatever survived that far. A
# check that cannot describe its own failure sends the reader to the corpus instead of to the bytes.
#
# `od -c` and `cmp -l` are POSIX and present in BSD userland. `cat -A` is GNU-only, `od -t` predates
# nothing but is wordier, and `diff` has no byte mode at all. Only the differing lines are dumped, and
# only the first few, because the point is to localize the difference rather than reprint the corpus.
#
# Called on the failing path only. Nothing here runs when a condition passes.
byte_evidence() {
    printf 'byte-level evidence, because the two sides above can render identically:\n'
    printf '  file sizes: %s bytes expected, %s bytes actual\n' \
        "$(wc -c <"$1" | tr -d ' ')" "$(wc -c <"$2" | tr -d ' ')"

    # The first differing offset and the two byte values there, which is the one thing `diff` will
    # never tell you. `|| true` because `cmp` exits non-zero exactly when it has something to say, and
    # redirected rather than piped so `set -o pipefail` has no opinion about `head` closing early.
    cmp -l "$1" "$2" >"$work/cmp-l.txt" 2>&1 || true
    if [[ -s $work/cmp-l.txt ]]; then
        printf '  cmp -l (byte offset, expected octal, actual octal), first 8:\n'
        head -8 "$work/cmp-l.txt" | sed -e 's/^/    /'
    else
        printf '  cmp -l reported nothing, so the two files are byte-identical and the mismatch is\n'
        printf '  upstream of this comparison -- look at how each side was built, not at its content.\n'
    fi

    # Line numbers that differ, including lines present in one file and not the other. Concatenation
    # forces a string comparison: awk would otherwise compare two numeric-looking lines as numbers.
    awk 'NR==FNR { expected[FNR] = $0; next }
         { if (!(FNR in expected) || ("" $0) != ("" expected[FNR])) print FNR }
         END { for (i = FNR + 1; i in expected; i++) print i }' \
        "$1" "$2" >"$work/differing-lines.txt"

    printf '  %s of %s line(s) differ; the first %s dumped below\n' \
        "$(wc -l <"$work/differing-lines.txt" | tr -d ' ')" \
        "$(wc -l <"$1" | tr -d ' ')" \
        "$(head -5 "$work/differing-lines.txt" | wc -l | tr -d ' ')"

    for n in $(head -5 "$work/differing-lines.txt"); do
        printf '    line %s expected: ' "$n"
        dump_line "$1" "$n"
        printf '    line %s actual:   ' "$n"
        dump_line "$2" "$n"
    done
}

# One line of a file as `od -c`, prefixed by its own length in bytes.
#
# `sed -n "${2}p"` re-adds a trailing newline that is not part of the line, so it is stripped before
# both the count and the dump -- and stripped with `tr -d '\n'`, which leaves a CR alone. A CR is
# precisely the kind of byte this function exists to show, so removing it here would defeat the
# purpose.
dump_line() {
    sed -n "${2}p" <"$1" | tr -d '\n' >"$work/line.txt"
    printf '%s bytes\n' "$(wc -c <"$work/line.txt" | tr -d ' ')"
    od -c <"$work/line.txt" | sed -e 's/^/      /'
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
# `tr -d '\r'` on this side too. The expected side gets one inside `strip_comments`, and the asymmetry
# was real: a CR reaching only one of the two files is a mismatch that renders identically, which is
# the exact failure shape this condition produced on windows-latest. No CR was found in that failure,
# so this is not the fix for it -- it closes a gap that would have been indistinguishable from it.
jq -r '[.[] | .test_cases[]? | .unchecked_expectations[]? .name]
       | group_by(.) | map("\(.[0]) \(length)") | .[]' "$report" \
    | tr -d '\r' | LC_ALL=C sort >"$work/actual/unchecked-expectations.txt"

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
        # This used to read "the same rule names, but at least one changed how many expectations it
        # carries", which claimed more than it knew and cost a real investigation. All `comm` compared
        # was `cut -d' ' -f1` output, and that discards everything from the first space onward -- so a
        # count, the separator, or any trailing byte lands in this branch identically. On
        # windows-latest it fired with every count unchanged, and the sentence sent the reader to the
        # corpus. What is actually established is stated instead, and the bytes below decide the rest.
        detail="$detail
  every rule name matches, so the difference is at or after the first space on at least one line: a
  count, the separator, or a byte that does not render. That is the whole of what
  \`cut -d' ' -f1\` and \`comm\` can see -- the byte-level evidence below is what distinguishes them."
    fi

    fail "condition 2 (unchecked-expectation set): does not match
  .github/registry-corpus-state/unchecked-expectations.txt$detail

$(diff -u "$work/expected/unchecked-expectations.txt" \
        "$work/actual/unchecked-expectations.txt" || true)

$(byte_evidence "$work/expected/unchecked-expectations.txt" \
        "$work/actual/unchecked-expectations.txt")"
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

    # The same byte evidence as condition 2, and this condition needs it more, not less: these are
    # file paths, one of the three expected ones begins with a literal space, and a path whose only
    # difference is leading or trailing whitespace appears in `appeared` and `disappeared` at once
    # looking like the same string twice.
    fail "condition 5 (orphaned-test-file set): does not match
  .github/registry-corpus-state/orphaned-test-files.txt$detail

$(byte_evidence "$work/expected/orphaned-test-files.txt" \
        "$work/actual/orphaned-test-files.txt")"
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
