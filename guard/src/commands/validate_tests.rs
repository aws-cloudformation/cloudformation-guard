use super::super::*;
use super::*;
use pretty_assertions::assert_eq;

#[test]
fn test_deserialize_payload_success() {
    let serialized_payload = "{\"data\":[\"data as string 1\",\"data as string 2\"], \"rules\":[\"rules as string 1\",\"rules as string 2\"]}";
    let deserialized_payload = deserialize_payload(serialized_payload).unwrap();
    assert_eq!(
        deserialized_payload.list_of_data,
        vec!["data as string 1", "data as string 2"]
    );
    assert_eq!(
        deserialized_payload.list_of_rules,
        vec!["rules as string 1", "rules as string 2"]
    );
}

#[test]
#[should_panic]
fn test_deserialize_payload_malformed_string() {
    let serialized_payload = "{\"data:[\"data as string 1\",\"data as string 2\"], \"rules\":[\"rules as string 1\",\"rules as string 2\"]}";
    deserialize_payload(serialized_payload).unwrap();
}

#[test]
#[should_panic]
fn test_deserialize_payload_unrecognized_property() {
    let serialized_payload = "{\"data\":[\"data as string 1\",\"data as string 2\"], \"wrongProperty\":\"wrongProperty\"}";
    deserialize_payload(serialized_payload).unwrap();
}

#[test]
#[should_panic]
fn test_deserialize_payload_empty_input() {
    let serialized_payload = "";
    deserialize_payload(serialized_payload).unwrap();
}

#[test]
fn the_names_a_walk_passed_over_are_dropped_once_it_finds_a_file() {
    // The names are printed in one case only, when the whole walk found nothing, so a walk that has
    // found a file holds none of them: the ones kept so far go, and a later one is not kept. The
    // common run, a directory of templates beside a README and a lockfile, then holds no name at
    // all past its first template.
    let mut skipped = PassedOver::new();
    skipped.skip("README.md".to_string());
    skipped.skip("Cargo.lock".to_string());
    assert_eq!(skipped.names(), ["README.md", "Cargo.lock"]);

    skipped.found();
    assert!(skipped.names().is_empty(), "{:?}", skipped.names());
    skipped.skip("NOTICE".to_string());
    assert!(skipped.names().is_empty(), "{:?}", skipped.names());

    // A walk that finds nothing keeps every name, in the order met.
    let mut skipped = PassedOver::new();
    skipped.skip("b.txt".to_string());
    skipped.skip("a.txt".to_string());
    assert_eq!(skipped.names(), ["b.txt", "a.txt"]);
}

#[test]
fn test_supported_extensions() {
    // Data extensions
    assert!(has_a_supported_extension(
        "blah.json",
        &DATA_FILE_SUPPORTED_EXTENSIONS
    ));
    assert!(has_a_supported_extension(
        "blah.jsn",
        &DATA_FILE_SUPPORTED_EXTENSIONS
    ));
    assert!(has_a_supported_extension(
        "blah.yaml",
        &DATA_FILE_SUPPORTED_EXTENSIONS
    ));
    assert!(has_a_supported_extension(
        "blah.template",
        &DATA_FILE_SUPPORTED_EXTENSIONS
    ));
    assert!(has_a_supported_extension(
        "blah.yml",
        &DATA_FILE_SUPPORTED_EXTENSIONS
    ));
    // unsupported
    assert!(!has_a_supported_extension(
        "blah.txt",
        &DATA_FILE_SUPPORTED_EXTENSIONS
    ));
    assert!(!has_a_supported_extension(
        "blah",
        &DATA_FILE_SUPPORTED_EXTENSIONS
    ));

    // The match is a plain suffix compare, so it is case sensitive. This governs what a directory
    // walk picks up and nothing else: a file named as a `--data` argument is read without consulting
    // this predicate, so an uppercased extension is not a reason to skip a file the user asked for.
    assert!(!has_a_supported_extension(
        "blah.YAML",
        &DATA_FILE_SUPPORTED_EXTENSIONS
    ));
    assert!(!has_a_supported_extension(
        "blah.Json",
        &DATA_FILE_SUPPORTED_EXTENSIONS
    ));

    // Rules extensions
    assert!(has_a_supported_extension(
        "blah.guard",
        &RULE_FILE_SUPPORTED_EXTENSIONS
    ));
    assert!(has_a_supported_extension(
        "blah.ruleset",
        &RULE_FILE_SUPPORTED_EXTENSIONS
    ));
    // unsupported
    assert!(!has_a_supported_extension(
        "blah.txt",
        &RULE_FILE_SUPPORTED_EXTENSIONS
    ));
    assert!(!has_a_supported_extension(
        "blah",
        &RULE_FILE_SUPPORTED_EXTENSIONS
    ));
}

/// A trailer that names a data file or a site holding a control character writes the character as its
/// escape, as every other notice naming a file or a position does, so the trailer stays one line and a
/// path's ESC or bidi control never reaches the terminal raw.
///
/// The once-per-site notices themselves are escaped where they are built (`location_for_notice`), but
/// the trailer is built from the raw site key, the position's `Display` as recorded, and from the data
/// file names as given on the command line, so a line feed in a file name split the trailer into two
/// lines, the second unprefixed, and an ESC in a rules path went to stderr as written. Three controls
/// here, one each in a later file's name, in the first name that tells two lists apart, and in the site:
/// each comes out as its `\u{..}` or `\n` escape and the trailers hold no raw control.
#[test]
fn a_trailer_escapes_the_controls_in_its_file_names_and_its_site() {
    use crate::rules::DeprecationKind;
    use std::collections::BTreeMap;

    let site = |path: &str| {
        RepeatedNotice::Site((
            DeprecationKind::FilterOverABoundMap,
            format!("Location[file:{path}, line:4, column:9]"),
        ))
    };
    let mut repeated = BTreeMap::new();
    // A site in a rules path holding an ESC, drawn again by a data file holding a line feed.
    repeated.insert(
        site("r\u{1b}[31m.guard"),
        vec!["two\nlines.yaml".to_string(), "plain.yaml".to_string()],
    );
    // Two sites whose later-file lists read the same shortened and differ at a file name holding a
    // right-to-left override: the phrase that tells them apart names that file.
    let shared: Vec<String> = (2..=5).map(|i| format!("t{i}.yaml")).collect();
    let mut with_bidi = shared.clone();
    with_bidi.push("t\u{202e}6.yaml".to_string());
    let mut with_plain = shared.clone();
    with_plain.push("t7.yaml".to_string());
    repeated.insert(site("a.guard"), with_bidi);
    repeated.insert(site("b.guard"), with_plain);

    let lines = repeated_notice_trailers(&repeated);
    assert_eq!(3, lines.len(), "{:?}", lines);
    for line in &lines {
        assert!(
            !line.contains(['\n', '\r', '\u{1b}', '\u{202e}']),
            "a trailer holds no raw control character: {:?}",
            line
        );
    }
    let esc_line = lines
        .iter()
        .find(|l| l.contains("two\\nlines.yaml"))
        .unwrap_or_else(|| {
            panic!(
                "no trailer names the file with the escaped line feed: {:?}",
                lines
            )
        });
    assert!(
        esc_line.contains("Location[file:r\\u{1b}[31m.guard, line:4, column:9]"),
        "the site's ESC is written as its escape: {:?}",
        esc_line
    );
    assert!(
        lines.iter().any(|l| l.contains("not t\\u{202e}6.yaml")),
        "the file that tells two lists apart is named with its control escaped: {:?}",
        lines
    );
}

/// The file that tells two lists apart is the first one, in run order, that the neighbor's list holds and
/// this one lacks, wherever in the lists the two differ: here the lists share their first three names and
/// their count, one lacks `t5.yaml` and the other `t9.yaml`, and each trailer names the other's file. The
/// lists are read against a set of names built once per group, so the cell holds whatever structure finds
/// the name; it is a control on the answer, not a change in what is printed.
#[test]
fn the_file_that_tells_two_lists_apart_is_found_wherever_the_lists_differ() {
    use crate::rules::DeprecationKind;
    use std::collections::BTreeMap;

    let all: Vec<String> = (2..=10).map(|i| format!("t{i}.yaml")).collect();
    let without = |skip: &str| -> Vec<String> {
        all.iter().filter(|f| f.as_str() != skip).cloned().collect()
    };
    let site = |line: u32| {
        RepeatedNotice::Site((
            DeprecationKind::FilterOverABoundMap,
            format!("Location[file:r.guard, line:{line}, column:30]"),
        ))
    };
    let mut repeated = BTreeMap::new();
    repeated.insert(site(1), without("t5.yaml"));
    repeated.insert(site(2), without("t9.yaml"));

    let lines = repeated_notice_trailers(&repeated);
    assert_eq!(2, lines.len(), "{:?}", lines);
    let at = |line: u32| {
        lines
            .iter()
            .find(|l| l.contains(&format!("line:{line},")))
            .unwrap_or_else(|| panic!("no trailer for the site at line {line}: {:?}", lines))
    };
    assert!(
        at(1).contains(" and 5 more, not t5.yaml: "),
        "the list lacking t5 names it, found in the middle of the neighbor's list: {:?}",
        at(1)
    );
    assert!(
        at(2).contains(" and 5 more, not t9.yaml: "),
        "the list lacking t9 names it, found at the end of the neighbor's list: {:?}",
        at(2)
    );
}

/// Two hundred templates over two filter sites, site A missed by `t50` alone and site B by `t60` alone:
/// both later-file lists hold 198 names and open with the same three, so shortened they would read the
/// same. Each trailer still names three files and counts the rest, and is told from the other by the
/// first name its list lacks and the other's holds (`not t50.yaml` on A's line, `not t60.yaml` on B's),
/// so each line stays short whatever the directory's size. A third group whose list is one shorter
/// reads differently shortened already and carries no such phrase. Red before: two groups with one
/// shortened reading each named all 198 files.
#[test]
fn two_trailers_over_two_hundred_files_stay_bounded_and_are_told_apart() {
    use crate::rules::DeprecationKind;
    use std::collections::BTreeMap;

    let later: Vec<String> = (2..=200).map(|i| format!("t{i}.yaml")).collect();
    let without = |skip: &[&str]| -> Vec<String> {
        later
            .iter()
            .filter(|f| !skip.contains(&f.as_str()))
            .cloned()
            .collect()
    };
    let site = |line: u32| {
        RepeatedNotice::Site((
            DeprecationKind::FilterOverABoundMap,
            format!("Location[file:r.guard, line:{line}, column:30]"),
        ))
    };
    let mut repeated = BTreeMap::new();
    repeated.insert(site(1), without(&["t50.yaml"]));
    repeated.insert(site(2), without(&["t60.yaml"]));
    repeated.insert(site(3), without(&["t50.yaml", "t70.yaml"]));

    let lines = repeated_notice_trailers(&repeated);
    assert_eq!(3, lines.len(), "{:?}", lines);
    for line in &lines {
        assert!(
            line.len() < 200,
            "a trailer over two hundred files stays short, got {} bytes: {:?}",
            line.len(),
            line
        );
        assert!(
            line.starts_with("NOTE: also drawn by t2.yaml, t3.yaml, t4.yaml and "),
            "{:?}",
            line
        );
    }
    let at = |line: u32| {
        lines
            .iter()
            .find(|l| l.contains(&format!("line:{line},")))
            .unwrap_or_else(|| panic!("no trailer for the site at line {line}: {:?}", lines))
    };
    assert!(
        at(1).contains(" and 195 more, not t50.yaml: the filter notice for the site at "),
        "A's list lacks t50, which B's holds: {:?}",
        at(1)
    );
    assert!(
        at(2).contains(" and 195 more, not t60.yaml: the filter notice for the site at "),
        "B's list lacks t60, which A's holds: {:?}",
        at(2)
    );
    assert!(
        at(3).contains(" and 194 more: the filter notice for the site at ")
            && !at(3).contains(", not "),
        "a list that reads differently shortened carries no phrase: {:?}",
        at(3)
    );
}

/// A file name in a warning keeps its backslashes and has its control characters escaped: a Windows
/// path `\\?\C:\dir\t.yaml` reads in the warning as it reads on stdout and in the report, once, and a
/// name holding a line feed still gives a one-line warning. Red before: every backslash in the name
/// was doubled, so one file was named two ways on one run's streams.
#[test]
fn a_file_name_in_a_warning_keeps_its_backslashes_and_escapes_control_characters() {
    use crate::utils::writer::{WriteBuffer, Writer};

    let mut writer = Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::Vec(vec![]))
        .expect("Failed to create writer.");
    report_no_data_evaluated(
        &mut writer,
        &[
            "\\\\?\\C:\\dir\\t.yaml".to_string(),
            "li\nne.txt".to_string(),
        ],
    )
    .expect("the warnings are written");
    let stderr = writer.err_to_stripped().expect("failed to read stderr");
    // The reporter ends with its "no data files were evaluated" line; the per-file lines are the ones
    // under test.
    let lines: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("was not evaluated because its extension"))
        .collect();
    assert_eq!(2, lines.len(), "one line per file, got {:?}", stderr);
    assert!(
        lines[0].starts_with("Warning: \\\\?\\C:\\dir\\t.yaml was not evaluated"),
        "the path is written as given, once: {:?}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("Warning: li\\nne.txt was not evaluated"),
        "the line feed is written as its escape: {:?}",
        lines[1]
    );
}

/// The structured output names the map a wildcard filter was refused at as the path of the check that
/// failed closed on the refusal's marker: `Resources.*.Properties.Cfg[*][ x | R1 !exists ]` refused at
/// `R`'s `Cfg` (every entry holds `R1 !exists` by a miss, nothing grounds the enumeration) gives the
/// sibling clause reading `%x` a marker at `/Resources/R/Properties/Cfg`, the path the refusal's text
/// names and the path the same filter inside a predicate marks, and no check's path is `/Resources/R`,
/// the `.*` entry the loop held, where the marker stood before. Read through the JSON reporter as a
/// consumer reads it, so the path a machine is handed is the one pinned.
#[test]
fn the_structured_output_names_the_refused_map_as_the_path_of_a_refusals_marker(
) -> crate::rules::Result<()> {
    use crate::commands::reporters::validate::structured::StructuredEvaluator;
    use crate::rules::path_value::PathAwareValue;
    use crate::utils::writer::{WriteBuffer, Writer};
    use std::convert::TryFrom;

    const RULES: &str = "rule r { Resources.*.Properties.Cfg[*][ x | R1 !exists ] !empty or Resources.F exists\n  some Resources.*.Properties.Cfg.%x.Kind == 'k' }";
    const DOCUMENT: &str = r#"{
        "Resources": {
            "R": { "Type": "X", "Properties": { "Cfg": {
                "R1": { "Ref": "P" },
                "A": { "Kind": "k" },
                "B": { "Kind": "k" }
            } } },
            "F": { "Type": "Y" }
        }
    }"#;
    let rule_info = [RuleFileInfo {
        content: RULES.to_string(),
        file_name: "refused-cfg.guard".to_string(),
    }];
    let data = vec![DataFile {
        content: DOCUMENT.to_string(),
        path_value: PathAwareValue::try_from(DOCUMENT)?,
        name: "template.json".to_string(),
    }];
    let mut writer = Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::Vec(vec![]))?;
    let mut evaluator = StructuredEvaluator {
        rule_info: &rule_info,
        input_params: None,
        data,
        output: OutputFormatType::JSON,
        writer: &mut writer,
        exit_code: 0,
    };
    let exit_code = evaluator.evaluate()?;
    let stdout = writer.stripped()?;
    assert_eq!(
        FAILURE_STATUS_CODE, exit_code,
        "the rule fails closed on the refusal: {}",
        stdout
    );
    let paths: Vec<&str> = stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("\"path\": \""))
        .filter_map(|rest| rest.split('"').next())
        .collect();
    assert!(
        paths.contains(&"/Resources/R/Properties/Cfg"),
        "the refused map is the path of the check that failed closed, among {:?}",
        paths
    );
    assert!(
        !paths.contains(&"/Resources/R"),
        "no check's path is the entry the loop held, among {:?}",
        paths
    );
    Ok(())
}
