//! The rules `rulegen` writes from a template evaluate PASS against that template, and they are
//! exactly the rules the template calls for.
//!
//! This lives beside the loader rather than under `tests/` because it has to read the template the
//! way `rulegen` reads it. `rulegen` reads through the loader `validate` reads with, and the test's
//! model of what a template holds has to come from the same reading, or the two disagree wherever
//! YAML has two readings: a `!!` global tag the loader refuses and `serde_yaml` keeps as a tagged
//! node, a merge key the loader resolves and `serde_yaml` keeps as a property named `<<`, an integer
//! key the loader reads as text. The loader is crate-private, and a test under `tests/` is an
//! external user of the crate, so the one-reader version of this test can only be here.
//!
//! Measured on `loader-collides-merge-keys-template.yaml`, whose merge source holds the keys `1` and
//! `"1"`: the loader resolves the merge into the one property `1`, `rulegen` writes
//! `Properties."1" == "b"`, and this model, reading through the same loader, expects the one property
//! `1`. The two-reader version of this test, reading with `serde_yaml`, expected a property named
//! `<<` and failed on that template. On `double-bang-tag-read-as-the-loader-reads-it-template.yaml`
//! the loader here reads `!!If [IsProd, Foo, Bar]` as a plain sequence, `rulegen` writes
//! `RoleName == ["IsProd","Foo","Bar"]`, and this model expects `RoleName`; a loader that refuses
//! `!!` tags gives `rulegen` nothing and this model expects nothing, so the two agree either way,
//! where a reader that resolved the tag on its own would report the rule as lost.
//!
//! `rulegen` and `validate` run in-process as the command structs, through `Executable::execute`.
//! `rulegen`'s warnings go to the `Writer`'s error side, which is read back from a file because
//! reading either side consumes the `Writer`; `validate` takes the generated rules and the template as
//! a payload and reports as `--structured -o json`, read per rule.

use crate::commands::rulegen::Rulegen;
use crate::commands::validate::{OutputFormatType, ShowSummaryType, Validate};
use crate::commands::{Executable, ERROR_STATUS_CODE, SUCCESS_STATUS_CODE};
use crate::rules::exprs::{GuardClause, QueryPart, RuleClause, RulesFile};
use crate::rules::parser::{rules_file, Span};
use crate::rules::path_value::{MapValue, PathAwareValue};
use crate::rules::values::read_from;
use crate::utils::reader::{ReadBuffer, Reader};
use crate::utils::writer::{WriteBuffer, WriteBuffer::Vec as WBVec, Writer};
use pretty_assertions::assert_eq;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Cursor;
use std::path::{Path, PathBuf};

type Fields = indexmap::IndexMap<String, PathAwareValue>;

/// The entries of `value` when it is a mapping, and `None` otherwise. The same reading `rulegen`
/// applies to a resource and to its `Properties`.
fn fields_of(value: &PathAwareValue) -> Option<&Fields> {
    match value {
        PathAwareValue::Map((_, MapValue { values, .. })) => Some(values),
        _ => None,
    }
}

/// The rule name `rulegen` derives from a resource type, `AWS::S3::Bucket` -> `aws_s3_bucket`: the
/// command's own function, so the two cannot drift.
fn rule_name_for_type(resource_type: &str) -> String {
    crate::commands::rulegen::rule_name_for(resource_type)
}

/// What the loader made of a template: the properties it holds, or the loader's refusal.
///
/// The two are kept apart because they mean different things for the test. `Read` with an empty
/// map is a template `rulegen` has nothing to write for, and its refusal is checked against the
/// omission model. `LoaderRefused` is a template neither `rulegen` nor this model ever saw the
/// inside of; the two agree about it by construction, so agreement proves nothing, and a loader
/// that started refusing most fixtures would leave every check green. Loader refusals are therefore
/// held to `LOADER_REFUSALS`, a pinned list: a refusal is checked against it the moment it happens,
/// with the loader's words, and the whole set is compared at the end; `LOADER_DECIDES` names the one
/// template whose reading is the loader's to decide, with its expectation pinned per side.
enum Template {
    Read {
        /// Per type, the properties every resource of it carries: what `rulegen` writes a clause
        /// for, and what the test expects.
        counted: BTreeMap<String, BTreeSet<String>>,
        /// Per type, every property any resource of it carries: what a `rulegen` warning can be
        /// about, since it also warns about a property only some resources carry.
        carried: BTreeMap<String, BTreeSet<String>>,
    },
    LoaderRefused(String),
}

/// Templates the loader refuses, and `rulegen` with it, as measured on this tree. Exact: a template
/// joining or leaving this set fails with a one-line diff, so a loader that stops reading a fixture
/// it reads today, or starts reading one it refuses, is named rather than counted.
const LOADER_REFUSALS: &[&str] = &["resources/rulegen/data-dir/missing-comma-template.json"];

/// A template whose reading the loader decides, allowed on either side, with both sides pinned.
struct LoaderDecided {
    /// The template, below the crate root.
    path: &'static str,
    /// The read side: per type, the properties the loader hands `rulegen`, so "the loader read it"
    /// is a measurement and not whatever the loader happened to return.
    read_side: &'static [(&'static str, &'static [&'static str])],
    /// The refused side: words the loader's refusal has to hold, so a refusal for any other cause,
    /// a broken document included, is not "the loader decided" and fails.
    refused_wording: &'static [&'static str],
}

/// Templates whose reading the loader decides. Measured on this tree: the loader reads
/// `!!If [IsProd, Foo, Bar]` as a plain sequence, so the read side runs here; a loader that refuses
/// `!!` global tags takes the refused side, and the test says which side ran. The refused wording
/// comes from the loader that refuses the tag, whose message reads "cfn-guard does not read the tag
/// `!!If` at <location>. An intrinsic function is written with one `!`, as `!If`."; the location is
/// left out of the pin.
///
/// A decided template is counted apart from the matched, round-tripped and refused tallies, so
/// both floors read the same number whichever side it takes; a floor that counted it would have
/// been one short on the refused side, and re-pinning a floor whenever the loader flips is hand
/// maintenance this test exists to avoid. Every entry has to be a template the walk finds, and the
/// number of decided templates seen has to equal this table's length, so a renamed or removed
/// fixture is named rather than quietly counted as nothing.
const LOADER_DECIDES: &[LoaderDecided] = &[LoaderDecided {
    path: "resources/rulegen/data-dir/double-bang-tag-read-as-the-loader-reads-it-template.yaml",
    read_side: &[("AWS::IAM::Role", &["RoleName"])],
    refused_wording: &[
        "does not read the tag `!!If`",
        "written with one `!`, as `!If`",
    ],
}];

/// The `LOADER_DECIDES` entry for `template`, if it is one.
fn loader_decided(root: &Path, template: &Path) -> Option<&'static LoaderDecided> {
    LOADER_DECIDES
        .iter()
        .find(|decided| root.join(decided.path) == template)
}

/// A read side as the model reports it: type -> property names.
fn read_side_as_properties(read_side: &[(&str, &[&str])]) -> BTreeMap<String, BTreeSet<String>> {
    read_side
        .iter()
        .map(|(resource_type, properties)| {
            (
                (*resource_type).to_owned(),
                properties.iter().map(|p| (*p).to_owned()).collect(),
            )
        })
        .collect()
}

/// The properties the template at `path` gives `rulegen` to write, by resource type: for each
/// distinct string `Type`, the names of the properties carried by every resource of that type. A
/// type is in the map only if that set is non-empty, and a rule is expected for a type only while
/// its set stays non-empty.
///
/// Read through the loader `rulegen` reads with, so a tagged scalar, a merge key, or a non-string
/// key is read here exactly as it is there. A template the loader refuses is reported as
/// `Template::LoaderRefused` with the loader's words; one whose `Resources` is absent or not a
/// mapping is `Read` with nothing in it, which is what `rulegen` has to work with too, and the
/// refusal branch takes both.
///
/// A generated clause is evaluated against every resource the rule's `Type ==` filter admits, so
/// `rulegen` drops a property that only some resources of the type carry, and a type left with no
/// property gets no rule. A template declaring five `AWS::S3::Bucket` resources of which two carry
/// `Properties` gets no bucket rule; reading "has `Properties`" as "gets a rule" over-counts it (the
/// repository-wide pass below walks such a template, `validate`'s functions fixture). A resource
/// with a string `Type` and no
/// `Properties` still counts toward its type, as it does in `rulegen`; one with no string `Type`, or
/// with a `Type` that cannot be a rule name (`rulegen`'s own `reason_no_rule_is_keyed_on`, asked
/// here of the same text), counts nowhere, as there.
///
/// Three more omissions are about a property's value or name rather than the template's shape and
/// are not modeled here: a value `rulegen` cannot render, a boolean observed both ways, and a
/// property name holding a line ending or another control character, each of which drops that one
/// property. Each such property is listed, by template, in `properties_omitted_with_a_reason` with
/// the warning `rulegen` prints for it, and the test removes that one property from this map before
/// deciding which rules to expect. An entry excuses one property, never a type: a type that keeps
/// another property keeps its rule. A template that round-trips has to write exactly the rules left;
/// one `rulegen` refuses has to have none left. A type's rules vanishing with no entry for its last
/// property fails naming the type, whichever way `rulegen` went.
///
/// A name holding a line ending can be listed: `rulegen` prints the warning for it and writes the
/// name into the comment it leaves in the rule body with the line ending escaped, so the file parses
/// and exits 0. A comment carrying the line ending raw would fail `rulegen`'s own parse and refuse
/// the template with "Parsing error with generated rules file" while its other properties were still
/// expected. The escaped form is pinned by
/// `rulegen_tests::test_rulegen_escapes_a_control_character_in_the_omission_comment` (its
/// `line_feed` case: a `"Line\nBreak"` property beside a kept one, exit 0, the kept clause written,
/// the comment naming `Line\nBreak`) and by
/// `rulegen_tests::test_rulegen_tells_a_line_feed_from_a_backslash_n_in_the_comment`. A name holding
/// a tab, or a `: `, is warned about the same way, and
/// `control-character-in-a-property-name-template.yaml` lists one.
///
/// What this round-trip does not see is a clause weaker than the template inside a kept rule, such
/// as `IN [50, 500]` over two volumes: the clause is there, under the right property, and a PASS
/// from `validate` says only that the source template does not fail it. The model here checks which
/// rules and which clauses exist and that the template passes, not what a clause compares against.
fn properties_expected_from(path: &Path) -> Template {
    let Ok(contents) = std::fs::read_to_string(path) else {
        panic!("{} stopped being readable", path.display());
    };
    let marked = match read_from(&contents) {
        Ok(marked) => marked,
        Err(error) => return Template::LoaderRefused(error.to_string()),
    };
    let template = match PathAwareValue::try_from(marked) {
        Ok(template) => template,
        Err(error) => return Template::LoaderRefused(error.to_string()),
    };
    let Some(resources) = fields_of(&template)
        .and_then(|root| root.get("Resources"))
        .and_then(fields_of)
    else {
        return Template::Read {
            counted: BTreeMap::new(),
            carried: BTreeMap::new(),
        };
    };

    let mut declared: BTreeMap<&str, usize> = BTreeMap::new();
    let mut carrying: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for resource in resources.values() {
        let Some(resource) = fields_of(resource) else {
            continue;
        };
        let Some(PathAwareValue::String((_, resource_type))) = resource.get("Type") else {
            continue;
        };
        // A type `rulegen` cannot key a rule on is dropped there with the whole resource, so it
        // counts nowhere here either; the question is `rulegen`'s own, asked of the same text.
        if crate::commands::rulegen::reason_no_rule_is_keyed_on(resource_type).is_some() {
            continue;
        }
        *declared.entry(resource_type.as_str()).or_insert(0) += 1;

        let Some(properties) = resource.get("Properties").and_then(fields_of) else {
            continue;
        };
        for name in properties.keys() {
            *carrying
                .entry((resource_type.as_str(), name.as_str()))
                .or_insert(0) += 1;
        }
    }

    let mut counted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut carried: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for ((resource_type, property), carriers) in &carrying {
        carried
            .entry((*resource_type).to_owned())
            .or_default()
            .insert((*property).to_owned());
        if *carriers == declared[resource_type] {
            counted
                .entry((*resource_type).to_owned())
                .or_default()
                .insert((*property).to_owned());
        }
    }
    Template::Read { counted, carried }
}

/// Properties `properties_expected_from` counts and `rulegen` rightly writes no clause for, by
/// template: the resource type, the property name, and the reason `rulegen` gives when it prints
/// `Warning: no check generated for <Type>.Properties.<name>: <reason>` for it. The test looks for
/// that line in `rulegen`'s output of the same run, so an entry made for one omission does not
/// excuse another, and it removes that one property from the expected set: a type that keeps
/// another property keeps its rule, and a type left with none is expected to have none.
///
/// The list is exhaustive: the pairs `rulegen` warned about among the counted properties have to
/// equal the pairs listed here, so a new omission anywhere is red until it is recorded. Every entry
/// has to be load-bearing: the test fails on one naming a property the template gives `rulegen`
/// nothing for anyway, on one whose line `rulegen` did not print, on one whose property still got a
/// clause, and on one whose template the walk did not find.
fn properties_omitted_with_a_reason(
) -> BTreeMap<PathBuf, Vec<(&'static str, &'static str, &'static str)>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    const BOTH_WAYS: &str = "the template holds both true and false for it";
    const CONTROL_CHARACTER_IN_NAME: &str =
        "the property name holds a line ending or another control \
         character, and a guard string literal ends at the end of its line";
    // `IntoIterator::into_iter`, not `.into_iter()`: on an array, edition 2018 resolves the
    // method to the slice iterator and yields references.
    IntoIterator::into_iter([
        (
            "resources/rulegen/data-dir/boolean-seen-both-ways-template.yaml",
            vec![("AWS::EC2::Volume", "Encrypted", BOTH_WAYS)],
        ),
        (
            "resources/rulegen/data-dir/bucket-and-boolean-seen-both-ways-template.yaml",
            vec![("AWS::EC2::Volume", "Encrypted", BOTH_WAYS)],
        ),
        (
            "resources/rulegen/data-dir/boolean-seen-both-ways-beside-a-kept-property-template.yaml",
            vec![("AWS::EC2::Volume", "Encrypted", BOTH_WAYS)],
        ),
        (
            "resources/rulegen/data-dir/control-character-in-a-property-name-template.yaml",
            // The property is `Tab<TAB>: Name`; rulegen prints the warning with the control
            // character escaped, as `Tab\t: Name`, so the marker is matched in that form and the
            // model's own entry carries the name as the template holds it.
            vec![("AWS::S3::Bucket", "Tab\t: Name", CONTROL_CHARACTER_IN_NAME)],
        ),
        (
            "resources/rulegen/data-dir/colon-space-property-name-pair-template.yaml",
            vec![("AWS::EC2::Volume", "A: B", BOTH_WAYS)],
        ),
    ])
    .map(|(path, omitted)| (root.join(path), omitted))
    .collect()
}

/// The rules `rulegen` wrote, parsed with the crate's own rules-file parser, the one `validate`
/// reads them with. There is no second reader of the text: a quoted property name comes back the
/// way the evaluator will see it, whatever `rulegen` chose to escape. A text `rulegen` reported
/// success on that this parser refuses is a defect of its own and panics with the parser's words.
fn parse_generated(generated: &str) -> RulesFile<'_> {
    match rules_file(Span::new_extra(generated, "")) {
        Ok(Some(file)) => file,
        Ok(None) => panic!(
            "the rules-file parser read no rules out of what rulegen wrote:\n{}",
            generated
        ),
        Err(error) => panic!(
            "the rules-file parser refused what rulegen wrote ({}):\n{}",
            error, generated
        ),
    }
}

/// The property names each written rule holds a clause for, by rule name, from the parsed file:
/// each clause's query is the rule's variable, then `Properties`, then the property, so the name is
/// the key that follows `Properties`. Comment lines are not clauses and the parser never sees them.
fn clauses_written(file: &RulesFile<'_>) -> BTreeMap<String, BTreeSet<String>> {
    file.guard_rules
        .iter()
        .map(|rule| {
            let mut properties = BTreeSet::new();
            for disjunction in &rule.block.conjunctions {
                for clause in disjunction {
                    let RuleClause::Clause(GuardClause::Clause(access)) = clause else {
                        continue;
                    };
                    let mut after_properties = false;
                    for part in &access.access_clause.query.query {
                        match part {
                            QueryPart::Key(key) if after_properties => {
                                properties.insert(key.clone());
                                break;
                            }
                            QueryPart::Key(key) => after_properties = key == "Properties",
                            _ => after_properties = false,
                        }
                    }
                }
            }
            (rule.rule_name.clone(), properties)
        })
        .collect()
}

/// The names of the rules `rulegen` wrote, from the parsed file, one per resource type.
fn generated_rule_names(file: &RulesFile<'_>) -> BTreeSet<String> {
    file.guard_rules
        .iter()
        .map(|rule| rule.rule_name.clone())
        .collect()
}

/// Does `path` look like a CloudFormation template, meaning worth handing to `rulegen`? A YAML
/// `Resources` key at column 0, or a JSON `"Resources"` key at any indent (a JSON root key is
/// always indented), each with any spacing before its colon, is enough.
///
/// Deliberately a text check and not a read through the loader: a template the loader refuses has
/// to be walked, so that `rulegen`'s refusal of it lands in the refusal branch with its own
/// expectation, which is what `properties_expected_from` returns for it. Column 0 for YAML keeps
/// out the `test` command's YAML data files, whose `Resources:` sits under an `input:` block, when
/// the repository-wide pass walks that tree; its JSON data files are still admitted there, and a
/// file this admits that holds no usable `Resources` mapping is refused by `rulegen` with its own
/// sentence inside the parse error, which that pass counts apart from the loader's refusals, as
/// `Exit5::NoResourcesMapping`. Under rulegen's own directory the one file the loader refuses is
/// `missing-comma-template.json`, pinned in `LOADER_REFUSALS`.
fn is_cloudformation_template(path: &Path) -> bool {
    // A key, then optional whitespace, then the colon: `Resources:` and `Resources :` both count.
    let is_key_then_colon = |rest: &str| rest.trim_start().starts_with(':');
    std::fs::read_to_string(path).is_ok_and(|contents| {
        contents.lines().any(|line| {
            line.strip_prefix("Resources")
                .is_some_and(is_key_then_colon)
                || line
                    .trim_start()
                    .strip_prefix("\"Resources\"")
                    .is_some_and(is_key_then_colon)
        })
    })
}

/// A property name as `rulegen` prints it in a warning: each control character, each backslash and
/// the Unicode line and paragraph separators written as its Rust escape (`\t`, `\n`, `\\`,
/// `\u{2028}`), everything else as it is. `rulegen` escapes them so that a name holding a line
/// ending still reads as one warning line; the model keeps the name as the template holds it, so the
/// two meet here, where a warning line is composed or read.
fn as_rulegen_prints(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c == '\\' || c.is_control() || c == '\u{2028}' || c == '\u{2029}' {
                c.escape_debug().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// The templates this round trip walks: `rulegen`'s own fixtures, `resources/rulegen/data-dir`.
///
/// `rulegen`'s reading of its fixtures is the subject here, so the walk is the directory that holds
/// them. The other fixture trees under `resources` (validate's, the test command's, the readme's) are
/// pinned by their own tests, and a template added to any of them for its own test's sake is not a
/// round-trip case: walking the whole of `resources` made every such addition owe an entry in this
/// file's lists, and a tree with a few hundred of them owed dozens at once.
fn templates_under_resources() -> Vec<PathBuf> {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("resources");
    root.push("rulegen");
    root.push("data-dir");

    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .map(walkdir::DirEntry::into_path)
        .filter(|path| {
            path.extension().is_some_and(|extension| {
                matches!(
                    extension.to_str(),
                    Some("yaml" | "yml" | "json" | "template")
                )
            }) && is_cloudformation_template(path)
        })
        .collect()
}

/// The array a `validate --structured -o json` report holds under `key`, or a panic that prints
/// the whole report, so a shape change shows up as the document rather than as an empty set.
fn report_array<'a>(report: &'a serde_json::Value, key: &str) -> &'a [serde_json::Value] {
    // Edition 2018: `panic!` given only a string literal prints it unformatted, so the values go in
    // as positional arguments.
    let Some(entries) = report.get(key) else {
        panic!(
            "validate --structured -o json report has no `{}` field:\n{:#}",
            key, report
        );
    };
    let Some(entries) = entries.as_array() else {
        panic!(
            "validate --structured -o json `{}` is not an array:\n{:#}",
            key, report
        );
    };
    entries
}

/// The rule names under `compliant` or `not_applicable`, which the structured report lists as bare
/// strings. An element that is not a string is a shape this test does not know, and it panics with
/// the report rather than being skipped.
fn reported_rule_names(report: &serde_json::Value, key: &str) -> BTreeSet<String> {
    report_array(report, key)
        .iter()
        .map(|entry| match entry.as_str() {
            Some(name) => name.to_owned(),
            None => panic!(
                "validate --structured -o json `{}` holds a non-string entry {}:\n{:#}",
                key, entry, report
            ),
        })
        .collect()
}

/// The scratch directory that holds `rulegen`'s stderr capture, removed when dropped. The templates
/// the tests give `rulegen` are the committed fixtures, so nothing else is written here. Owning the
/// removal here rather than at the end of the
/// test body means a failing run cleans up too: a panic anywhere after the guard is made unwinds
/// through this `Drop`, where an end-of-body removal is never reached and would leave the directory
/// behind for every failing run. Every removal ignores a missing path, so a run that wrote nothing is
/// fine.
struct Scratch {
    dir: PathBuf,
    stderr_path: PathBuf,
}

impl Scratch {
    /// One directory per test and process: the tests of this module run in one process, and a
    /// shared path would let one test's `Drop` remove the stderr file the other is reading.
    fn new(label: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("cfn-guard-rulegen-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("Failed to create the scratch directory.");
        let stderr_path = dir.join("rulegen.stderr");
        Scratch { dir, stderr_path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Only what this test created, by name; nothing recursive.
        let _ = std::fs::remove_file(&self.stderr_path);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// `rulegen` on `template_path`, in-process: its exit code, the rules it wrote to stdout, and what
/// it wrote to stderr. The error side is a file because reading either side consumes the `Writer`.
fn run_rulegen(template_path: &str, stderr_path: &Path) -> (i32, String, String) {
    // Built as the struct, not through the crate root's builder: this module is compiled into the
    // binary crate as well, where `crate::RulegenBuilder` does not exist.
    let rulegen = Rulegen {
        output: None,
        template: template_path.to_owned(),
    };
    let stderr_file = File::create(stderr_path).expect("Failed to create the stderr file.");
    let mut writer = Writer::new_with_err(WBVec(vec![]), WriteBuffer::File(stderr_file))
        .expect("Failed to create the writer.");
    let mut reader = Reader::new(ReadBuffer::Cursor(Cursor::new(vec![])));
    let status_code = rulegen
        .execute(&mut writer, &mut reader)
        .unwrap_or_else(|error| panic!("rulegen on {template_path} fell over: {}", error));
    let generated = writer
        .into_string()
        .expect("Failed to read the rules rulegen wrote.");
    let rulegen_stderr =
        std::fs::read_to_string(stderr_path).expect("Failed to read rulegen's stderr.");
    (status_code, generated, rulegen_stderr)
}

/// `validate --structured -o json` of `generated` against `template_contents`, in-process, both
/// handed over as a payload: its exit code and the report it printed.
fn run_validate(generated: &str, template_contents: &str) -> (i32, String) {
    let payload = serde_json::json!({ "rules": [generated], "data": [template_contents] });
    // The same shape `ValidateBuilder` produces for `--payload --structured -o json -S none`,
    // built here as the struct for the reason given in `run_rulegen`.
    let validate = Validate {
        rules: vec![],
        data: vec![],
        input_params: vec![],
        template_type: None,
        output_format: OutputFormatType::JSON,
        // `-S none` as given, not the format's default: the field is an `Option` so that a caller who
        // set nothing is told apart from one who asked for no summary.
        show_summary: Some(vec![ShowSummaryType::None]),
        alphabetical: false,
        last_modified: false,
        verbose: false,
        print_json: false,
        payload: true,
        structured: true,
    };
    let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create the writer.");
    let mut reader = Reader::new(ReadBuffer::Cursor(Cursor::new(
        payload.to_string().into_bytes(),
    )));
    let status_code = validate
        .execute(&mut writer, &mut reader)
        .unwrap_or_else(|error| panic!("validate fell over on rulegen's output: {}", error));
    let report = writer
        .stripped()
        .expect("Failed to read the validate report.");
    (status_code, report)
}

/// Generate rules from every template under `resources`, then validate the generated rules against
/// the template they came from.
///
/// A generated rule that fails its own source template is a defect, and this one property catches
/// the whole class at once. It has caught two generations of the class: templates that generated
/// rules failing their own template, and templates that generated nothing while exiting 0, which
/// `validate` then reported as compliant against zero rules. Both times the emitter and the reader
/// disagreed about one value; `rulegen` now reads the template through the loader, and so does this
/// test, so there is one reading rather than two.
///
/// The only two outcomes allowed: rules that pass their own template, or a non-zero status saying
/// why there are none. Exiting 0 having written nothing is what this forbids.
///
/// "Pass" is read per rule from `validate --structured -o json`, not from the exit code. `validate`
/// exits 0 when every rule in the file is skipped, and it exits 0 when the file declares no rule, so
/// the exit code alone cannot tell a rule that evaluated its template and passed from one whose
/// `when` guard never selected anything. A `rulegen` that wrapped every rule in a guard its own
/// template cannot satisfy round-tripped green on the exit code; it does not round-trip green on the
/// report, because each rule it wrote has to appear under `compliant`, none under `not_applicable`,
/// and `not_compliant` has to be empty.
///
/// Every template is held to one rule, whichever way `rulegen` goes. The properties the template
/// calls for come from `properties_expected_from`, by type. The omissions `rulegen` warned about
/// among those properties have to equal, pair for pair, the ones listed for the template in
/// `properties_omitted_with_a_reason`, each with the reason `rulegen` gave; those are then taken
/// out. A rule is expected for every type with a property left, and inside it a clause for every
/// property left. A template that round-trips has to write exactly those rules with exactly those
/// clauses; one `rulegen` refuses has to have none left, and has to have written nothing. So a type
/// whose rules vanish, into a refusal or beside a surviving type, fails naming it; a clause dropped
/// with no warning, or written for a property `rulegen` said it dropped, fails naming the rule and
/// the property; an omission not on the list, or an entry with no warning behind it, fails naming
/// the pair; a refusal for a cause other than the one on record fails naming the line that was not
/// printed; and a template that moves between round-tripping and refused fails one way or the
/// other, with one exception: when the loader itself stops reading a template, `rulegen` and this
/// model agree about it by construction. Loader refusals are therefore held to `LOADER_REFUSALS`,
/// an exact list compared at the end, with `LOADER_DECIDES` naming the templates allowed either way,
/// each with its read side and its refused wording pinned. Two floors, on templates matched and
/// on templates round-tripped, are pinned so the walk cannot quietly shrink on either side; they
/// move only when fixtures are removed, and name the walked paths when they fail. Neither floor
/// counts a `LOADER_DECIDES` template, so both measure only loader-independent templates and hold
/// the same in a tree whose loader takes the other side; the tally line reports the decided
/// templates on their own, with the side each took.
///
/// The tally and the refused paths are printed at the end of the test and read with
/// `cargo test --lib rulegen_round_trip -- --nocapture`. A refused template gives `rulegen` nothing
/// to write for: the loader refuses it, no properties at all, properties only on a resource with no
/// `Type`, or every candidate property dropped, as with the two listed templates whose only property
/// is a boolean observed both ways.
///
/// The library test target is the one that runs this. `main.rs` declares `mod rules;` itself, so
/// this module is compiled into the binary crate's test target too, and the walk would run twice
/// per `cargo test`; in the binary target, where `CARGO_BIN_NAME` is set at compile time, the test
/// returns at once.
#[test]
fn generated_rules_evaluate_against_their_own_template() {
    if option_env!("CARGO_BIN_NAME").is_some() {
        return;
    }

    let templates = templates_under_resources();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let loader_decides: BTreeSet<PathBuf> = LOADER_DECIDES
        .iter()
        .map(|decided| root.join(decided.path))
        .collect();
    let pinned_loader_refusals: BTreeSet<PathBuf> =
        LOADER_REFUSALS.iter().map(|p| root.join(p)).collect();

    // A floor pinned to the count when it was last set, so a walk that finds fewer templates than
    // it did (a filter that stopped matching, a directory that moved) is a failure and not a
    // quieter pass. Adding a template never breaks it; it moves only when fixtures are removed,
    // and the message lists what was walked so the missing one is a one-line diff. Templates the
    // loader decides are left out of the count, as they are out of the round-tripped floor below,
    // so both floors measure only loader-independent templates and read the same in a tree whose
    // loader takes the other side.
    let loader_independent = templates
        .iter()
        .filter(|template| !loader_decides.contains(*template))
        .count();
    assert!(
        loader_independent >= 12,
        "expected rulegen's fixture directory to hold at least the 12 loader-independent templates \
         it held when this was pinned, found {}:\n{}",
        loader_independent,
        templates
            .iter()
            .map(|template| template.display().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    );

    let omitted_with_a_reason = properties_omitted_with_a_reason();
    let scratch = Scratch::new("round-trip");
    let stderr_path = scratch.stderr_path.clone();
    let mut round_tripped = 0;
    let mut refused: BTreeSet<PathBuf> = BTreeSet::new();
    // The loader's refusals with the loader's words, so the comparison at the end shows why.
    let mut loader_refused: BTreeMap<PathBuf, String> = BTreeMap::new();
    // Templates the loader decides, by the side they took, kept out of the two tallies above so the
    // floors read the same whichever side runs.
    let mut decided_read = 0;
    let mut decided_refused = 0;

    for template in &templates {
        let template_path = template.display().to_string();
        let (status_code, generated, rulegen_stderr) = run_rulegen(&template_path, &stderr_path);

        // What the loader made of the template, as its own outcome. A template the loader decides
        // has its read side pinned, so "the loader read it" is a measurement and not a shrug.
        let decided = loader_decided(&root, template);
        let (counted, carried) = match properties_expected_from(template) {
            Template::Read { counted, carried } => {
                if let Some(decided) = decided {
                    assert_eq!(
                        read_side_as_properties(decided.read_side),
                        counted,
                        "the loader read {template_path}, and what it read differs from the \
                         pinned read side"
                    );
                    println!("loader decided: read {}", template_path);
                }
                (counted, carried)
            }
            Template::LoaderRefused(reason) => {
                // The loader's refusal is judged here, with the loader's words: the path has to be
                // one `LOADER_REFUSALS` or `LOADER_DECIDES` names, so a loader that stopped reading a
                // fixture is reported as that and not, further down, as a stale omission entry on a
                // template this run never read. The omission checks are skipped: there is nothing
                // of the template to hold them against. rulegen has to have refused it too, and
                // written nothing.
                assert!(
                    decided.is_some() || pinned_loader_refusals.contains(template),
                    "the loader refused {template_path} ({}), and the path is in neither \
                     LOADER_REFUSALS nor LOADER_DECIDES; if the refusal is right, pin it there",
                    reason
                );
                if let Some(decided) = decided {
                    // The refused side is pinned as the read side is: only a refusal of the tag
                    // itself, in the loader's words, is the loader deciding.
                    assert!(
                        decided
                            .refused_wording
                            .iter()
                            .all(|words| reason.contains(words)),
                        "the loader refused {template_path}, but not for the reason it is allowed \
                         to decide: expected the words {:?} in `{}`",
                        decided.refused_wording,
                        reason
                    );
                    println!("loader decided: refused {} ({reason})", template_path);
                }
                assert!(
                    status_code != SUCCESS_STATUS_CODE,
                    "the loader refused {template_path} ({}) but rulegen, reading with the same \
                     loader, wrote rules for it:\n{generated}",
                    reason
                );
                assert!(
                    generated.trim().is_empty(),
                    "rulegen refused {template_path} but wrote:\n{}",
                    generated
                );
                loader_refused.insert(template.clone(), reason);
                if decided.is_some() {
                    decided_refused += 1;
                } else {
                    refused.insert(template.clone());
                }
                continue;
            }
        };

        // The exit code first, so a rulegen that fell over on a template is reported as that, and
        // not as a listed omission that this run's output does not mention.
        assert!(
            status_code == SUCCESS_STATUS_CODE || status_code == ERROR_STATUS_CODE,
            "rulegen on {template_path} exited {status_code}, which is neither success nor the \
             documented error code:\n{}",
            rulegen_stderr
        );

        // The properties the template calls for, by type, less the ones listed as omitted for a
        // reason rulegen printed. Each entry has to earn its place: the property has to be one the
        // model counts, and the line has to be in rulegen's output for this run. An entry removes
        // one property; a type keeps its rule while any property is left.
        let mut expected_properties = counted.clone();
        let listed = omitted_with_a_reason
            .get(template)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        for (resource_type, property, reason) in listed {
            let removed = expected_properties
                .get_mut(*resource_type)
                .is_some_and(|properties| properties.remove(*property));
            assert!(
                removed,
                "{template_path} lists {resource_type}.Properties.{property} as a property rulegen \
                 omits, but the template gives rulegen nothing for it anyway (it is not carried by \
                 every resource of the type), so the entry is stale; counted {:?}",
                counted
            );
            let marker = format!(
                "no check generated for {resource_type}.Properties.{}: {reason}",
                as_rulegen_prints(property)
            );
            assert!(
                rulegen_stderr.contains(&marker),
                "{template_path} lists {resource_type}.Properties.{property} as omitted because \
                 rulegen prints `{marker}`, but this run's output does not say so, so the omission \
                 on record is not the one that happened:\n{}",
                rulegen_stderr
            );
        }

        // And the other direction: every omission rulegen reported for a property the model counts
        // has to be on the list. A refusal that widens, or a new reason, is then a failure naming
        // the property, and an entry with no warning behind it is caught by the same comparison.
        // The warning lines are read against the names the template holds by
        // `warned_counted_pairs`, which the repository walk's classifier shares.
        let listed_pairs: BTreeSet<(String, String)> = listed
            .iter()
            .map(|(resource_type, property, _)| {
                ((*resource_type).to_owned(), (*property).to_owned())
            })
            .collect();
        let warned_pairs = warned_counted_pairs(&rulegen_stderr, &counted, &carried);
        assert_eq!(
            listed_pairs, warned_pairs,
            "the omissions rulegen reported for {template_path} among the properties every \
             resource of a type carries (right) and the ones listed for it (left) \
             differ:\n{rulegen_stderr}"
        );

        let expected_clauses: BTreeMap<String, BTreeSet<String>> = expected_properties
            .iter()
            .filter(|(_, properties)| !properties.is_empty())
            .map(|(resource_type, properties)| {
                (rule_name_for_type(resource_type), properties.clone())
            })
            .collect();
        let expected: BTreeSet<String> = expected_clauses.keys().cloned().collect();

        if status_code != SUCCESS_STATUS_CODE {
            // A refusal writes nothing: the exit code is what says there are no rules, and text
            // beside it would be a rules file the caller was told not to expect.
            assert!(
                generated.trim().is_empty(),
                "rulegen refused {template_path} but wrote:\n{}",
                generated
            );

            // A refusal is right when the template gives rulegen nothing to write once the listed
            // omissions are taken out. Otherwise a type's rules vanished, and this names it rather
            // than count the template as one more refusal.
            assert!(
                expected.is_empty(),
                "rulegen refused {template_path}, whose resource types have a property every \
                 resource of the type carries, so the rules for {:?} vanished with no reason on \
                 record; if the refusal is right, list the dropped property in \
                 properties_omitted_with_a_reason with the reason rulegen prints for \
                 it:\n{rulegen_stderr}",
                expected
            );

            if decided.is_some() {
                decided_refused += 1;
            } else {
                refused.insert(template.clone());
            }
            continue;
        }

        assert!(
            !generated.trim().is_empty(),
            "rulegen reported success on {} but wrote no rules",
            template_path
        );

        let template_contents =
            std::fs::read_to_string(template).expect("Failed to read the template.");
        let (validate_status, validate_output) = run_validate(&generated, &template_contents);

        assert_eq!(
            SUCCESS_STATUS_CODE, validate_status,
            "rules generated from {template_path} do not pass it:\n{generated}\n{validate_output}"
        );

        // One data document in, one report out. Read the rules by name rather than trusting the
        // status: SKIP and "no rules" both exit 0 above.
        let reports: serde_json::Value =
            serde_json::from_str(&validate_output).unwrap_or_else(|error| {
                panic!(
                    "validate --structured -o json on rules generated from {template_path} did not \
                     print JSON ({}):\n{validate_output}",
                    error
                )
            });
        let report = match reports.as_array() {
            Some(reports) if reports.len() == 1 => &reports[0],
            _ => panic!(
                "validate --structured -o json on rules generated from {template_path} did not \
                 print an array of exactly one report:\n{}",
                validate_output
            ),
        };

        let parsed = parse_generated(&generated);
        let written = generated_rule_names(&parsed);
        // This crate is on edition 2018, where `assert!` and `panic!` given only a string literal
        // print it unformatted and `{template_path}` stays as typed. Each `assert!` message below
        // therefore passes at least one positional argument, which routes the whole string through
        // `format_args!`, and the `{name}` captures then expand as well. The `assert_eq!` messages
        // carry none and need none: `assert_eq!` always formats its message through `format_args!`.
        assert!(
            !written.is_empty(),
            "rulegen reported success on {template_path} but the text it wrote declares no \
             rule:\n{}",
            generated
        );

        // One rule per resource type the template gave rulegen properties for, less the listed
        // omissions. Reading the names out of the generated rules alone cannot see a type that was
        // dropped: a rulegen that kept the first type's rule and lost the second would still have
        // every rule it wrote pass, so the expected set comes from the template.
        assert_eq!(
            expected, written,
            "the resource types rulegen had properties for in {template_path} and the rules it \
             wrote differ:\n{generated}\n{rulegen_stderr}"
        );

        // Inside each rule, one clause per property left after the listed omissions. A clause
        // written for a listed omission (a refusal logged and the clause emitted anyway) and a
        // clause missing for a kept property (dropped with no warning) are both red here, naming
        // the rule and the property; the rule name alone cannot see either.
        assert_eq!(
            expected_clauses,
            clauses_written(&parsed),
            "the clauses rulegen wrote for {template_path} (right) and the properties the template \
             calls for less the listed omissions (left) differ by rule:\n{generated}\n{rulegen_stderr}"
        );

        let compliant = reported_rule_names(report, "compliant");
        let not_applicable = reported_rule_names(report, "not_applicable");
        let not_compliant = report_array(report, "not_compliant");

        assert!(
            not_applicable.is_empty(),
            "rules generated from {template_path} were skipped against it rather than evaluated; a \
             generated rule whose guard its own template cannot satisfy checks nothing: \
             {:?}\n{generated}\n{validate_output}",
            not_applicable
        );
        assert!(
            not_compliant.is_empty(),
            "rules generated from {template_path} failed it:\n{generated}\n{}",
            validate_output
        );
        assert_eq!(
            written, compliant,
            "the rules rulegen wrote for {template_path} and the rules validate reported PASS for \
             it differ:\n{generated}\n{validate_output}"
        );

        if decided.is_some() {
            decided_read += 1;
        } else {
            round_tripped += 1;
        }
    }

    // Every template the loader is allowed to decide has to have been walked and seen on one side
    // or the other, else a renamed or removed fixture drops out of the decided count while the
    // floors, which leave decided templates out by design, say nothing.
    for decided in LOADER_DECIDES {
        assert!(
            templates.contains(&root.join(decided.path)),
            "{} is listed in LOADER_DECIDES but is not a template the walk found",
            decided.path
        );
    }
    assert_eq!(
        LOADER_DECIDES.len(),
        decided_read + decided_refused,
        "LOADER_DECIDES names {} templates and the walk saw {decided_read} read and \
         {decided_refused} refused",
        LOADER_DECIDES.len()
    );

    // The loader's refusals, exactly, less the templates the loader is allowed to decide. A
    // refusal of an unlisted path already failed inside the walk, naming the loader; what this adds
    // is the other direction, a pinned path the loader now reads, and the whole picture with the
    // loader's words when either side moves.
    let loader_refused_outside_its_say: BTreeMap<PathBuf, String> = loader_refused
        .iter()
        .filter(|(path, _)| !loader_decides.contains(*path))
        .map(|(path, reason)| (path.clone(), reason.clone()))
        .collect();
    assert_eq!(
        pinned_loader_refusals,
        loader_refused_outside_its_say
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        "the templates the loader refuses (right) and the pinned list (left) differ; the loader's \
         words:\n{:#?}",
        loader_refused_outside_its_say
    );

    // The second floor, pinned like the first. Every move between round-tripping and refused that
    // the loader did not cause is already a failure inside the walk; what this adds is that the
    // round-tripping side cannot quietly shrink either, by a loader change or anything else. It
    // moves only when a round-tripping fixture is removed. A template the loader decides is not in
    // this count, so the floor holds the same on either of its sides.
    assert!(
        round_tripped >= 10,
        "expected at least the 10 templates of rulegen's fixture directory that round-tripped when \
         this was pinned (templates the loader decides not counted), got {round_tripped}; \
         refused:\n{}\nwalked:\n{}",
        refused
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join("\n"),
        templates
            .iter()
            .map(|template| template.display().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    );

    // An entry for a template the walk never reached is never checked inside it, so it is checked
    // here: a listed path has to be one of the templates found.
    for path in omitted_with_a_reason.keys() {
        assert!(
            templates.contains(path),
            "{} is listed in properties_omitted_with_a_reason but is not a template the walk found",
            path.display()
        );
    }

    // The tally. Shown by `cargo test --lib rulegen_round_trip -- --nocapture`.
    println!(
        "{} templates matched, {round_tripped} round-tripped, {} refused, {} decided by the loader \
         ({decided_read} read, {decided_refused} refused)",
        templates.len(),
        refused.len(),
        decided_read + decided_refused
    );
    for path in &refused {
        println!("refused: {}", path.display());
    }
    for (path, reason) in &loader_refused {
        println!("loader refused: {} ({reason})", path.display());
    }
    // `scratch` is dropped here, and on any panic above, and removes its directory either way.
}

/// The `(type, property)` pairs `rulegen`'s stderr warns about among the properties the model
/// counts. Each warning line is read against the names the template holds, never by parsing a name
/// back out of the text: the line's subject has to be a type, then `.Properties.`, then a property
/// some resource of that type carries, followed by `: `. The longest such property wins, so a line
/// about `A: B` is not also read as a line about `A`, and the candidates are every carried name and
/// not only the counted ones, because `rulegen` warns about a property only some resources carry as
/// well; the pair is recorded only when the property is one the model counts. A name may hold a tab
/// or a `: `, and the text is `rulegen`'s to format. Shared by the exact-list test, which compares
/// the result with its omission list, and by `classify_exit_5`, which requires every counted pair.
fn warned_counted_pairs(
    rulegen_stderr: &str,
    counted: &BTreeMap<String, BTreeSet<String>>,
    carried: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<(String, String)> {
    rulegen_stderr
        .lines()
        .filter_map(|line| line.strip_prefix("Warning: no check generated for "))
        .filter_map(|subject| {
            carried.iter().find_map(|(resource_type, names)| {
                let rest = subject
                    .strip_prefix(resource_type.as_str())?
                    .strip_prefix(".Properties.")?;
                let name = names
                    .iter()
                    .filter(|name| {
                        rest.strip_prefix(as_rulegen_prints(name).as_str())
                            .is_some_and(|after| after.starts_with(": "))
                    })
                    .max_by_key(|name| name.len())?;
                counted
                    .get(resource_type)
                    .is_some_and(|properties| properties.contains(name))
                    .then(|| (resource_type.clone(), name.clone()))
            })
        })
        .collect()
}

/// Why `classify_exit_5` refuses an exit 5: one reason per cause, so the walk's failure names it.
const PARSE_OF_GENERATED_FAILED: &str = "rulegen's own parse of what it generated failed";
const CANDIDATE_DROPPED_SILENTLY: &str =
    "a counted candidate was dropped with no warning naming it";
const NO_KNOWN_SENTENCE: &str = "stderr matched no known sentence";
const MODEL_REFUSED_RULEGEN_READ: &str =
    "the loader's model refused the template but rulegen read it";
const RULEGEN_REFUSED_MODEL_READ: &str =
    "rulegen refused the template but the loader's model read it";
const MODEL_COUNTS_A_REFUSED_TYPE: &str = "the model counts a type rulegen refuses as a whole";

/// The four reasons `rulegen` exits 5 that the repository walk below accepts, read off its stderr
/// and the loader's model of the template.
#[derive(Debug, PartialEq, Eq)]
enum Exit5 {
    /// The loader refused the template on both sides: the model's reading, and `rulegen`'s stderr,
    /// which carries the loader's words on one line.
    LoaderRefused,
    /// The loader read the document, but it has no usable `Resources` mapping: `rulegen` refuses it
    /// with its own sentence inside the same line, and the model reads no property at all from it.
    /// What a `test` command's JSON spec file under `resources` is.
    NoResourcesMapping,
    /// The loader's model holds candidate properties, a warning line names every one of them, and
    /// `rulegen` says no rules were generated: every candidate was omitted.
    OmittedEverything,
    /// The loader's model holds no candidate property, so there was nothing to write, and `rulegen`
    /// says so; it may also have warned about a property only some resources of a type carry.
    NothingToWrite,
}

/// Which accepted reason an exit 5 of `rulegen` was, or the reason the walk refuses it, read off its
/// stderr and `model`, the loader's own reading of the template (`properties_expected_from`).
///
/// `rulegen` exits 5 on three paths, each with its own stderr, and each sentence is matched as the
/// start of a line, never as a substring: the parser's message quotes the generated text, which can
/// carry anything a template holds. The loader's refusal is one line starting "Unable to read the
/// template". Nothing left to write prints exactly "No rules were generated from this template, so
/// no rules file was written. Validating against an empty rules file reports every template
/// compliant." after the warnings for what it dropped. Its own parse of the file it generated
/// failing prints "Parsing error with generated rules file, Error = ..." followed by the shorter "No
/// rules file was written. Validating against an empty rules file reports every template
/// compliant.", and never the sentence of the second path.
///
/// The parse failure is tested first and refused whatever else is printed: it is a defect in what
/// `rulegen` wrote, never an omission, and a stderr that also carried the loader's words or the
/// no-rules sentence would still be one. Then the two readers have to agree on a refusal: a template
/// the model's loader refused is accepted only with `rulegen`'s refusal line, as the loader's
/// refusal; a template the model read is accepted with that line only when the line gives
/// `rulegen`'s own structural reason (no `Resources` section, or one that is not a mapping of
/// resources) and the model read no property from it, which is what the repository holds in a `test`
/// command's JSON spec file, and that is counted apart, as a document with no `Resources` mapping.
/// Any other refusal on one side alone is refused with the disagreement as its reason, and the
/// disagreement is named only on evidence: a template the model refused is "read by `rulegen`" when
/// stderr carries a warning line or the no-rules sentence, the two things `rulegen` prints only after
/// reading a template; a stderr with neither, empty or in wording this function has never seen,
/// matched no known sentence, and that is the reason given. Then the no-rules sentence is required.
/// Then the model decides between the two accepted reasons: with no candidate property there was
/// nothing to write, and a warning about a property only some resources carry may or may not be
/// there; with candidates, every one of them has to be named by a warning line
/// (`warned_counted_pairs`, the exact-list test's own matching), because a warning about an unshared
/// property, or about one candidate, says nothing about the others. A resource-level warning that
/// `rulegen` refuses a counted type as a whole (`its Type "<T>"`) covers none of that type's pairs:
/// the model asks `rulegen`'s own question before it counts a type, so such a line on a counted type
/// is drift between the model and `rulegen`, and is refused as that.
fn classify_exit_5(rulegen_stderr: &str, model: &Template) -> Result<Exit5, &'static str> {
    let line_starts = |prefix: &str| rulegen_stderr.lines().any(|line| line.starts_with(prefix));
    if line_starts("Parsing error with generated rules file") {
        return Err(PARSE_OF_GENERATED_FAILED);
    }
    let rulegen_refused = line_starts("Unable to read the template");
    // `rulegen`'s own structural refusal, on a document the loader read: the line carries one of its
    // two sentences, and the model, which reads nothing from a document with no usable `Resources`
    // mapping, holds no property at all.
    let no_resources_mapping = rulegen_stderr.lines().any(|line| {
        line.starts_with("Unable to read the template")
            && (line.contains("Template lacks a Resources section")
                || line.contains("Template Resources section has an invalid structure"))
    });
    // What shows `rulegen` read a template: it warned about a property, or it said no rules were
    // generated. A refusal line is neither, and a stderr with none of the three says nothing.
    let no_rules_sentence =
        line_starts("No rules were generated from this template, so no rules file was written");
    let rulegen_read = no_rules_sentence || line_starts("Warning: ");
    let (counted, carried) = match model {
        Template::LoaderRefused(_) if rulegen_refused => return Ok(Exit5::LoaderRefused),
        Template::LoaderRefused(_) if rulegen_read => return Err(MODEL_REFUSED_RULEGEN_READ),
        Template::LoaderRefused(_) => return Err(NO_KNOWN_SENTENCE),
        Template::Read { counted, carried }
            if rulegen_refused
                && no_resources_mapping
                && counted.is_empty()
                && carried.is_empty() =>
        {
            return Ok(Exit5::NoResourcesMapping)
        }
        Template::Read { .. } if rulegen_refused => return Err(RULEGEN_REFUSED_MODEL_READ),
        Template::Read { counted, carried } => (counted, carried),
    };
    if !line_starts("No rules were generated from this template, so no rules file was written") {
        return Err(NO_KNOWN_SENTENCE);
    }
    if counted.is_empty() {
        return Ok(Exit5::NothingToWrite);
    }
    // A type `rulegen` refuses as a whole gets one warning about each resource of it, not one per
    // property: `Warning: no check generated for resource <id>: its Type "<T>" ...`, the type quoted
    // in Rust debug spelling. The model asks `rulegen`'s own question before it counts a type, so a
    // counted type with such a line means the two have drifted apart, and that is refused by name
    // rather than read as the type's pairs being covered, which would have let the drift pass.
    let type_refused_as_a_whole = |resource_type: &str| {
        let marker = format!(": its Type {:?} ", resource_type);
        rulegen_stderr.lines().any(|line| {
            line.starts_with("Warning: no check generated for resource ") && line.contains(&marker)
        })
    };
    if counted
        .keys()
        .any(|resource_type| type_refused_as_a_whole(resource_type))
    {
        return Err(MODEL_COUNTS_A_REFUSED_TYPE);
    }
    let warned = warned_counted_pairs(rulegen_stderr, counted, carried);
    let every_candidate_named = counted.iter().all(|(resource_type, properties)| {
        properties
            .iter()
            .all(|property| warned.contains(&(resource_type.clone(), property.clone())))
    });
    if every_candidate_named {
        Ok(Exit5::OmittedEverything)
    } else {
        Err(CANDIDATE_DROPPED_SILENTLY)
    }
}

/// A `Template::Read` model for the table below: per type, the counted properties and the carried
/// ones (the counted ones are carried too).
fn model_read(types: &[(&str, &[&str], &[&str])]) -> Template {
    let mut counted = BTreeMap::new();
    let mut carried = BTreeMap::new();
    for (resource_type, counted_names, carried_names) in types {
        let shared: BTreeSet<String> = counted_names.iter().map(|n| (*n).to_owned()).collect();
        let all: BTreeSet<String> = carried_names
            .iter()
            .chain(counted_names.iter())
            .map(|n| (*n).to_owned())
            .collect();
        if !shared.is_empty() {
            counted.insert((*resource_type).to_owned(), shared);
        }
        if !all.is_empty() {
            carried.insert((*resource_type).to_owned(), all);
        }
    }
    Template::Read { counted, carried }
}

fn model_refused() -> Template {
    Template::LoaderRefused("the loader's reason".to_owned())
}

/// `classify_exit_5` accepts an exit 5 for its four known reasons and refuses every other with a
/// reason of its own. It is "every property omitted" only when the loader's model holds candidate
/// properties, a warning line names every one of them, and `rulegen`'s own sentence that no rules
/// were generated follows; with no candidate it is "nothing to write", warning or not. A warning
/// about an unshared property, or about one candidate of two, or about one type of two, leaves a
/// candidate dropped with no warning naming it, and is refused as that. A resource-level warning that
/// `rulegen` refuses a counted type as a whole covers none of its pairs: the model asks `rulegen`'s
/// question before counting a type, so the line is drift between the two, refused by name. The two
/// readers have to agree on a refusal: the loader's words from `rulegen` on a template the model
/// read, or a warning or the no-rules sentence on one the model refused, is refused with the
/// disagreement as its reason, as the exact-list test holds the two to agree; a stderr that shows
/// neither reading nor refusal (empty, or wording never seen) on a template the model refused matched
/// no known sentence, and says so rather than claiming `rulegen` read it; `rulegen`'s own structural
/// sentence, either of its two spellings, on a document the model read no property from is accepted
/// and counted apart from the loader's refusals. The
/// parse-failure path ("Parsing error with generated rules file", then "No rules file was written
/// ...") is refused first whatever else stderr holds, the loader's words or the no-rules sentence
/// beside it included, which `rulegen` never prints on that path; the rows carry the sentences as
/// the source spells them, with a stand-in for the parser's own message, because no template in this
/// tree reaches that path. Every sentence is matched at the start of a line, so the loader's words
/// inside a warning's text are not a refusal. Each refusal carries its own reason, which the walk
/// prints. Red with any warning taken as naming every candidate, with the model's refusal folded
/// into "no candidates", with the loader's words tested before the parse failure as substrings, with
/// an empty stderr beside a refused model read as `rulegen` having read the template, and with one
/// reason for every refusal; green as written.
#[rstest::rstest]
#[case::every_counted_candidate_omitted_with_its_warning(
    "Warning: no check generated for AWS::S3::Bucket.Properties.P: its value holds a line ending or \
     another control character, and a guard string literal ends at the end of its line\nNo rules \
     were generated from this template, so no rules file was written. Validating against an empty \
     rules file reports every template compliant.\n",
    model_read(&[("AWS::S3::Bucket", &["P"], &[])]),
    Ok(Exit5::OmittedEverything)
)]
#[case::two_counted_candidates_each_with_its_warning(
    "Warning: no check generated for A.Properties.P: a reason\nWarning: no check generated for \
     B.Properties.Q: a reason\nNo rules were generated from this template, so no rules file was \
     written. Validating against an empty rules file reports every template compliant.\n",
    model_read(&[("A", &["P"], &[]), ("B", &["Q"], &[])]),
    Ok(Exit5::OmittedEverything)
)]
#[case::no_candidates_with_a_warning_about_an_unshared_property(
    "Warning: no check generated for AWS::S3::Bucket.Properties.Q: only some resources of the type \
     carry it\nNo rules were generated from this template, so no rules file was written. Validating \
     against an empty rules file reports every template compliant.\n",
    model_read(&[("AWS::S3::Bucket", &[], &["Q"])]),
    Ok(Exit5::NothingToWrite)
)]
#[case::no_candidates_without_a_warning(
    "No rules were generated from this template, so no rules file was written. Validating against \
     an empty rules file reports every template compliant.\n",
    model_read(&[("AWS::S3::Bucket", &[], &[])]),
    Ok(Exit5::NothingToWrite)
)]
#[case::candidates_but_nothing_said_about_dropping_them(
    "No rules were generated from this template, so no rules file was written. Validating against \
     an empty rules file reports every template compliant.\n",
    model_read(&[("AWS::S3::Bucket", &["P"], &[])]),
    Err(CANDIDATE_DROPPED_SILENTLY)
)]
#[case::a_counted_candidate_dropped_while_an_unshared_property_is_warned_about(
    "Warning: no check generated for AWS::S3::Bucket.Properties.Q: only some resources of the type \
     carry it\nNo rules were generated from this template, so no rules file was written. Validating \
     against an empty rules file reports every template compliant.\n",
    model_read(&[("AWS::S3::Bucket", &["P"], &["Q"])]),
    Err(CANDIDATE_DROPPED_SILENTLY)
)]
#[case::one_warning_does_not_cover_a_second_counted_candidate(
    "Warning: no check generated for A.Properties.P: a reason\nNo rules were generated from this \
     template, so no rules file was written. Validating against an empty rules file reports every \
     template compliant.\n",
    model_read(&[("A", &["P"], &[]), ("B", &["Q"], &[])]),
    Err(CANDIDATE_DROPPED_SILENTLY)
)]
#[case::loader_refused_on_both_sides(
    "Unable to read the template some.yaml: the loader's reason\n",
    model_refused(),
    Ok(Exit5::LoaderRefused)
)]
#[case::the_model_refused_but_rulegen_read_the_template(
    "No rules were generated from this template, so no rules file was written. Validating against \
     an empty rules file reports every template compliant.\n",
    model_refused(),
    Err(MODEL_REFUSED_RULEGEN_READ)
)]
#[case::the_model_refused_and_a_warning_shows_rulegen_read_the_template(
    "Warning: no check generated for AWS::S3::Bucket.Properties.P: a reason\n",
    model_refused(),
    Err(MODEL_REFUSED_RULEGEN_READ)
)]
#[case::the_model_refused_and_rulegen_said_nothing_known(
    "",
    model_refused(),
    Err(NO_KNOWN_SENTENCE)
)]
#[case::the_model_refused_and_rulegen_said_something_unknown(
    "some new wording this test has never seen\n",
    model_refused(),
    Err(NO_KNOWN_SENTENCE)
)]
#[case::rulegen_refused_a_template_the_model_read(
    "Unable to read the template some.yaml: the loader's reason\n",
    model_read(&[("AWS::S3::Bucket", &["P"], &[])]),
    Err(RULEGEN_REFUSED_MODEL_READ)
)]
#[case::a_document_with_no_resources_section_is_counted_apart_from_the_loaders_refusals(
    "Unable to read the template some.json: Parser Error when parsing `Template lacks a Resources \
     section`\n",
    model_read(&[]),
    Ok(Exit5::NoResourcesMapping)
)]
#[case::a_resources_section_that_is_not_a_mapping_is_counted_the_same_way(
    "Unable to read the template some.yaml: Parser Error when parsing `Template Resources section \
     has an invalid structure: it is not a mapping of logical id to resource`\n",
    model_read(&[]),
    Ok(Exit5::NoResourcesMapping)
)]
#[case::the_structural_reason_does_not_excuse_a_template_the_model_read_properties_from(
    "Unable to read the template some.json: Parser Error when parsing `Template lacks a Resources \
     section`\n",
    model_read(&[("AWS::S3::Bucket", &["P"], &[])]),
    Err(RULEGEN_REFUSED_MODEL_READ)
)]
#[case::a_counted_type_that_rulegen_refuses_as_a_whole_is_drift_between_the_two(
    "Warning: no check generated for resource R: its Type \"Custom::My-Thing\" gives the rule name \
     \"custom_my-thing\", and a rule name is one ASCII letter, then only letters, digits and \
     underscores\nNo rules were generated from this template, so no rules file was written. \
     Validating against an empty rules file reports every template compliant.\n",
    model_read(&[("Custom::My-Thing", &["P"], &[])]),
    Err(MODEL_COUNTS_A_REFUSED_TYPE)
)]
#[case::the_generated_file_failed_to_parse(
    "Warning: no check generated for AWS::S3::Bucket.Properties.P: its value holds a line ending or \
     another control character, and a guard string literal ends at the end of its line\nParsing \
     error with generated rules file, Error = Parser Error when parsing `rule aws_s3_bucket {`\nNo \
     rules file was written. Validating against an empty rules file reports every template \
     compliant.\n",
    model_read(&[("AWS::S3::Bucket", &["P"], &[])]),
    Err(PARSE_OF_GENERATED_FAILED)
)]
#[case::a_parse_failure_beside_the_no_rules_sentence_is_still_a_failure(
    "Warning: no check generated for AWS::S3::Bucket.Properties.P: its value holds a line ending or \
     another control character, and a guard string literal ends at the end of its line\nParsing \
     error with generated rules file, Error = Parser Error when parsing `rule aws_s3_bucket {`\nNo \
     rules were generated from this template, so no rules file was written. Validating against an \
     empty rules file reports every template compliant.\n",
    model_read(&[("AWS::S3::Bucket", &["P"], &[])]),
    Err(PARSE_OF_GENERATED_FAILED)
)]
#[case::a_parse_failure_beside_the_loaders_words_is_still_a_failure(
    "Unable to read the template some.yaml: the loader's reason\nParsing error with generated rules \
     file, Error = Parser Error when parsing `rule aws_s3_bucket {`\nNo rules file was written. \
     Validating against an empty rules file reports every template compliant.\n",
    model_refused(),
    Err(PARSE_OF_GENERATED_FAILED)
)]
#[case::the_loaders_words_inside_another_line_are_not_a_refusal(
    "Warning: no check generated for AWS::S3::Bucket.Properties.P: its value holds the text Unable \
     to read the template, which is a value and not a reason\nNo rules were generated from this \
     template, so no rules file was written. Validating against an empty rules file reports every \
     template compliant.\n",
    model_read(&[("AWS::S3::Bucket", &["P"], &[])]),
    Ok(Exit5::OmittedEverything)
)]
#[case::warned_and_nothing_else(
    "Warning: no check generated for AWS::S3::Bucket.Properties.P: a reason\n",
    model_read(&[("AWS::S3::Bucket", &["P"], &[])]),
    Err(NO_KNOWN_SENTENCE)
)]
#[case::silent("", model_read(&[("AWS::S3::Bucket", &[], &[])]), Err(NO_KNOWN_SENTENCE))]
fn classify_exit_5_accepts_only_known_reasons(
    #[case] stderr: &str,
    #[case] model: Template,
    #[case] expected: Result<Exit5, &'static str>,
) {
    assert_eq!(expected, classify_exit_5(stderr, &model), "{:?}", stderr);
}

/// A resource whose `Type` cannot be a rule name counts nowhere in the model, and `rulegen` agrees
/// on the same template: a rule and its variable are written bare, so the type's name with `::` as
/// `_` and lowercased has to be one ASCII letter followed by letters, digits and underscores, and
/// `rulegen` drops a resource whose type is not, with one warning about the resource. The model asks
/// `rulegen`'s own question, and this test holds the two together on one document, the committed
/// fixture `type-that-cannot-be-a-rule-name-beside-a-bucket-template.yaml`, which the exact-list
/// round trip above also walks: the model counts only the bucket, and `rulegen` run on the same file
/// exits 0, prints exactly one warning, about resource `Thing` and its type, and writes the bucket
/// rule and no other. A model that counted such a type expected a rule `rulegen` never writes and, in
/// the repository walk, a per-property warning `rulegen` never prints. One fixture, so the spelling
/// lives in one place; `Scratch` holds only the stderr file. Red with the model accepting any string
/// `Type`; green asking `rulegen`'s question. As for the walks, the library test target runs this
/// once; in the binary target, where `CARGO_BIN_NAME` is set at compile time, it returns at once.
#[test]
fn a_type_that_cannot_be_a_rule_name_counts_nowhere_in_the_model() {
    if option_env!("CARGO_BIN_NAME").is_some() {
        return;
    }

    let scratch = Scratch::new("unnameable-type");
    let mut template_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    template_path.push("resources");
    template_path.push("rulegen");
    template_path.push("data-dir");
    template_path.push("type-that-cannot-be-a-rule-name-beside-a-bucket-template.yaml");
    let (counted, carried) = match properties_expected_from(&template_path) {
        Template::Read { counted, carried } => (counted, carried),
        // Edition 2018: `panic!` does not capture names, so the argument is positional.
        Template::LoaderRefused(reason) => {
            panic!("the loader refused the fixture: {}", reason)
        }
    };
    let only_the_bucket: BTreeMap<String, BTreeSet<String>> =
        IntoIterator::into_iter([("AWS::S3::Bucket".to_owned(), {
            let mut bucket_name = BTreeSet::new();
            bucket_name.insert("BucketName".to_owned());
            bucket_name
        })])
        .collect();
    assert_eq!(only_the_bucket, counted, "counted");
    assert_eq!(only_the_bucket, carried, "carried");

    let (status_code, generated, rulegen_stderr) =
        run_rulegen(&template_path.display().to_string(), &scratch.stderr_path);
    assert_eq!(
        SUCCESS_STATUS_CODE, status_code,
        "rulegen on the fixture:\n{}",
        rulegen_stderr
    );
    let warnings: Vec<&str> = rulegen_stderr
        .lines()
        .filter(|line| line.starts_with("Warning: "))
        .collect();
    assert_eq!(
        1,
        warnings.len(),
        "one warning, about the resource and its type:\n{}",
        rulegen_stderr
    );
    assert!(
        warnings[0].starts_with(
            "Warning: no check generated for resource Thing: its Type \"Custom::My-Thing\" "
        ),
        "{}",
        rulegen_stderr
    );
    let rules = parse_generated(&generated);
    let written = generated_rule_names(&rules);
    assert_eq!(
        1,
        written.len(),
        "only the bucket rule is written:\n{}",
        generated
    );
    assert!(
        written.contains("aws_s3_bucket"),
        "the bucket rule is written:\n{}",
        generated
    );
}

/// Every CloudFormation template anywhere under `resources` is one `rulegen` reads or refuses
/// without falling over, and what it writes round-trips.
///
/// The exact-list round trip above owns `rulegen`'s own fixtures. This pass walks the whole
/// `resources` tree the way that test once did -- every yaml, yml, json or template file with a
/// `Resources` key -- and asserts categories, never paths, so a fixture added anywhere for its own
/// test's sake owes nothing here. Each template is one of: round-tripped (`rulegen` exits 0, the
/// rules it wrote parse with the crate's parser and `validate` reports none of them failing or
/// skipped against the template they came from); round-tripped with a warning (the same, after
/// `rulegen` warned that it generated no check for some property); refused by the loader (exit 5,
/// `rulegen`'s stderr carries the loader's words, which start "Unable to read the template", and the
/// model's loader refused it too); no `Resources` mapping (exit 5 with the same line carrying
/// `rulegen`'s own structural sentence, on a document the loader read and the model read no property
/// from, a `test` command's JSON spec file); omitted everything (exit 5 on a template the loader's
/// model gives candidate properties, after `rulegen` warned about every one of them by name and then
/// said no rules were generated); or nothing to write (exit 5 on a template the model gives no
/// candidate property, `rulegen` saying no rules were generated, with or without a warning about a
/// property only some resources of a type carry). The two are told apart by the model,
/// `properties_expected_from`, and the warnings are matched to the counted pairs by name
/// (`classify_exit_5`). Any other exit code, any other exit 5 (a warning without the no-rules
/// sentence, a counted candidate dropped with no warning naming it, a resource-level warning that
/// `rulegen` refuses a counted type as a whole, which is drift between the model and `rulegen`, the
/// two readers disagreeing on a refusal, or "Parsing error with generated rules file", which is
/// `rulegen` refusing what it wrote), a generated file the parser refuses, or a generated rule that
/// fails or
/// skips its own template is a failure naming the template and the reason. The counts per category
/// go into the assertion message,
/// so a reader sees the shape of the tree at the time; there is no floor a new fixture can breach,
/// only the control that the walk found templates at all.
///
/// The library test target is the one that runs this, as for the exact-list round trip above: the
/// module is compiled into the binary crate's test target too, and this walk ran `rulegen` and
/// `validate` over the whole tree a second time there on every `cargo test`; in the binary target,
/// where `CARGO_BIN_NAME` is set at compile time, the test returns at once.
#[test]
fn every_template_in_the_repository_is_read_or_refused_by_rulegen() {
    if option_env!("CARGO_BIN_NAME").is_some() {
        return;
    }

    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("resources");
    let mut templates: Vec<PathBuf> = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .map(walkdir::DirEntry::into_path)
        .filter(|path| {
            path.extension().is_some_and(|extension| {
                matches!(
                    extension.to_str(),
                    Some("yaml" | "yml" | "json" | "template")
                )
            }) && is_cloudformation_template(path)
        })
        .collect();
    templates.sort();
    assert!(
        !templates.is_empty(),
        "the walk found no template under resources, so this pass measured nothing"
    );

    let scratch = Scratch::new("repository");
    let stderr_path = scratch.stderr_path.clone();
    let (mut round_tripped, mut round_tripped_with_a_warning, mut loader_refused) = (0, 0, 0);
    let (mut no_resources_mapping, mut omitted_everything, mut nothing_to_write) = (0, 0, 0);
    for template in &templates {
        let template_path = template.display().to_string();
        let (status_code, generated, rulegen_stderr) = run_rulegen(&template_path, &stderr_path);
        let warned = rulegen_stderr.contains("no check generated for");
        match status_code {
            0 => {
                let template_contents =
                    std::fs::read_to_string(template).expect("Failed to read the template.");
                let parsed = parse_generated(&generated);
                drop(parsed);
                let (_, validate_output) = run_validate(&generated, &template_contents);
                // Edition 2018: `panic!` does not capture names, so the arguments are positional.
                let reports: serde_json::Value = serde_json::from_str(&validate_output)
                    .unwrap_or_else(|error| {
                        panic!(
                            "validate's report for the rules generated from {} is not JSON ({}):\n{}",
                            template_path, error, validate_output
                        )
                    });
                // One data document in, one report out, as in the exact-list round trip above.
                let report = match reports.as_array() {
                    Some(reports) if reports.len() == 1 => &reports[0],
                    _ => panic!(
                        "validate's report for the rules generated from {} is not an array of \
                         exactly one report:\n{}",
                        template_path, validate_output
                    ),
                };
                let not_applicable = reported_rule_names(report, "not_applicable");
                let not_compliant = report_array(report, "not_compliant");
                assert!(
                    not_applicable.is_empty() && not_compliant.is_empty(),
                    "rules generated from {template_path} were skipped ({:?}) or failed ({}) against \
                     the template they came from:\n{generated}\n{validate_output}",
                    not_applicable,
                    not_compliant.len()
                );
                if warned {
                    round_tripped_with_a_warning += 1;
                } else {
                    round_tripped += 1;
                }
            }
            5 => {
                let model = properties_expected_from(template);
                match classify_exit_5(&rulegen_stderr, &model) {
                    Ok(Exit5::LoaderRefused) => loader_refused += 1,
                    Ok(Exit5::NoResourcesMapping) => no_resources_mapping += 1,
                    Ok(Exit5::OmittedEverything) => omitted_everything += 1,
                    Ok(Exit5::NothingToWrite) => nothing_to_write += 1,
                    Err(reason) => panic!(
                        "rulegen on {} exited 5 and this pass refuses it: {}; stdout:\n{}\nstderr:\n{}",
                        template_path, reason, generated, rulegen_stderr
                    ),
                }
            }
            other => panic!(
                "rulegen on {} exited {} for a reason this pass does not know; stdout:\n{}\nstderr:\n{}",
                template_path, other, generated, rulegen_stderr
            ),
        }
    }

    let counted = round_tripped
        + round_tripped_with_a_warning
        + loader_refused
        + no_resources_mapping
        + omitted_everything
        + nothing_to_write;
    assert_eq!(
        templates.len(),
        counted,
        "{} templates walked: {round_tripped} round-tripped, {round_tripped_with_a_warning} \
         round-tripped after a warning, {loader_refused} refused by the loader, \
         {no_resources_mapping} with no Resources mapping, {omitted_everything} with every property \
         omitted, {nothing_to_write} with nothing to write",
        templates.len()
    );
    println!(
        "{} templates walked: {round_tripped} round-tripped, {round_tripped_with_a_warning} \
         round-tripped after a warning, {loader_refused} refused by the loader, \
         {no_resources_mapping} with no Resources mapping, {omitted_everything} with every property \
         omitted, {nothing_to_write} with nothing to write",
        templates.len()
    );
}
