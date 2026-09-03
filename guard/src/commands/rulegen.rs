use std::fs;

use crate::commands::Executable;
use crate::commands::{ERROR_STATUS_CODE, SUCCESS_STATUS_CODE};
use crate::rules::errors::Error;
use crate::rules::path_value::{MapValue, PathAwareValue};
use crate::rules::Result;
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;
use clap::Args;
use std::collections::{BTreeMap, HashMap, HashSet};
// The crate is edition 2018, where `TryFrom` is not in the prelude.
use std::convert::TryFrom;
use std::io::Write;
use string_builder::Builder;

/// Resource type -> property name -> the values the template holds for that property across every
/// resource of that type, each already rendered as guard source.
pub type RuleMap = HashMap<String, HashMap<String, HashSet<String>>>;

/// The property values of one mapping in the template, as the evaluator will see them.
type Fields = indexmap::IndexMap<String, PathAwareValue>;

const ABOUT: &str = "Autogenerate rules from an existing JSON- or YAML- formatted data. (Currently works with only CloudFormation templates)";
const TEMPLATE_HELP: &str = "Provide path to a CloudFormation template file in JSON or YAML";
const OUTPUT_HELP: &str = "Write to output file";

#[derive(Debug, Clone, Eq, PartialEq, Args)]
#[clap(arg_required_else_help = true)]
#[clap(about=ABOUT)]
/// .
/// The Rulegen command auto generates rules from an existing CloudFormation template
/// Please note this currently only works on CloudFormation templates
pub struct Rulegen {
    /// the path to the file which the generated rules will be outputted to
    /// default None
    /// if set to None rules will be outputted to the stdout
    #[arg(short, long, help=OUTPUT_HELP)]
    pub(crate) output: Option<String>,
    /// the path to the CloudFormation template
    #[arg(short, long, help=TEMPLATE_HELP)]
    pub(crate) template: String,
}

impl Executable for Rulegen {
    /// .
    /// autogenerate rules from an existing CloudFormation template
    ///
    /// This function will return an error if
    /// - any of the specified paths do not exist
    /// - illegal json or yaml syntax present in any of the data/input parameter files
    fn execute(&self, writer: &mut Writer, _: &mut Reader) -> Result<i32> {
        let template_contents = fs::read_to_string(&self.template)?;

        let (rule_map, omissions) = match generate_rule_map(&template_contents) {
            Ok(generated) => generated,
            // A template cfn-guard cannot read is the caller's input rather than cfn-guard
            // breaking, and it is the same class `validate` gives `ERROR_STATUS_CODE`. This used to
            // be `process::exit(1)` inside the walk: an ad-hoc code that collides with
            // `TEST_ERROR_STATUS_CODE`, is not one `rulegen` documents, and takes the process down
            // from inside a library function, so an in-process caller could not survive a template
            // it had not pre-validated.
            //
            // A template that does not *exist* keeps -1, through the `?` above. `File::open`
            // returns `IoError`, which is the same line `validate` draws.
            Err(e) => {
                writer.write_err(format!(
                    "Unable to read the template {}: {e}",
                    self.template
                ))?;

                return Ok(ERROR_STATUS_CODE);
            }
        };

        // The status code is `print_rules`'s to decide. It used to be `SUCCESS_STATUS_CODE`
        // whatever happened, including when the generated text failed to re-parse and nothing at
        // all was written: a caller that ran `rulegen` and then `validate` against its output saw
        // two successes and had evaluated no rules.
        print_rules(rule_map, omissions, writer)
    }
}

/// Public wrapper over `generate_rule_map`, kept because it is public API of the library. It reports
/// the omissions itself, since a caller holding only the map has no other way to learn about them.
///
/// `dead_code` because `main.rs` compiles this module tree as its own crate and reaches `rulegen`
/// through `generate_rule_map`, so nothing in the binary calls this. Same reason the argument-name
/// constants in `commands/mod.rs` carry the attribute.
#[allow(dead_code)]
pub fn parse_template_and_call_gen(
    template_contents: &str,
    writer: &mut Writer,
) -> Result<RuleMap> {
    let (rule_map, omissions) = generate_rule_map(template_contents)?;
    report(&omissions, writer);

    Ok(rule_map)
}

/// The template as the evaluator will see it, read through the loader the evaluator reads it with.
///
/// This is the whole of the fix for rulegen emitting literals the tool then declines to match. It
/// used to be `serde_yaml::from_str` into `serde_json::Value`, a second reader with its own
/// resolution rules, and every place the two readers disagreed produced a clause the source template
/// fails. Measured over 36 one-property templates, one per YAML spelling, before this change:
///
/// | template writes | the loader reads | rulegen emitted | round-trip |
/// |---|---|---|---|
/// | `P:`, `P: null`, `P: ~` | null | `""` | fails |
/// | `{Inner: null}`, `[a, null]` | null, nested | `""`, nested | fails |
/// | `P: .nan`, `P: .inf` | the text `.nan` | `""` | fails |
/// | `P: 1e-400` | the text `1e-400` | `0.0` | fails |
/// | `P: 0b101` | the text `0b101` | `5` | fails |
/// | `P: 9223372036854775809` | the text | a 19-digit int literal | does not parse |
/// | `<<: {A: 1}` | the merge resolved | a key named `<<` | fails |
/// | `!Ref`, `!GetAtt`, any `!Foo` | `{Fn::Foo: ...}` | -- | aborted, exit 1 |
///
/// Ten of those emitted a clause the template does not satisfy. Five aborted the process, which is
/// every CloudFormation template using a short-form intrinsic -- `serde_yaml` will not deserialise a
/// tagged node into `serde_json::Value` at all.
///
/// Reconciling the two readers by hand is not possible, and that is the reason to read once rather
/// than a preference. `serde_yaml` maps `.nan` and an *empty* node to the same `Value::Null`, and the
/// loader reads the first as the string `.nan` and the second as null -- so no rendering rule over
/// `serde_json::Value` can be right for both, because the distinction is gone before rendering
/// starts. Reading with the loader removes the class instead of tracking it: the value rendered is
/// the value compared, so a new resolution rule in the loader cannot desynchronise them.
///
/// `PathAwareValue` rather than the loader's `MarkedValue`, because the conversion between them is
/// where a mapping's duplicate keys collapse last-write-wins. A template writing `P` twice must
/// generate a clause about the value the evaluator will see, which is the second one.
fn load_template(template_contents: &str) -> Result<PathAwareValue> {
    // Every loader failure is normalised to `ParseError` here. `read_from` passes
    // `MissingDocument`, `UnsupportedDocument` and `InternalError(InvalidKeyType)` through
    // unflattened so that a caller can word them, and `execute` words all of them the same way --
    // it has one thing to say, which is that the template could not be read.
    let marked = crate::rules::values::read_from(template_contents)
        .map_err(|e| Error::ParseError(format!("{e}")))?;

    PathAwareValue::try_from(marked)
}

/// The rule map, plus what the template holds that the generated rules will not describe.
///
/// The omissions travel with the map rather than being written here, so `print_rules` can put each
/// one in the position its clause would have held. A rules file that is simply missing a property
/// reads as though the template never carried one, and the person reading the file later is not the
/// person who saw stderr.
fn generate_rule_map(template_contents: &str) -> Result<(RuleMap, Vec<Omission>)> {
    let template = load_template(template_contents)?;

    let resources =
        match fields_of(&template).and_then(|root| root.get("Resources")) {
            Some(resources) => match fields_of(resources) {
                Some(resources) => resources,
                None => return Err(Error::ParseError(String::from(
                    "Template Resources section has an invalid structure: it is not a mapping of \
                     logical id to resource",
                ))),
            },
            None => {
                return Err(Error::ParseError(String::from(
                    "Template lacks a Resources section",
                )))
            }
        };

    Ok(gen_rules(resources))
}

/// The entries of `value` when it is a mapping, and `None` otherwise.
fn fields_of(value: &PathAwareValue) -> Option<&Fields> {
    match value {
        PathAwareValue::Map((_, MapValue { values, .. })) => Some(values),
        _ => None,
    }
}

/// Something in the template the generated rules do not describe, and why not.
///
/// Collected rather than written where it is found, because every walk in this file is over a
/// `HashMap`: the order a resource or a property is visited in is not the order it appears in the
/// template, and it is not even the same order twice. `report` sorts before writing.
///
/// A `Property` carries the type and name separately rather than a ready-made sentence so that
/// `print_rules` can put its comment in the rule block, in the position the clause would have held.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Omission {
    /// A resource that belongs to no rule block at all, because it has no usable `Type`.
    Resource { name: String, reason: String },
    Property {
        resource_type: String,
        name: String,
        reason: String,
    },
}

impl Omission {
    fn property(
        resource_type: impl Into<String>,
        name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Omission::Property {
            resource_type: resource_type.into(),
            name: name.into(),
            reason: reason.into(),
        }
    }

    /// What was left out: `resource <name>`, or `<type>.Properties.<name>`.
    fn subject(&self) -> String {
        match self {
            Omission::Resource { name, .. } => format!("resource {name}"),
            Omission::Property {
                resource_type,
                name,
                ..
            } => format!("{resource_type}.Properties.{name}"),
        }
    }

    fn reason(&self) -> &str {
        match self {
            Omission::Resource { reason, .. } | Omission::Property { reason, .. } => reason,
        }
    }

    /// The same sentence as a comment, indented to sit where the clause would have been.
    ///
    /// The generated file is what a user reads and edits, and a property that is simply absent from
    /// it reads as though the template never carried one. The person reading the file later is not
    /// the person who saw stderr.
    fn comment(&self) -> String {
        format!(
            "  # no check generated for {}: {}\n",
            self.subject(),
            self.reason()
        )
    }
}

fn report(omissions: &[Omission], writer: &mut Writer) {
    let mut sorted = omissions.iter().collect::<Vec<_>>();
    sorted.sort();
    for omission in sorted {
        writer
            .write_err(format!(
                "Warning: no check generated for {}: {}",
                omission.subject(),
                omission.reason()
            ))
            .expect("failed to write to stderr");
    }
}

/// True when `name` can be written bare after the `.` in a query.
///
/// This is the parser's `var_name`: one ASCII alphabetic character, then alphanumerics and
/// underscores. Anything else -- a space, a dot, a slash, a hyphen, a leading digit -- has to be
/// quoted, which `property_name` accepts as the other half of its alternation. Emitted bare, such a
/// name ended the query early and took the whole file's parse with it.
fn is_bare_property_name(name: &str) -> bool {
    let mut chars = name.chars();
    if !matches!(chars.next(), Some(c) if c.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|c| c.is_alphanumeric() || c == '_')
}

/// `name` as it appears after the `.` in a query: bare where `var_name` accepts it, quoted where it
/// does not, and `None` where no guard literal can carry it at all.
fn property_path_segment(name: &str) -> Option<String> {
    if is_bare_property_name(name) {
        return Some(name.to_string());
    }

    quote_guard_string(name)
}

/// `s` as a guard double-quoted string literal, or `None` when no literal denotes it.
///
/// A string literal understands two escapes -- `\\`, and a backslash before the quote that opened
/// the literal -- and `scan_escaped_literal` ends the literal at the end of its line. So a value
/// holding a line ending cannot be written at all, and neither can one holding a tab or any other
/// control character: a backslash before anything but a backslash or the opening quote is not an
/// escape and stays in the value, so `\n` reads back as the two characters `\` and `n`.
///
/// The value used to be pasted between two quotes with its newlines deleted and no escaping. A
/// value holding a quote produced a clause that did not parse; a value spanning two lines produced
/// one that parsed and asserted the two lines run together, which is a string the template never
/// held. Refusing to write a clause is the call the parser already makes on a range no value can
/// satisfy, and for the same reason: a check that cannot be right is worse than no check.
fn quote_guard_string(s: &str) -> Option<String> {
    if s.chars().any(char::is_control) {
        return None;
    }

    let mut quoted = String::with_capacity(s.len() + 2);
    quoted.push('"');
    for c in s.chars() {
        if c == '\\' || c == '"' {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');

    Some(quoted)
}

/// The reason no guard literal denotes a value holding a control character.
///
/// Named because `value_to_guard` reaches it from two arms -- a string value, and a key inside a
/// mapping value -- and a test pins the sentence. The *property* name has its own sentence, in
/// `print_rules`, because a name and a value are two different things to have to fix.
const CONTROL_CHARACTER: &str =
    "its value holds a line ending or another control character, and a guard string literal ends at \
     the end of its line";

/// A loaded template value as guard source, or the reason no guard literal denotes it.
///
/// The value is the one the evaluator will compare against, so the only question here is which text
/// the *rules* parser reads back as that same value. Each arm was measured by generating the clause
/// and validating it against the template it came from; the spellings that need saying:
///
/// - a null is `null`. It used to be `""`, calibrated against a loader that resolved an empty node
///   to the empty string, and the commit that made an empty node null inverted it -- `"NULL"` against
///   `""` is `not comparable null, String`, so the clause could not pass at any depth.
/// - a whole float carries its fractional part, so `2.0` is "2.0" and not Rust's "2". `1e20` matters
///   more than `2.0` does: `f64::to_string` gives it as 21 digits with no point, which the rules
///   parser rejects as an integer literal too wide for `i64`, and the whole generated file was then
///   discarded. With the point it round-trips, up to `1e300`.
/// - a non-finite float is refused. The loader cannot produce one from a document -- `.nan` and
///   `.inf` stay strings and reach the arm above as text -- so this is unreachable through
///   `rulegen`'s own entry point, and it is written as a refusal rather than as `unreachable!()`
///   because that is a panic waiting for the day something widens what can arrive.
/// - `Regex`, `Char` and the three ranges are only ever built by the rules parser, never by the data
///   loader. They are enumerated rather than swept into a wildcard so that a variant added to
///   `PathAwareValue` fails to compile here instead of silently becoming a refusal.
///
/// A string is escaped rather than pasted in raw, and one no literal can carry is refused rather
/// than corrupted; see `quote_guard_string`.
fn value_to_guard(value: &PathAwareValue) -> std::result::Result<String, String> {
    match value {
        PathAwareValue::Null(_) => Ok(String::from("null")),
        PathAwareValue::String((_, s)) => {
            quote_guard_string(s).ok_or_else(|| String::from(CONTROL_CHARACTER))
        }
        PathAwareValue::Bool((_, b)) => Ok(b.to_string()),
        PathAwareValue::Int((_, i)) => Ok(i.to_string()),
        PathAwareValue::Float((_, f)) => float_to_guard(*f),
        PathAwareValue::List((_, items)) => {
            let rendered = items
                .iter()
                .map(value_to_guard)
                .collect::<std::result::Result<Vec<String>, String>>()?;

            Ok(format!("[{}]", rendered.join(",")))
        }
        PathAwareValue::Map((_, MapValue { values, .. })) => {
            let rendered = values
                .iter()
                .map(|(name, field)| {
                    let name =
                        quote_guard_string(name).ok_or_else(|| String::from(CONTROL_CHARACTER))?;

                    Ok(format!("{name}:{}", value_to_guard(field)?))
                })
                .collect::<std::result::Result<Vec<String>, String>>()?;

            Ok(format!("{{{}}}", rendered.join(",")))
        }
        PathAwareValue::Regex(..)
        | PathAwareValue::Char(..)
        | PathAwareValue::RangeInt(..)
        | PathAwareValue::RangeChar(..)
        | PathAwareValue::RangeFloat(..) => Err(String::from(
            "its value is of a kind only a rules file can hold, so no template can produce it and \
             no literal here denotes it",
        )),
    }
}

/// A float as a guard float literal, keeping a fractional part on a whole number.
///
/// `f64::to_string` drops it -- `2.0` is "2" -- and the rules parser then reads an integer, which for
/// anything past `i64` does not parse at all. The same rule is already applied where the loader
/// renders a float used as a mapping key, for the same reason: a YAML-to-JSON conversion keeps the
/// point.
fn float_to_guard(f: f64) -> std::result::Result<String, String> {
    if !f.is_finite() {
        return Err(String::from(
            "its value is a non-finite float, which no guard float literal denotes",
        ));
    }

    Ok(if f.fract() == 0.0 {
        format!("{f:.1}")
    } else {
        f.to_string()
    })
}

#[allow(clippy::map_entry)]
fn gen_rules(cfn_resources: &Fields) -> (RuleMap, Vec<Omission>) {
    // Create hashmap of resource name, property name and property values
    // For example, the following template:
    //
    //        {
    //            "Resources": {
    //                "NewVolume" : {
    //                    "Type" : "AWS::EC2::Volume",
    //                    "Properties" : {
    //                        "Size" : 500,
    //                        "Encrypted": false,
    //                        "AvailabilityZone" : "us-west-2b"
    //                    }
    //                },
    //                "NewVolume2" : {
    //                    "Type" : "AWS::EC2::Volume",
    //                    "Properties" : {
    //                        "Size" : 50,
    //                        "Encrypted": false,
    //                        "AvailabilityZone" : "us-west-2c"
    //                    }
    //                }
    //            }
    //        }
    //
    //
    // The data structure would contain:
    // <AWS::EC2::Volume> <Encrypted> <false>
    //                    <Size> <500, 50>
    //                    <AvailabilityZone> <us-west-2c, us-west-2b>
    //
    //
    //
    let mut rule_map: RuleMap = HashMap::new();
    let mut omissions: Vec<Omission> = Vec::new();
    // A property one of whose values cannot be written, keyed by (resource type, property name).
    //
    // The whole property has to go, not the one value: a property is collapsed across every
    // resource of its type, so keeping the values that can be written would emit a clause asserting
    // that the resources whose value was dropped hold one of the others.
    let mut unwritable: HashMap<(String, String), String> = HashMap::new();
    // How many resources of each type the template declares, and how many of those carry each
    // property. A clause is evaluated against every resource the rule's `Type ==` filter admits, so
    // a property only some of them carry produces a clause the source template itself fails --
    // `Tags == [...]` against a bucket that has no `Tags` is a retrieval failure, not a skip.
    let mut resources_of_type: HashMap<String, usize> = HashMap::new();
    let mut resources_with_property: HashMap<(String, String), usize> = HashMap::new();

    for (name, cfn_resource) in cfn_resources {
        // A resource that is not a mapping has neither a `Type` nor `Properties`, so it falls into
        // the same silent skip as one carrying only a `Type`.
        let cfn_resource = match fields_of(cfn_resource) {
            Some(fields) => fields,
            None => continue,
        };

        let props = cfn_resource.get("Properties").and_then(fields_of);

        // Every generated rule is keyed on the resource type, and this used to be
        // `cfn_resource["Type"].as_str().unwrap()`, read inside the property loop. A resource
        // carrying `Properties` and no usable `Type` reached that `unwrap` on a `None` and aborted
        // the process, exit 101, with a panic message naming a line of this file. Two templates
        // committed under `guard/resources/validate/mixed-extension-dir` do exactly that, and
        // `non-string-type-template.yaml` is one added property away from it.
        //
        // Skipping the resource is what the loop already does with one that has no `Properties`.
        let type_name = match cfn_resource.get("Type") {
            Some(PathAwareValue::String((_, type_name))) => Some(type_name),
            _ => None,
        };

        let resource_type = match (type_name, &props) {
            (Some(resource_type), _) => resource_type.to_string(),
            // No `Properties` to generate anything from, so a missing `Type` costs nothing here and
            // is not worth telling the user about.
            (None, None) => continue,
            (None, Some(_)) => {
                omissions.push(Omission::Resource {
                    name: name.clone(),
                    reason: match cfn_resource.get("Type") {
                        None => String::from(
                            "it has no Type, and a generated rule is keyed on the resource type",
                        ),
                        // Rendered through the same function the clauses use, so the sentence names
                        // the `Type` the way a clause would have written it. A `Type` that cannot be
                        // rendered at all -- one holding a line ending, say -- has nothing worth
                        // quoting back, and the reason it is unusable does not depend on its text.
                        Some(not_a_string) => match value_to_guard(not_a_string) {
                            Ok(rendered) => format!(
                                "its Type is {rendered} rather than a string, and a generated rule is keyed on the resource type"
                            ),
                            Err(_) => String::from(
                                "its Type is not a string, and a generated rule is keyed on the resource type"
                            ),
                        },
                    },
                });
                continue;
            }
        };

        // Counted before the `Properties` check, and whatever those properties turn out to be: a
        // resource of this type with no properties at all is still one the rule's clauses are
        // evaluated against.
        *resources_of_type.entry(resource_type.clone()).or_insert(0) += 1;

        let props = match props {
            Some(props) => props,
            None => continue,
        };

        for (prop_name, prop_val) in props {
            *resources_with_property
                .entry((resource_type.clone(), prop_name.clone()))
                .or_insert(0) += 1;

            // The value is rendered here, once, rather than at emission: the set below holds
            // guard source, and two resources of one type agree only if their values render the
            // same way.
            let rendered = match value_to_guard(prop_val) {
                Ok(rendered) => rendered,
                Err(reason) => {
                    unwritable.insert((resource_type.clone(), prop_name.clone()), reason);
                    continue;
                }
            };

            if !rule_map.contains_key(&resource_type) {
                let value_set: HashSet<String> = vec![rendered].into_iter().collect();

                let mut property_map = HashMap::new();
                property_map.insert(prop_name.clone(), value_set);
                rule_map.insert(resource_type.clone(), property_map);
            } else {
                let property_map = rule_map.get_mut(&resource_type).unwrap();

                if !property_map.contains_key(prop_name) {
                    let value_set: HashSet<String> = vec![rendered].into_iter().collect();
                    property_map.insert(prop_name.clone(), value_set);
                } else {
                    let value_set = property_map.get_mut(prop_name).unwrap();
                    value_set.insert(rendered);
                }
            };
        }
    }

    for ((resource_type, prop_name), carried) in &resources_with_property {
        let declared = resources_of_type[resource_type];
        if *carried < declared {
            unwritable
                .entry((resource_type.clone(), prop_name.clone()))
                .or_insert_with(|| {
                    format!(
                        "only {carried} of the {declared} resources of this type carry it, and a clause over the type is evaluated against all of them"
                    )
                });
        }
    }

    for ((resource_type, prop_name), reason) in unwritable {
        if let Some(property_map) = rule_map.get_mut(&resource_type) {
            property_map.remove(&prop_name);
            if property_map.is_empty() {
                rule_map.remove(&resource_type);
            }
        }
        omissions.push(Omission::property(resource_type, prop_name, reason));
    }

    (rule_map, omissions)
}

/// The clause for one property, or the reason there is none.
///
/// A property the template holds more than one value for collapses into one `IN` clause. The
/// docstring on `print_rules` used to claim that clause is "interpreted as ALL by default", which
/// it is not: `IN` is a disjunction, and the clause asks only that each resource hold one of the
/// values *some* resource of that type holds. For a boolean observed both ways that is
/// `IN [false, true]`, which no boolean value can fail, so the generated rule cannot tell the
/// insecure template from the secure one. `Encrypted: false` on both volumes passes it.
///
/// Such a clause is refused rather than written, which is what the parser does with a range literal
/// no value can satisfy and with a non-finite float bound: a clause no document can move reads as a
/// PASS with nothing to notice, and the argument for refusing it is that it cannot be right, not
/// that it is unusual. The one narrowing is that only the boolean case is refused -- `Size IN
/// [50, 500]` is weaker than the docstring claimed but a template with `Size: 100` still fails it.
fn emit_clause(
    variable_name: &str,
    path_segment: &str,
    values: &HashSet<String>,
) -> std::result::Result<String, String> {
    let mut rendered = values.iter().cloned().collect::<Vec<String>>();
    rendered.sort();

    match rendered.len() {
        0 => Err(String::from("no value for it was recorded")),
        1 => Ok(format!(
            "  %{variable_name}.Properties.{path_segment} == {}\n",
            rendered[0]
        )),
        // `sort` above puts `false` before `true`, and those are the only two renderings a JSON
        // boolean has. A template holding the *strings* "true" and "false" renders them with their
        // quotes and does not match here.
        2 if rendered[0] == "false" && rendered[1] == "true" => Err(String::from(
            "the template holds both true and false for it, and `IN [false, true]` is a clause no boolean value can fail",
        )),
        _ => Ok(format!(
            "  %{variable_name}.Properties.{path_segment} IN [{}]\n",
            rendered.join(", ")
        )),
    }
}

// Prints the generated rules data structure to stdout. If there are properties mapping to
// multiple values in the template, the rules are put in one statement using the IN keyword. See
// `emit_clause` for what that clause does and does not assert.
// Using the same example in the comment above, the rules printed for the template will be:
//     let aws_ec2_volume_resources = Resources.*[ Type == 'AWS::EC2::Volume' ]
//     rule aws_ec2_volume when %aws_ec2_volume_resources !empty {
//          %aws_ec2_volume_resources.Properties.AvailabilityZone IN ["us-west-2b", "us-west-2c"]
//          %aws_ec2_volume_resources.Properties.Encrypted == false
//          %aws_ec2_volume_resources.Properties.Size IN [50, 500]
//     }
fn print_rules(
    rule_map: RuleMap,
    mut omissions: Vec<Omission>,
    writer: &mut Writer,
) -> Result<i32> {
    let mut str = Builder::default();
    let mut rules_written = 0usize;

    // Sorted, not in `HashMap` order. Two resources with five properties between them produced 16
    // distinct outputs over 30 runs, because a `HashMap`'s iteration order is seeded per process.
    // A generator whose output moves between runs cannot be committed, diffed or reviewed, and the
    // one integration test over this command passes only because its fixture has a single type
    // holding a single property.
    let mut resources = rule_map.keys().collect::<Vec<&String>>();
    resources.sort();

    for resource in resources {
        let properties = &rule_map[resource];
        let resource_name_underscore = resource.replace("::", "_").to_lowercase();
        let variable_name = format!("{}_resources", resource_name_underscore);

        // One line per property name, in name order, whether that line is a clause or the comment
        // saying why there is none. `gen_rules` already removed the properties it could not write
        // from the map, so its omissions and the clauses below are over disjoint names.
        let mut body: BTreeMap<String, String> = omissions
            .iter()
            .filter_map(|omission| match omission {
                Omission::Property {
                    resource_type,
                    name,
                    ..
                } if resource_type == resource => Some((name.clone(), omission.comment())),
                _ => None,
            })
            .collect();
        let mut clauses = 0usize;
        let mut refused: Vec<Omission> = Vec::new();

        let mut names = properties.keys().collect::<Vec<&String>>();
        names.sort();

        for property in names {
            let clause = match property_path_segment(property) {
                Some(path_segment) => {
                    emit_clause(&variable_name, &path_segment, &properties[property])
                }
                None => Err(String::from(
                    "the property name holds a line ending or another control character, and a guard string literal ends at the end of its line",
                )),
            };

            match clause {
                Ok(clause) => {
                    body.insert(property.clone(), clause);
                    clauses += 1;
                }
                Err(reason) => {
                    let omission = Omission::property(resource, property, reason);
                    body.insert(property.clone(), omission.comment());
                    refused.push(omission);
                }
            }
        }

        omissions.extend(refused);

        // No clause, no rule. A rule with an empty body does not parse, and one that checked
        // nothing would pass every document -- the shape this whole function is here to avoid. The
        // comments go with it; `report` below is the channel that survives.
        if clauses == 0 {
            continue;
        }

        str.append(format!(
            "let {} = Resources.*[ Type == '{}' ]\n",
            variable_name, resource
        ));
        str.append(format!(
            "rule {} when %{} !empty {{\n",
            resource_name_underscore, variable_name
        ));
        for line in body.into_values() {
            str.append(line);
        }
        str.append("}\n");
        rules_written += 1;
    }

    report(&omissions, writer);

    // An empty rules file is not a check: `validate -r` against one reports every document
    // compliant, so a caller that generates rules and then validates against them goes green
    // having evaluated nothing. Exiting non-zero is the only thing that distinguishes it from a
    // run that checked something and found it compliant, because both print nothing and both used
    // to exit 0.
    if rules_written == 0 {
        writer.write_err(String::from(
            "No rules were generated from this template, so no rules file was written. \
             Validating against an empty rules file reports every template compliant.",
        ))?;

        return Ok(ERROR_STATUS_CODE);
    }

    // validate rules generated
    let generated_rules = str.string().unwrap();

    let span = crate::rules::parser::Span::new_extra(&generated_rules, "");
    match crate::rules::parser::rules_file(span) {
        Ok(_rules) => {
            write!(writer, "{}", generated_rules)?;

            Ok(SUCCESS_STATUS_CODE)
        }
        Err(e) => {
            writer.write_err(format!(
                "Parsing error with generated rules file, Error = {e}"
            ))?;
            writer.write_err(String::from(
                "No rules file was written. Validating against an empty rules file reports every \
                 template compliant.",
            ))?;

            Ok(ERROR_STATUS_CODE)
        }
    }
}

#[cfg(test)]
#[path = "rulegen_tests.rs"]
mod rulegen_tests;
