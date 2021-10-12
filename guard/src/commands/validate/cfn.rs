use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::path_value::traversal::{Traversal, TraversalResult};
use crate::rules::eval_context::{ClauseReport, EventRecord, UnaryCheck, simplifed_json_from_root, GuardClauseReport, UnaryComparison, ValueUnResolved, BinaryCheck, BinaryComparison, RuleReport};
use std::io::Write;
use crate::rules::Status;
use crate::commands::tracker::StatusContext;
use std::collections::{HashMap, HashSet, BTreeMap};
use lazy_static::lazy_static;
use crate::rules::UnResolved;
use regex::Regex;
use crate::rules::path_value::PathAwareValue;
use crate::rules::errors::{Error, ErrorKind};
use serde::{Serialize, Serializer};
use crate::rules::values::CmpOperator;
use std::hash::{Hash, Hasher};
use serde::ser::{SerializeStruct, SerializeMap};

use std::ops::{Deref, DerefMut};
use std::cmp::Ordering;

lazy_static! {
    static ref CFN_RESOURCES: Regex = Regex::new(r"^/Resources/(?P<name>[^/]+)(/?P<rest>.*$)?").ok().unwrap();
}

#[derive(Debug)]
pub(crate) struct CfnAware<'reporter>{
    next: Option<&'reporter dyn Reporter>,
}

#[derive(Clone, Debug)]
struct IdentityKey<'key, T: PartialOrd> {
    key: &'key T,
}

impl<'key, T: PartialOrd> Hash for IdentityKey<'key, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(self.key, state)
    }
}

impl<'key, T: PartialOrd> PartialEq for IdentityKey<'key, T> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.key, other.key)
    }
}

impl<'key, T: PartialOrd> Eq for IdentityKey<'key, T> {}

impl<'key, T: PartialOrd> PartialOrd for IdentityKey<'key, T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.key.partial_cmp(other.key)
    }
}

impl<'key, T: PartialOrd> Ord for IdentityKey<'key, T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.partial_cmp(other) {
            Some(o) => o,
            None => Ordering::Equal
        }
    }
}

// type IdentityHashMap<'key, K, V> = HashMap<IdentityKey<'key, K>, V>;


type IdentityHashMap<'key, K, V> = BTreeMap<IdentityKey<'key, K>, V>;

impl<'reporter> CfnAware<'reporter> {
    pub(crate) fn new() -> CfnAware<'reporter> {
        CfnAware{ next: None }
    }

    pub(crate) fn new_with(next: &'reporter dyn Reporter) -> CfnAware {
        CfnAware { next: Some(next) }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) enum ResolvedFailure<'report, 'value: 'report> {
    Unary(&'report UnaryComparison<'value>),
    Binary(&'report BinaryComparison<'value>),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UnResolvedProperty<'report> {
    remaining_query: &'report str,
    reason: &'report Option<String>,
    cmp: (CmpOperator, bool)
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UnaryResolvedProperty<'report> {
    message: &'report str,
    error: &'report str,
    cmp: (CmpOperator, bool)
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BinaryResolvedProperty<
    'report,
    'value: 'report> {
    to: &'value PathAwareValue,
    error: &'report str,
    message: &'report str,
    cmp: (CmpOperator, bool),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) enum FailedProperty<'report, 'value: 'report> {
    RetrievalError(UnResolvedProperty<'report>),
    UnaryError(UnaryResolvedProperty<'report>),
    BinaryError(BinaryResolvedProperty<'report, 'value>)
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PropertyError<
    'report,
    'value: 'report>
{
    from: &'value PathAwareValue,
    errors: Vec<FailedProperty<'report, 'value>>
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ResourceView<'report, 'value: 'report> {
    resource_id: &'value str,
    #[serde(rename = "type")]
    resource_type: &'value str,
    rule_name: &'value str,
    cdk_path: Option<&'value str>,
    errors: Vec<PropertyError<'report, 'value>>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Overall<'report, 'value: 'report> {
    data_file: &'report str,
    rules_file: &'report str,
    status: Status,
    non_compliant: Vec<ResourceView<'report, 'value>>,
    compliant: &'report HashSet<String>,
    not_applicable: &'report HashSet<String>,
}

fn find_guard_clause_failures<'report, 'value: 'report>(clause_report: &'report ClauseReport<'value>)
    -> Vec<&'report GuardClauseReport<'value>> {
    if let ClauseReport::Clause(gac) = clause_report {
        return vec![gac]
    }
    let checks = match clause_report {
        ClauseReport::Rule(report)  => &report.checks,
        ClauseReport::Disjunctions(report) => &report.checks,
        _ => return vec![],
    };
    checks.iter().map(|each| find_guard_clause_failures(each))
        .fold(Vec::new(), |mut vec, others| {
            vec.extend(others);
            vec
        })
}

impl<'reporter> Reporter for CfnAware<'reporter> {

    fn report(
        &self,
        _writer: &mut dyn Write,
        _status: Option<Status>,
        _failed_rules: &[&StatusContext],
        _passed_or_skipped: &[&StatusContext],
        _longest_rule_name: usize,
        _rules_file: &str,
        _data_file: &str,
        _data: &Traversal<'_>,
        _output_format_type: OutputFormatType) -> crate::rules::Result<()> {
        Ok(())
    }

    fn report_eval<'value>(
        &self,
        write: &mut dyn Write,
        status: Status,
        root_record: &EventRecord<'value>,
        rules_file: &str,
        data_file: &str,
        data: &Traversal<'value>,
        outputType: OutputFormatType) -> crate::rules::Result<()> {

        let root = data.root().unwrap();
        if let Ok(_) = data.at("/Resources", root) {
            let record = simplifed_json_from_root(root_record)?;
            let mut by_resources: HashMap<
                &str,
                (ResourceView,
                 IdentityHashMap<
                     '_,
                     PathAwareValue,
                     Vec<
                         FailedProperty<
                             '_,
                             '_
                         >
                     >
                 >
                )
            > = HashMap::new();
            for each_rule in &record.not_compliant {
                let rule_name = match each_rule {
                    ClauseReport::Rule(RuleReport{name, ..}) => *name,
                    _ => unreachable!()
                };
                for each in find_guard_clause_failures(each_rule) {
                    let value= match each {
                        GuardClauseReport::Unary(unary) => {
                            match &unary.check {
                                UnaryCheck::Resolved(UnaryComparison{value, ..}) => *value,
                                UnaryCheck::UnResolved(ValueUnResolved{value: UnResolved{traversed_to: value, ..}, ..}) =>
                                    *value,
                                _ => {
                                    continue;
                                }
                            }
                        },

                        GuardClauseReport::Binary(binary) => {
                            match &binary.check {
                                BinaryCheck::Resolved(BinaryComparison{from: value, ..}) |
                                BinaryCheck::UnResolved(ValueUnResolved{value: UnResolved{traversed_to: value, ..}, ..}) => *value,
                            }
                        }
                    };
                    let resource_name = match CFN_RESOURCES.captures(value.self_path().0.as_str()) {
                        Some(cap) => {
                            cap.get(1).unwrap().as_str()
                        },
                        _ => unreachable!()
                    };
                    let root = data.root().unwrap();
                    let mut resource_views= by_resources.entry(resource_name).or_insert_with(|| {
                        let path = format!("/Resources/{}", resource_name);
                        let resource = match data.at(&path, root) {
                            Ok(TraversalResult::Value(val)) => val,
                            _ => unreachable!()
                        };
                        let resource_type = match data.at("0/Type", resource) {
                            Ok(TraversalResult::Value(val)) => match val.value() {
                                PathAwareValue::String((_, v)) => v.as_str(),
                                _ => unreachable!()
                            }
                            _ => unreachable!()
                        };
                        let cdk_path = match data.at("0/Metadata/aws.cdk.path", resource) {
                            Ok(TraversalResult::Value(val)) => match val.value() {
                                PathAwareValue::String((_, v)) => Some(v.as_str()),
                                _ => unreachable!()
                            },
                            _ => None
                        };
                        (ResourceView {
                            resource_id: resource_name,
                            rule_name,
                            resource_type,
                            cdk_path,
                            errors: vec![]
                        },
                        IdentityHashMap::new())
                    });

                    match each {
                        GuardClauseReport::Binary(bin) => match &bin.check {
                            BinaryCheck::UnResolved(un) => {
                                resource_views.1.entry(
                                    IdentityKey{key: un.value.traversed_to}
                                ).or_insert(vec![]).push(
                                    FailedProperty::RetrievalError(UnResolvedProperty {
                                        remaining_query: &un.value.remaining_query,
                                        cmp: un.comparison,
                                        reason: &un.value.reason
                                    }));
                            }

                            BinaryCheck::Resolved(cmp) => {
                                resource_views.1.entry(
                                    IdentityKey{key: cmp.from}
                                ).or_insert(vec![]).push(
                                    FailedProperty::BinaryError(BinaryResolvedProperty {
                                        cmp: cmp.comparison,
                                        to: cmp.to,
                                        error: bin.messages.error_message.as_ref().map_or(
                                            "", String::as_str),
                                        message: bin.messages.custom_message.as_ref().map_or(
                                            "", String::as_str)
                                    })
                                );
                            }
                        },

                        GuardClauseReport::Unary(unary) => match &unary.check {
                            UnaryCheck::UnResolved(un) => {
                                resource_views.1.entry(
                                    IdentityKey{key: un.value.traversed_to}
                                ).or_insert(vec![]).push(
                                FailedProperty::RetrievalError(UnResolvedProperty {
                                    remaining_query: &un.value.remaining_query,
                                    cmp: un.comparison,
                                    reason: &un.value.reason
                                }));
                            },
                            UnaryCheck::Resolved(unary_cmp) => {
                                resource_views.1.entry(
                                    IdentityKey{key: unary_cmp.value}
                                ).or_insert(vec![]).push(
                                    FailedProperty::UnaryError(UnaryResolvedProperty {
                                        cmp: unary_cmp.comparison,
                                        error: unary.message.error_message.as_ref().map_or(
                                            "", String::as_str),
                                        message: unary.message.custom_message.as_ref().map_or(
                                            "", String::as_str)
                                    })
                                );
                            },
                            UnaryCheck::UnResolvedContext(_) => {}
                        }
                    }
                }
            }

            let mut aggr_by_resources = Vec::with_capacity(by_resources.len());
            for (_resource_id, (mut view, id_map)) in by_resources {
                for (from, errors) in id_map {
                    view.errors.push(PropertyError {
                        from: from.key,
                        errors
                    });
                }
                aggr_by_resources.push(view);
            }

            let overall = Overall {
                status,
                compliant: &record.compliant,
                not_applicable: &record.not_applicable,
                non_compliant: aggr_by_resources,
                rules_file,
                data_file,
            };

            match outputType {
                OutputFormatType::JSON => serde_json::to_writer(write, &overall)?,
                OutputFormatType::YAML => serde_yaml::to_writer(write, &overall)?,
                OutputFormatType::SingleLineSummary => single_line(write, &overall)?,
            }

            Ok(())
        }
        else {
            self.next.map_or(
                Ok(()), |next|
                next.report_eval(
                    write,
                    status,
                    root_record,
                    rules_file,
                    data_file,
                    data,
                    outputType)
                )
        }
    }
}

fn single_line(writer: &mut dyn Write,
               overall: &Overall<'_, '_>) -> crate::rules::Result<()> {
    writeln!(writer, "Evaluating data {} against rules {}", overall.data_file, overall.rules_file)?;
    writeln!(writer, "Number of non-compliant resources {}", overall.non_compliant.len())?;
    for each_resource in &overall.non_compliant {
        let (id, type_, rule_name) = (
            each_resource.resource_id,
            each_resource.resource_type,
            each_resource.rule_name
        );
        for each_prop_error in &each_resource.errors {
            for each_err in &each_prop_error.errors {
                match each_err {
                    FailedProperty::UnaryError(UnaryResolvedProperty{error, message, ..}) |
                    FailedProperty::BinaryError(BinaryResolvedProperty{message, error, ..}) => {
                        writeln!(
                            writer,
                            "Resource(Id={id}, Type={type_}) was not compliant with rule [{rule}]. Message [{msg}]. {err}",
                            id=id,
                            type_=type_,
                            err=error,
                            msg=message,
                            rule=rule_name,
                        )?;
                    },

                    FailedProperty::RetrievalError(up) => {
                        let cmp_str = crate::rules::eval_context::cmp_str(up.cmp);
                        writeln!(
                            writer,
                            "Resource(Id={id}, Type={type_}) was not compliant with rule [{rule}] due to retrieval error. Remaining Query [{query}], traversed until [{value}]. {err}",
                            id=id,
                            type_=type_,
                            rule=rule_name,
                            query=up.remaining_query,
                            err=up.reason.as_ref().map_or("", |r| r),
                            value=each_prop_error.from
                        )?;
                    }
                }
            }
        }
    }

    Ok(())
}