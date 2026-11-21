use super::*;
use crate::exprs::*;
use crate::path_value::*;
use pretty_assertions::assert_eq;
use std::convert::TryFrom;

#[test]
fn extraction_test() -> Result<()> {
    let rules_files = r#"
    let aws_route53_recordset_resources = Resources.*[ Type == 'AWS::Route53::RecordSet' ]
    rule aws_route53_recordset when %aws_route53_recordset_resources !empty {
      %aws_route53_recordset_resources.Properties.Comment == "DNS name for my instance."
      let targets = [["",["SubdomainWild",".","HostedZoneName"]], ["",["SubdomainInternal",".","HostedZoneName"]], ["",["SubdomainMaster",".","HostedZoneName"]], ["",["SubdomainDefault",".","HostedZoneName"]]]
      %aws_route53_recordset_resources.Properties.Name IN %targets
      %aws_route53_recordset_resources.Properties.Type == "A"
      %aws_route53_recordset_resources.Properties.ResourceRecords IN [["Master.PrivateIp"], ["Infra1.PrivateIp"]]
      %aws_route53_recordset_resources.Properties.TTL == "900"
      %aws_route53_recordset_resources.Properties.HostedZoneName == "HostedZoneName"
    }
    "#;

    let rules = RulesFile::try_from(rules_files)?;
    let path_value = PathAwareValue::try_from("{}")?;
    let root_scope = root_scope(&rules, Rc::new(path_value));
    assert_eq!(rules.guard_rules.len(), 1);
    assert_eq!(root_scope.rules.len(), 1);
    assert_eq!(
        root_scope
            .rules
            .get("aws_route53_recordset")
            .map(|s| s.first())
            .and_then(|s| s.copied()),
        rules.guard_rules.first()
    );

    Ok(())
}

//
// Query Testing without Filtering
//
pub struct BasicQueryTesting<'record, 'value> {
    pub root: Rc<PathAwareValue>,
    pub recorder: Option<&'record mut dyn RecordTracer<'value>>,
}

impl<'record, 'value, 'loc: 'value> EvalContext<'value, 'loc>
    for BasicQueryTesting<'record, 'value>
{
    fn query(&mut self, query: &'value [QueryPart<'_>]) -> Result<Vec<QueryResult>> {
        query_retrieval(0, query, self.root(), self)
    }

    fn find_parameterized_rule(&mut self, _: &str) -> Result<&'value ParameterizedRule<'loc>> {
        todo!()
    }

    fn root(&mut self) -> Rc<PathAwareValue> {
        Rc::clone(&self.root)
    }
    fn rule_status(&mut self, _: &str, _: crate::eval::ClauseRole) -> Result<Status> {
        todo!()
    }
    fn resolve_variable(&mut self, _: &str) -> Result<Vec<QueryResult>> {
        todo!()
    }
    fn add_variable_capture_key(&mut self, _: &'value str, _: Rc<PathAwareValue>) -> Result<()> {
        todo!()
    }
}

impl<'record, 'value, 'loc: 'value> RecordTracer<'value> for BasicQueryTesting<'record, 'value> {
    fn start_record(&mut self, context: &str) -> Result<()> {
        self.recorder
            .as_mut()
            .map_or(Ok(()), |r| (*r).start_record(context))
    }
    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.recorder
            .as_mut()
            .map_or(Ok(()), |r| (*r).end_record(context, record))
    }
}

#[test]
fn no_query_return_root() -> Result<()> {
    let path_value = PathAwareValue::try_from("{}")?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value.clone()),
        recorder: None,
    };
    let query_results = eval.query(&[])?;
    assert!(!query_results.is_empty());
    assert_eq!(query_results.len(), 1);
    let path_ref = match &query_results[0] {
        QueryResult::Resolved(r) => r,
        _ => unreachable!(),
    };
    assert_eq!(&path_value, &**path_ref);
    Ok(())
}

#[test]
fn empty_value_return_unresolved() -> Result<()> {
    let path_value = PathAwareValue::try_from("{}")?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value.clone()),
        recorder: None,
    };
    let query = AccessQuery::try_from("Resources.*")?.query;
    let query_results = eval.query(&query)?;
    assert!(!query_results.is_empty());
    assert_eq!(query_results.len(), 1);
    let path_ref = match &query_results[0] {
        QueryResult::UnResolved(ur) => &ur.traversed_to,
        _ => unreachable!(),
    };

    assert_eq!(&path_value, &**path_ref);

    Ok(())
}

#[test]
fn non_empty_value_return_results() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
           s3:
             Type: AWS::S3::Bucket
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
        "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };
    let query = AccessQuery::try_from("Resources.*")?.query;
    let query_results = eval.query(&query)?;
    assert!(!query_results.is_empty());
    assert_eq!(query_results.len(), 2); // 2 resources
    for each in query_results {
        assert!(matches!(each, QueryResult::Resolved(_)));
    }

    let paths = [
        Path::try_from("/Resources/s3")?,
        Path::try_from("/Resources/ec2/Properties")?,
    ];
    let query = AccessQuery::try_from("Resources.*.Properties.Tags")?.query;
    let query_results = eval.query(&query)?;
    assert!(!query_results.is_empty());
    assert_eq!(query_results.len(), 2); // 2 resources
    for each in query_results {
        match each {
            QueryResult::UnResolved(ur) => {
                let path = ur.traversed_to.self_path();
                println!("{}", path);
                assert!(paths.contains(path));
            }

            _ => unreachable!(),
        }
    }

    Ok(())
}

#[test]
fn non_empty_value_mixed_results() -> Result<()> {
    let query = AccessQuery::try_from("Resources.*.Properties.Tags")?.query;
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
           s3:
             Type: AWS::S3::Bucket
             Properties:
               Tags:
                 - Key: 1
                   Value: 1
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
        "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };
    let query_results = eval.query(&query)?;
    assert!(!query_results.is_empty());
    assert_eq!(query_results.len(), 2); // 2 resources
    for each in query_results {
        match each {
            QueryResult::Literal(_) => unreachable!(),
            QueryResult::Resolved(res) => {
                assert_eq!(res.self_path().0.as_str(), "/Resources/s3/Properties/Tags");
                assert!(res.is_list());
            }

            QueryResult::UnResolved(ur) => {
                assert_eq!(
                    ur.traversed_to.self_path().0.as_str(),
                    "/Resources/ec2/Properties"
                );
            }
        }
    }

    Ok(())
}

#[test]
fn non_empty_value_with_missing_list_property() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
           s3:
             Type: AWS::S3::Bucket
             Properties:
               Tags:
                 - Key: 1
                   Value: 1
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
        "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };
    let query = AccessQuery::try_from("Resources.*.Properties.Tags[*].Value")?.query;
    let query_results = eval.query(&query)?;
    assert!(!query_results.is_empty());
    assert_eq!(query_results.len(), 2); // 2 resources
    for each in query_results {
        match each {
            QueryResult::Literal(_) => unreachable!(),
            QueryResult::Resolved(res) => {
                assert_eq!(
                    res.self_path().0.as_str(),
                    "/Resources/s3/Properties/Tags/0/Value"
                );
                assert!(res.is_scalar());
            }

            QueryResult::UnResolved(ur) => {
                assert_eq!(
                    ur.traversed_to.self_path().0.as_str(),
                    "/Resources/ec2/Properties"
                );
            }
        }
    }

    Ok(())
}

#[test]
fn non_empty_value_with_empty_list_property() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
           s3:
             Type: AWS::S3::Bucket
             Properties:
               Tags:
                 - Key: 1
                   Value: 1
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
               Tags: []
        "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };
    let query = AccessQuery::try_from("Resources.*.Properties.Tags[*].Value")?.query;
    let query_results = eval.query(&query)?;
    assert!(!query_results.is_empty());
    assert_eq!(query_results.len(), 2); // 2 resources
    for each in query_results {
        match each {
            QueryResult::Literal(_) => unreachable!(),
            QueryResult::Resolved(res) => {
                assert_eq!(
                    res.self_path().0.as_str(),
                    "/Resources/s3/Properties/Tags/0/Value"
                );
                assert!(res.is_scalar());
            }

            QueryResult::UnResolved(ur) => {
                assert_eq!(
                    ur.traversed_to.self_path().0.as_str(),
                    "/Resources/ec2/Properties/Tags"
                );
            }
        }
    }

    Ok(())
}

#[test]
fn map_filter_keys() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
           s3Bucket:
             Type: AWS::S3::Bucket
             Properties:
               Tags:
                 - Key: 1
                   Value: 1
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
               Tags: []
        "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };
    let query = AccessQuery::try_from("Resources[ keys == /s3/ ]")?.query;
    let query_results = eval.query(&query)?;
    assert!(!query_results.is_empty());
    assert_eq!(query_results.len(), 1); // 2 resources
    for each in query_results {
        match each {
            QueryResult::Resolved(res) => {
                assert_eq!(res.self_path().0.as_str(), "/Resources/s3Bucket");
                assert!(res.is_map());
            }

            _ => unreachable!(),
        }
    }

    //
    // Testing other operations
    //
    let query = AccessQuery::try_from("Resources[ keys in [/s3/, /ec2/] ]")?.query;
    let query_results = eval.query(&query)?;
    assert_eq!(query_results.len(), 2);
    for each in query_results {
        match each {
            QueryResult::Resolved(res) => {
                let path = res.self_path().0.as_str();
                assert!(path == "/Resources/s3Bucket" || path == "/Resources/ec2",);
                assert!(res.is_map());
            }

            _ => unreachable!(),
        }
    }

    //
    // !in test
    //
    let query = AccessQuery::try_from("Resources[ keys not in [/ec2/] ]")?.query;
    let query_results = eval.query(&query)?;
    assert_eq!(query_results.len(), 1);
    for each in query_results {
        match each {
            QueryResult::Resolved(res) => {
                let path = res.self_path().0.as_str();
                assert!(path == "/Resources/s3Bucket");
                assert!(res.is_map());
            }

            _ => unreachable!(),
        }
    }

    //
    // !!= test
    //
    let query = AccessQuery::try_from("Resources[ keys != /ec2/ ]")?.query;
    let query_results = eval.query(&query)?;
    assert_eq!(query_results.len(), 1);
    for each in query_results {
        match each {
            QueryResult::Resolved(res) => {
                let path = res.self_path().0.as_str();
                assert!(path == "/Resources/s3Bucket");
                assert!(res.is_map());
            }

            _ => unreachable!(),
        }
    }

    Ok(())
}

#[test]
fn test_with_converter() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
           s3:
             Type: AWS::S3::Bucket
             Properties:
               Tags:
                 - Key: 1
                   Value: 1
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
               Tags: []
        "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };
    let query = AccessQuery::try_from("resources.*.properties.tags[*].value")?.query;
    let query_results = eval.query(&query)?;
    assert!(!query_results.is_empty());
    assert_eq!(query_results.len(), 2); // 2 resources
    for each in query_results {
        match each {
            QueryResult::Literal(_) => unreachable!(),
            QueryResult::Resolved(res) => {
                assert_eq!(
                    res.self_path().0.as_str(),
                    "/Resources/s3/Properties/Tags/0/Value"
                );
                assert!(res.is_scalar());
            }

            QueryResult::UnResolved(ur) => {
                assert_eq!(
                    ur.traversed_to.self_path().0.as_str(),
                    "/Resources/ec2/Properties/Tags"
                );
            }
        }
    }

    Ok(())
}

// FIXME: break this up into multiple tests
#[test]
fn test_handle_function_call() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
           s3:
             Type: AWS::S3::Bucket
             Properties:
               Tags:
                 - Key: 1
                   Value: 1
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               Arn: arn:aws:newservice:us-west-2:123456789012:Table/extracted
               ImageId: ami-123456789012
               Strings:
                   Arn: arn:aws:newservice:us-west-2:123456789012:Table/extracted
                   ImageId: ami-123456789012
               Tags: []
               Policy: |
                {
                   "Principal": "*",
                   "Actions": ["s3*", "ec2*"]
                }
        "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };
    // regex_replace
    let query = AccessQuery::try_from("resources.ec2.properties.Arn")?.query;
    let query_results = eval.query(&query)?;
    let path = Path::new("Literal".to_string(), 0, 0);

    let extracted_expr = PathAwareValue::String((
        path.clone(),
        "^arn:(\\w+):(\\w+):([\\w0-9-]+):(\\d+):(.+)$".to_string(),
    ));
    let extracted = QueryResult::Literal(Rc::new(extracted_expr));

    let replaced_expr =
        PathAwareValue::String((path.clone(), "${1}/${4}/${3}/${2}-${5}".to_string()));
    let replaced = QueryResult::Literal(Rc::new(replaced_expr));

    let args = vec![
        query_results.clone(),
        vec![extracted.clone()],
        vec![replaced.clone()],
    ];

    let res = FunctionName::RegexReplace.call(&args)?;
    let path_value = res[0].as_ref().unwrap();
    if let PathAwareValue::String((_, val)) = path_value {
        assert_eq!("aws/123456789012/us-west-2/newservice-Table/extracted", val);
    }

    // extracted expr is invalid
    let not_a_string = AccessQuery::try_from("resources.ec2.properties.tags")?.query;
    let query_results2 = eval.query(&not_a_string)?;
    let args = vec![
        query_results.clone(),
        query_results2,
        vec![replaced.clone()],
    ];
    let res = FunctionName::RegexReplace.call(&args);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(err, Error::ParseError(_)));
    assert_eq!(
        err.to_string(),
        String::from("Parser Error when parsing `regex_replace function requires the second argument to be a string`")
    );

    // extracted expr is invalid
    let not_a_string = AccessQuery::try_from("resources.ec2.properties.tags")?.query;
    let query_results2 = eval.query(&not_a_string)?;
    let args = vec![
        query_results.clone(),
        vec![extracted.clone()],
        query_results2,
    ];
    let res = FunctionName::RegexReplace.call(&args);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(err, Error::ParseError(_)));
    assert_eq!(
        err.to_string(),
        String::from("Parser Error when parsing `regex_replace function requires the third argument to be a string`")
    );

    // first argument is not a string type so res is an Ok(None)
    let not_a_string = AccessQuery::try_from("resources.ec2.properties.tags")?.query;
    let query_results2 = eval.query(&not_a_string)?;
    let args = vec![query_results2, vec![extracted.clone()], vec![replaced]];
    let res = FunctionName::RegexReplace.call(&args)?;
    assert_eq!(res.len(), 1);
    assert!(res[0].is_none());

    let from_query = PathAwareValue::Int((path.clone(), 0));
    let from = QueryResult::Literal(Rc::new(from_query));

    let to_query = PathAwareValue::Int((path.clone(), 3));
    let to = QueryResult::Literal(Rc::new(to_query));

    // substring - happy path
    let args = vec![query_results.clone(), vec![from.clone()], vec![to.clone()]];
    let res = FunctionName::Substring.call(&args)?;

    let path_value = res[0].as_ref().unwrap();
    if let PathAwareValue::String((_, val)) = path_value {
        assert_eq!("arn", val);
    }

    // first argument is not a string type so res is an Ok(None)
    let not_a_string = AccessQuery::try_from("resources.ec2.properties.tags")?.query;
    let query_results2 = eval.query(&not_a_string)?;
    let args = vec![query_results2, vec![from.clone()], vec![to.clone()]];
    let res = FunctionName::Substring.call(&args)?;
    assert_eq!(res.len(), 1);
    assert!(res[0].is_none());

    // second argument is not a number
    let args = vec![query_results.clone(), vec![extracted.clone()], vec![to]];
    let res = FunctionName::Substring.call(&args);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(err, Error::ParseError(_)));
    assert_eq!(
        err.to_string(),
        String::from("Parser Error when parsing `substring function requires the second argument to be a number`")
    );

    // third argument is not a number
    let args = vec![query_results.clone(), vec![from.clone()], vec![extracted]];
    let res = FunctionName::Substring.call(&args);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(err, Error::ParseError(_)));
    assert_eq!(
        err.to_string(),
        String::from("Parser Error when parsing `substring function requires the third argument to be a number`")
    );

    // join happy path
    let image_id_query = AccessQuery::try_from("resources.ec2.properties.strings.*")?.query;
    let image_id_result = eval.query(&image_id_query)?;

    let char_delim_query = PathAwareValue::Char((path.clone(), ','));
    let char_delim = QueryResult::Literal(Rc::new(char_delim_query));
    let string_delim_query = PathAwareValue::Char((path, ','));
    let string_delim = QueryResult::Literal(Rc::new(string_delim_query));

    let args = vec![image_id_result.clone(), vec![char_delim]];
    let res = FunctionName::Join.call(&args)?;
    let path_value = res[0].as_ref().unwrap();
    if let PathAwareValue::String((_, val)) = path_value {
        assert_eq!(
            "arn:aws:newservice:us-west-2:123456789012:Table/extracted,ami-123456789012",
            val
        );
    }

    let args = vec![image_id_result.clone(), vec![string_delim]];
    let res = FunctionName::Join.call(&args)?;
    let path_value = res[0].as_ref().unwrap();
    if let PathAwareValue::String((_, val)) = path_value {
        assert_eq!(
            "arn:aws:newservice:us-west-2:123456789012:Table/extracted,ami-123456789012",
            val
        );
    }

    let args = vec![image_id_result, vec![from]];
    let res = FunctionName::Join.call(&args);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(err, Error::ParseError(_)));
    assert_eq!(err.to_string(), "Parser Error when parsing `join function requires the second argument to be either a char or string`", );

    Ok(())
}

const VERSIONING_TEMPLATE: &str = r#"Resources:
  LogsBucket:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: Suspended
"#;

const VERSIONING_STATUS_LOCATION: Location = Location { line: 5, col: 16 };

fn failed_comparison_location(rules: &str, data: &str, failed_value: &str) -> Result<Location> {
    let rules_file = RulesFile::try_from(rules)?;
    let root = PathAwareValue::try_from(crate::values::read_from(data)?)?;
    let mut scope = root_scope(&rules_file, Rc::new(root));
    scope.enable_provenance_tracking();
    crate::eval::eval_rules_file(&rules_file, &mut scope, None)?;
    let report = scope.reset_recorder().into_file_report()?;

    let failed_value_marker = format!("Value=\"{}\"]", failed_value);
    let messages = report
        .not_compliant
        .iter()
        .flat_map(ClauseReport::get_message)
        .find(|messages| {
            messages
                .error_message
                .as_ref()
                .is_some_and(|message| message.contains(&failed_value_marker))
        })
        .unwrap_or_else(|| panic!("no failed comparison reported for {}", failed_value));
    Ok(messages
        .location
        .expect("a failed comparison must carry a location"))
}

#[test]
fn failed_comparison_with_a_literal_on_the_right_is_located_at_the_input_value() -> Result<()> {
    let rules = r#"rule versioning_enabled {
        Resources.*.Properties.VersioningConfiguration.Status == "Enabled"
    }"#;

    let location = failed_comparison_location(rules, VERSIONING_TEMPLATE, "Suspended")?;

    assert_eq!(VERSIONING_STATUS_LOCATION, location);
    Ok(())
}

#[test]
fn failed_comparison_with_a_literal_on_the_left_is_located_at_the_input_value() -> Result<()> {
    let rules = r#"let enabled = "Enabled"
    rule versioning_enabled {
        %enabled == Resources.*.Properties.VersioningConfiguration.Status
    }"#;

    let location = failed_comparison_location(rules, VERSIONING_TEMPLATE, "Enabled")?;

    assert_eq!(VERSIONING_STATUS_LOCATION, location);
    Ok(())
}

#[test]
fn failed_comparison_between_input_values_is_located_at_the_left_value_at_the_document_origin(
) -> Result<()> {
    let rules = r#"rule top_level_keys_match_expected {
        this[ keys == Expected ] !empty
    }"#;
    let data = "Wrong: 1\nExpected: Different\n";

    let location = failed_comparison_location(rules, data, "Wrong")?;

    assert_eq!(Location::new(0, 0), location);
    Ok(())
}

#[derive(Debug)]
enum FailedCheck {
    Comparison(ComparisonClauseCheck, Option<ReportProvenance>),
    InComparison(InComparisonCheck, Option<ReportProvenance>),
}

impl FailedCheck {
    fn origin(&self) -> ValueOrigin {
        let provenance = match self {
            FailedCheck::Comparison(_, provenance) | FailedCheck::InComparison(_, provenance) => {
                provenance
            }
        };
        provenance
            .unwrap_or_else(|| panic!("a failed comparison must keep its provenance: {:?}", self))
            .from_origin
    }

    fn left(&self) -> &QueryResult {
        match self {
            FailedCheck::Comparison(check, _) => &check.from,
            FailedCheck::InComparison(check, _) => &check.from,
        }
    }
}

fn collect_failed_checks(
    record: &EventRecord<'_>,
    provenance: &ProvenanceRecord,
    checks: &mut Vec<FailedCheck>,
) {
    assert_eq!(record.children.len(), provenance.children.len());
    for (child, child_provenance) in record.children.iter().zip(&provenance.children) {
        collect_failed_checks(child, child_provenance, checks);
    }
    match &record.container {
        Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(check)))
            if check.status == Status::FAIL =>
        {
            checks.push(FailedCheck::Comparison(
                check.clone(),
                provenance.provenance,
            ))
        }
        Some(RecordType::ClauseValueCheck(ClauseCheck::InComparison(check)))
            if check.status == Status::FAIL =>
        {
            checks.push(FailedCheck::InComparison(
                check.clone(),
                provenance.provenance,
            ))
        }
        _ => {}
    }
}

struct Evaluated {
    checks: Vec<FailedCheck>,
    locations: Vec<Location>,
}

fn evaluate_failures(rules: &str, data: &str) -> Result<Evaluated> {
    let rules_file = RulesFile::try_from(rules)?;
    let root = PathAwareValue::try_from(crate::values::read_from(data)?)?;
    let mut scope = root_scope(&rules_file, Rc::new(root));
    scope.enable_provenance_tracking();
    crate::eval::eval_rules_file(&rules_file, &mut scope, None)?;
    let tracker = scope.reset_recorder();
    let mut checks = vec![];
    collect_failed_checks(
        tracker.final_event.as_ref().unwrap(),
        tracker.final_provenance.as_ref().unwrap(),
        &mut checks,
    );
    let locations = tracker
        .into_file_report()?
        .not_compliant
        .iter()
        .flat_map(ClauseReport::get_message)
        .filter_map(|messages| messages.location)
        .collect();
    Ok(Evaluated { checks, locations })
}

fn single_failure(rules: &str, data: &str) -> Result<(FailedCheck, Location)> {
    let Evaluated {
        mut checks,
        locations,
    } = evaluate_failures(rules, data)?;
    assert_eq!(1, checks.len(), "expected exactly one failed check");
    assert_eq!(1, locations.len(), "expected exactly one reported failure");
    let check = checks.remove(0);
    assert!(
        matches!(check.left(), QueryResult::Resolved(_)),
        "failed checks record their left operand as resolved, as before: {:?}",
        check
    );
    Ok((check, locations[0]))
}

const BUCKET_TEMPLATE: &str = r#"Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: MyBucket
      MaxSize: 1
      Modes: [Disabled, "Off"]
      Status: Suspended
      Tags: [a, b]
"#;

const BUCKET_KEY_LOCATION: Location = Location { line: 1, col: 2 };
const BUCKET_NAME_LOCATION: Location = Location { line: 4, col: 18 };
const MAX_SIZE_LOCATION: Location = Location { line: 5, col: 15 };
const MODES_LOCATION: Location = Location { line: 6, col: 13 };
const STATUS_LOCATION: Location = Location { line: 7, col: 14 };
const FIRST_TAG_LOCATION: Location = Location { line: 8, col: 13 };
const SECOND_TAG_LOCATION: Location = Location { line: 8, col: 16 };

fn assert_located(
    rules: &str,
    expected_origin: ValueOrigin,
    expected_location: Location,
) -> Result<()> {
    let (check, location) = single_failure(rules, BUCKET_TEMPLATE)?;
    assert_eq!(expected_origin, check.origin(), "{:?}", check);
    assert_eq!(expected_location, location, "{:?}", check);
    Ok(())
}

#[test]
fn a_member_of_a_rules_map_is_compared_at_the_input_value() -> Result<()> {
    assert_located(
        r#"let limits = {min: 2}
        rule r { %limits.min <= Resources.Bucket.Properties.MaxSize }"#,
        ValueOrigin::RulesFile,
        MAX_SIZE_LOCATION,
    )
}

#[test]
fn a_member_of_a_filtered_rules_list_is_compared_at_the_input_value() -> Result<()> {
    assert_located(
        r#"let limits = [{min: 2}]
        rule r { %limits[ min > 0 ].min <= Resources.Bucket.Properties.MaxSize }"#,
        ValueOrigin::RulesFile,
        MAX_SIZE_LOCATION,
    )
}

#[test]
fn a_function_of_a_rules_literal_is_compared_at_the_input_value() -> Result<()> {
    assert_located(
        r#"let two = parse_int("2")
        rule r { %two <= Resources.Bucket.Properties.MaxSize }"#,
        ValueOrigin::RulesFile,
        MAX_SIZE_LOCATION,
    )?;
    assert_located(
        r#"let parsed = json_parse('{"min": 2}')
        rule r { %parsed.min <= Resources.Bucket.Properties.MaxSize }"#,
        ValueOrigin::RulesFile,
        MAX_SIZE_LOCATION,
    )
}

#[test]
fn a_function_of_an_input_value_is_located_at_that_value() -> Result<()> {
    assert_located(
        r#"let name = to_lower(Resources.Bucket.Properties.BucketName)
        rule r { %name == "other" }"#,
        ValueOrigin::Input,
        BUCKET_NAME_LOCATION,
    )?;
    assert_located(
        r#"let name = to_upper(to_lower(Resources.Bucket.Properties.BucketName))
        rule r { %name == "OTHER" }"#,
        ValueOrigin::Input,
        BUCKET_NAME_LOCATION,
    )?;
    assert_located(
        r#"let tags = count(Resources.Bucket.Properties.Tags[*])
        rule r { %tags >= 5 }"#,
        ValueOrigin::Input,
        FIRST_TAG_LOCATION,
    )
}

#[test]
fn a_count_of_nothing_is_not_an_input_value() -> Result<()> {
    let Evaluated { checks, .. } = evaluate_failures(
        r#"let none = count(Resources.*[ Type == "AWS::EC2::Volume" ])
        rule r { %none >= 1 }"#,
        BUCKET_TEMPLATE,
    )?;
    let count_check = checks
        .iter()
        .find(|check| matches!(check, FailedCheck::Comparison(c, _) if c.comparison == (CmpOperator::Ge, false)))
        .expect("the count comparison fails");
    assert_eq!(ValueOrigin::RulesFile, count_check.origin());
    Ok(())
}

#[test]
fn a_block_over_a_rules_literal_is_compared_at_the_input_value() -> Result<()> {
    assert_located(
        r#"let limits = {min: 2}
        let max = Resources.Bucket.Properties.MaxSize
        rule r { %limits { min <= %max } }"#,
        ValueOrigin::RulesFile,
        MAX_SIZE_LOCATION,
    )?;
    assert_located(
        r#"let limits = {inner: {min: 2}}
        let max = Resources.Bucket.Properties.MaxSize
        rule r { %limits.inner {
            let min = min
            %min <= %max
        } }"#,
        ValueOrigin::RulesFile,
        MAX_SIZE_LOCATION,
    )
}

#[test]
fn a_block_over_input_values_is_located_at_the_input_value() -> Result<()> {
    assert_located(
        r#"rule r { Resources.Bucket.Properties { MaxSize >= 5 } }"#,
        ValueOrigin::Input,
        MAX_SIZE_LOCATION,
    )?;
    assert_located(
        r#"let two = 2
        AWS::S3::Bucket when Properties.MaxSize < %two { Properties.MaxSize >= 5 }"#,
        ValueOrigin::Input,
        MAX_SIZE_LOCATION,
    )
}

#[test]
fn a_parameterized_rule_argument_keeps_the_origin_of_the_call_site_value() -> Result<()> {
    assert_located(
        r#"rule check(v) { %v <= Resources.Bucket.Properties.MaxSize }
        rule r { check(2) }"#,
        ValueOrigin::RulesFile,
        MAX_SIZE_LOCATION,
    )?;
    assert_located(
        r#"let limits = {min: 2}
        rule check(v) { %v <= Resources.Bucket.Properties.MaxSize }
        rule r { check(%limits.min) }"#,
        ValueOrigin::RulesFile,
        MAX_SIZE_LOCATION,
    )?;
    assert_located(
        r#"rule check(v) { %v >= 5 }
        rule r { check(Resources.Bucket.Properties.MaxSize) }"#,
        ValueOrigin::Input,
        MAX_SIZE_LOCATION,
    )
}

#[test]
fn a_captured_input_key_is_located_at_the_key() -> Result<()> {
    assert_located(
        r#"let buckets = Resources[ name | Type == "AWS::S3::Bucket" ]
        rule r when %buckets !empty { %name == "Other" }"#,
        ValueOrigin::Input,
        BUCKET_KEY_LOCATION,
    )
}

#[test]
fn a_negated_comparison_of_an_input_value_is_located_at_the_input_value() -> Result<()> {
    assert_located(
        r#"rule r { Resources.Bucket.Properties.Status != "Suspended" }"#,
        ValueOrigin::Input,
        STATUS_LOCATION,
    )
}

#[test]
fn membership_of_a_rules_literal_in_an_input_list_is_located_at_the_list() -> Result<()> {
    assert_located(
        r#"let enabled = "Enabled"
        rule r { %enabled IN Resources.Bucket.Properties.Modes }"#,
        ValueOrigin::RulesFile,
        MODES_LOCATION,
    )?;
    assert_located(
        r#"let disabled = "Disabled"
        rule r { %disabled NOT IN Resources.Bucket.Properties.Modes }"#,
        ValueOrigin::RulesFile,
        MODES_LOCATION,
    )?;
    assert_located(
        r#"let wanted = ["Disabled", "On"]
        rule r { %wanted IN Resources.Bucket.Properties.Modes }"#,
        ValueOrigin::RulesFile,
        MODES_LOCATION,
    )?;
    assert_located(
        r#"rule check(v) { %v IN Resources.Bucket.Properties.Modes }
        rule r { check("Enabled") }"#,
        ValueOrigin::RulesFile,
        MODES_LOCATION,
    )
}

#[test]
fn membership_of_a_rules_list_in_an_input_scalar_is_located_at_the_input() -> Result<()> {
    let Evaluated { checks, locations } = evaluate_failures(
        r#"let wanted = ["Enabled", "On"]
        rule r { %wanted IN Resources.Bucket.Properties.Status }"#,
        BUCKET_TEMPLATE,
    )?;
    assert_eq!(2, checks.len(), "{:?}", checks);
    assert!(
        checks
            .iter()
            .all(|check| check.origin() == ValueOrigin::RulesFile),
        "{:?}",
        checks
    );
    assert_eq!(vec![STATUS_LOCATION, STATUS_LOCATION], locations);

    let Evaluated { checks, locations } = evaluate_failures(
        r#"let rejected = ["Suspended", "On"]
        rule r { %rejected NOT IN Resources.Bucket.Properties.Status }"#,
        BUCKET_TEMPLATE,
    )?;
    assert_eq!(1, checks.len(), "{:?}", checks);
    assert_eq!(ValueOrigin::RulesFile, checks[0].origin());
    assert_eq!(vec![STATUS_LOCATION], locations);
    Ok(())
}

#[test]
fn membership_of_an_input_value_is_located_at_the_input_value() -> Result<()> {
    assert_located(
        r#"rule r { Resources.Bucket.Properties.Status IN ["Enabled"] }"#,
        ValueOrigin::Input,
        STATUS_LOCATION,
    )?;
    assert_located(
        r#"rule r { Resources.Bucket.Properties.Status NOT IN ["Suspended"] }"#,
        ValueOrigin::Input,
        STATUS_LOCATION,
    )?;
    assert_located(
        r#"rule r { Resources.Bucket.Properties.Tags IN [["x"]] }"#,
        ValueOrigin::Input,
        Location { line: 8, col: 12 },
    )
}

#[test]
fn a_query_difference_taken_from_the_right_keeps_the_right_origin() -> Result<()> {
    let Evaluated { checks, locations } = evaluate_failures(
        r#"let single = {v: "x"}
        rule r { %single.v == Resources.Bucket.Properties.Tags[*] }"#,
        BUCKET_TEMPLATE,
    )?;

    let differences = checks
        .iter()
        .filter(|check| matches!(check, FailedCheck::InComparison(..)))
        .collect::<Vec<_>>();
    assert_eq!(2, differences.len(), "{:?}", checks);
    for check in differences {
        assert_eq!(ValueOrigin::Input, check.origin(), "{:?}", check);
    }
    assert_eq!(vec![FIRST_TAG_LOCATION, SECOND_TAG_LOCATION], locations);
    Ok(())
}

#[test]
fn a_rules_side_query_difference_is_located_at_the_input_query() -> Result<()> {
    let Evaluated { checks, locations } = evaluate_failures(
        r#"let allowed = {values: ["a", "b", "c"]}
        rule r { Resources.Bucket.Properties.Tags[*] == %allowed.values[*] }"#,
        BUCKET_TEMPLATE,
    )?;

    let differences = checks
        .iter()
        .filter(|check| matches!(check, FailedCheck::InComparison(..)))
        .collect::<Vec<_>>();
    assert_eq!(1, differences.len(), "{:?}", checks);
    assert_eq!(ValueOrigin::RulesFile, differences[0].origin());
    assert_eq!(vec![FIRST_TAG_LOCATION], locations);
    Ok(())
}

#[test]
fn failed_comparison_record_keeps_a_rules_literal_on_the_left_resolved() -> Result<()> {
    let rules = r#"let enabled = "Enabled"
    rule versioning_enabled {
        %enabled == Resources.*.Properties.VersioningConfiguration.Status
    }"#;

    let (check, _) = single_failure(rules, VERSIONING_TEMPLATE)?;

    assert_eq!(ValueOrigin::RulesFile, check.origin());
    Ok(())
}

#[test]
fn failed_comparison_record_marks_an_input_value_on_the_left_as_input() -> Result<()> {
    let rules = r#"rule versioning_enabled {
        Resources.*.Properties.VersioningConfiguration.Status == "Enabled"
    }"#;

    let (check, _) = single_failure(rules, VERSIONING_TEMPLATE)?;

    assert_eq!(ValueOrigin::Input, check.origin());
    Ok(())
}

#[test]
fn an_input_key_at_the_document_origin_is_input() -> Result<()> {
    let rules = r#"rule top_level_keys_match_expected {
        this[ keys == Expected ] !empty
    }"#;
    let Evaluated { checks, .. } = evaluate_failures(rules, "Wrong: 1\nExpected: Different\n")?;

    let wrong = checks
        .iter()
        .find(|check| {
            check
                .left()
                .resolved()
                .is_some_and(|v| v.self_path().1 == Location::new(0, 0))
        })
        .expect("the `Wrong` key is reported");
    assert_eq!(ValueOrigin::Input, wrong.origin());
    Ok(())
}

#[test]
fn provenance_changes_only_the_provenance_aware_report_location() -> Result<()> {
    let literal = Rc::new(PathAwareValue::String((
        Path::new("".to_string(), 0, 0),
        "Enabled".to_string(),
    )));
    let input = Rc::new(PathAwareValue::String((
        Path::new("/Status".to_string(), 5, 16),
        "Suspended".to_string(),
    )));
    let comparison = || {
        RecordType::ClauseValueCheck(ClauseCheck::Comparison(ComparisonClauseCheck {
            comparison: (CmpOperator::Eq, false),
            from: QueryResult::Resolved(Rc::clone(&input)),
            to: Some(QueryResult::Resolved(Rc::clone(&literal))),
            message: None,
            custom_message: None,
            status: Status::FAIL,
        }))
    };
    let membership = || {
        RecordType::ClauseValueCheck(ClauseCheck::InComparison(InComparisonCheck {
            comparison: (CmpOperator::In, false),
            from: QueryResult::Resolved(Rc::clone(&literal)),
            to: vec![QueryResult::Resolved(Rc::clone(&input))],
            message: None,
            custom_message: None,
            status: Status::FAIL,
        }))
    };
    let tracked = |record: RecordType<'static>, provenance: Option<ReportProvenance>| {
        let mut tracker = RecordTracker::with_provenance_tracking(true);
        tracker.start_record("file")?;
        tracker.start_record("rule")?;
        tracker.start_record("clause")?;
        match provenance {
            Some(provenance) => tracker.end_record_with_provenance("clause", record, provenance)?,
            None => tracker.end_record("clause", record)?,
        }
        tracker.end_record(
            "rule",
            RecordType::RuleCheck(NamedStatus {
                name: "rule",
                status: Status::FAIL,
                message: None,
            }),
        )?;
        tracker.end_record(
            "file",
            RecordType::FileCheck(NamedStatus {
                name: "file",
                status: Status::FAIL,
                message: None,
            }),
        )?;
        Ok::<_, Error>(tracker)
    };
    let located = |tracker: RecordTracker<'static>| -> Result<(EventRecord<'static>, Location)> {
        let record = tracker.final_event.clone().unwrap();
        let report = tracker.into_file_report()?;
        let location = report
            .not_compliant
            .iter()
            .flat_map(ClauseReport::get_message)
            .find_map(|messages| messages.location)
            .expect("the failed comparison is reported");
        Ok((record, location))
    };
    let assert_raw_unchanged = |plain: &EventRecord<'_>, with_provenance: &EventRecord<'_>| {
        assert_eq!(plain, with_provenance);
        assert_eq!(
            serde_json::to_value(plain).unwrap(),
            serde_json::to_value(with_provenance).unwrap()
        );
        let container = |record: &EventRecord<'_>| {
            record.children[0].children[0]
                .container
                .as_ref()
                .unwrap()
                .to_string()
        };
        assert_eq!(container(plain), container(with_provenance));
    };

    let plain = tracked(comparison(), None)?;
    let plain_report = simplified_json_from_root(plain.final_event.as_ref().unwrap())?;
    let (plain_record, plain_location) = located(plain)?;
    let (record, location) = located(tracked(
        comparison(),
        Some(ReportProvenance {
            from_origin: ValueOrigin::Input,
            report_location: None,
        }),
    )?)?;
    assert_raw_unchanged(&plain_record, &record);
    assert_eq!(Location::new(0, 0), plain_location);
    assert_eq!(
        Some(plain_location),
        plain_report
            .not_compliant
            .iter()
            .flat_map(ClauseReport::get_message)
            .find_map(|messages| messages.location)
    );
    assert_eq!(Location::new(5, 16), location);

    let (plain_record, plain_location) = located(tracked(membership(), None)?)?;
    let (record, location) = located(tracked(
        membership(),
        Some(ReportProvenance {
            from_origin: ValueOrigin::RulesFile,
            report_location: None,
        }),
    )?)?;
    assert_raw_unchanged(&plain_record, &record);
    assert_eq!(Location::new(0, 0), plain_location);
    assert_eq!(Location::new(5, 16), location);
    Ok(())
}

#[test]
fn provenance_is_not_applied_to_a_record_whose_shape_changed() -> Result<()> {
    let literal = Rc::new(PathAwareValue::String((
        Path::new("".to_string(), 0, 0),
        "Enabled".to_string(),
    )));
    let input = Rc::new(PathAwareValue::String((
        Path::new("/Status".to_string(), 5, 16),
        "Suspended".to_string(),
    )));
    let tracked = || -> Result<RecordTracker<'static>> {
        let mut tracker = RecordTracker::with_provenance_tracking(true);
        tracker.start_record("file")?;
        tracker.start_record("rule")?;
        tracker.start_record("clause")?;
        tracker.end_record_with_provenance(
            "clause",
            RecordType::ClauseValueCheck(ClauseCheck::Comparison(ComparisonClauseCheck {
                comparison: (CmpOperator::Eq, false),
                from: QueryResult::Resolved(Rc::clone(&input)),
                to: Some(QueryResult::Resolved(Rc::clone(&literal))),
                message: None,
                custom_message: None,
                status: Status::FAIL,
            })),
            ReportProvenance {
                from_origin: ValueOrigin::Input,
                report_location: None,
            },
        )?;
        tracker.end_record(
            "rule",
            RecordType::RuleCheck(NamedStatus {
                name: "rule",
                status: Status::FAIL,
                message: None,
            }),
        )?;
        tracker.end_record(
            "file",
            RecordType::FileCheck(NamedStatus {
                name: "file",
                status: Status::FAIL,
                message: None,
            }),
        )?;
        Ok(tracker)
    };
    let located = |tracker: RecordTracker<'static>| -> Result<Location> {
        Ok(tracker
            .into_file_report()?
            .not_compliant
            .iter()
            .flat_map(ClauseReport::get_message)
            .find_map(|messages| messages.location)
            .expect("the failed comparison is reported"))
    };

    assert_eq!(Location::new(5, 16), located(tracked()?)?);

    let mut reshaped = tracked()?;
    let rule = &mut reshaped.final_event.as_mut().unwrap().children[0];
    rule.children.insert(0, EventRecord::default());
    assert_eq!(Location::new(0, 0), located(reshaped)?);

    let mut renamed = tracked()?;
    renamed.final_event.as_mut().unwrap().children[0].children[0].context = "other".to_string();
    assert_eq!(Location::new(0, 0), located(renamed)?);
    Ok(())
}

fn failed_comparison_location_with_input_parameters(
    rules: &str,
    parameters: &str,
    register_parameters: bool,
) -> Result<Location> {
    let rules_file = RulesFile::try_from(rules)?;
    let parameters = PathAwareValue::try_from(crate::values::read_from(parameters)?)?;
    let template = PathAwareValue::try_from(crate::values::read_from(VERSIONING_TEMPLATE)?)?;
    let root = parameters.clone().merge(template)?;
    let mut scope = root_scope(&rules_file, Rc::new(root));
    scope.enable_provenance_tracking();
    if register_parameters {
        scope.register_input_parameters(&parameters);
    }
    crate::eval::eval_rules_file(&rules_file, &mut scope, None)?;
    let report = scope.reset_recorder().into_file_report()?;

    let messages = report
        .not_compliant
        .iter()
        .flat_map(ClauseReport::get_message)
        .collect::<Vec<_>>();
    assert_eq!(1, messages.len(), "{:?}", messages);
    Ok(messages[0]
        .location
        .expect("a failed comparison must carry a location"))
}

#[test]
fn failed_comparison_with_an_input_parameter_is_located_at_the_template_value() -> Result<()> {
    let parameters = "\n\n\n\n\n\n\n\nExpectedStatus: Enabled\n";
    let parameter_location = Location::new(8, 16);
    let cases = [
        r#"rule parameter_on_the_right {
            Resources.*.Properties.VersioningConfiguration.Status == ExpectedStatus
        }"#,
        r#"rule parameter_on_the_left {
            ExpectedStatus == Resources.*.Properties.VersioningConfiguration.Status
        }"#,
        r#"rule parameter_in_template_value {
            ExpectedStatus IN Resources.*.Properties.VersioningConfiguration.Status
        }"#,
    ];

    for rules in cases {
        assert_eq!(
            VERSIONING_STATUS_LOCATION,
            failed_comparison_location_with_input_parameters(rules, parameters, true)?,
            "{}",
            rules
        );
    }
    assert_eq!(
        parameter_location,
        failed_comparison_location_with_input_parameters(cases[0], parameters, false)?,
        "without registered parameters the merged root is all input"
    );
    Ok(())
}

#[test]
fn failed_comparison_with_only_rules_and_parameter_operands_has_no_data_file_location() -> Result<()>
{
    let parameters =
        "\n\n\n\n\n\n\n\nExpectedStatus: Enabled\nCurrentStatus: Suspended\nAllowedStatuses: [Enabled]\n";
    let cases = [
        r#"rule parameter_only_scalar {
            CurrentStatus == ExpectedStatus
        }"#,
        r#"rule parameter_only_membership {
            CurrentStatus IN AllowedStatuses
        }"#,
        r#"rule parameter_versus_rules_literal {
            CurrentStatus == "Enabled"
        }"#,
        r#"let suspended = "Suspended"
        rule rules_literal_versus_parameter {
            %suspended == ExpectedStatus
        }"#,
        r#"rule parameter_in_rules_literal {
            CurrentStatus IN ["Enabled"]
        }"#,
        r#"let suspended = "Suspended"
        rule rules_literal_in_parameter {
            %suspended IN AllowedStatuses
        }"#,
    ];

    for rules in cases {
        assert_eq!(
            Location::default(),
            failed_comparison_location_with_input_parameters(rules, parameters, true)?,
            "{}",
            rules
        );
    }
    Ok(())
}

#[test]
fn evaluation_without_provenance_tracking_records_no_provenance() -> Result<()> {
    let rules = r#"let enabled = "Enabled"
    rule versioning_enabled {
        %enabled == Resources.*.Properties.VersioningConfiguration.Status
        %enabled IN Resources.*.Properties.VersioningConfiguration.Status
    }"#;
    let rules_file = RulesFile::try_from(rules)?;
    let root = PathAwareValue::try_from(crate::values::read_from(VERSIONING_TEMPLATE)?)?;
    let mut scope = root_scope(&rules_file, Rc::new(root));
    crate::eval::eval_rules_file(&rules_file, &mut scope, None)?;

    assert!(scope.value_origins.is_none());
    let tracker = scope.reset_recorder();
    assert!(!tracker.track_provenance);
    assert!(tracker.provenance.is_empty());
    assert!(tracker.final_provenance.is_none());

    let baseline = simplified_json_from_root(tracker.final_event.as_ref().unwrap())?;
    assert_eq!(
        serde_json::to_value(&baseline).unwrap(),
        serde_json::to_value(&tracker.into_file_report()?).unwrap()
    );
    Ok(())
}

#[test]
fn failed_in_comparison_with_a_scalar_literal_on_the_left_is_located_at_the_input_value(
) -> Result<()> {
    let rules = r#"let enabled = "Enab"
    rule versioning_enabled {
        %enabled IN Resources.*.Properties.VersioningConfiguration.Status
    }"#;

    let (check, location) = single_failure(rules, VERSIONING_TEMPLATE)?;

    assert_eq!(VERSIONING_STATUS_LOCATION, location);
    assert_eq!(ValueOrigin::RulesFile, check.origin());
    Ok(())
}

#[test]
fn not_comparable_in_comparison_with_a_list_literal_on_the_left_is_located_at_the_input_value(
) -> Result<()> {
    let rules = r#"let allowed = ["Enabled"]
    rule versioning_allowed {
        %allowed IN Resources.*.Properties.VersioningConfiguration.Status
    }"#;
    let data = r#"Resources:
  ListedBucket:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: [Enabled]
  LogsBucket:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: Suspended
"#;

    let (check, location) = single_failure(rules, data)?;

    assert_eq!(ValueOrigin::RulesFile, check.origin());
    assert!(
        matches!(&check, FailedCheck::Comparison(c, _) if c.message.is_some()),
        "expected a not-comparable record"
    );
    assert_eq!(Location::new(10, 16), location);
    Ok(())
}

const MIXED_CAPTURE_DATA: &str = r#"Inputs:
  InputOnly:
    Type: Selected
Different:
  - Other
Allowed:
  - InputOnly
  - RuleOnly
"#;

const INPUT_ONLY_KEY_LOCATION: Location = Location { line: 1, col: 2 };

#[test]
fn a_capture_name_reused_across_rules_and_input_maps_keeps_each_value_origin() -> Result<()> {
    let expectations = [
        ("==", "Different[*]", Location::new(4, 4)),
        ("!=", "Allowed[*]", Location::new(6, 4)),
        ("IN", "Different[*]", Location::new(4, 4)),
        ("NOT IN", "Allowed[*]", Location::new(6, 4)),
    ];
    for (operator, compared_with, compared_location) in expectations {
        let rules = format!(
            r#"let rules_root = {{"Container": {{"RuleOnly": {{"Type": "Selected"}}}}}}
            rule mixed {{
                %rules_root {{ Container[ captured | Type == "Selected" ] !empty }}
                Inputs[ captured | Type == "Selected" ] !empty
                %captured {} {}
            }}"#,
            operator, compared_with
        );
        let Evaluated { checks, locations } = evaluate_failures(&rules, MIXED_CAPTURE_DATA)?;

        let origin_of = |key: &str| {
            checks
                .iter()
                .find(|check| {
                    check.left().resolved().is_some_and(
                        |value| matches!(&*value, PathAwareValue::String((_, s)) if s == key),
                    )
                })
                .unwrap_or_else(|| panic!("{}: no failure for {} in {:?}", operator, key, checks))
                .origin()
        };
        assert_eq!(ValueOrigin::Input, origin_of("InputOnly"), "{}", operator);
        assert_eq!(
            ValueOrigin::RulesFile,
            origin_of("RuleOnly"),
            "{}",
            operator
        );
        assert_eq!(
            vec![compared_location, INPUT_ONLY_KEY_LOCATION],
            locations,
            "{}",
            operator
        );
    }
    Ok(())
}

#[test]
fn an_element_wise_function_over_mixed_captures_keeps_each_value_origin() -> Result<()> {
    let rules = r#"let rules_root = {"Container": {"RuleOnly": {"Type": "Selected"}}}
    rule mixed {
        %rules_root { Container[ captured | Type == "Selected" ] !empty }
        Inputs[ captured | Type == "Selected" ] !empty
        let lowered = to_lower(%captured)
        %lowered == Different[*]
    }"#;
    let Evaluated { checks, locations } = evaluate_failures(rules, MIXED_CAPTURE_DATA)?;

    let origin_of = |key: &str| {
        checks
            .iter()
            .find(|check| {
                check.left().resolved().is_some_and(
                    |value| matches!(&*value, PathAwareValue::String((_, s)) if s == key),
                )
            })
            .unwrap_or_else(|| panic!("no failure for {} in {:?}", key, checks))
            .origin()
    };
    assert_eq!(ValueOrigin::Input, origin_of("inputonly"));
    assert_eq!(ValueOrigin::RulesFile, origin_of("ruleonly"));
    assert_eq!(
        vec![Location::new(4, 4), INPUT_ONLY_KEY_LOCATION],
        locations
    );
    Ok(())
}
