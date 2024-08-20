use super::*;
use crate::rules::exprs::*;
use crate::rules::path_value::*;
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
pub(crate) struct BasicQueryTesting<'record, 'value> {
    pub(crate) root: Rc<PathAwareValue>,
    pub(crate) recorder: Option<&'record mut dyn RecordTracer<'value>>,
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
    fn rule_status(&mut self, _: &str) -> Result<Status> {
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

    let res = try_handle_function_call(FunctionName::RegexReplace, &args)?;
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
    let res = try_handle_function_call(FunctionName::RegexReplace, &args);
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
    let res = try_handle_function_call(FunctionName::RegexReplace, &args);
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
    let res = try_handle_function_call(FunctionName::RegexReplace, &args)?;
    assert_eq!(res.len(), 1);
    assert!(res[0].is_none());

    let from_query = PathAwareValue::Int((path.clone(), 0));
    let from = QueryResult::Literal(Rc::new(from_query));

    let to_query = PathAwareValue::Int((path.clone(), 3));
    let to = QueryResult::Literal(Rc::new(to_query));

    // substring - happy path
    let args = vec![query_results.clone(), vec![from.clone()], vec![to.clone()]];
    let res = try_handle_function_call(FunctionName::Substring, &args)?;

    let path_value = res[0].as_ref().unwrap();
    if let PathAwareValue::String((_, val)) = path_value {
        assert_eq!("arn", val);
    }

    // first argument is not a string type so res is an Ok(None)
    let not_a_string = AccessQuery::try_from("resources.ec2.properties.tags")?.query;
    let query_results2 = eval.query(&not_a_string)?;
    let args = vec![query_results2, vec![from.clone()], vec![to.clone()]];
    let res = try_handle_function_call(FunctionName::Substring, &args)?;
    assert_eq!(res.len(), 1);
    assert!(res[0].is_none());

    // second argument is not a number
    let args = vec![query_results.clone(), vec![extracted.clone()], vec![to]];
    let res = try_handle_function_call(FunctionName::Substring, &args);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(err, Error::ParseError(_)));
    assert_eq!(
        err.to_string(),
        String::from("Parser Error when parsing `substring function requires the second argument to be a number`")
    );

    // third argument is not a number
    let args = vec![query_results.clone(), vec![from.clone()], vec![extracted]];
    let res = try_handle_function_call(FunctionName::Substring, &args);
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
    let res = try_handle_function_call(FunctionName::Join, &args)?;
    let path_value = res[0].as_ref().unwrap();
    if let PathAwareValue::String((_, val)) = path_value {
        assert_eq!(
            "arn:aws:newservice:us-west-2:123456789012:Table/extracted,ami-123456789012",
            val
        );
    }

    let args = vec![image_id_result.clone(), vec![string_delim]];
    let res = try_handle_function_call(FunctionName::Join, &args)?;
    let path_value = res[0].as_ref().unwrap();
    if let PathAwareValue::String((_, val)) = path_value {
        assert_eq!(
            "arn:aws:newservice:us-west-2:123456789012:Table/extracted,ami-123456789012",
            val
        );
    }

    let args = vec![image_id_result, vec![from]];
    let res = try_handle_function_call(FunctionName::Join, &args);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(err, Error::ParseError(_)));
    assert_eq!(err.to_string(), "Parser Error when parsing `join function requires the second argument to be either a char or string`", );

    Ok(())
}
