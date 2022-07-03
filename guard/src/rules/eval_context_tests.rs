use super::*;
use crate::rules::path_value::*;
use crate::rules::exprs::*;
use std::convert::TryFrom;

#[test]
fn extraction_test() -> Result<()> {
    let rules_files = r###"
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
    "###;

    let rules = RulesFile::try_from(rules_files)?;
    let path_value = PathAwareValue::try_from("{}")?;
    let root_scope = root_scope(&rules, &path_value)?;
    assert_eq!(rules.guard_rules.len(), 1);
    assert_eq!(root_scope.rules.len(), 1);
    assert_eq!(root_scope.rules.get("aws_route53_recordset").map(|s| s.get(0))
                   .map(|s| match s { Some(r) => Some(*r), None => None })
                   .flatten(), rules.guard_rules.get(0));

    Ok(())
}

//
// Query Testing without Filtering
//
pub(crate) struct BasicQueryTesting<'record, 'value> {
    pub(crate) root: &'value PathAwareValue,
    pub(crate) recorder: Option<&'record mut dyn RecordTracer<'value>>,
}

impl<'record, 'value, 'loc: 'value> EvalContext<'value, 'loc> for BasicQueryTesting<'record, 'value> {
    fn query(&mut self, query: &'value [QueryPart<'_>]) -> Result<Vec<QueryResult<'value>>> {
        query_retrieval(0, query, self.root, self)
    }

    fn find_parameterized_rule(&mut self, rule_name: &str) -> Result<&'value ParameterizedRule<'loc>> {
        todo!()
    }

    fn root(&mut self) -> &'value PathAwareValue { self.root }
    fn rule_status(&mut self, rule_name: &str) -> Result<Status> { todo!() }
    fn resolve_variable(&mut self, variable_name: &str) -> Result<Vec<QueryResult<'value>>> { todo!() }
    fn add_variable_capture_key(&mut self, variable_name: &'value str, key: &'value PathAwareValue) -> Result<()> {
        todo!()
    }
}

impl<'record, 'value, 'loc: 'value> RecordTracer<'value> for BasicQueryTesting<'record, 'value> {
    fn start_record(&mut self, context: &str) -> Result<()> {
        self.recorder.as_mut().map_or(
            Ok(()),
            |r| (*r).start_record(context)
        )
    }
    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.recorder.as_mut().map_or(
            Ok(()),
            |r| (*r).end_record(context, record))
    }
}

#[test]
fn no_query_return_root() -> Result<()> {
    let path_value = PathAwareValue::try_from("{}")?;
    let mut eval = BasicQueryTesting { root: &path_value, recorder: None };
    let query_results = eval.query(&[])?;
    assert_eq!(query_results.is_empty(), false);
    assert_eq!(query_results.len(), 1);
    let path_ref = match query_results[0] {
        QueryResult::Resolved(r) => r,
        _ => unreachable!()
    };
    assert_eq!(std::ptr::eq(&path_value, path_ref), true);
    Ok(())
}

#[test]
fn empty_value_return_unresolved() -> Result<()> {
    let path_value = PathAwareValue::try_from("{}")?;
    let mut eval = BasicQueryTesting { root: &path_value, recorder: None };
    let query = AccessQuery::try_from("Resources.*")?.query;
    let query_results = eval.query(&query)?;
    assert_eq!(query_results.is_empty(), false);
    assert_eq!(query_results.len(), 1);
    let path_ref = match &query_results[0] {
        QueryResult::UnResolved(ur) => ur.traversed_to,
        _ => unreachable!()
    };
    assert_eq!(std::ptr::eq(&path_value, path_ref), true);
    Ok(())
}

#[test]
fn non_empty_value_return_results() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
        Resources:
           s3:
             Type: AWS::S3::Bucket
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
        "#)?
    )?;
    let mut eval = BasicQueryTesting { root: &path_value, recorder: None };
    let query = AccessQuery::try_from("Resources.*")?.query;
    let query_results = eval.query(&query)?;
    assert_eq!(query_results.is_empty(), false);
    assert_eq!(query_results.len(), 2); // 2 resources
    for each in query_results {
        assert_eq!(matches!(each, QueryResult::Resolved(_)), true);
    }

    let paths = [
        Path::try_from("/Resources/s3")?,
        Path::try_from("/Resources/ec2/Properties")?
    ];
    let query = AccessQuery::try_from("Resources.*.Properties.Tags")?.query;
    let query_results = eval.query(&query)?;
    assert_eq!(query_results.is_empty(), false);
    assert_eq!(query_results.len(), 2); // 2 resources
    for each in query_results {
        match each {
            QueryResult::UnResolved(ur) => {
                let path = ur.traversed_to.self_path();
                println!("{}", path);
                assert_eq!(paths.contains(path), true);
            },

            _ => unreachable!()
        }
    }

    Ok(())
}

#[test]
fn non_empty_value_mixed_results() -> Result<()> {
    let query = AccessQuery::try_from("Resources.*.Properties.Tags")?.query;
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
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
        "#)?
    )?;
    let mut eval = BasicQueryTesting { root: &path_value, recorder: None };
    let query_results = eval.query(&query)?;
    assert_eq!(query_results.is_empty(), false);
    assert_eq!(query_results.len(), 2); // 2 resources
    for each in query_results {
        match each {
            QueryResult::Literal(_) => unreachable!(),
            QueryResult::Resolved(res) => {
                assert_eq!(res.self_path().0.as_str(), "/Resources/s3/Properties/Tags");
                assert_eq!(res.is_list(), true);
            },

            QueryResult::UnResolved(ur) => {
                assert_eq!(ur.traversed_to.self_path().0.as_str(), "/Resources/ec2/Properties");
            }
        }
    }

    Ok(())
}

#[test]
fn non_empty_value_with_missing_list_property() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
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
        "#)?
    )?;
    let mut eval = BasicQueryTesting { root: &path_value, recorder: None };
    let query = AccessQuery::try_from("Resources.*.Properties.Tags[*].Value")?.query;
    let query_results = eval.query(&query)?;
    assert_eq!(query_results.is_empty(), false);
    assert_eq!(query_results.len(), 2); // 2 resources
    for each in query_results {
        match each {
            QueryResult::Literal(_) => unreachable!(),
            QueryResult::Resolved(res) => {
                assert_eq!(res.self_path().0.as_str(), "/Resources/s3/Properties/Tags/0/Value");
                assert_eq!(res.is_scalar(), true);
            },

            QueryResult::UnResolved(ur) => {
                assert_eq!(ur.traversed_to.self_path().0.as_str(), "/Resources/ec2/Properties");
            }
        }
    }

    Ok(())
}

#[test]
fn non_empty_value_with_empty_list_property() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
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
        "#)?
    )?;
    let mut eval = BasicQueryTesting { root: &path_value, recorder: None };
    let query = AccessQuery::try_from("Resources.*.Properties.Tags[*].Value")?.query;
    let query_results = eval.query(&query)?;
    assert_eq!(query_results.is_empty(), false);
    assert_eq!(query_results.len(), 2); // 2 resources
    for each in query_results {
        match each {
            QueryResult::Literal(_) => unreachable!(),
            QueryResult::Resolved(res) => {
                assert_eq!(res.self_path().0.as_str(), "/Resources/s3/Properties/Tags/0/Value");
                assert_eq!(res.is_scalar(), true);
            },

            QueryResult::UnResolved(ur) => {
                assert_eq!(ur.traversed_to.self_path().0.as_str(), "/Resources/ec2/Properties/Tags");
            }
        }
    }

    Ok(())
}

#[test]
fn map_filter_keys() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
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
        "#)?
    )?;
    let mut eval = BasicQueryTesting { root: &path_value, recorder: None };
    let query = AccessQuery::try_from("Resources[ keys == /s3/ ]")?.query;
    let query_results = eval.query(&query)?;
    assert_eq!(query_results.is_empty(), false);
    assert_eq!(query_results.len(), 1); // 2 resources
    for each in query_results {
        match each {
            QueryResult::Resolved(res) => {
                assert_eq!(res.self_path().0.as_str(), "/Resources/s3Bucket");
                assert_eq!(res.is_map(), true);
            },

            _ => unreachable!()
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
                assert_eq!(path == "/Resources/s3Bucket" || path == "/Resources/ec2", true);
                assert_eq!(res.is_map(), true);
            },

            _ => unreachable!()
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
                assert_eq!(path == "/Resources/s3Bucket", true);
                assert_eq!(res.is_map(), true);
            },

            _ => unreachable!()
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
                assert_eq!(path == "/Resources/s3Bucket", true);
                assert_eq!(res.is_map(), true);
            },

            _ => unreachable!()
        }
    }

    Ok(())
}

#[test]
fn test_with_converter() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
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
        "#)?
    )?;
    let mut eval = BasicQueryTesting { root: &path_value, recorder: None };
    let query = AccessQuery::try_from("resources.*.properties.tags[*].value")?.query;
    let query_results = eval.query(&query)?;
    assert_eq!(query_results.is_empty(), false);
    assert_eq!(query_results.len(), 2); // 2 resources
    for each in query_results {
        match each {
            QueryResult::Literal(_) => unreachable!(),
            QueryResult::Resolved(res) => {
                assert_eq!(res.self_path().0.as_str(), "/Resources/s3/Properties/Tags/0/Value");
                assert_eq!(res.is_scalar(), true);
            },

            QueryResult::UnResolved(ur) => {
                assert_eq!(ur.traversed_to.self_path().0.as_str(), "/Resources/ec2/Properties/Tags");
            }
        }
    }

    Ok(())
}