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
    /// Nothing is recorded here, so nothing has been.
    fn has_deprecation_site(&mut self, _: DeprecationKind, _: &FileLocation<'_>) -> bool {
        false
    }

    fn has_quiet_filter_site(&mut self, _: DeprecationKind, _: &FileLocation<'_>, _: &str) -> bool {
        false
    }

    fn has_quiet_record_at(&mut self, _: DeprecationKind, _: &FileLocation<'_>) -> bool {
        false
    }

    fn record_quiet_filter_site(&mut self, _: DeprecationKind, _: &FileLocation<'_>, _: &str) {}

    /// This double binds nothing.
    fn variable_binding_source(&mut self, _: &str) -> Option<BindingSource<'value, 'loc>> {
        None
    }

    /// This double binds nothing: no chain can be read through it.
    fn quiet_record_key_step(
        &mut self,
        _: &str,
        _: usize,
    ) -> crate::rules::eval_context::QuietRecordKey {
        crate::rules::eval_context::QuietRecordKey::PathByFallback
    }

    /// This double's root is the value under test, read as a document.
    fn root_quiet_record_key(&mut self, _: usize) -> crate::rules::eval_context::QuietRecordKey {
        crate::rules::eval_context::QuietRecordKey::Path
    }

    fn query(&mut self, query: &'value [QueryPart<'_>]) -> Result<Vec<QueryResult>> {
        query_retrieval(0, query, self.root(), self, QueryStart::Document, false)
    }

    fn find_parameterized_rule(&mut self, _: &str) -> Result<&'value ParameterizedRule<'loc>> {
        todo!()
    }

    fn root(&mut self) -> Rc<PathAwareValue> {
        Rc::clone(&self.root)
    }

    fn document_root(&mut self) -> Rc<PathAwareValue> {
        Rc::clone(&self.root)
    }
    fn query_start(&self) -> QueryStart {
        QueryStart::Document
    }
    fn in_predicate(&self) -> bool {
        false
    }
    fn empty_selection(&self) -> Option<Rc<EmptySelection>> {
        None
    }
    fn reads_beside_the_map(&self) -> bool {
        true
    }
    fn fallback_root(&mut self) -> Rc<PathAwareValue> {
        self.root()
    }
    fn is_top_level_alias(&self, _: &str, _: MergedKeys) -> bool {
        false
    }
    fn rule_status(&mut self, _: &str, _: crate::rules::eval::ClauseRole) -> Result<Status> {
        todo!()
    }
    fn resolve_variable(&mut self, _: &str) -> Result<Vec<QueryResult>> {
        todo!()
    }
    /// This double binds no variables, so no name holds a literal or a capture.
    fn literal_binding(&self, _: &str) -> Option<Vec<Rc<PathAwareValue>>> {
        None
    }
    /// `todo!()` rather than `None`, to match `resolve_variable` above. This double binds no variables,
    /// so a query that reaches either has already left what it can answer; returning `None` here would
    /// let such a query be judged as unprojected instead of failing loudly.
    fn variable_binding_query(
        &mut self,
        _: &str,
        _: MergedKeys,
    ) -> Option<&'value AccessQuery<'loc>> {
        todo!()
    }
    fn variable_shape(&mut self, _: &str, _: MergedKeys) -> (RhsEnumeration, PassedOn) {
        todo!()
    }
    fn variable_lists_keys(&self, _: &str, _: MergedKeys) -> bool {
        todo!()
    }
    fn query_with_shape(
        &mut self,
        query: &'value [QueryPart<'loc>],
    ) -> Result<(Vec<QueryResult>, RhsEnumeration, PassedOn)> {
        query_retrieval_shaped(query, self.root(), self, QueryStart::Document, false)
    }
    /// The same reasoning as `variable_binding_query`: this double binds no projection to ask about.
    fn projection_member_keys(
        &mut self,
        _: &str,
        _: MergedKeys,
    ) -> Result<Option<Rc<ProjectionKeys>>> {
        todo!()
    }
    fn add_variable_capture(&mut self, _: &'value str, _: QueryResult) -> Result<()> {
        todo!()
    }
    fn variable_capture_len(&self, _: &str) -> usize {
        0
    }
    fn truncate_variable_capture(&mut self, _: &'value str, _: usize) -> Result<()> {
        todo!()
    }
    /// Keeps no captures, so an enumeration's per-entry frame has nothing to scope here; a no-op rather
    /// than `todo!()` because every `[*]` and `.*` a query test walks opens one.
    fn open_capture_frame(&mut self) {}
    fn begin_capture_entry(&mut self) {}
    fn end_capture_entry(&mut self) {}
    fn end_capture_entry_detached(&mut self) -> EntryCaptures<'value> {
        EntryCaptures::default()
    }
    fn refile_captures(&mut self, _captures: EntryCaptures<'value>) {}
    fn close_capture_frame(&mut self) {}
    fn add_variable_capture_key_below_the_entry(
        &mut self,
        name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.add_variable_capture_key(name, key)
    }
    /// Binds no captures and collects no notices, so the capture and notice methods answer as the
    /// trait's former defaults did: nothing to forget, no capture under any name, the nested-block
    /// reading is `resolve_variable`'s, a merged key is a captured key, an index capture is dropped.
    /// Said here rather than inherited, so that this double is one of the implementors the compiler
    /// lists when a method is added.
    fn reset_captures(&mut self) {}
    fn binding_is_a_capture(&mut self, _: &str, _: MergedKeys) -> bool {
        false
    }
    fn resolve_variable_from_nested_block(
        &mut self,
        name: &'value str,
        _: UnboundName,
    ) -> Result<Vec<QueryResult>> {
        self.resolve_variable(name)
    }
    fn add_merged_capture(&mut self, name: &'value str, result: QueryResult) -> Result<()> {
        self.add_variable_capture(name, result)
    }
    fn add_variable_capture_index(&mut self, _: &str, _: Rc<PathAwareValue>) -> Result<()> {
        Ok(())
    }
    fn record_deprecation(&mut self, _: String) {}
    /// Notices are dropped and no measurement is ever on: this double is handed to `resolve_function`
    /// by tests that read its values, not its notices, and `BlockScope::lookup` asks its parent whether
    /// a measurement is on before it memoizes.
    fn record_deprecation_once(
        &mut self,
        _: DeprecationKind,
        _: &FileLocation<'_>,
        _: String,
    ) -> bool {
        false
    }
    /// A cache of its own per ask: this double evaluates no `[*]` filter twice.
    fn predicate_regexes(
        &self,
        _: &FileLocation<'_>,
    ) -> Rc<crate::rules::eval_context::CompiledRegexes> {
        Rc::default()
    }
    fn set_measurement(&mut self, _: Measurement) {}
    fn measurement(&self) -> Measurement {
        Measurement::Off
    }
    /// No notice is ever recorded through this double, so no `when` is ever settled.
    fn when_is_settled(
        &self,
        _: &FileLocation<'loc>,
        _: MoveDirection,
        _: Option<&BTreeSet<BindingId<'value>>>,
    ) -> bool {
        false
    }
    fn when_has_settled_measurements(&self, _: &FileLocation<'loc>, _: MoveDirection) -> bool {
        false
    }
    fn settle_when(
        &mut self,
        _: &FileLocation<'loc>,
        _: MoveDirection,
        _: Option<BTreeSet<BindingId<'value>>>,
    ) {
    }
    fn binding_owners(&self, _: &str) -> Option<BTreeSet<BindingId<'value>>> {
        None
    }
    /// No root behind this double, so no memo: a probe under it keeps its per-enumeration cache alone.
    fn document_binding_memo(
        &self,
    ) -> Option<Rc<std::cell::RefCell<super::DocumentBindingMemo<'value>>>> {
        None
    }
    fn resolving_a_binding(&self) -> bool {
        false
    }
    fn within_parameterized_call(&self) -> bool {
        false
    }
    /// Binds no variables, so nothing here is on a chain to a function's result.
    fn function_chain(&mut self, _: &str) -> Option<FunctionChain<'value>> {
        None
    }
    fn function_result_entries(&mut self, _: &str) -> Option<Result<Rc<FunctionEntries>>> {
        None
    }
    fn record_warning(&mut self, _: &FileLocation<'_>, _: &str, _: &str, _: String) {}
    fn record_capture_warning(&mut self, _: &FileLocation<'_>, _: &str, _: String) {}
    fn record_unraised_refusal(
        &mut self,
        _: &FileLocation<'_>,
        _: &str,
        _: crate::rules::UnraisedVerdict,
        _: &[String],
    ) {
    }
    /// Binds no variables, so nothing here is resolved.
    fn variable_is_resolved(&self, _: &str) -> bool {
        false
    }
    fn data_file_name(&self) -> Option<&'value str> {
        None
    }
    fn case_label(&self) -> Option<&str> {
        None
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

/// A query names one property. Answering it with a differently-named one is a wrong answer, not a
/// lenient one, and the report says so: the resolved path is the property the data has, so
/// `Properties.Tags.Name` against `Properties.Tag.Name` produced a ComparisonError over
/// `/Resources/s3/Properties/Tag/Name` and compared a value the rule never asked about.
#[test]
fn a_query_for_a_plural_property_does_not_resolve_to_a_singular_one() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
           s3:
             Type: AWS::S3::Bucket
             Properties:
               Tag:
                 Name: mybucket
        "#,
    )?)?;
    let root = Rc::new(path_value);

    for query in [
        "Resources.s3.Properties.Tags.Name",
        "Resources.s3.Properties.Policies.Name",
    ] {
        let parsed = AccessQuery::try_from(query)?.query;
        let mut eval = BasicQueryTesting {
            root: Rc::clone(&root),
            recorder: None,
        };
        let query_results = eval.query(&parsed)?;
        assert_eq!(query_results.len(), 1);
        match &query_results[0] {
            QueryResult::UnResolved(ur) => assert_eq!(
                ur.traversed_to.self_path().0.as_str(),
                "/Resources/s3/Properties"
            ),
            QueryResult::Resolved(res) => panic!(
                "{query} resolved to {}, a property it did not name",
                res.self_path().0.as_str()
            ),
            QueryResult::Literal(_) => unreachable!(),
        }
    }

    Ok(())
}

/// The leniency that is meant to be there: one property spelled in another case convention is the
/// same property, so a query may name it in any of them.
///
/// Here to keep the fix above from being read as "switch the leniency off". `resources` and
/// `bucket_encryption` reach `Resources` and `BucketEncryption` through `to_pascal_case`, and the
/// lowercase `value`/`key` pair is the form AWS registry rules rely on.
#[test]
fn case_convention_leniency_still_resolves_the_same_property() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
           s3:
             Type: AWS::S3::Bucket
             Properties:
               BucketEncryption:
                 Enabled: true
               Tags:
                 - Key: Name
                   Value: mybucket
        "#,
    )?)?;
    let root = Rc::new(path_value);

    for (query, expected_path) in [
        (
            "resources.s3.properties.bucket_encryption.enabled",
            "/Resources/s3/Properties/BucketEncryption/Enabled",
        ),
        (
            "resources.s3.properties.tags[0].value",
            "/Resources/s3/Properties/Tags/0/Value",
        ),
        (
            "resources.s3.properties.tags[0].key",
            "/Resources/s3/Properties/Tags/0/Key",
        ),
    ] {
        let parsed = AccessQuery::try_from(query)?.query;
        let mut eval = BasicQueryTesting {
            root: Rc::clone(&root),
            recorder: None,
        };
        let query_results = eval.query(&parsed)?;
        assert_eq!(query_results.len(), 1);
        match &query_results[0] {
            QueryResult::Resolved(res) => {
                assert_eq!(res.self_path().0.as_str(), expected_path)
            }
            QueryResult::UnResolved(ur) => panic!(
                "{query} did not resolve, stopped at {}",
                ur.traversed_to.self_path().0.as_str()
            ),
            QueryResult::Literal(_) => unreachable!(),
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
    // The offending argument came from the template (a query result), so the clause has no answer on
    // this data and the error is `Unevaluatable`; the literal arguments below stay `IncompatibleError`.
    assert!(matches!(err, Error::Unevaluatable(_)));
    assert_eq!(
        err.to_string(),
        String::from("Clause could not be evaluated against the incoming context `regex_replace function requires the second argument to be a string`")
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
    assert!(matches!(err, Error::Unevaluatable(_)));
    assert_eq!(
        err.to_string(),
        String::from("Clause could not be evaluated against the incoming context `regex_replace function requires the third argument to be a string`")
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
    assert!(matches!(err, Error::IncompatibleError(_)));
    assert_eq!(
        err.to_string(),
        String::from("Types or variable assignments are incompatible `substring function requires the second argument to be a number`")
    );

    // third argument is not a number
    let args = vec![query_results.clone(), vec![from.clone()], vec![extracted]];
    let res = FunctionName::Substring.call(&args);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(err, Error::IncompatibleError(_)));
    assert_eq!(
        err.to_string(),
        String::from("Types or variable assignments are incompatible `substring function requires the third argument to be a number`")
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
    assert!(matches!(err, Error::IncompatibleError(_)));
    assert_eq!(err.to_string(), "Types or variable assignments are incompatible `join function requires the second argument to be either a char or string`", );

    Ok(())
}

/// Two resources under one nesting level, differing in `Type` so a filter can pick one and in `S` so a
/// clause over the picked one can fail on named data.
const NESTED_RESOURCES: &str = r#"
Outer:
  Nested:
    A:
      Type: "AWS::S3::Bucket"
      S: "abc"
    B:
      Type: "AWS::EC2::Instance"
      S: "zzz"
"#;

/// A list of maps. Its members are maps, which is what makes `[*]` over one a documented pass-through
/// and so leaves the *number* of enumerations unobservable here -- only whether the list itself was
/// enumerated shows.
const ITEMS: &str = r#"
Cfg:
  Items:
    - V: 1
    - V: 2
"#;

/// A list of lists, which is the one value shape that makes the *count* of enumerations observable:
/// `IS_LIST` over the two inner lists passes and over the four scalars inside them fails.
const GROUPS: &str = r#"
Cfg:
  Groups:
    - [1, 2]
    - [3, 4]
"#;

fn status_of(rules: &str, template: &str) -> Result<Status> {
    let rules_file = RulesFile::try_from(rules)?;
    let value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(template).unwrap())?;
    let mut scope = root_scope(&rules_file, Rc::new(value));
    crate::rules::eval::eval_rules_file(&rules_file, &mut scope, None)
}

/// A binding whose own right-hand side is rooted at a variable still owes the enumeration its reader
/// asks for.
///
/// `query_projects` answered `true` for every variable-rooted binding, on two artifacts of the query
/// rather than observations about it: `is_variable` is true at index 0, which is the root case rather
/// than the interpolated-key case that counting `is_variable` is for, and `access_query` reserves slot
/// 1 of every such query, which `expansion_at` then reports as an expansion.
///
/// So the reader skipped its own reserved slot and handed the whole `Outer.Nested` map to the filter,
/// which tested `Type` against a map that has no `Type` and selected nothing -- and an assertion over
/// an empty selection is not applicable, so this exited 0 with nothing on either channel where the
/// literal spelling exits 19 naming `/Outer/Nested/B/S`. Both spellings are cases of one test because
/// the defect was that they disagreed.
#[rstest::rstest]
#[case::variable_rooted("let o = Outer\nlet m = %o.Nested\n")]
#[case::literal_rooted("let m = Outer.Nested\n")]
fn a_variable_rooted_binding_still_owes_the_enumeration_its_reader_asks_for(
    #[case] bindings: &str,
) -> Result<()> {
    let rules = format!(
        "{}rule chk {{ %m[ Type == \"AWS::EC2::Instance\" ].S == \"abc\" }}",
        bindings
    );

    assert_eq!(
        status_of(&rules, NESTED_RESOURCES)?,
        Status::FAIL,
        "the filter must pick B out of Nested's entries, whichever way m is bound"
    );

    Ok(())
}

/// The list-valued reading of the same defect, where the wrong answer is a pass rather than a silence.
///
/// `%l[*] IS_LIST` over a list of maps has to enumerate the list and find each entry is not a list.
/// Judging the binding as already enumerated skipped the reader's slot, so the test saw the list itself
/// and passed.
#[rstest::rstest]
#[case::variable_rooted("let c = Cfg\nlet l = %c.Items\n")]
#[case::literal_rooted("let l = Cfg.Items\n")]
fn a_variable_rooted_list_binding_is_still_one_list(#[case] bindings: &str) -> Result<()> {
    let rules = format!("{}rule check {{ %l[*] IS_LIST }}", bindings);

    assert_eq!(
        status_of(&rules, ITEMS)?,
        Status::FAIL,
        "each entry of Items is a struct, so enumerating the list fails on both"
    );

    Ok(())
}

/// A parameterized rule's argument is a binding like any other, so the same question is asked of it.
///
/// `ResolvedParameterContext::variable_binding_query` records the call site's query and reports it
/// correctly; it fed the same `query_projects`, so an argument written `%c.Items` was judged as having
/// enumerated when `Cfg.Items` was not.
#[rstest::rstest]
#[case::variable_rooted(
    "let c = Cfg\nrule inner(p) { %p[*] IS_LIST }\nrule outer { inner(%c.Items) }"
)]
#[case::literal_rooted("rule inner(p) { %p[*] IS_LIST }\nrule outer { inner(Cfg.Items) }")]
fn a_query_argument_rooted_at_a_variable_is_judged_by_what_it_resolved_to(
    #[case] rules: &str,
) -> Result<()> {
    assert_eq!(
        status_of(rules, ITEMS)?,
        Status::FAIL,
        "the argument names one list either way, so inner has to enumerate it"
    );

    Ok(())
}

/// A wildcard the author wrote at a variable root *is* the binding's last act, and must keep counting.
///
/// The over-wide control for the test above: `query_projects`' `2 =>` arm answers `true` for `%g[*]`,
/// and reading that arm as `parts_project_from(query, 2)` -- the obvious reading of "the reserved slot
/// is not evidence" -- makes `let x = %g[*]` unprojected where `let x = Cfg.Groups[*]` is not, so the
/// two spellings of one binding disagree. Both cases are asserted, and only the first can move.
///
/// A reading clause of `%x[*] IS_LIST` asserted PASS cannot separate the two questions it would stand
/// between. `%x[*]` puts the author's own `[*]` at slot 1, so the reader's slot decision is settled by
/// `slot_is_the_authors` before the binding judgment is consulted at all -- and with
/// `binding_enumerated` short-circuiting ahead of that gate, its PASS is the reader skipping the
/// author's wildcard, not the binding's projection being respected. Measured over `GROUPS` with
/// `let x = Cfg.Groups[*]` in that state: `%x[*] IS_LIST` is exit 0 where `%x.*` and `%x[ n ]`, the
/// same enumeration spelled the two ways that do get a reserved slot, are each exit 19 naming all four
/// scalars. `both_wildcards_the_author_wrote_at_a_variable_root_run` below asserts the non-projecting
/// half of that same mechanism.
///
/// So the instrument is one that still observes the binding judgment after the gate is total: a
/// list of maps with a filter after the reserved slot. `[*]` on a map is a pass-through *except* before
/// a filter, where it expands the map into its entries, so consuming the slot keeps each item as the
/// filter's subject and walking it drops to that item's own values, where the predicate cannot apply
/// and selects nothing. That is the `validate/functions/rules/count.guard` mechanism, and it is the
/// only family that separates the two readings without one side being a retrieval error: over `ITEMS`
/// with the `2 =>` arm reading `parts_project_from`, `case_1` goes PASS to FAIL and `case_2` does not
/// move, which is the disagreement this test exists to catch.
#[rstest::rstest]
#[case::variable_rooted("let g = Cfg.Items\nlet x = %g[*]\n")]
#[case::literal_rooted("let x = Cfg.Items[*]\n")]
fn a_wildcard_the_author_wrote_at_a_variable_root_is_the_bindings_last_act(
    #[case] bindings: &str,
) -> Result<()> {
    let rules = format!("{}rule check {{ %x[ V == 1 ] !empty }}", bindings);

    assert_eq!(
        status_of(&rules, ITEMS)?,
        Status::PASS,
        "x holds Items' two entries either way, so the filter tests each entry and selects the one \
         whose V is 1"
    );

    Ok(())
}

/// The reader's slot decision does not consult the binding when the author wrote slot 1 themselves.
///
/// `access_query` retags a bare `[*]` at slot 1 in place rather than inserting in front of it, so
/// there is no reserved slot in these queries to consume and the author's wildcard runs -- whatever
/// the binding did.
///
/// Three spellings of one enumeration over one binding, which is `access_query`'s own grouping: it
/// leaves `[*]` alone and inserts the reserved slot in front of `.*` and `[ name ]`. All three must
/// answer alike, and that needs no oracle outside the tree. Both projection sides are cases, because a
/// repair that reached agreement by breaking the non-projecting side would otherwise pass: with
/// `binding_enumerated` short-circuiting ahead of the gate, the projecting case answered exit 0 PASS on
/// `[*]` against exit 19 on the other two, and the non-projecting case already agreed.
///
/// Every spelling reports rather than aborting on the first, so a change that moves two is not read as
/// moving one.
#[rstest::rstest]
#[case::a_projecting_binding("let x = Cfg.Groups[*]\n")]
#[case::a_projecting_binding_through_a_variable("let g = Cfg.Groups\nlet x = %g[*]\n")]
#[case::a_binding_that_does_not_project("let x = Cfg.Groups\n")]
fn one_enumeration_spelled_three_ways_answers_alike_at_a_variable_root(
    #[case] bindings: &str,
) -> Result<()> {
    let mut answers = Vec::new();
    for spelling in ["[*]", ".*", "[ n ]"] {
        let rules = format!("{}rule check {{ %x{} IS_LIST }}", bindings, spelling);
        answers.push((spelling, status_of(&rules, GROUPS)?));
    }

    let first = answers[0].1;
    let disagreeing: Vec<_> = answers.iter().filter(|(_, s)| *s != first).collect();
    assert!(
        disagreeing.is_empty(),
        "`[*]`, `.*` and `[ n ]` are one enumeration of what x holds, so they cannot disagree: {:?}",
        answers
    );

    Ok(())
}

/// A binding that is nothing but a variable reports that variable's binding.
///
/// `let b = %a` runs no part of its own query, so whether `b` holds members is whatever the answer is
/// for `a`, and no property of `[%a]` says. Answering from the query itself said `true` for
/// `let a = Outer.Nested`, which binds one map, and the reader then filtered that map instead of its
/// entries: exit 0 and silent.
///
/// `RootScope::variable_binding_query` is what follows `%a` here, and it follows it in the scope that
/// wrote the `let` rather than in the scope that reads the answer. Both are the same scope in this
/// file, which is why either placement passes these two cells; the cells that separate them are in
/// `a_let_chain_is_followed_in_the_scope_that_wrote_it` in `eval_tests.rs`, where the reader sits
/// inside a scope that binds `a` to something else.
#[rstest::rstest]
#[case::through_a_variable("let a = Outer.Nested\nlet b = %a\n")]
#[case::directly("let b = Outer.Nested\n")]
fn a_binding_that_is_only_a_variable_reports_that_variables_binding(
    #[case] bindings: &str,
) -> Result<()> {
    let rules = format!(
        "{}rule chk {{ %b[ Type == \"AWS::EC2::Instance\" ].S == \"abc\" }}",
        bindings
    );

    assert_eq!(
        status_of(&rules, NESTED_RESOURCES)?,
        Status::FAIL,
        "b holds the Nested map either way, so the filter picks B out of its entries"
    );

    Ok(())
}

/// And it reports it in the other direction too, which is why following the chain cannot be dropped for
/// a plain `false`.
///
/// `let a = Outer.Nested.*` hands back the two resources, so `let b = %a` does as well and the filter
/// tests each resource -- B, whose `S` is `zzz`. Reading `%b` as unprojected walks the reader's slot
/// instead, expanding each resource into its own property values and applying the filter to strings,
/// which a predicate about keys passes over (`a_scalar_entry` in `wildcard_entry_closure`), so the
/// selection is empty and an assertion that something holds cannot pass.
///
/// The clause asserts what holds so that either reading of the query is distinguishable. Asserting the
/// failing comparison instead does not discriminate: both readings answer FAIL, one on B's `S` and the
/// other on a retrieval error, and the status alone cannot tell them apart.
#[rstest::rstest]
#[case::through_a_variable("let a = Outer.Nested.*\nlet b = %a\n")]
#[case::directly("let b = Outer.Nested.*\n")]
fn a_projecting_binding_reached_through_a_variable_still_projects(
    #[case] bindings: &str,
) -> Result<()> {
    let rules = format!(
        "{}rule chk {{ %b[ Type == \"AWS::EC2::Instance\" ].S == \"zzz\" }}",
        bindings
    );

    assert_eq!(
        status_of(&rules, NESTED_RESOURCES)?,
        Status::PASS,
        "b holds the two resources either way, so the filter picks B and reads its own S"
    );

    Ok(())
}

/// Both wildcards the author wrote at a variable root run.
///
/// `access_query` leaves slot 1 alone when a bare `[*]` already occupies it, so `%g[*][*]` carries two
/// author-written expansions and no reserved slot. Consuming slot 1 anyway ran one of them: `IS_LIST`
/// saw the two inner lists and passed, where `Cfg.Groups[*][*]` reaches the four scalars and fails on
/// each.
///
/// A bare `[*]` at slot 2 is what says slot 1 was not inserted, and only this spelling of two
/// author-written expansions has one. `%g[*].*` and `%g[*][ n ]` parse to the same parts as `%g.*` and
/// `%g[ n ]`, so they are unrepresentable rather than unfixed -- see the arm this pins for why no
/// reading of the parts can tell them apart.
#[rstest::rstest]
#[case::variable_rooted("let g = Cfg.Groups\nrule chk { %g[*][*] IS_LIST }")]
#[case::literal_rooted("rule chk { Cfg.Groups[*][*] IS_LIST }")]
fn both_wildcards_the_author_wrote_at_a_variable_root_run(#[case] rules: &str) -> Result<()> {
    assert_eq!(
        status_of(rules, GROUPS)?,
        Status::FAIL,
        "two wildcards reach the scalars inside Groups' entries, and none of them is a list"
    );

    Ok(())
}

/// And the wildcard the author wrote runs whether or not the binding projected.
///
/// The test above is this same mechanism for a binding that does not project, and it passed throughout:
/// `slot_is_the_authors` gated the collection-addressing side of the reader's disjunction from the
/// start. `binding_enumerated` short-circuited ahead of that gate, so for a binding that *did* project
/// the author's `[*]` was consumed as though it were the reserved slot and the query ran nothing after
/// its root.
///
/// Two bindings hold one identical value, which is what makes the pairs comparable at all: over
/// `Groups: [[1, 2], [3, 4]]`, `Cfg.Groups[0]` and `Cfg.Groups[*]` each leave `[1, 2]` in hand, and
/// `Cfg.Groups[*]` is projecting where `Cfg.Groups[0]` is not, because `part_projects` counts an
/// expansion and not an index. The identity row is asserted rather than assumed: it fails first if the
/// premise stops holding, and without it a repair that changed what either binding *holds* would read as
/// having reached agreement.
///
/// Every pair reports. A per-pair `assert_eq!` stops at the first disagreement and says nothing about
/// the rest, and this arm's failures were spread across three tails.
///
/// The two tails deliberately absent are `%v.Value` and `%v[ keys == /Key/ ]`, which still disagree
/// between these two bindings and do so through a different predicate: `query_projects` does not count a
/// trailing `Index`, so the indexed binding walks the reserved slot where the projecting one consumes
/// it. Measured, the deviant side there is the *indexed* binding -- `%projected.Value` reproduces its
/// literal oracle `Cfg.Groups[*].Value` message for message, and `Cfg.Groups[0].Value` gives that same
/// answer, so `%direct.Value`'s `provided value ["alpha"]` is the one answer no literal spelling gives.
/// Closing it is a change to `part_projects` that moves every `let v = Q[0]` binding, so it is not this
/// test's subject and is named here rather than left for a reader to rediscover.
#[test]
fn an_authored_wildcard_runs_over_a_projecting_and_a_non_projecting_binding_alike() -> Result<()> {
    const BINDINGS: &str = "let direct = Cfg.Groups[0]\nlet projected = Cfg.Groups[*]\n";

    // The premise. Both names must hold the one same list before any pair below means anything.
    for name in ["direct", "projected"] {
        let rules = format!("{}rule ident {{ %{} IS_LIST }}", BINDINGS, name);
        assert_eq!(
            Status::PASS,
            status_of(&rules, GROUPS)?,
            "%{} must hold Groups' first entry, which is a list",
            name
        );
    }

    // Tails whose first written part is the author's own bare `[*]`, so no reserved slot exists in the
    // reading query and the author's wildcard has to run on both sides.
    let tails = ["[*] IS_LIST", "[*][*] IS_LIST", "[*][ this == 1 ] !empty"];

    let mut disagreed = Vec::new();
    for tail in tails {
        let of = |name: &str| -> Result<Status> {
            status_of(
                &format!("{}rule chk {{ %{}{} }}", BINDINGS, name, tail),
                GROUPS,
            )
        };
        let (d, p) = (of("direct")?, of("projected")?);
        if d != p {
            disagreed.push(format!("%v{tail}: direct={d:?}, projected={p:?}"));
        }
    }

    assert!(
        disagreed.is_empty(),
        "{} of {} tails answer differently for two bindings holding one identical list:\n  {}",
        disagreed.len(),
        tails.len(),
        disagreed.join("\n  ")
    );

    Ok(())
}

/// A projecting binding still consumes the reserved slot before a filter.
///
/// The over-wide control for the test above: walking slot 1 unconditionally would expand each already
/// selected bucket into its own property values and test the predicate against those, so nothing is
/// selected and the count is 0. `validate/functions/rules/count.guard` is this shape, and it is the
/// existing test that says the skip has to survive.
#[test]
fn a_projecting_binding_consumes_the_reserved_slot_before_a_filter() -> Result<()> {
    let rules = "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
                 rule blocked_buckets {\n\
                 let blocked = %buckets[ Properties.Blocked == true ]\n\
                 let how_many = count(%blocked)\n\
                 %how_many == 1\n\
                 }";
    let template = r#"
Resources:
  BucketA:
    Type: "AWS::S3::Bucket"
    Properties:
      Blocked: true
  BucketB:
    Type: "AWS::S3::Bucket"
    Properties:
      Blocked: false
"#;

    assert_eq!(
        status_of(rules, template)?,
        Status::PASS,
        "the filter tests each selected bucket, so exactly one of the two is blocked"
    );

    Ok(())
}

const TAGS_BY_KEY: &str = r#"
Cfg:
  KeyList: [A, B]
  Tags:
    A:
      x: 1
      y: 2
    B:
      x: 1
      y: 4
"#;

/// Whatever may follow a literal key may follow an interpolated one, and means the same thing.
///
/// `Cfg.Tags.%k` names the entries of `Tags` that `%k` resolves to, and the part after it is applied
/// to each of those entries exactly as it would be after `Cfg.Tags.A`. The walker accepted a key, a
/// bare `[*]` and an index there and returned `IncompatibleError` for everything else, so `.*`,
/// `[ x == 1 ]` and `[ keys == 'x' ]` after `%k` parsed and then failed every evaluation at exit 19
/// with "variable interpolation is not supported" -- a rules file holding one of them read as a
/// failing template rather than as an unsupported rule, and the message named `query[1]` (`Tags`,
/// a plain key) rather than the part it had refused.
///
/// Each tail is run through both spellings, and both must equal the verdict measured for the literal
/// one; the literal cells are the controls that say the expected column is the language's answer and
/// not this test's. `.x`, `[*]` and `[0].x` are the three the walker always took and must not move.
/// `.* == 1` is here so a FAIL on the merits is still a FAIL: `y` is 2 and 4, and the interpolated
/// spelling has to report that rather than pass through. `[ x == 1 ]` after the key is a filter over
/// one map that names the map's own key and selects nothing, which is refused after a literal key
/// (`eval_tests::a_key_filter_over_a_member_whose_key_the_predicate_names_but_selects_nothing_is_refused`),
/// so it FAILs, and the interpolated spelling has to be refused the same way.
#[test]
fn a_part_after_an_interpolated_key_means_what_it_means_after_a_literal_one() -> Result<()> {
    const BINDING: &str = "let k = Cfg.KeyList[*]\n";

    let cells: [(&str, Status); 8] = [
        (".* exists", Status::PASS),
        (".* >= 1", Status::PASS),
        (".* == 1", Status::FAIL),
        ("[ x == 1 ] exists", Status::FAIL),
        ("[ keys == 'x' ] exists", Status::PASS),
        ("[ keys == 'x' ] == 1", Status::PASS),
        (".x == 1", Status::PASS),
        ("[*] exists", Status::PASS),
    ];

    let mut disagreed = Vec::new();
    for (tail, expected) in cells {
        for (label, subject) in [("interpolated", "Cfg.Tags.%k"), ("literal", "Cfg.Tags.A")] {
            let rules = format!("{}rule chk {{ {}{} }}", BINDING, subject, tail);
            let actual = status_of(&rules, TAGS_BY_KEY)?;
            if actual != expected {
                disagreed.push(format!(
                    "{label} {subject}{tail}: wanted {expected:?}, got {actual:?}"
                ));
            }
        }
    }

    assert!(
        disagreed.is_empty(),
        "{} of {} cells disagree with the literal-key answer:\n  {}",
        disagreed.len(),
        cells.len() * 2,
        disagreed.join("\n  ")
    );

    // The index after the key is the one part the walker consumes rather than hands on, and it
    // selects among the keys. `x` is 1 under both keys and cannot tell them apart; `y` is 2 under
    // `A` and 4 under `B`, so `[0].y == 2` holds only if `[0]` is `A`, `[1].y == 4` only if `[1]`
    // is `B`, and `[0].y == 4` has to fail.
    let mut cells = Vec::new();
    // `[0][ x == 1 ]` is the key the index chose with a filter after it: the index selected `A`, so
    // the filter selects among `A`'s entries exactly as `Cfg.Tags.A[ x == 1 ]` does (which the table
    // above measures as refused, since `x` is a key of `A` and nothing was selected), and not as
    // `Rules[0][ f ]` tests one element.
    for (tail, expected) in [
        ("[0].y == 2", Status::PASS),
        ("[1].y == 4", Status::PASS),
        ("[0].y == 4", Status::FAIL),
        ("[0][ x == 1 ] exists", Status::FAIL),
    ] {
        let actual = status_of(
            &format!("{}rule chk {{ Cfg.Tags.%k{} }}", BINDING, tail),
            TAGS_BY_KEY,
        )?;
        if actual != expected {
            cells.push(format!(
                "Cfg.Tags.%k{tail}: wanted {expected:?}, got {actual:?}"
            ));
        }
    }
    assert!(
        cells.is_empty(),
        "the index did not select the key it names:\n  {}",
        cells.join("\n  ")
    );

    Ok(())
}

/// A block-level binding that is not a query shadows an enclosing one that is.
///
/// `variable_binding_query` consulted `variable_queries` and nothing else, while `resolve_variable`
/// consults six stores before it. So a name bound at the reading scope by a literal and by a projecting
/// query further out resolved to the literal values and was *reported* as the shadowed query.
///
/// The sharp end is that adding an unrelated file-level assignment changed a verdict: with
/// `let n = Cfg.Items.*` at file level the block's `%n[*]` was judged as already enumerated, so the
/// whole literal list reached `== "a"` and the clause failed with "PathAwareValues are not comparable
/// array, String". The other three cases are the same rule without the conjunction, and all four have
/// always had the same answer.
#[rstest::rstest]
#[case::an_unrelated_file_level_projection("let n = Cfg.Items.*\n")]
#[case::nothing_at_file_level("")]
#[case::a_projection_under_another_name("let other = Cfg.Items.*\n")]
#[case::a_file_level_binding_that_does_not_project("let n = Cfg\n")]
fn a_block_level_literal_is_read_as_a_literal_whatever_encloses_it(
    #[case] preamble: &str,
) -> Result<()> {
    let rules = format!(
        "{}rule check {{ Cfg {{ let n = [ \"a\", \"b\" ]\n some %n[*] == \"a\" }} }}",
        preamble
    );

    assert_eq!(
        status_of(&rules, ITEMS)?,
        Status::PASS,
        "the block's own list holds \"a\", and nothing outside the block can change that"
    );

    Ok(())
}

/// One variable-rooted clause answers the same in two rules.
///
/// The over-wide control for the test above: `resolved_variables` is read before `variable_queries` by
/// `resolve_variable`, so mirroring it here looks called for and is not. It is a memo of the query
/// that already ran, so treating a name in it as "not bound by a query" makes the second read of a
/// binding disagree with the first -- and `reset_captures` does not clear it, so the disagreement
/// crosses rules.
///
/// The clause is a filter after the reserved slot rather than `%l[*] IS_LIST`, because `%l[*]` does not
/// observe the binding judgment at all: the author's `[*]` occupies slot 1, so `slot_is_the_authors`
/// settles the reader's decision and the memo defect is invisible through it. Asserting FAIL on it
/// instead would not help -- a disagreement between the two rules also
/// aggregates to FAIL, so the assertion could not fail for the reason it exists. Over `ITEMS` with
/// `binding_enumerated` forced false, this is PASS to FAIL.
/// Asked per rule rather than of the file, because the file's aggregate cannot carry this property.
/// `eval_rules_file` returns one `Status` for the whole file, so "both rules FAIL" and "first PASS,
/// second FAIL" are the same answer -- and *sameness between the two rules* is exactly what is being
/// asserted. Pinning the aggregate would re-pin a test that cannot fail for the reason it exists.
/// `RootScope::rule_status` answers from the memo the run fills, so asking after it reports what each
/// rule decided.
#[test]
fn one_variable_rooted_clause_answers_the_same_in_two_rules() -> Result<()> {
    let rules = "let l = Cfg.Items.*\n\
                 rule first { %l[ V == 1 ] !empty }\n\
                 rule second { %l[ V == 1 ] !empty }";

    // The instrument first, on a file whose two rules are meant to differ. Without this the equality
    // below is also satisfied by `rule_status` reporting one value for every name, which is the shape
    // of a test that cannot fail.
    {
        let control = "rule first { Cfg.Items exists }\nrule second { Cfg.Items[*].V == 9 }";
        let control_file = RulesFile::try_from(control)?;
        let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(ITEMS)?)?;
        let mut scope = root_scope(&control_file, Rc::new(value));
        crate::rules::eval::eval_rules_file(&control_file, &mut scope, None)?;
        assert_eq!(
            (Status::PASS, Status::FAIL),
            (
                scope.rule_status("first", crate::rules::eval::ClauseRole::Assertion)?,
                scope.rule_status("second", crate::rules::eval::ClauseRole::Assertion)?
            ),
            "per-rule status has to be able to report two different answers for one file, or the \
             equality below witnesses nothing"
        );
    }

    let rules_file = RulesFile::try_from(rules)?;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(ITEMS)?)?;
    let mut scope = root_scope(&rules_file, Rc::new(value));
    let whole = crate::rules::eval::eval_rules_file(&rules_file, &mut scope, None)?;

    let first = scope.rule_status("first", crate::rules::eval::ClauseRole::Assertion)?;
    let second = scope.rule_status("second", crate::rules::eval::ClauseRole::Assertion)?;

    assert_eq!(
        first, second,
        "one clause read twice cannot answer differently. The memo `resolve_variable` fills is not a \
         record that the name is unbound by a query, and `reset_captures` does not clear it, so a \
         disagreement here crosses rules"
    );

    assert_eq!(
        (Status::PASS, Status::PASS, Status::PASS),
        (first, second, whole),
        "l holds Items' two entries in both rules, so both filters select the entry whose V is 1"
    );

    Ok(())
}

/// A capture name a block declares but never binds is answered by the enclosing query, projection and
/// all.
///
/// The other over-wide control: `BlockScope` holds `capture_names`, and mirroring it here alongside
/// `literals` and `captured` looks like the same kind of thing. It is not. `lookup` reads it only after
/// the deferral has failed, to decide what an unbound name means -- so a name the block declares and
/// this iteration did not capture still resolves from the enclosing `let`, and reporting `None` for it
/// describes a binding that produced nothing while the values came from one that projects.
///
/// The `or` is what leaves `nm` unbound: its first branch passes, so the capturing clause never runs.
/// That is one of the three ways an iteration captures nothing, and the one that does not also fail the
/// rule for an unrelated reason.
///
/// A filter after the reserved slot rather than `%nm[*] IS_LIST`, for the reason given at
/// `one_variable_rooted_clause_answers_the_same_in_two_rules`: the author's `[*]` at slot 1 settles the
/// reader's decision without consulting the binding, so `%nm[*]` cannot see a `None` reported for `nm`.
/// Over `ITEMS` with `binding_enumerated` forced false, this is PASS to FAIL.
#[test]
fn a_declared_but_unbound_capture_is_answered_by_the_enclosing_query() -> Result<()> {
    let rules = "let nm = Cfg.Items.*\n\
                 rule check {\n\
                 Cfg {\n\
                 Items exists\n\
                 or Items[ nm | this == 99 ] !empty\n\
                 %nm[ V == 1 ] !empty\n\
                 }\n\
                 }";

    assert_eq!(
        status_of(rules, ITEMS)?,
        Status::PASS,
        "nm resolves to Items' two entries, so the filter selects the entry whose V is 1"
    );

    Ok(())
}

/// A parameter shadowing the `let` it is passed still owes its reader the enumeration.
///
/// Paired with `query_projects_terminates_on_a_cycle_and_follows_a_chain`, and both belong. That one
/// hands `query_projects` a `BindingsOnly` holding `a -> b -> a` and reads the `bool` back. No rules
/// file can produce that map: `first_let_cycle` rejects a cyclic `let` graph before evaluation, at
/// exit 5, with a message naming the ring -- `Variables a -> b -> a are defined in terms of each
/// other`. So it proves the recursion terminates, which is the property that has no verdict attached
/// to it, on a shape the language cannot express. What it cannot show is what any of this is worth to
/// a reader, because `BindingsOnly` answers nothing but `variable_binding_query` and there is no
/// evaluation behind the `bool` at all.
///
/// These cases supply that reader, and the property they pin does not depend on the refusal at all. All
/// three bind `let a = Cfg.Items`, which does **not** project, so all three owe PASS: the reader's own
/// `[*]` has to enumerate `Items`, and each entry is a struct. They differ only in how the name travels
/// from that `let` to the reader, and asserting one verdict across three routes is the point -- a repair
/// that fixes one spelling of a scope hop and leaves another is what these catch.
///
/// - `direct` is `rule inner(a)` called as `inner(%a)`, where the parameter shadows the `let` it is
///   handed. `ResolvedParameterContext::variable_binding_query` forwards a bare `%v` argument to the
///   parent scope, so `a` is judged where it was written and the answer is `Cfg.Items`.
/// - `through_an_intermediate_binding` puts a second hop in: `let b = %a` invoked as `inner(%b)` against
///   a parameter named `a`. A forward that defers one level does not finish a chain of two, so this is
///   the spelling that outlives a one-level repair.
/// - `literal_rooted` names no variable and is the oracle for what `IS_STRUCT` owes over this template:
///   a change to that operator moves all three cells together and cannot be mistaken for a change in how
///   a binding is read.
///
/// Which of them reaches `query_projects`' cycle refusal is a separate and moving question, so it is
/// recorded as a dated measurement rather than as a property of any cell. Instrument: the refusal's own
/// body -- the `rooted_through.contains` branch, distinct from the whole one-part arm that holds it --
/// replaced with `panic!`, whole lib suite, `--no-fail-fast`. One test fires, and it is none
/// of these three cells: it is `query_projects_terminates_on_a_cycle_and_follows_a_chain`, the hand-built
/// `BindingsOnly` resolver's own. Its firing is the control that says the probe can fire at all, and the
/// 1490 that passed beside it sum to the suite's own 1491.
///
/// The two counts nest, which is how to check this paragraph against `BindingsOnly`'s without running
/// anything: the refusal body sits inside the one-part arm, so a probe on the body can never fire more
/// tests than a probe on the whole arm. Both figures under the same instrument -- now the arm fires 1
/// and the body 1; before chain steps were resolved in the scope that wrote them, the arm fired 5 and
/// the body 3. Any pair here that has the body exceeding the arm is wrong on its face without a
/// measurement.
///
/// What the body reached before that change was
/// `eval_tests::a_parameter_query_root_is_judged_against_the_callers_binding`,
/// `through_an_intermediate_binding` and `query_projects_terminates_on_a_cycle_and_follows_a_chain`. The
/// first of those is a production route, which is why the count matters beyond bookkeeping: a count that
/// named only the two cells from this file would understate the closure by one, and a regression
/// reopening that route would then read as a long-standing condition rather than as new.
///
/// Resolving every step of a chain in the scope that wrote it is what took it to one: that closed the
/// last route a parsed `.guard` file has into that arm, leaving only the hand-built resolver. **None of
/// these three cells changes verdict when that count moves** -- they assert what the reader is owed, not
/// which internal answered it -- so a reader who finds this paragraph stale should correct the paragraph
/// and leave the cells alone.
///
/// What the refusal returns is worth less than it looks either way, and that is why no cell asserts on
/// it. It is termination and nothing else -- see `query_projects`' one-part arm for the seven-shape
/// split, where `false` is right for a non-projecting caller binding and a silent SKIP for a projecting
/// one. `Cfg.Items` does not project, so a cell that reaches the refusal here lands on the side where
/// `false` happens to be correct. Do not read that as the refusal having answered well.
///
/// Removing the refusal is not a wrong verdict but a stack overflow. Under libtest the overflow takes
/// the whole process, not just this test's thread, so check that mutation with this test filtered.
#[rstest::rstest]
#[case::direct("let a = Cfg.Items\nrule inner(a) { %a[*] IS_STRUCT }\nrule main { inner(%a) }")]
#[case::through_an_intermediate_binding(
    "let a = Cfg.Items\nlet b = %a\nrule inner(a) { %a[*] IS_STRUCT }\nrule main { inner(%b) }"
)]
#[case::literal_rooted("rule main { Cfg.Items[*] IS_STRUCT }")]
fn a_parameter_shadowing_the_let_it_is_passed_still_owes_its_enumeration(
    #[case] rules: &str,
) -> Result<()> {
    assert_eq!(
        status_of(rules, ITEMS)?,
        Status::PASS,
        "the reader's own `[*]` has to enumerate Items, and both of its entries are structs"
    );

    Ok(())
}

/// A resolver that answers `variable_binding_query` from a fixed table and refuses everything else.
///
/// For asking `query_projects` directly, which is the only way to reach a cyclic `let` graph: the
/// evaluator cannot be used, because `resolve_variable` recurses through the same edges and overflows
/// the stack on one long before a verdict exists to assert on.
///
/// It is also the only way left to reach `query_projects`' one-part arm at all, and that is a property of
/// this table rather than of the arm: it hands back a bare `%v` as recorded, where every production scope
/// follows one to its end before answering. Measured by making that arm `panic!`: of the
/// whole lib suite, the test below is the only one that fires. That figure bounds the refusal-body figure
/// recorded on `a_parameter_shadowing_the_let_it_is_passed_still_owes_its_enumeration`, because the body
/// is inside this arm -- before chain steps were resolved in their own scope, this arm fired 5 and the
/// body 3.
struct BindingsOnly<'value, 'loc: 'value> {
    bindings: &'value HashMap<&'value str, AccessQuery<'loc>>,
}

impl<'value, 'loc: 'value> EvalContext<'value, 'loc> for BindingsOnly<'value, 'loc> {
    /// Nothing is recorded here, so nothing has been.
    fn has_deprecation_site(&mut self, _: DeprecationKind, _: &FileLocation<'_>) -> bool {
        false
    }

    fn has_quiet_filter_site(&mut self, _: DeprecationKind, _: &FileLocation<'_>, _: &str) -> bool {
        false
    }

    fn has_quiet_record_at(&mut self, _: DeprecationKind, _: &FileLocation<'_>) -> bool {
        false
    }

    fn record_quiet_filter_site(&mut self, _: DeprecationKind, _: &FileLocation<'_>, _: &str) {
        todo!()
    }

    /// The binding as given, every one a `let`.
    fn variable_binding_source(&mut self, name: &str) -> Option<BindingSource<'value, 'loc>> {
        self.bindings.get(name).map(BindingSource::Let)
    }

    /// Every binding here is a `let` this one scope owns, so each hop continues here; a name the table
    /// does not hold has no parent to answer for it and the chain cannot be read.
    fn quiet_record_key_step(
        &mut self,
        variable_name: &str,
        hops_left: usize,
    ) -> crate::rules::eval_context::QuietRecordKey {
        match self.bindings.get(variable_name).map(BindingSource::Let) {
            Some(source) => crate::rules::eval_context::quiet_record_key_of_binding(
                self,
                source,
                Some(variable_name),
                hops_left,
            ),
            None => crate::rules::eval_context::QuietRecordKey::PathByFallback,
        }
    }

    /// This table's `let`s read the document: a key head ends the chain at the document's root.
    fn root_quiet_record_key(&mut self, _: usize) -> crate::rules::eval_context::QuietRecordKey {
        crate::rules::eval_context::QuietRecordKey::Path
    }

    fn query(&mut self, _: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult>> {
        todo!()
    }
    fn find_parameterized_rule(&mut self, _: &str) -> Result<&'value ParameterizedRule<'loc>> {
        todo!()
    }
    fn root(&mut self) -> Rc<PathAwareValue> {
        todo!()
    }
    fn document_root(&mut self) -> Rc<PathAwareValue> {
        todo!()
    }
    fn query_start(&self) -> QueryStart {
        todo!()
    }
    fn in_predicate(&self) -> bool {
        todo!()
    }
    fn empty_selection(&self) -> Option<Rc<EmptySelection>> {
        None
    }
    fn reads_beside_the_map(&self) -> bool {
        todo!()
    }
    fn fallback_root(&mut self) -> Rc<PathAwareValue> {
        todo!()
    }
    fn is_top_level_alias(&self, _: &str, _: MergedKeys) -> bool {
        todo!()
    }
    fn rule_status(&mut self, _: &str, _: crate::rules::eval::ClauseRole) -> Result<Status> {
        todo!()
    }
    fn resolve_variable(&mut self, _: &str) -> Result<Vec<QueryResult>> {
        todo!()
    }
    /// Every binding here is a query, so no name holds a literal or a capture.
    fn literal_binding(&self, _: &str) -> Option<Vec<Rc<PathAwareValue>>> {
        None
    }
    fn variable_binding_query(
        &mut self,
        name: &str,
        _: MergedKeys,
    ) -> Option<&'value AccessQuery<'loc>> {
        self.bindings.get(name)
    }
    /// This table is read by `query_projects` alone and resolves nothing, so no shape is recorded, and a
    /// name that names its value passed nothing on.
    fn variable_shape(&mut self, _: &str, _: MergedKeys) -> (RhsEnumeration, PassedOn) {
        (RhsEnumeration::Names, PassedOn::default())
    }
    /// Nor any capture.
    fn variable_lists_keys(&self, _: &str, _: MergedKeys) -> bool {
        false
    }
    fn query_with_shape(
        &mut self,
        _: &'value [QueryPart<'loc>],
    ) -> Result<(Vec<QueryResult>, RhsEnumeration, PassedOn)> {
        todo!()
    }
    /// Nothing here runs a query, so a projection's containers cannot be asked of this double; a test
    /// that reaches it has left what the double can answer and should fail loudly.
    fn projection_member_keys(
        &mut self,
        _: &str,
        _: MergedKeys,
    ) -> Result<Option<Rc<ProjectionKeys>>> {
        todo!()
    }
    fn add_variable_capture(&mut self, _: &'value str, _: QueryResult) -> Result<()> {
        todo!()
    }
    fn variable_capture_len(&self, _: &str) -> usize {
        0
    }
    fn truncate_variable_capture(&mut self, _: &'value str, _: usize) -> Result<()> {
        todo!()
    }
    /// Keeps no captures, so an enumeration's per-entry frame has nothing to scope here; a no-op rather
    /// than `todo!()` because every `[*]` and `.*` a query test walks opens one.
    fn open_capture_frame(&mut self) {}
    fn begin_capture_entry(&mut self) {}
    fn end_capture_entry(&mut self) {}
    fn end_capture_entry_detached(&mut self) -> EntryCaptures<'value> {
        EntryCaptures::default()
    }
    fn refile_captures(&mut self, _captures: EntryCaptures<'value>) {}
    fn close_capture_frame(&mut self) {}
    fn add_variable_capture_key_below_the_entry(
        &mut self,
        name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.add_variable_capture_key(name, key)
    }
    /// Binds names through queries only, so none of them is a capture: the one question of these a
    /// binding-walk test can reach is answered. The rest are what this double cannot answer, and a test
    /// that reaches one has left what it measures and should fail loudly.
    fn binding_is_a_capture(&mut self, _: &str, _: MergedKeys) -> bool {
        false
    }
    fn reset_captures(&mut self) {
        todo!()
    }
    fn resolve_variable_from_nested_block(
        &mut self,
        _: &'value str,
        _: UnboundName,
    ) -> Result<Vec<QueryResult>> {
        todo!()
    }
    fn add_merged_capture(&mut self, _: &'value str, _: QueryResult) -> Result<()> {
        todo!()
    }
    fn add_variable_capture_index(&mut self, _: &str, _: Rc<PathAwareValue>) -> Result<()> {
        todo!()
    }
    fn record_deprecation(&mut self, _: String) {
        todo!()
    }
    fn record_deprecation_once(
        &mut self,
        _: DeprecationKind,
        _: &FileLocation<'_>,
        _: String,
    ) -> bool {
        todo!()
    }
    /// A cache of its own per ask: this double evaluates no `[*]` filter twice.
    fn predicate_regexes(
        &self,
        _: &FileLocation<'_>,
    ) -> Rc<crate::rules::eval_context::CompiledRegexes> {
        Rc::default()
    }
    fn set_measurement(&mut self, _: Measurement) {
        todo!()
    }
    fn measurement(&self) -> Measurement {
        todo!()
    }
    fn when_is_settled(
        &self,
        _: &FileLocation<'loc>,
        _: MoveDirection,
        _: Option<&BTreeSet<BindingId<'value>>>,
    ) -> bool {
        todo!()
    }
    fn when_has_settled_measurements(&self, _: &FileLocation<'loc>, _: MoveDirection) -> bool {
        todo!()
    }
    fn settle_when(
        &mut self,
        _: &FileLocation<'loc>,
        _: MoveDirection,
        _: Option<BTreeSet<BindingId<'value>>>,
    ) {
        todo!()
    }
    fn binding_owners(&self, _: &str) -> Option<BTreeSet<BindingId<'value>>> {
        todo!()
    }
    fn document_binding_memo(
        &self,
    ) -> Option<Rc<std::cell::RefCell<super::DocumentBindingMemo<'value>>>> {
        todo!()
    }
    fn resolving_a_binding(&self) -> bool {
        todo!()
    }
    fn within_parameterized_call(&self) -> bool {
        todo!()
    }
    fn function_chain(&mut self, _: &str) -> Option<FunctionChain<'value>> {
        todo!()
    }
    fn function_result_entries(&mut self, _: &str) -> Option<Result<Rc<FunctionEntries>>> {
        todo!()
    }
    fn record_warning(&mut self, _: &FileLocation<'_>, _: &str, _: &str, _: String) {
        todo!()
    }
    fn record_capture_warning(&mut self, _: &FileLocation<'_>, _: &str, _: String) {
        todo!()
    }
    fn record_unraised_refusal(
        &mut self,
        _: &FileLocation<'_>,
        _: &str,
        _: crate::rules::UnraisedVerdict,
        _: &[String],
    ) {
        todo!()
    }
    fn data_file_name(&self) -> Option<&'value str> {
        todo!()
    }
    fn case_label(&self) -> Option<&str> {
        todo!()
    }
    fn variable_is_resolved(&self, _: &str) -> bool {
        todo!()
    }
}

/// `variable_is_resolved` answers from what the root scope holds, and only from that: a literal, a key
/// captured by a filter and a key merged up from a block are held as they are bound, a query or a
/// function call is held once `lookup` has memoized it, and a name the scope does not bind is not held.
#[test]
fn the_root_scope_holds_literals_captures_merged_keys_and_memoized_lets() -> Result<()> {
    let rules = r#"
    let lit = "a"
    let q = Resources
    let f = to_lower(Resources.A.Type)
    rule r { Resources exists }
    "#;
    let rules_file = RulesFile::try_from(rules)?;
    let value = Rc::new(PathAwareValue::try_from(
        r#"{ Resources: { A: { Type: "AWS::S3::Bucket" } } }"#,
    )?);
    let mut root = root_scope(&rules_file, Rc::clone(&value));

    assert!(
        root.variable_is_resolved("lit"),
        "a literal is held as bound"
    );
    assert!(
        !root.variable_is_resolved("q"),
        "a query is not held before it is read"
    );
    assert!(
        !root.variable_is_resolved("f"),
        "a call is not held before it is read"
    );
    assert!(
        !root.variable_is_resolved("nosuch"),
        "an unbound name is not held"
    );

    root.resolve_variable("q")?;
    assert!(
        root.variable_is_resolved("q"),
        "a query is held once memoized"
    );
    assert!(
        !root.variable_is_resolved("f"),
        "reading one let holds no other"
    );

    root.add_variable_capture_key("k", Rc::clone(&value))?;
    assert!(root.variable_is_resolved("k"), "a captured key is held");
    root.add_merged_capture_key("m", Rc::clone(&value))?;
    assert!(root.variable_is_resolved("m"), "a merged key is held");
    Ok(())
}

/// A block scope answers for the names it binds and defers the rest: its own literal is held, its own
/// query is not held until its own `lookup` memoizes it, even when an outer `let` of the same name is
/// memoized in the parent, and its own captured and merged keys are held. A name it does not bind is the
/// parent's to answer for.
#[test]
fn a_block_scope_holds_its_own_bindings_and_defers_the_rest() -> Result<()> {
    let rules = r#"
    let outer_lit = "outer"
    let q = Resources
    rule r {
        let lit = "inner"
        let q = Resources.A
        Resources exists
    }
    "#;
    let rules_file = RulesFile::try_from(rules)?;
    let value = Rc::new(PathAwareValue::try_from(
        r#"{ Resources: { A: { Type: "AWS::S3::Bucket" } } }"#,
    )?);
    let mut root = root_scope(&rules_file, Rc::clone(&value));
    root.resolve_variable("q")?;
    assert!(
        root.variable_is_resolved("q"),
        "control: the outer q is memoized"
    );

    let block = &rules_file.guard_rules[0].block;
    let mut scope = block_scope(block, Rc::clone(&value), &mut root);
    assert!(
        scope.variable_is_resolved("lit"),
        "the block's literal is held"
    );
    assert!(
        !scope.variable_is_resolved("q"),
        "the block's own q shadows the memoized outer one and is not read yet"
    );
    assert!(
        scope.variable_is_resolved("outer_lit"),
        "a name the block does not bind is the parent's"
    );
    assert!(
        !scope.variable_is_resolved("nosuch"),
        "an unbound name is not held"
    );

    scope.resolve_variable("q")?;
    assert!(
        scope.variable_is_resolved("q"),
        "the block's q is held once its lookup memoized it"
    );

    scope.add_variable_capture_key("k", Rc::clone(&value))?;
    assert!(
        scope.variable_is_resolved("k"),
        "a key the block captured is held"
    );
    scope.add_merged_capture_key("m", Rc::clone(&value))?;
    assert!(
        scope.variable_is_resolved("m"),
        "a key merged into the block is held"
    );
    Ok(())
}

impl<'value, 'loc: 'value> RecordTracer<'value> for BindingsOnly<'value, 'loc> {
    fn start_record(&mut self, _: &str) -> Result<()> {
        todo!()
    }
    fn end_record(&mut self, _: &str, _: RecordType<'value>) -> Result<()> {
        todo!()
    }
}

/// The query a notice names parses back as the query it names.
///
/// A key that is not a bare identifier (`AWS::CloudFormation::Authentication`) is stored without its
/// quotes and was rendered without them, and a filter's conjuncts were joined with `;`, which the
/// grammar does not read; the text in a notice could not be pasted back into a rule. Each query here
/// is parsed, rendered, parsed again from the rendering and rendered again, and the two renderings have
/// to agree; the first also has to be the spelling named, so the test says what the renderer writes.
#[rstest::rstest]
#[case::a_key_that_is_not_a_bare_identifier_is_quoted(
    r#"Resources."AWS::CloudFormation::Authentication".Properties"#,
    r#"Resources."AWS::CloudFormation::Authentication".Properties"#
)]
#[case::a_key_holding_a_dash_is_quoted_because_the_grammar_refuses_it_bare(
    r#"Resources."my-key".Properties"#,
    r#"Resources."my-key".Properties"#
)]
#[case::a_filter_with_two_conjuncts_and_a_disjunction(
    "Resources.*[ Type == 'X' Properties.Count > 1 or Name exists ].Properties.Tags",
    "Resources.*[ Type == 'X' Properties.Count > 1 or Name exists ].Properties.Tags"
)]
#[case::a_quoted_key_inside_a_filter(
    r#"Resources.*[ "Fn::Sub" exists ].Properties"#,
    r#"Resources.*[ "Fn::Sub" exists ].Properties"#
)]
#[case::a_regex_and_a_string_holding_a_quote(
    r#"Resources.*[ Type == /S3/ Name != "it's" ].Properties"#,
    r#"Resources.*[ Type == /S3/ Name != "it's" ].Properties"#
)]
#[case::a_later_non_ascii_letter_is_bare_as_the_parser_reads_it(
    "Resources.café.Properties",
    "Resources.café.Properties"
)]
#[case::a_leading_underscore_or_non_ascii_letter_is_quoted(
    r#"Resources."_lead"."éclair".Properties"#,
    r#"Resources."_lead"."éclair".Properties"#
)]
#[case::a_key_holding_a_double_quote_takes_single_quotes(
    r#"Resources.'say "hi"'.Properties"#,
    r#"Resources.'say "hi"'.Properties"#
)]
#[case::a_key_holding_both_quotes_and_a_backslash_is_escaped(
    r#"Resources."it's \"x\" \\ y".Properties"#,
    r#"Resources."it's \"x\" \\ y".Properties"#
)]
#[case::a_string_holding_a_backslash_is_escaped(
    r#"Resources.*[ Name == 'a\\b' ].Properties"#,
    r#"Resources.*[ Name == 'a\\b' ].Properties"#
)]
#[case::a_variable_root_an_index_and_an_enumeration("%p[*].Ports[0]", "%p[*].Ports[0]")]
#[case::a_variable_root_followed_by_a_key_prints_no_slot("%p.Ports", "%p.Ports")]
#[case::a_variable_root_followed_by_an_index_prints_no_slot("%p[0]", "%p[0]")]
#[case::a_variable_root_followed_by_a_filter_prints_no_slot(
    "%p[ Type == 'X' ].Ports",
    "%p[ Type == 'X' ].Ports"
)]
#[case::a_map_key_filter(
    "Resources[ keys == 'R' ].Properties",
    "Resources[ keys == 'R' ].Properties"
)]
#[case::this_and_a_named_wildcard_as_a_key_filter_argument_spells_them(
    "this.Wanted[ w ].Name",
    "this.Wanted[ w ].Name"
)]
fn a_query_as_written_parses_back_as_itself(
    #[case] query: &str,
    #[case] written: &str,
) -> Result<()> {
    fn parsed(rules: &str) -> Result<AccessQuery<'_>> {
        let file = RulesFile::try_from(rules)?;
        match file.assignments.into_iter().next().map(|each| each.value) {
            Some(LetValue::AccessClause(query)) => Ok(query),
            other => panic!("{}: expected a query assignment, got {:?}", rules, other),
        }
    }

    let first = format!("let q = {query}");
    let rendered =
        query_as_written(&parsed(&first)?.query).expect("every part here has a rendering");
    assert_eq!(written, rendered, "{query}: rendered as written");

    let second = format!("let q = {rendered}");
    let again = query_as_written(&parsed(&second)?.query).expect("every part here has a rendering");
    assert_eq!(
        rendered, again,
        "{query}: the rendering parses back as itself"
    );
    Ok(())
}

/// `query_projects` terminates on a cycle in the `let` graph, and on a chain the length of one.
///
/// Only the `%v`-alone arm recurses, and it refuses a name already on the chain -- so each step
/// consumes one name no later step can reuse and the depth is at most the number of distinct names.
/// Without the refusal this is not a wrong answer but a stack overflow, which is not a verdict.
///
/// The chain case is here so the cycle case cannot pass by the recursion never happening: `a` -> `b` ->
/// `c` -> `Resources.*` has to be followed to its end to report that it projects.
///
/// A cyclic `let` graph is the shape no rules file reaches, so this asserts on the `bool` and stops
/// there. That makes this the one cell that keeps the refusal covered whatever happens to the routes a
/// parsed file has into it, and there are fewer of those than there were: each repair that resolves a
/// name in the scope that wrote it closes another, and closing the last one leaves this resolver as the
/// only caller. `BindingsOnly` is written for that job on purpose -- `query_projects` takes any
/// `EvalContext` and has to stay total for one that answers unwalked -- so read this as coverage of the
/// arm and not as evidence that a `.guard` file can get here.
///
/// It says nothing about which `bool` is owed, and there is no answer to that. See `query_projects`'
/// one-part arm: `false` is correct for a non-projecting caller binding and a silent SKIP for a
/// projecting one, so the constant carries no projection information at all and only the returning
/// matters. `a_parameter_shadowing_the_let_it_is_passed_still_owes_its_enumeration` is where a verdict
/// exists, and its doc records which of its cells currently reach this arm as a dated measurement.
#[test]
fn query_projects_terminates_on_a_cycle_and_follows_a_chain() -> Result<()> {
    let mut cyclic = HashMap::new();
    cyclic.insert("a", AccessQuery::try_from("%b")?);
    cyclic.insert("b", AccessQuery::try_from("%a")?);
    let mut resolver = BindingsOnly { bindings: &cyclic };
    let start = AccessQuery::try_from("%a")?;
    assert!(
        !query_projects(&start.query, &mut resolver, &mut vec!["reader"]),
        "a cycle has no binding to report, and answering `false` walks the reserved slot rather than \
         silently skipping it"
    );

    let mut chained = HashMap::new();
    chained.insert("a", AccessQuery::try_from("%b")?);
    chained.insert("b", AccessQuery::try_from("%c")?);
    chained.insert("c", AccessQuery::try_from("Resources.*")?);
    let mut resolver = BindingsOnly { bindings: &chained };
    let start = AccessQuery::try_from("%a")?;
    assert!(
        query_projects(&start.query, &mut resolver, &mut vec!["reader"]),
        "the chain ends at a projection, so every name on it holds members"
    );

    Ok(())
}

/// The quiet record's key follows the binding chain to what it ends at, and falls back to the path, the
/// reading before provenance was read, when the chain cannot be read.
///
/// `quiet_record_key` decides whether a filter site's quiet verdict on a map is recorded by the map's
/// path (a chain ending at a document query, or at a function over one), not at all (a chain ending at
/// a rules-file literal or at a function over rules-file text; the evaluator rows of
/// `a_quiet_verdict_is_keyed_by_the_maps_provenance_and_not_by_its_path_alone` reach those two ends,
/// which this table of `let`s cannot build), or by the path as a fallback. The fallback is the pre-221
/// behavior and never "record nothing": a name the resolver has no binding source for (a filter capture
/// or a merged key answers `None`; `BasicQueryTesting` answers `None` for every name), a cycle of `let`s
/// (walked to the hop bound, never to a `%name`-less head) and a query with no part all read as the
/// path key. Cells:
/// - `let a = %b`, `let b = %c`, `let c = Resources.*`: the chain ends at a document query, the path key;
/// - `let a = Resources`: one hop, the path key;
/// - `let a = %b`, `let b = %a`: a cycle, the fallback;
/// - a name with no binding, and a resolver with no binding sources at all: the fallback.
#[test]
fn quiet_record_key_falls_back_to_the_path_when_the_binding_chain_cannot_be_read() -> Result<()> {
    use crate::rules::eval_context::{quiet_record_key, QuietRecordKey};

    let mut chained = HashMap::new();
    chained.insert("a", AccessQuery::try_from("%b")?);
    chained.insert("b", AccessQuery::try_from("%c")?);
    chained.insert("c", AccessQuery::try_from("Resources.*")?);
    let mut resolver = BindingsOnly { bindings: &chained };
    assert_eq!(
        QuietRecordKey::Path,
        quiet_record_key(&mut resolver, "a"),
        "a chain of lets ending at a document query records by the map's path"
    );
    assert_eq!(
        QuietRecordKey::Path,
        quiet_record_key(&mut resolver, "c"),
        "a let bound to a document query records by the map's path"
    );
    assert_eq!(
        QuietRecordKey::PathByFallback,
        quiet_record_key(&mut resolver, "nobody"),
        "a name with no binding source cannot be read: the path key, as before"
    );

    let mut cyclic = HashMap::new();
    cyclic.insert("a", AccessQuery::try_from("%b")?);
    cyclic.insert("b", AccessQuery::try_from("%a")?);
    let mut resolver = BindingsOnly { bindings: &cyclic };
    assert_eq!(
        QuietRecordKey::PathByFallback,
        quiet_record_key(&mut resolver, "a"),
        "a cycle of lets never reaches an end: the hop bound stops the walk at the path key"
    );

    let value = PathAwareValue::try_from(r#"{ "Resources": {} }"#)?;
    let mut resolver = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    assert_eq!(
        QuietRecordKey::PathByFallback,
        quiet_record_key(&mut resolver, "r"),
        "a resolver with no binding source for the name reads as the path key, never as no record"
    );
    Ok(())
}

/// The fallback key records by the path everywhere but at the root path `""`: every rules-file literal
/// is built there, so a fallback record at `""` would let the first literal at a site decide for every
/// other literal at it, the collision the provenance key removes, and a chain that cannot be read has no
/// way to tell a literal at `""` from the document. `quiet_record_path` is the one question every
/// record and lookup in `announce_a_filter_that_lost_its_map` asks: a chain that ends at a document
/// query records at `""` (the document itself) and below it, under the path; a chain that cannot be read
/// records below `""` only.
#[test]
fn the_fallback_key_records_no_quiet_verdict_at_the_root_path() -> Result<()> {
    use crate::rules::eval_context::quiet_record_path;

    let mut bindings = HashMap::new();
    bindings.insert("doc", AccessQuery::try_from("Resources.*")?);
    let mut resolver = BindingsOnly {
        bindings: &bindings,
    };
    for (label, name, map_path, expected) in [
        (
            "a document chain records the document itself",
            "doc",
            "",
            true,
        ),
        (
            "a document chain records a map below the root",
            "doc",
            "/m",
            true,
        ),
        (
            "the fallback records nothing at the root path",
            "nobody",
            "",
            false,
        ),
        (
            "the fallback records a map below the root by its path",
            "nobody",
            "/m",
            true,
        ),
    ] {
        assert_eq!(
            expected,
            quiet_record_path(&mut resolver, name, map_path).is_some(),
            "{label}"
        );
        assert_eq!(
            expected.then(|| map_path.to_string()),
            quiet_record_path(&mut resolver, name, map_path),
            "{label}: a path key is the path itself"
        );
    }
    Ok(())
}

/// A map of maps, each with a `Sub` map under it.
///
/// Two entries, so the list a finished block hands up is a union over iterations rather than one
/// iteration's key, and a `Sub` map under each so a filter inside a block has a key to capture.
const CAPTURE_SHADOWED_ITEMS: &str = r#"
Items:
  i1:
    Meta:
      Kind: alpha
    Sub:
      s1:
        Other: x
  i2:
    Meta:
      Kind: alpha
    Sub:
      s2:
        Other: y
"#;

/// The same, one level deeper: `Sub`'s entries each carry a `Deep` map to capture from.
///
/// For the block-level reading of the defect, where the merged keys sit in a `BlockScope` rather than in
/// `RootScope` and nothing ever clears them.
const CAPTURE_SHADOWED_SUBS: &str = r#"
Items:
  i1:
    Meta:
      Kind: alpha
    Sub:
      s1:
        Tag:
          Name: x
        Deep:
          d1:
            K: 1
      s2:
        Tag:
          Name: x
        Deep:
          d2:
            K: 2
"#;

/// Keys merged out of one block do not answer the binding question inside the next one.
///
/// Two chains walk one name here and they disagreed. The reading block's `resolve_variable` finds
/// nothing of its own and defers to `resolve_variable_from_nested_block`, which withholds the merged
/// map, so the values come from `let its = Items.*` -- a projecting query. `variable_binding_query` read
/// the merged map whatever the reading was, found the first block's keys under the same name there, and
/// answered `None`: "did not enumerate". So the reserved slot was walked instead of consumed, the filter
/// after it ran one level too deep, it matched nothing, and an assertion over an empty selection is not
/// applicable. Exit 0 with nothing on either channel.
///
/// Both cases must FAIL, which is the property rather than the symptom. The only difference between them
/// is whether the first block names its capture, and that cannot decide what the second block's `%its`
/// is judged against -- the second block does not read the capture at all.
#[rstest::rstest]
#[case::the_capture_shadows_the_name("Sub[ its | Other exists ] !empty")]
#[case::no_capture_at_all("Sub[ Other exists ] !empty")]
fn merged_keys_do_not_answer_the_binding_question_inside_another_block(
    #[case] capturing_clause: &str,
) -> Result<()> {
    let rules = format!(
        "let its = Items.*\n\
         rule demo {{\n\
         Items.*[ Meta.Kind == 'alpha' ] {{ {} }}\n\
         Items.*[ Meta.Kind == 'alpha' ] {{ %its[ Meta.Kind == 'alpha' ].Meta.Kind == \"zzz\" }}\n\
         }}",
        capturing_clause
    );

    assert_eq!(
        status_of(&rules, CAPTURE_SHADOWED_ITEMS)?,
        Status::FAIL,
        "its holds Items' two entries in the second block either way, and neither Kind is zzz"
    );

    Ok(())
}

/// The block-level reading of the same disagreement, which no reset can hide.
///
/// `reset_captures` clears `RootScope`'s merged map, so the file-level shape above has a window: move the
/// capturing block into a rule of its own and the reading rule answers correctly, which is what isolates
/// the merged map as the cause. A `BlockScope`'s merged map has no such window. `reset_captures` is
/// overridden only by `RootScope` and its one production caller runs between top-level rules, so a key a
/// nested block handed to an enclosing block stays there for every later clause in that block.
///
/// `let subs = Sub.*` is block-level here, which also puts the shadowed binding and the merged keys in
/// the same scope rather than in two.
#[rstest::rstest]
#[case::the_capture_shadows_the_name("Deep[ subs | K exists ] !empty")]
#[case::no_capture_at_all("Deep[ K exists ] !empty")]
fn a_blocks_merged_keys_do_not_answer_for_a_sibling_nested_block(
    #[case] capturing_clause: &str,
) -> Result<()> {
    let rules = format!(
        "rule demo {{\n\
         Items.*[ Meta.Kind == 'alpha' ] {{\n\
         let subs = Sub.*\n\
         Sub.*[ Tag.Name == 'x' ] {{ {} }}\n\
         Sub.*[ Tag.Name == 'x' ] {{ %subs[ Tag.Name == 'x' ].Tag.Name == \"zzz\" }}\n\
         }}\n\
         }}",
        capturing_clause
    );

    assert_eq!(
        status_of(&rules, CAPTURE_SHADOWED_SUBS)?,
        Status::FAIL,
        "subs holds Sub's two entries in the second nested block either way, and neither Name is zzz"
    );

    Ok(())
}

/// A scope that only forwards the question hands on the reading, not a fresh one.
///
/// `ResolvedParameterContext` sits between a parameterized rule's body and the caller's scope, and it
/// answers for the call's own parameters and forwards everything else. A name that is not a parameter is
/// therefore judged by the caller's bindings -- and it has to be judged by them under the *reading the
/// asking clause has*, or the forward arrives as a question about a different resolution of the name.
/// Here the caller's merged keys and a file-level projecting `let` share the name `its`, the clause
/// reading it sits inside a block, and the values it sees come from the `let`; so the forwarded question
/// has to reach the caller's scope as `Hidden` and come back with that `let`.
///
/// Worth its own case because forwarding is where a discriminant is easiest to drop: nothing about the
/// forward fails to compile if the reading is replaced with a constant, and this scope is on the path of
/// every clause in every parameterized rule body.
#[test]
fn a_forwarding_scope_hands_on_the_reading_it_was_asked() -> Result<()> {
    let rules = "let its = Items.*\n\
                 rule inner(tag) {\n\
                 %tag == \"keep\"\n\
                 Items.*[ Meta.Kind == 'alpha' ] { %its[ Meta.Kind == 'alpha' ].Meta.Kind == \"zzz\" }\n\
                 }\n\
                 rule demo {\n\
                 Items.*[ Meta.Kind == 'alpha' ] { Sub[ its | Other exists ] !empty }\n\
                 inner(\"keep\")\n\
                 }";

    assert_eq!(
        status_of(rules, CAPTURE_SHADOWED_ITEMS)?,
        Status::FAIL,
        "its is not one of inner's parameters, so it resolves to Items' two entries through the \
         forward, and neither Kind is zzz"
    );

    Ok(())
}

/// Both readings of one name, asked of the only store whose reach differs between them.
///
/// `lookup` gates the merged map on the reading and reads every other store on both, so the merged map
/// is the only place `variable_binding_query` could disagree with it. It did, by reading that map
/// whatever the reading was. Both cells are needed and each of them fails a different way:
///
/// - `Visible` must stay `None`. The merged keys are what a clause at this scope's own level resolves
///   to, and a filter capture is not a query. Reporting the shadowed `let` here would describe a
///   projection for values it never produced, which is the defect the guard on this map exists to
///   prevent -- so a repair that simply drops the guard reddens this cell.
/// - `Hidden` must report the `let`. Those same keys are out of reach of a clause inside another block,
///   so that clause's values come from `let nm` and from nothing else, and `None` for it says "did not
///   enumerate" about a query that did.
#[test]
fn merged_keys_are_out_of_reach_of_a_nested_block_for_both_questions() -> Result<()> {
    let rules_file = RulesFile::try_from("let nm = Cfg.Items.*\nrule chk { %nm[*] IS_STRUCT }")?;
    let value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(ITEMS).unwrap())?;
    let mut scope = root_scope(&rules_file, Rc::new(value));
    scope.add_merged_capture_key(
        "nm",
        Rc::new(PathAwareValue::String((
            Path::new("/Cfg/Items/0".to_string(), 0, 0),
            "s1".to_string(),
        ))),
    )?;

    assert!(
        scope
            .variable_binding_query("nm", MergedKeys::Visible)
            .is_none(),
        "a clause at this scope's own level resolves nm to the merged key, which no query produced"
    );

    assert_eq!(
        scope.variable_binding_query("nm", MergedKeys::Hidden),
        Some(&AccessQuery::try_from("Cfg.Items.*")?),
        "a clause inside another block cannot see the merged key, so its values are the let's"
    );

    Ok(())
}

/// The population question walks the same chain under the same reading as the binding question, so the
/// two cannot disagree about one name.
///
/// `is_top_level_alias` follows `let r = %all` to `let all = Resources` through the same `binding_step`
/// that `variable_binding_query` uses, and it carries the reading the asking clause has, so wherever the
/// binding question reports a single-key query the population question says yes, and wherever it reports
/// `None` (a capture, a merged key, a literal) the population question says no. The cells read both
/// answers for both readings, with and without a key merged up under a name on the chain, and assert the
/// agreement itself rather than a fixed table, so the walk's own rules (a merged key is in reach only
/// under `Visible`; an alias followed within a scope is read at that scope's own level, `Visible`, as
/// `binding_step` resets the reading when it follows one) decide the values and the test cannot drift
/// from them. The arm that defers a name to the parent carries the reading with it; asking `Visible`
/// there would let a nested block's two walks over one chain disagree.
#[test]
fn the_population_question_follows_an_alias_chain_under_the_reading_it_was_asked() -> Result<()> {
    let rules_file = RulesFile::try_from(
        "let all = Resources\nlet r = %all\nrule chk { %r.*[ Type exists ] !empty }",
    )?;
    let value = PathAwareValue::try_from(r#"{"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}"#)?;
    let mut scope = root_scope(&rules_file, Rc::new(value));

    let agreement =
        |scope: &mut RootScope<'_, '_>, name: &str, merged: MergedKeys| -> (bool, bool) {
            let binding_is_a_single_key = scope
                .variable_binding_query(name, merged)
                .map(|query| query.query.len() == 1)
                .unwrap_or(false);
            (
                scope.is_top_level_alias(name, merged),
                binding_is_a_single_key,
            )
        };

    for (reading, merged) in [
        ("Visible", MergedKeys::Visible),
        ("Hidden", MergedKeys::Hidden),
    ] {
        let (population, single_key) = agreement(&mut scope, "r", merged);
        assert!(
            population && single_key,
            "with nothing merged, r reaches `let all = Resources` under {}: population {}, binding {}",
            reading,
            population,
            single_key
        );
    }

    // A key merged up under `r` itself: in reach at this scope's own level, out of reach for a nested
    // block, and both questions must say so.
    scope.add_merged_capture_key(
        "r",
        Rc::new(PathAwareValue::String((
            Path::new("/Resources/B".to_string(), 0, 0),
            "B".to_string(),
        ))),
    )?;
    let (population, single_key) = agreement(&mut scope, "r", MergedKeys::Visible);
    assert!(
        !population && !single_key,
        "at this scope's own level `r` is the merged key, no alias of anything: population {}, binding {}",
        population,
        single_key
    );
    let (population, single_key) = agreement(&mut scope, "r", MergedKeys::Hidden);
    assert!(
        population && single_key,
        "inside another block the merged key is out of reach and the chain reaches the let: population {}, binding {}",
        population,
        single_key
    );

    // A key merged up under `all`, the name the chain is followed to: `binding_step` reads a followed
    // alias at this scope's own level, so both questions see the merged key under either reading, and
    // they still agree.
    scope.reset_captures();
    scope.add_merged_capture_key(
        "all",
        Rc::new(PathAwareValue::String((
            Path::new("/Resources/B".to_string(), 0, 0),
            "B".to_string(),
        ))),
    )?;
    for (reading, merged) in [
        ("Visible", MergedKeys::Visible),
        ("Hidden", MergedKeys::Hidden),
    ] {
        let (population, single_key) = agreement(&mut scope, "r", merged);
        assert_eq!(
            population, single_key,
            "the two walks over one chain agree under {} with `all` merged",
            reading
        );
    }

    Ok(())
}

/// A capture made in a referenced rule's condition is not read by the rule that referenced it.
///
/// `rule_status` evaluates the referenced rule against this scope, in the middle of the referencing
/// rule, and a rule's `when` condition is evaluated against the scope it is handed. So `helper`'s
/// condition appended `Bkt` to the `captured` entry `main`'s own condition had filled with `MyRole`,
/// and `%b == "MyRole"` in `main` compared both. `reset_captures` runs only between top-level rules,
/// so nothing separated the two while `main` was still running.
///
/// Asked per rule, because the file's one `Status` cannot tell "both pass" from "helper passes and
/// main fails" apart; see `one_variable_rooted_clause_answers_the_same_in_two_rules`. The control is
/// the same file with the reference after the comparison, which always passed: the two orders have to
/// agree, and the agreed answer has to be the one the data gives.
///
/// Both reference shapes, because they reach the referenced rule by different scopes: a named rule
/// through `RootScope::rule_status`, a parameterized call through a `ResolvedParameterContext` built
/// at the call site. The second filed the called rule's captures with its parent, so `p("x")` leaked
/// `Bkt` into `main` exactly as the named reference had.
///
/// What this reads: `rule_status` after `eval_rules_file` answers from the memo that run filled for
/// each top-level rule, so the two statuses are the run's own verdicts and no rule is evaluated a
/// second time to produce them. The memo cannot answer differently for the two orders unless the run
/// did.
#[test]
fn a_referenced_rules_condition_capture_is_not_read_by_the_referencing_rule() -> Result<()> {
    const TEMPLATE: &str = r#"
    Resources:
      MyRole:
        Type: AWS::IAM::Role
      Bkt:
        Type: AWS::S3::Bucket
    "#;
    // `main`'s status alone: a parameterized rule has no top-level verdict to ask for, and the named
    // helper's own PASS is not what is in question.
    let shapes = [
        (
            "named rule",
            "rule helper when Resources[ b | Type == 'AWS::S3::Bucket' ] !empty { Resources exists }\n",
            "helper",
        ),
        (
            "parameterized rule",
            "rule p(x) when Resources[ b | Type == 'AWS::S3::Bucket' ] !empty { Resources exists }\n",
            "p(\"x\")",
        ),
    ];

    let mut per_case = Vec::new();
    for (shape, referenced, reference) in shapes {
        for (order, body) in [
            ("reference first", format!("{reference}\n%b == \"MyRole\"")),
            ("comparison first", format!("%b == \"MyRole\"\n{reference}")),
        ] {
            let rules = format!(
                "{referenced}rule main when Resources[ b | Type == 'AWS::IAM::Role' ] !empty \
                 {{\n{body}\n}}"
            );
            let rules_file = RulesFile::try_from(rules.as_str())?;
            let value =
                PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(TEMPLATE)?)?;
            let mut scope = root_scope(&rules_file, Rc::new(value));
            crate::rules::eval::eval_rules_file(&rules_file, &mut scope, None)?;
            per_case.push((
                shape,
                order,
                scope.rule_status("main", crate::rules::eval::ClauseRole::Assertion)?,
            ));
        }
    }

    assert_eq!(
        vec![
            ("named rule", "reference first", Status::PASS),
            ("named rule", "comparison first", Status::PASS),
            ("parameterized rule", "reference first", Status::PASS),
            ("parameterized rule", "comparison first", Status::PASS),
        ],
        per_case,
        "main's own capture is exactly [MyRole] in every cell; a FAIL with the reference first means \
         the referenced rule's condition wrote into the map main was reading"
    );

    Ok(())
}

/// A capture on a filter over a list binds the element the predicate selected, in every spelling that
/// reaches a list element.
///
/// The map arms bind an entry's key. A list element has none, and the list arms bound nothing, so a
/// name written there was counted as declared and resolved to an empty selection: `%t !empty` failed
/// blaming the selection, `%t.Value == 'dev'` had nothing to read, and `%t exists` skipped. The last is
/// the dangerous one -- a rule that selects a tag and then "checks" it passed at exit 0 having checked
/// nothing -- and the `when` shape here is how that skip becomes a verdict the file can show: unbound,
/// the gate does not open and the body's failing comparison never runs.
///
/// Four spellings, because they reach the element by different arms: `[*][ ... ]` over a list of maps
/// arrives at the map arm with a wildcard predecessor, `[ ... ]` directly on the list at the list arm,
/// and the same two over a list of scalars at the arm for a value that is neither map nor list. The map
/// control is the key-binding shape and the undeclared control is still an error, so the fix is to bind
/// the name rather than to stop reporting that it is unbound.
#[test]
fn a_list_filter_capture_binds_the_selected_element() -> Result<()> {
    const TAGGED: &str = r#"
    Resources:
      B:
        Type: AWS::S3::Bucket
        Properties:
          Names: [x, y]
          Tags:
            - Key: Name
              Value: dev
            - Key: Env
              Value: prod
    "#;
    let cases = [
        (
            "wildcard then filter, map elements, not empty",
            "rule r { Resources.*.Properties.Tags[*][ t | Key == 'Name' ] !empty\n%t !empty }",
            Status::PASS,
        ),
        (
            "filter on the list, map elements, not empty",
            "rule r { Resources.*.Properties.Tags[ t | Key == 'Name' ] !empty\n%t !empty }",
            Status::PASS,
        ),
        (
            "the selected element's field",
            "rule r { Resources.*.Properties.Tags[*][ t | Key == 'Name' ] !empty\n%t.Value == 'dev' }",
            Status::PASS,
        ),
        (
            "exists opens a gate over a failing body",
            "rule r { Resources.*.Properties.Tags[*][ t | Key == 'Name' ] !empty\n\
             when %t exists { %t.Value == 'zzz' } }",
            Status::FAIL,
        ),
        (
            "wildcard then filter, scalar elements",
            "rule r { Resources.*.Properties.Names[*][ n | this == 'x' ] !empty\n%n == 'x' }",
            Status::PASS,
        ),
        (
            "filter on the list, scalar elements",
            "rule r { Resources.*.Properties.Names[ n | this == 'x' ] !empty\n%n == 'x' }",
            Status::PASS,
        ),
        (
            "map capture control",
            "rule r { Resources[ nm | Type == 'AWS::S3::Bucket' ] !empty\n%nm == 'B' }",
            Status::PASS,
        ),
    ];

    let mut got = Vec::new();
    for (label, rules, _) in &cases {
        got.push((*label, status_of(rules, TAGGED)?));
    }
    assert_eq!(
        cases
            .iter()
            .map(|(label, _, want)| (*label, *want))
            .collect::<Vec<_>>(),
        got,
        "a FAIL where PASS is wanted is the capture resolving to no values; a PASS on the gate case is \
         `%t exists` skipping over an unbound name"
    );

    assert!(
        status_of(
            "rule r { Resources.*.Properties.Tags[*][ Key == 'Name' ] !empty\n%t !empty }",
            TAGGED
        )
        .is_err(),
        "a name no filter declares is the rules file's error, and binding declared names must not \
         change that"
    );

    Ok(())
}

/// The one capture contract, on three paths where a capture can bind nothing or the wrong thing.
///
/// A capture over a map's entries binds the key; a capture over a list binds the element. Three paths
/// did neither or did the wrong one:
///
/// - A named wildcard over a list, `Tags[ t ]`, parses to `AllIndices(Some("t"))` and bound only when
///   the value was a map. Over a list it bound nothing, so `%t exists` skipped and a `when` on it never
///   opened its body.
/// - A capture consumed the reserved slot like any other variable root: `variable_binding_query`
///   answers `None` for it, which the root-variable arm read as "did not enumerate" and so walked the
///   slot. A key is a scalar and the walk is a pass-through for it, which is why this went unnoticed
///   while every capture was a key. A list element is not: `%g IS_LIST` over a captured `[1, 2]`
///   enumerated the two numbers and failed, and `%t[ Key == 'Name' ]` over a captured tag walked into
///   the tag's own entries and selected nothing. A capture's values are already the members, so the
///   slot is consumed, as it is for a projecting `let`.
/// - A capture on a projection, `%buckets[ b | ... ]` over `let buckets = Resources.*[ ... ]`, reached
///   the filter arm through the consumed slot with the member in hand and no key, and bound the member:
///   `%b` was the bucket's body. The member's path ends in its key, so the key is bound from there; a
///   member of a projected *list* has an index there and binds the element.
///
/// `Resources.B.%t` with `t` bound to a tag is pinned as what it is, an error: the interpolated-key
/// walk wants a string and is handed a map. Whether that should resolve is a question for that walk,
/// not for the binding.
#[test]
fn a_capture_binds_the_key_of_a_map_entry_and_the_element_of_a_list_on_every_path() -> Result<()> {
    const TEMPLATE: &str = r#"
    Cfg:
      Groups:
        - [1, 2]
        - [3, 4]
      Items:
        - V: 1
        - V: 2
      Digits:
        "0": {v: 1}
        "1": {v: 2}
    Resources:
      A:
        Type: AWS::S3::Bucket
        Properties:
          Tags:
            - Key: Name
              Value: dev
            - Key: Env
              Value: prod
      Vol:
        Type: AWS::EC2::Volume
        Properties:
          Size: 8
      R1:
        Type: AWS::IAM::Role
        Properties:
          Labels:
            x: {v: 1}
          Policies:
            P1: {Action: a}
            P2: {Action: b}
      R2:
        Type: AWS::IAM::Role
        Properties:
          Labels:
            y: {v: 2}
          Policies:
            P1: {Action: a}
            P2: {Action: b}
    X:
      Labels:
        a: prod
        b: dev
      Annotations:
        kubernetes.io/name: {v: 1}
        other/thing: {v: 2}
      paths:
        /pets: {get: {}}
        /: {get: {}}
    "#;
    let cases = [
        (
            "a named wildcard over a list binds the element, so `exists` is decided",
            "rule r { Resources.A.Properties.Tags[ t ] !empty\nwhen %t exists { %t.Key == 'zzz' } }",
            Status::FAIL,
        ),
        (
            "a list-valued capture is read whole",
            "rule r { Cfg.Groups[ g | some this[*] == 1 ] !empty\n%g IS_LIST }",
            Status::PASS,
        ),
        (
            "a filter on a map-valued capture tests the element, not its entries",
            "rule r { Resources.A.Properties.Tags[ t | Key == 'Name' ] !empty\n%t[ Key == 'Name' ] !empty }",
            Status::PASS,
        ),
        (
            "a capture on a projection of a map binds the logical id",
            "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
             rule r { %buckets[ b | Properties exists ] !empty\n%b == 'A' }",
            Status::PASS,
        ),
        (
            "a capture on a projection of a list binds the element",
            "let items = Cfg.Items.*\nrule r { %items[ i | V == 1 ] !empty\n%i.V == 1 }",
            Status::PASS,
        ),
        (
            "control: the plain key capture still binds the key",
            "rule r { Resources[ nm | Type == 'AWS::S3::Bucket' ] !empty\n%nm == 'A' }",
            Status::PASS,
        ),
        // The key comes from the parent container, never from the member's path string: a key
        // holding `/` is one key, and the path's last segment is not it.
        (
            "a projected map entry whose key holds a slash binds the whole key",
            "let a = X.Annotations.*\nrule r { %a[ k | v == 1 ] !empty\n%k == 'kubernetes.io/name' }",
            Status::PASS,
        ),
        (
            "projected OpenAPI paths bind `/pets` and `/`",
            "let p = X.paths.*\nrule r { %p[ q | get exists ] !empty\n%q in ['/pets', '/'] }",
            Status::PASS,
        ),
        (
            "a projection of scalar entries binds the value",
            "let m = X.Labels.*\nrule r { %m[ k | this == 'prod' ] !empty\n%k == 'prod' }",
            Status::PASS,
        ),
        (
            "the direct filter on the same map binds the key",
            "rule r { X.Labels[ k | this == 'prod' ] !empty\n%k == 'a' }",
            Status::PASS,
        ),
        // One enumeration decision for a capture: the query path reads the two captured lists
        // whole, and a function argument counts the same two.
        (
            "a function argument sees the capture as the query path does",
            "rule r { Cfg.Groups[ g | this[*] > 0 ] !empty\n%g IS_LIST\nlet n = count(%g)\n%n == 2 }",
            Status::PASS,
        ),
        // The parent container is found in the scope that OWNS the binding, not the reader's. A
        // file-level `let` is owned by the document root, so `Resources` is in reach from a block
        // clause or a type block body whose own root is the role resource. Resolving it through the
        // reader's scope found no `Resources` there and bound the member's body: the comparison
        // failed with "PathAwareValues are not comparable map, String" where the rule-level and
        // `when` spellings, whose roots are the document, passed.
        (
            "a projection capture read at rule level binds the key (control)",
            "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
             rule r { %buckets[ b | Properties exists ] !empty\n%b == 'A' }",
            Status::PASS,
        ),
        (
            "a projection capture read inside a `when` block binds the key (control)",
            "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
             rule r { when Resources exists { %buckets[ b | Properties exists ] !empty\n%b == 'A' } }",
            Status::PASS,
        ),
        (
            "a projection capture read inside a block clause over another resource binds the key",
            "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
             rule r { Resources.*[ Type == 'AWS::EC2::Volume' ] { \
             %buckets[ b | Properties exists ] !empty\n%b == 'A' } }",
            Status::PASS,
        ),
        (
            "a projection capture read inside a type block over another resource binds the key",
            "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
             rule r { AWS::EC2::Volume { %buckets[ b | Properties exists ] !empty\n%b == 'A' } }",
            Status::PASS,
        ),
        // Keys that are strings of digits: a map keyed "0" and "1" binds '0' and '1', because the
        // parent is a map. This row pins the parent-kind rule (a path-derived key read the digits as
        // list indices), not the owning-scope rule the rows above and below pin; the list-projection
        // row earlier in this table is its control.
        (
            "a projected map keyed '0' and '1' binds the keys '0' and '1', not the members",
            "let digits = Cfg.Digits.*\nrule r { %digits[ b | v exists ] !empty\n%b in ['0', '1'] }",
            Status::PASS,
        ),
        // Ownership is decided by the one walk that finds the binding. A separate owner computation
        // named the alias (`bs`) where the walk had already followed `%bs` to the file-level `let`,
        // so the prefix ran at the alias's scope -- the role resource -- and `b` bound the body.
        (
            "a projection read through an alias bound in the type block binds the key",
            "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
             rule r { AWS::EC2::Volume { let bs = %buckets\n\
             %bs[ b | Properties exists ] !empty\n%b == 'A' } }",
            Status::PASS,
        ),
        (
            "a projection passed as a parameterized rule's argument binds the key",
            "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
             rule check(bs) { %bs[ b | Properties exists ] !empty\n%b == 'A' }\n\
             rule r { AWS::EC2::Volume { check(%buckets) } }",
            Status::PASS,
        ),
        // The walk hands off to a parent block as `Hidden`, as every other lookup does: a key a
        // nested `when` captured under the same name is not this reader's binding.
        (
            "a sibling block's merged capture of the same name does not hide the file-level binding",
            "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
             rule r { AWS::IAM::Role { \
             when Properties.Labels exists { Properties.Labels[ buckets | v exists ] !empty }\n\
             when Properties exists { %buckets[ b | Properties exists ] !empty\n%b == 'A' } } }",
            Status::PASS,
        ),
        // The capture's count, measured and pinned as a pair so neither can become a duplicate-driven
        // number: inside an iteration `%id` holds the ids this read captured (one bucket here); after
        // the type block it holds the union over both roles' iterations, as a merged key does.
        // Finding the projection's container plays no part in either, and is memoized per binding
        // only for its cost.
        (
            "inside a type block iteration the capture counts the ids of that read",
            "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
             rule r { AWS::IAM::Role { %buckets[ id | Properties exists ] !empty\n\
             let n = count(%id)\n%n == 1 } }",
            Status::PASS,
        ),
        (
            "after the type block the capture is the union over both iterations",
            "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
             rule r { AWS::IAM::Role { %buckets[ id | Properties exists ] !empty }\n\
             let n = count(%id)\n%n == 2 }",
            Status::PASS,
        ),
        // A block-level `let` is owned by the block's scope, whose root is the role; a block clause
        // nested in it reads the projection with the role's own root, not the policy it iterates.
        (
            "a block-level projection read from a nested block clause binds the key",
            "rule r { AWS::IAM::Role { let pols = Properties.Policies.*\n\
             Properties.Policies.* { %pols[ p | Action exists ] !empty\n%p in ['P1', 'P2'] } } }",
            Status::PASS,
        ),
    ];

    let mut got = Vec::new();
    for (label, rules, _) in &cases {
        got.push((*label, status_of(rules, TEMPLATE)?));
    }
    assert_eq!(
        cases
            .iter()
            .map(|(label, _, want)| (*label, *want))
            .collect::<Vec<_>>(),
        got
    );

    // The interpolation walk still refuses a map as a key. The refusal is the data's (the capture holds
    // what the template holds), so it is held like every other data-side refusal rather than returned:
    // the clause fails, the rule fails, and the run goes on. The rules-file
    // spelling of a non-string key is the one that still returns at once.
    let interpolated = status_of(
        "rule r { Resources.A.Properties.Tags[ t | Key == 'Name' ] !empty\nResources.A.%t exists }",
        TEMPLATE,
    );
    assert!(
        matches!(&interpolated, Ok(Status::FAIL)),
        "a map-valued capture used as an interpolated key is refused by that walk and the clause fails; got {:?}",
        interpolated
    );

    Ok(())
}

/// A capture passed to a parameterized rule as a bare `%g` is read whole in the called rule, as `%g` is
/// read in the caller: a captured tag is filtered as one map, a captured list is one list.
///
/// The parameter's values are the caller's `g`, and `ResolvedParameterContext::binding_step` already
/// defers a bare-`%v` argument to the caller for the binding question. `binding_is_a_capture` answered
/// `false` for every parameter before asking, so the root-variable arm walked the reserved slot into
/// the captured value: `%x[ Key == 'Name' ]` over a captured tag walked into the tag's entries and the
/// filter met a string, "Filter on value type that was not a struct or array", exit 19, where the
/// caller's `%t[ Key == 'Name' ]` passes. One contract on every path, broken through a parameter. The
/// list shape reads PASS on both sides here and is kept as the pin.
#[test]
fn a_capture_passed_to_a_parameterized_rule_is_read_whole() -> Result<()> {
    assert_eq!(
        status_of(
            "rule check(x) { %x[ Key == 'Name' ] !empty }\n\
             rule r { Resources.A.Properties.Tags[ t | Key == 'Name' ] !empty\ncheck(%t) }",
            "Resources:\n  A:\n    Properties:\n      Tags:\n        - Key: Name\n          Value: dev\n"
        )?,
        Status::PASS,
        "`%x` is the caller's captured tag, one map the filter tests whole; an error is the slot \
         walked into the tag's entries"
    );
    assert_eq!(
        status_of(
            "rule check(x) { %x IS_LIST }\n\
             rule r { Cfg.Groups[ g | some this[*] == 1 ] !empty\ncheck(%g) }",
            GROUPS
        )?,
        Status::PASS,
        "`%x` is the caller's capture `g`, one list, so IS_LIST holds; FAIL is the slot walked into \
         the list's scalars"
    );
    assert_eq!(
        status_of(
            "rule r { Cfg.Groups[ g | some this[*] == 1 ] !empty\n%g IS_LIST }",
            GROUPS
        )?,
        Status::PASS,
        "control: the same capture read in the capturing rule"
    );
    // A parameter passed as a projecting query still owes nothing, and one passed as an unprojected
    // list still owes its enumeration: the deferral is for a bare `%v` only.
    assert_eq!(
        status_of(
            "rule check(x) { %x[*] IS_LIST }\nrule r { check(Cfg.Groups) }",
            GROUPS
        )?,
        Status::PASS,
        "control: `Cfg.Groups` is one list of two lists, enumerated by the author's `[*]`"
    );
    Ok(())
}

/// `let x = %g` over a filter capture `g` is the same binding under another name, so `%x` is read as
/// `%g` is: the captured members, whole. A captured list is one list to `IS_LIST` and one value to
/// `count`; a captured tag is one map to a filter and the map `.Value` is read from.
///
/// Every alias cell is paired with the capture read directly, because the defect was that they
/// disagreed. The binding walk already follows a `let` to the bare variable it names and answers
/// "no query" for a capture, so the root-variable arm asked whether *the alias* is a capture, which
/// it is not, and walked the reserved slot into the captured value: `%x IS_LIST` over a captured
/// `[1, 2]` tested the two numbers and failed, and `%x[ Key == 'Name' ]` over a captured tag walked
/// into the tag's entries and the filter met a string. The capture question now follows the same
/// aliases the binding walk does, in the scope that holds the `let`: a rule-level alias, a two-hop
/// alias, and one bound inside a type block whose own clause made the capture.
#[test]
fn an_alias_of_a_capture_is_read_as_the_capture_is() -> Result<()> {
    const TEMPLATE: &str = r#"
    Cfg:
      Groups:
        - [1, 2]
        - [3, 4]
    Resources:
      A:
        Type: AWS::S3::Bucket
        Properties:
          Tags:
            - Key: Name
              Value: dev
            - Key: Env
              Value: prod
    "#;
    const LIST_CAPTURE: &str = "Cfg.Groups[ g | this[*] > 0 ] !empty";
    const MAP_CAPTURE: &str = "Resources.A.Properties.Tags[ t | Key == 'Name' ] !empty";
    let cases = [
        (
            "control: a captured list is one list",
            format!("rule r {{ {LIST_CAPTURE}\n%g IS_LIST }}"),
            Status::PASS,
        ),
        (
            "an alias of a captured list is one list",
            format!("rule r {{ {LIST_CAPTURE}\nlet x = %g\n%x IS_LIST }}"),
            Status::PASS,
        ),
        (
            "control: a function counts the captured lists",
            format!("rule r {{ {LIST_CAPTURE}\nlet n = count(%g)\n%n == 2 }}"),
            Status::PASS,
        ),
        (
            "a function counts an alias of the capture the same",
            format!("rule r {{ {LIST_CAPTURE}\nlet x = %g\nlet n = count(%x)\n%n == 2 }}"),
            Status::PASS,
        ),
        (
            "control: a filter on a captured tag tests the tag",
            format!("rule r {{ {MAP_CAPTURE}\n%t[ Key == 'Name' ] !empty }}"),
            Status::PASS,
        ),
        (
            "a filter on an alias of a captured tag tests the tag",
            format!("rule r {{ {MAP_CAPTURE}\nlet x = %t\n%x[ Key == 'Name' ] !empty }}"),
            Status::PASS,
        ),
        (
            "control: a field of a captured tag",
            format!("rule r {{ {MAP_CAPTURE}\n%t.Value == 'dev' }}"),
            Status::PASS,
        ),
        (
            "a field of an alias of a captured tag",
            format!("rule r {{ {MAP_CAPTURE}\nlet x = %t\n%x.Value == 'dev' }}"),
            Status::PASS,
        ),
        (
            "a field of an alias still fails when the capture's would",
            format!("rule r {{ {MAP_CAPTURE}\nlet x = %t\n%x.Value == 'zzz' }}"),
            Status::FAIL,
        ),
        (
            "an alias of an alias is read the same",
            format!(
                "rule r {{ {MAP_CAPTURE}\nlet x = %t\nlet y = %x\n%y[ Key == 'Name' ] !empty }}"
            ),
            Status::PASS,
        ),
        (
            "an alias bound in a type block of the block's own capture",
            "rule r { AWS::S3::Bucket { Properties.Tags[ t | Key == 'Name' ] !empty\n\
             let x = %t\n%x[ Key == 'Name' ] !empty\n%x.Value == 'dev' } }"
                .to_string(),
            Status::PASS,
        ),
    ];

    let mut got = Vec::new();
    for (label, rules, _) in &cases {
        got.push((
            *label,
            status_of(rules, TEMPLATE).map_err(|error| error.to_string()),
        ));
    }
    assert_eq!(
        cases
            .iter()
            .map(|(label, _, want)| (*label, Ok::<Status, String>(*want)))
            .collect::<Vec<_>>(),
        got,
        "an alias cell that differs from its control is the reserved slot walked into the captured \
         value; an Err is the filter meeting the entries of a tag it should have tested whole"
    );

    Ok(())
}

/// An alias of a capture also has the capture's shape on the right-hand side of `IN`: a capture names
/// its values, so a captured string is a haystack and `Cfg.Prefix IN %a` holds for `gp` over a captured
/// `gp2`, and `let x = %a` is read the same way. The `let` records the shape its own retrieval
/// reported, which folds in the capture's `Names` and adds nothing for a bare `%a`, so the two agree
/// by construction; these pairs pin that, on each route an alias can be bound: at rule level, two
/// aliases deep, and in a type block whose own clause made the capture. Each pair compares the alias
/// against the capture rather than against a fixed verdict, because the contract is the agreement.
#[test]
fn an_alias_of_a_capture_has_the_captures_shape_under_in() -> Result<()> {
    const TEMPLATE: &str = r#"
    Cfg:
      Types: [gp2, gp3]
      Default: gp3
      Prefix: gp
      Other: io1
      Letter: A
    Resources:
      A:
        Type: AWS::S3::Bucket
        Properties:
          Short: de
          Tags:
            - Key: Name
              Value: dev
    "#;
    const LIST_CAPTURE: &str = "Cfg.Types[ a | this != 'none' ] !empty";
    const KEY_CAPTURE: &str = "Resources[ nm | Type == 'AWS::S3::Bucket' ] !empty";
    let pairs = [
        (
            "a captured string is a haystack to IN",
            format!("rule r {{ {LIST_CAPTURE}\nCfg.Prefix IN %a }}"),
            format!("rule r {{ {LIST_CAPTURE}\nlet x = %a\nCfg.Prefix IN %x }}"),
        ),
        (
            "a whole captured string is in the set",
            format!("rule r {{ {LIST_CAPTURE}\nCfg.Default IN %a }}"),
            format!("rule r {{ {LIST_CAPTURE}\nlet x = %a\nCfg.Default IN %x }}"),
        ),
        (
            "NOT IN over the capture",
            format!("rule r {{ {LIST_CAPTURE}\nCfg.Other NOT IN %a }}"),
            format!("rule r {{ {LIST_CAPTURE}\nlet x = %a\nCfg.Other NOT IN %x }}"),
        ),
        (
            "two aliases deep",
            format!("rule r {{ {LIST_CAPTURE}\nCfg.Prefix IN %a }}"),
            format!("rule r {{ {LIST_CAPTURE}\nlet x = %a\nlet y = %x\nCfg.Prefix IN %y }}"),
        ),
        (
            "a captured key is a haystack to IN",
            format!("rule r {{ {KEY_CAPTURE}\nCfg.Letter IN %nm }}"),
            format!("rule r {{ {KEY_CAPTURE}\nlet x = %nm\nCfg.Letter IN %x }}"),
        ),
        (
            "an alias bound in a type block of the block's own capture",
            "rule r { AWS::S3::Bucket { Properties.Tags[ t | Key == 'Name' ] !empty\n\
             Properties.Short IN %t.Value } }"
                .to_string(),
            "rule r { AWS::S3::Bucket { Properties.Tags[ t | Key == 'Name' ] !empty\n\
             let x = %t\nProperties.Short IN %x.Value } }"
                .to_string(),
        ),
        (
            "the capture on the left of IN",
            format!("rule r {{ {LIST_CAPTURE}\n%a IN ['gp2', 'gp3'] }}"),
            format!("rule r {{ {LIST_CAPTURE}\nlet x = %a\n%x IN ['gp2', 'gp3'] }}"),
        ),
        (
            "the capture on the left of IN against a shorter value",
            format!("rule r {{ {LIST_CAPTURE}\n%a IN ['gp'] }}"),
            format!("rule r {{ {LIST_CAPTURE}\nlet x = %a\n%x IN ['gp'] }}"),
        ),
        // The other route an alias takes: a parameterized rule's parameter, passed the capture.
        (
            "a parameter passed the capture, on the right of IN",
            format!("rule r {{ {LIST_CAPTURE}\nCfg.Prefix IN %a }}"),
            format!("rule check(p) {{ Cfg.Prefix IN %p }}\nrule r {{ {LIST_CAPTURE}\ncheck(%a) }}"),
        ),
        (
            "a parameter passed the capture, on the left of IN",
            format!("rule r {{ {LIST_CAPTURE}\n%a IN ['gp'] }}"),
            format!("rule check(p) {{ %p IN ['gp'] }}\nrule r {{ {LIST_CAPTURE}\ncheck(%a) }}"),
        ),
        (
            "a parameter passed an alias of the capture, on the right of IN",
            format!("rule r {{ {LIST_CAPTURE}\nCfg.Prefix IN %a }}"),
            format!(
                "rule check(p) {{ Cfg.Prefix IN %p }}\nrule r {{ {LIST_CAPTURE}\nlet x = %a\ncheck(%x) }}"
            ),
        ),
        (
            "a parameter passed a captured key, on the right of IN",
            format!("rule r {{ {KEY_CAPTURE}\nCfg.Letter IN %nm }}"),
            format!("rule check(p) {{ Cfg.Letter IN %p }}\nrule r {{ {KEY_CAPTURE}\ncheck(%nm) }}"),
        ),
    ];

    let mut readings = Vec::new();
    for (label, capture, alias) in &pairs {
        let of_capture = status_of(capture, TEMPLATE).map_err(|error| error.to_string());
        let of_alias = status_of(alias, TEMPLATE).map_err(|error| error.to_string());
        readings.push((*label, of_capture, of_alias));
    }
    assert!(
        readings.iter().all(|(_, capture, alias)| capture == alias),
        "(label, read through the capture, read through its alias): the alias must answer as the \
         capture does; readings: {:#?}",
        readings
    );

    Ok(())
}

/// Finding the key a projection produced a member under costs one lookup per member, after one pass
/// over the containers per binding, and nothing at all when the filter declares no capture.
///
/// Eight buckets and four roles. Inside `AWS::IAM::Role { ... }` the clause runs four times and reads
/// eight members each time. The containers the binding enumerated (`Resources`, twelve entries) are
/// indexed by member path once per binding, 12 probes, and each member is then one lookup, 4 x 8 = 32
/// probes: 44. Scanning the container's entries by path for every member instead cost the member's
/// position in the map each time, 1 + 2 + ... + 8 = 36 per role, 144 in all, and grows with the
/// number of resources cubed inside a type block. An unnamed filter `%buckets[ Properties exists ]`
/// binds no key and asks for none.
#[test]
fn a_projection_capture_finds_each_members_key_in_linear_time() -> Result<()> {
    use crate::rules::eval_context::PROJECTION_KEY_PROBES;

    let mut template = String::from("Resources:\n");
    for bucket in ["A", "B", "C", "D", "E", "F", "G", "H"] {
        template.push_str(&format!(
            "  {bucket}:\n    Type: AWS::S3::Bucket\n    Properties:\n      Name: {bucket}\n"
        ));
    }
    for role in ["R1", "R2", "R3", "R4"] {
        template.push_str(&format!(
            "  {role}:\n    Type: AWS::IAM::Role\n    Properties:\n      Name: {role}\n"
        ));
    }
    const NAMED: &str = "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
         rule r { AWS::IAM::Role { %buckets[ b | Properties exists ] !empty\n\
         %b in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'] } }";
    const UNNAMED: &str = "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n\
         rule r { AWS::IAM::Role { %buckets[ Properties exists ] !empty } }";

    PROJECTION_KEY_PROBES.with(|probes| probes.set(0));
    assert_eq!(status_of(NAMED, &template)?, Status::PASS);
    let named = PROJECTION_KEY_PROBES.with(|probes| probes.get());
    assert_eq!(
        named, 44,
        "12 entries indexed once for the binding plus 4 x 8 member lookups; a per-member scan of the \
         container's entries reads 144"
    );

    PROJECTION_KEY_PROBES.with(|probes| probes.set(0));
    assert_eq!(status_of(UNNAMED, &template)?, Status::PASS);
    let unnamed = PROJECTION_KEY_PROBES.with(|probes| probes.get());
    assert_eq!(
        unnamed, 0,
        "a filter with no capture name binds no key and asks for none"
    );
    Ok(())
}

/// The probe behind the bound-map filter notice runs once for the evaluation of a site that never
/// qualifies, and not at all under a measurement.
///
/// `let r = Resources` with `%r[ Type == 'AWS::S3::Bucket' ]` is the idiom the notice must stay quiet
/// on: the predicate does not hold on `Resources`, so the site never qualifies and no notice is ever
/// recorded for it; the one evaluation here re-runs the predicate against the map once, and the quiet
/// verdict the absence gate records at that exit spares the evaluations after the first (the collection
/// row of `an_object_the_predicate_did_not_hold_on_is_re_walked_once_or_not_at_all` pins that count
/// over twelve). A `when` whose conditions read a function result
/// holding an unresolved entry beside a resolved one is measured as well: its conditions are re-run
/// three times (as written, one at a time; with the unresolved entries dropped, as a set and one at a
/// time), and the root records no notice under a measurement, so a probe there can learn nothing and
/// the three re-runs paid for three probes. One probe for the evaluation, none for the readings.
///
/// The measurement is made visible, so the count of one means "not under the readings" and not "no
/// readings were taken": the first condition, `Resources.%lowered exists`, answers PASS as written and
/// FAIL with the unresolved entry dropped, so the `when` is announced as moved, and that notice is asserted
/// beside the count. A later change that stopped measuring this `when` would read one probe for a
/// different reason, and the missing notice would say so.
#[test]
fn the_bound_map_filter_probe_runs_once_and_not_under_a_measurement() -> Result<()> {
    use crate::rules::eval_context::BOUND_MAP_FILTER_PROBES;

    const TEMPLATE: &str = "Resources:\n\
         \x20 b:\n    Type: AWS::S3::Bucket\n    Properties:\n      Name: b\n\
         \x20 c:\n    Type: AWS::S3::Bucket\n    Properties:\n      Other: 1\n";
    const RULES: &str = "let r = Resources\n\
         let lowered = to_lower(Resources.*.Properties.Name)\n\
         rule r when Resources.%lowered exists\n\
                     %r[ Type == 'AWS::S3::Bucket' ] !empty { Resources.b.Type == 'AWS::S3::Bucket' }";

    BOUND_MAP_FILTER_PROBES.with(|probes| probes.set(0));
    let rules_file = RulesFile::try_from(RULES)?;
    let value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(TEMPLATE).unwrap())?;
    let mut scope = root_scope(&rules_file, Rc::new(value));
    let status = crate::rules::eval::eval_rules_file(&rules_file, &mut scope, None)?;
    let probes = BOUND_MAP_FILTER_PROBES.with(|probes| probes.get());
    let notices: Vec<String> = scope.deprecations().cloned().collect();
    assert_eq!(
        Status::SKIP,
        status,
        "the interpolated key reads the unresolved entry as well, so the gate does not open"
    );
    assert!(
        notices.iter().any(|notice| {
            notice.contains("the `when` whose condition `Resources.%lowered exists` is at")
                && notice.contains("answers FAIL where before this release it answered PASS")
        }),
        "the when was measured, and its answer moved: {:?}",
        notices
    );
    assert_eq!(
        probes, 1,
        "one probe for the evaluation as written; the three measured readings of the conditions \
         probe nothing, since no notice can be recorded under a measurement"
    );
    Ok(())
}

/// An idiom site whose predicate holds on the map by a pass anchored by nothing is read once per run, not
/// once per evaluation, and never pays the re-walk that counts a notice's selection.
///
/// `let r = Resources` with `%r[ Properties.Tags empty ] !empty` inside a type block that matches three of
/// the four resources: the clause is evaluated three times. The first evaluation probes once, reads the
/// four entries once, finds a uniform collection (every entry a map on which `Properties` resolves),
/// records the site as quiet, and the next two evaluations stop at the recorded-site check: 1 probe, 4
/// entry probes, 0 re-walks, no notice, the rule FAILing on the untagged buckets as it should. Sparing
/// a site only after it has recorded a notice would run every evaluation through the probe, the re-walk
/// over the four entries and the entry check, since a quiet site records none: 3 probes, 3 re-walks (12
/// predicate runs), 3 entry reads.
#[test]
fn a_quiet_bound_map_filter_site_is_read_once_and_never_re_walked() -> Result<()> {
    use crate::rules::eval_context::{
        BOUND_MAP_ENTRY_PROBES, BOUND_MAP_FILTER_PROBES, BOUND_MAP_FILTER_REWALKS,
    };

    const TEMPLATE: &str = "Resources:\n\
         \x20 b1:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: b1\n\
         \x20 b2:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: b2\n\
         \x20 b3:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: b3\n\
         \x20 q:\n    Type: AWS::SQS::Queue\n    Properties:\n      QueueName: q\n";
    const RULES: &str = "let r = Resources\n\
         rule r { AWS::S3::Bucket { %r[ Properties.Tags empty ] !empty } }";

    BOUND_MAP_FILTER_PROBES.with(|probes| probes.set(0));
    BOUND_MAP_FILTER_REWALKS.with(|rewalks| rewalks.set(0));
    BOUND_MAP_ENTRY_PROBES.with(|probes| probes.set(0));
    let rules_file = RulesFile::try_from(RULES)?;
    let value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(TEMPLATE).unwrap())?;
    let mut scope = root_scope(&rules_file, Rc::new(value));
    let status = crate::rules::eval::eval_rules_file(&rules_file, &mut scope, None)?;
    let probes = BOUND_MAP_FILTER_PROBES.with(|probes| probes.get());
    let rewalks = BOUND_MAP_FILTER_REWALKS.with(|rewalks| rewalks.get());
    let entry_probes = BOUND_MAP_ENTRY_PROBES.with(|probes| probes.get());
    let notices: Vec<String> = scope.deprecations().cloned().collect();

    assert_eq!(
        Status::PASS,
        status,
        "every bucket lacks tags, so the untagged selection is not empty in each of the three evaluations"
    );
    assert!(
        notices.is_empty(),
        "a uniform collection of resources is the idiom, nothing announced: {:?}",
        notices
    );
    assert_eq!(
        (probes, entry_probes, rewalks),
        (1, 4, 0),
        "one probe and one read of the four entries for the first evaluation, then the recorded quiet \
         site spares the other two; the re-walk is paid only when a notice goes out"
    );
    Ok(())
}

/// An object the predicate did not hold on is re-walked once per site for an absence check, and never
/// for a positive predicate.
///
/// `let s = spec` over a Deployment `spec` of `selector`, `template` and `strategy` (sub-maps sharing no
/// key name) with a scalar `replicas` beside them: an object. The filter sits inside a type block that
/// matches twelve buckets, so the clause is evaluated twelve times. Three predicates:
/// - `%s[ securityContext exists ] empty` does not hold on the object and can hold on no field of it
///   either, since `exists` never holds by absence, so nothing can have been gained: the probe stops it
///   before the object test, no entry is read, no re-walk is paid, and the quiet verdict is recorded
///   there, so the next eleven evaluations stop at the recorded-site check: one probe in all. Before
///   the absence check gated the branch, this site paid one probe and one re-walk and then stopped at
///   the recorded-site check too.
/// - `%s[ not securityContext exists ] !empty` is the same absence check spelled with a leading `not`,
///   which the evaluator applies as it applies `!exists`: held by absence on the object and announced
///   once, as the `!exists` control below is.
/// - `%s[ securityContext !exists ] empty` over a `spec` that carries a `securityContext` and whose
///   map-valued fields each carry one too (a scalar `replicas` beside them keeps it an object): the
///   predicate does not hold on the object, the walk selects nothing of use, both readings agree and
///   nothing is announced; the gained path's quiet exit records the verdict, so the re-walk is paid once
///   and the next eleven evaluations stop at the recorded-site check, the probe included.
/// - `%s[ securityContext !exists ] !empty` over the first `spec`, held by absence on the object and
///   announced as a lost selection: one probe, one re-walk, one notice, the control, as before.
#[test]
fn an_object_the_predicate_did_not_hold_on_is_re_walked_once_or_not_at_all() -> Result<()> {
    use crate::rules::eval_context::{
        BOUND_MAP_ENTRY_PROBES, BOUND_MAP_FILTER_PROBES, BOUND_MAP_FILTER_REWALKS,
    };

    let mut buckets = String::from("Resources:\n");
    for i in 0..12 {
        buckets.push_str(&format!(
            "  b{i}:\n    Type: AWS::S3::Bucket\n    Properties:\n      Name: b{i}\n"
        ));
    }
    let object = format!(
        "{buckets}spec:\n  replicas: 3\n  selector:\n    matchLabels:\n      app: a\n  template:\n    \
         metadata:\n      labels:\n        app: a\n  strategy:\n    type: Recreate\n"
    );
    let carrying = format!(
        "{buckets}spec:\n  replicas: 3\n  securityContext:\n    securityContext: {{}}\n  selector:\n    \
         securityContext:\n      runAsNonRoot: true\n"
    );
    // (probes, re-walks, entry probes, notices) over the twelve evaluations.
    type Counts = (usize, usize, usize, usize);
    let rows: [(&str, &str, &str, Counts); 6] = [
        (
            "a positive predicate that did not hold on the object: one probe, no re-walk, then the recorded quiet verdict on the other eleven evaluations",
            &object,
            "let s = spec\nrule r { AWS::S3::Bucket { %s[ securityContext exists ] empty } }",
            (1, 0, 0, 0),
        ),
        (
            "an absence check spelled with a leading `not`, held on the object: announced once as a lost selection, as the `!exists` spelling is",
            &object,
            "let s = spec\nrule r { AWS::S3::Bucket { %s[ not securityContext exists ] !empty } }",
            (1, 1, 0, 1),
        ),
        (
            "the `not` spelling that did not hold on the object and selected nothing: one re-walk, then the recorded quiet verdict",
            &carrying,
            "let s = spec\nrule r { AWS::S3::Bucket { %s[ not securityContext exists ] empty } }",
            (1, 1, 0, 0),
        ),
        (
            "an absence check that did not hold on the object and selected nothing: one re-walk, then the recorded quiet verdict",
            &carrying,
            "let s = spec\nrule r { AWS::S3::Bucket { %s[ securityContext !exists ] empty } }",
            (1, 1, 0, 0),
        ),
        (
            "the control: an absence check held on the object, announced once as a lost selection",
            &object,
            "let s = spec\nrule r { AWS::S3::Bucket { %s[ securityContext !exists ] !empty } }",
            (1, 1, 0, 1),
        ),
        (
            "the common idiom over a collection, `%r[ Type == 'AWS::S3::Bucket' ]` with `let r = Resources`, inside the type block: one probe, then the recorded quiet verdict on the other eleven evaluations",
            &object,
            "let r = Resources\nrule r { AWS::S3::Bucket { %r[ Type == 'AWS::S3::Bucket' ] !empty } }",
            (1, 0, 0, 0),
        ),
    ];
    for (label, doc, rules, expected) in rows {
        BOUND_MAP_FILTER_PROBES.with(|probes| probes.set(0));
        BOUND_MAP_FILTER_REWALKS.with(|rewalks| rewalks.set(0));
        BOUND_MAP_ENTRY_PROBES.with(|probes| probes.set(0));
        let rules_file = RulesFile::try_from(rules)?;
        let value =
            PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(doc).unwrap())?;
        let mut scope = root_scope(&rules_file, Rc::new(value));
        let _ = crate::rules::eval::eval_rules_file(&rules_file, &mut scope, None)?;
        let probes = BOUND_MAP_FILTER_PROBES.with(|probes| probes.get());
        let rewalks = BOUND_MAP_FILTER_REWALKS.with(|rewalks| rewalks.get());
        let entry_probes = BOUND_MAP_ENTRY_PROBES.with(|probes| probes.get());
        let notices = scope.deprecations().count();
        assert_eq!(
            (probes, rewalks, entry_probes, notices),
            expected,
            "{label}: (probes, re-walks, entry probes, notices) over twelve evaluations"
        );
    }
    Ok(())
}

/// A binding that holds several maps pays one probe per map, not one per map per evaluation.
///
/// `let props = Resources.*[ Type exists ].Properties` holds three properties maps, each a single
/// `BucketEncryption` sub-map on which `Tags !exists` holds vacuously: three uniform collections, each
/// quiet. The clause sits in a type block over the same three buckets, so it is evaluated three times
/// and the walk reaches every map on each. The quiet verdict is recorded per map at the site, so the
/// first evaluation probes the three maps and reads their one entry each, and the two evaluations after
/// it find every map recorded: three probes and three entry reads for nine map visits, no re-walk, and
/// nothing announced. Recorded by the site alone the first map would have silenced the other two;
/// recorded by nothing, every evaluation would pay the three probes again (nine).
#[test]
fn a_quiet_multi_map_binding_is_read_once_per_map_and_never_per_evaluation() -> Result<()> {
    use crate::rules::eval_context::{
        BOUND_MAP_ENTRY_PROBES, BOUND_MAP_FILTER_PROBES, BOUND_MAP_FILTER_REWALKS,
    };

    const ENCRYPTED: &str = "    Properties:\n      BucketEncryption:\n        ServerSideEncryptionConfiguration:\n          - ServerSideEncryptionByDefault:\n              SSEAlgorithm: AES256\n";
    let template = format!(
        "Resources:\n  b1:\n    Type: AWS::S3::Bucket\n{ENCRYPTED}  b2:\n    Type: AWS::S3::Bucket\n{ENCRYPTED}  b3:\n    Type: AWS::S3::Bucket\n{ENCRYPTED}"
    );
    const RULES: &str = "let props = Resources.*[ Type exists ].Properties\n\
         rule r { AWS::S3::Bucket { %props[ Tags !exists ] !empty } }";

    BOUND_MAP_FILTER_PROBES.with(|probes| probes.set(0));
    BOUND_MAP_FILTER_REWALKS.with(|rewalks| rewalks.set(0));
    BOUND_MAP_ENTRY_PROBES.with(|probes| probes.set(0));
    let rules_file = RulesFile::try_from(RULES)?;
    let value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(&template).unwrap())?;
    let mut scope = root_scope(&rules_file, Rc::new(value));
    let status = crate::rules::eval::eval_rules_file(&rules_file, &mut scope, None)?;
    let probes = BOUND_MAP_FILTER_PROBES.with(|probes| probes.get());
    let rewalks = BOUND_MAP_FILTER_REWALKS.with(|rewalks| rewalks.get());
    let entry_probes = BOUND_MAP_ENTRY_PROBES.with(|probes| probes.get());
    let notices: Vec<String> = scope.deprecations().cloned().collect();

    assert_eq!(
        Status::PASS,
        status,
        "no properties map carries Tags, so the selection is each properties map's `BucketEncryption` entry, three in each evaluation"
    );
    assert!(
        notices.is_empty(),
        "three uniform collections at one site, nothing announced: {:?}",
        notices
    );
    assert_eq!(
        (probes, entry_probes, rewalks),
        (3, 3, 0),
        "one probe and one entry read per map on the first evaluation, then every map's recorded quiet \
         verdict spares it on the two evaluations after; nine visits, three probes"
    );
    Ok(())
}

/// The probe over the map stops reading at the first conjunction that fails, and the probe over the
/// map's entries reads on past one only while no clause has resolved a key of the entry.
///
/// What the map-level probe answers is whether the predicate holds on the map, and a conjunction with
/// no pass and a failure settles that: the common idiom `%r[ Type == 'X' ... ]` on `Resources` fails
/// its first conjunction on every evaluation, once per matched resource inside a type block, and every
/// clause after it was still read for a `touched` flag that caller throws away. The per-entry probe
/// reads `touched` of a predicate that failed on the entry, a single bit: once some clause has resolved
/// a key of the entry nothing left in the predicate can change it, so the probe stops there too. The
/// case where reading on matters, a
/// conjunction that counts against the predicate on the entry without resolving a key of it followed by
/// one that does, is rare through the evaluator: the entry reading is paid only for a predicate that held
/// on the map by a pass anchored by nothing, and a clause that fails on an entry where the map held has
/// usually met a key the entry carries and the map lacked, which is a resolution, so `touched` is already
/// true when the conjunction counts against the predicate. A clause that errs on the entry (a refused
/// query returns before any grounding is noted) fails it untouched as well, so the read-on is kept and
/// pinned on the probe itself, by `the_entry_probe_reads_past_an_untouched_failure_until_a_clause_resolves_a_key`
/// below; no rules-file shape that reaches it through the evaluator is pinned. Three cells, each counting
/// the clauses `probe_predicate` evaluated over one run:
/// - a predicate whose first conjunction fails on the map: one clause read, not two;
/// - the same two conjunctions the other way round, the pass first: both read, since the stop is at
///   the failure and nothing before it is spared;
/// - a predicate that holds on the map by a vacuous pass beside a `when` that skips there, whose
///   `when` then fails on each of two entries after resolving `Type`: two reads on the map, then one
///   per entry, four in all; the trailing `Tags !exists` is read on no entry, since the failing `when`
///   already resolved a key of each.
#[test]
fn the_map_probe_stops_at_the_first_failing_conjunction_and_the_entry_probe_reads_on() -> Result<()>
{
    use crate::rules::eval_context::BOUND_MAP_PROBE_CLAUSE_READS;

    const TEMPLATE: &str = "Resources:\n\
         \x20 b1:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: b1\n\
         \x20 b2:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: b2\n";

    let mut disagreements = Vec::new();
    for (label, rules, expected_reads, expected_notices) in [
        (
            "the first conjunction fails on the map: the second is not read",
            "let r = Resources\nrule r { %r[ Type == 'AWS::Nope' Properties.Tags empty ] !empty }",
            1,
            0,
        ),
        (
            "the first conjunction passes vacuously and the second fails: both read",
            "let r = Resources\nrule r { %r[ Properties.Tags empty Type == 'AWS::Nope' ] !empty }",
            2,
            0,
        ),
        (
            "the entries are read past a failing conjunction only until a key resolves: the failing `when` resolved `Type`, so the trailing clause is not read",
            "let r = Resources\nrule r { %r[ when Type exists { Type == 'AWS::Nope' } Tags !exists ] !empty }",
            4,
            0,
        ),
    ] {
        BOUND_MAP_PROBE_CLAUSE_READS.with(|reads| reads.set(0));
        let rules_file = RulesFile::try_from(rules)?;
        let value = PathAwareValue::try_from(
            serde_yaml::from_str::<serde_yaml::Value>(TEMPLATE).unwrap(),
        )?;
        let mut scope = root_scope(&rules_file, Rc::new(value));
        crate::rules::eval::eval_rules_file(&rules_file, &mut scope, None)?;
        let reads = BOUND_MAP_PROBE_CLAUSE_READS.with(|reads| reads.get());
        let notices: Vec<String> = scope.deprecations().cloned().collect();
        if reads != expected_reads {
            disagreements.push(format!(
                "{label}: clause reads: wanted {expected_reads}, got {reads}"
            ));
        }
        if notices.len() != expected_notices {
            disagreements.push(format!(
                "{label}: notices: wanted {expected_notices}, got {notices:?}"
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "cells that disagreed:\n{}",
        disagreements.join("\n")
    );
    Ok(())
}

/// Asked whether the predicate touched the root, the probe reads on past a conjunction that counted
/// against the predicate without resolving a key of the root, and stops at the first clause that does;
/// asked only whether it held, it stops at that conjunction.
///
/// The test above reaches the probe through the evaluator, and no filter can put the distinguishing
/// shape in front of it there: the entry reading is paid only for a predicate that held on the map by a
/// pass anchored by nothing, and a conjunction that then counts against the predicate on an entry met a
/// key the entry carries, which is a resolution, so `touched` is already true when the stop is asked. So
/// the stop rule is pinned on the probe itself, with the entry as its root and the predicate written as a
/// filter would carry it: `Nope exists` fails on a resource without resolving anything (a miss at the
/// root's own first key anchors nothing, see `QuietScope::grounded`), and `Type == 'AWS::Nope'` fails
/// after resolving `Type`. Three cells, each counting the clauses the probe evaluated:
/// - asked whether it held, the probe stops at the untouched failure: one read, `DidNotHold { touched:
///   false }`;
/// - asked whether it touched, it reads on to the clause that resolves `Type`: two reads, `DidNotHold {
///   touched: true }` -- the answer a probe that stopped at the first failure would get wrong, reading the
///   entry as one the predicate never reached into;
/// - the same two conjunctions the other way round, asked whether it touched: the first resolves `Type`
///   and fails, nothing left can change the bit, one read.
#[test]
fn the_entry_probe_reads_past_an_untouched_failure_until_a_clause_resolves_a_key() -> Result<()> {
    use crate::rules::eval_context::BOUND_MAP_PROBE_CLAUSE_READS;

    const ENTRY: &str = r#"{ "Type": "AWS::S3::Bucket", "Properties": { "BucketName": "b" } }"#;
    let rules_file = RulesFile::try_from("rule r { Resources exists }")?;
    let mut disagreements = Vec::new();
    for (label, filter, reads, expected_reads, expected) in [
        (
            "asked whether it held: the untouched failure stops the probe",
            "Resources[ Nope exists Type == 'AWS::Nope' ]",
            ProbeReads::WhetherItHeld,
            1,
            Probe::DidNotHold { touched: false },
        ),
        (
            "asked whether it touched: the probe reads past the untouched failure to the clause that resolves `Type`",
            "Resources[ Nope exists Type == 'AWS::Nope' ]",
            ProbeReads::WhetherItTouched,
            2,
            Probe::DidNotHold { touched: true },
        ),
        (
            "asked whether it touched, the resolving clause first: the bit is settled, one read",
            "Resources[ Type == 'AWS::Nope' Nope exists ]",
            ProbeReads::WhetherItTouched,
            1,
            Probe::DidNotHold { touched: true },
        ),
    ] {
        let query = AccessQuery::try_from(filter)?;
        let conjunctions = match query.query.get(1) {
            Some(QueryPart::Filter(_, conjunctions)) => conjunctions,
            other => panic!("the query's second part is the filter, got {:?}", other),
        };
        let entry = PathAwareValue::try_from(ENTRY)?;
        let mut root = root_scope(&rules_file, Rc::new(entry.clone()));
        let mut quiet = QuietScope {
            root: Rc::new(entry),
            parent: &mut root,
            grounded: false,
            takes_the_fallback: false,
            cache: None,
        };
        BOUND_MAP_PROBE_CLAUSE_READS.with(|count| count.set(0));
        let probe = probe_predicate(conjunctions, &mut quiet, reads, ProbeReading::Evaluated);
        let counted = BOUND_MAP_PROBE_CLAUSE_READS.with(|count| count.get());
        if counted != expected_reads {
            disagreements.push(format!(
                "{label}: clause reads: wanted {expected_reads}, got {counted}"
            ));
        }
        if probe != expected {
            disagreements.push(format!("{label}: probe: wanted {expected:?}, got {probe:?}"));
        }
    }
    assert!(
        disagreements.is_empty(),
        "cells that disagreed:\n{}",
        disagreements.join("\n")
    );
    Ok(())
}

/// The one-object probe sorts an error a clause raises with the classifier the real `[*]` run's fold uses
/// (`eval::is_unevaluatable`), so an undecidable comparison is CARRIED, not returned at once: the probe
/// reads on to the conjunction after it, and a conjunction that fails for real decides the predicate as
/// the `[*]` run's failing conjunct drops the entry's undecided marker. Only an error that stops the `[*]`
/// run wherever it stands, a rules-file mistake (`Error::is_rules_file_mistake`) or an internal fault,
/// returns at once, before the conjunctions after it are read.
///
/// Pinned on the probe itself, as the one-object reading calls it (`the_one_object_reading_holds`: the
/// whole map as the root, `takes_the_fallback` set, `SkippedOnTheMapAsOneObject`), over `Cfg: { Mode:
/// fast, PROD: 1 }` under a document with no `Nope` beside the map, counting the clauses read:
/// - `Owner !exists  this[ keys == Nope ] !empty  Kind == 'k'`: the key filter's right-hand side resolves
///   nowhere (an undecidable comparison), the probe reads on to `Kind == 'k'`, which fails on the map
///   and decides: three reads, "did not hold", no error;
/// - the same without `Kind`: nothing decides, the carried error is returned after both conjunctions
///   were read, and it is the classifier's "the data could not answer";
/// - `parse_int('abc')` as the key filter's right-hand side, `Kind == 'k'` after it: the mistake is
///   returned at once, `Kind` unread, and it is a rules-file mistake.
#[test]
fn the_one_object_probe_carries_an_undecidable_comparison_and_returns_a_mistake_at_once(
) -> Result<()> {
    use crate::rules::eval_context::BOUND_MAP_PROBE_CLAUSE_READS;

    const DOCUMENT: &str = r#"{ "Env": "prod", "Cfg": { "Mode": "fast", "PROD": 1 } }"#;
    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        DidNotHold,
        CarriedError,
        MistakeAtOnce,
    }
    let rules_file = RulesFile::try_from("rule r { Cfg exists }")?;
    let mut disagreements = Vec::new();
    for (label, filter, expected_reads, expected) in [
        (
            "the undecidable key filter is carried and `Kind == 'k'` is read and decides",
            "Cfg[ Owner !exists  this[ keys == Nope ] !empty  Kind == 'k' ]",
            3,
            Outcome::DidNotHold,
        ),
        (
            "with nothing after it to decide, the carried error is returned once every conjunction was read",
            "Cfg[ Owner !exists  this[ keys == Nope ] !empty ]",
            2,
            Outcome::CarriedError,
        ),
        (
            "a rules-file mistake in the key filter returns at once, `Kind` unread",
            "Cfg[ Owner !exists  this[ keys == parse_int('abc') ] !empty  Kind == 'k' ]",
            2,
            Outcome::MistakeAtOnce,
        ),
    ] {
        let query = AccessQuery::try_from(filter)?;
        let conjunctions = match query.query.get(1) {
            Some(QueryPart::Filter(_, conjunctions)) => conjunctions,
            other => panic!("the query's second part is the filter, got {:?}", other),
        };
        let document = Rc::new(PathAwareValue::try_from(DOCUMENT)?);
        let map = match &*document {
            PathAwareValue::Map((_, map)) => Rc::new(map.values["Cfg"].clone()),
            other => panic!("the document is a map, got {:?}", other),
        };
        let mut root = root_scope(&rules_file, Rc::clone(&document));
        let mut quiet = QuietScope {
            root: map,
            parent: &mut root,
            grounded: false,
            takes_the_fallback: true,
            cache: None,
        };
        BOUND_MAP_PROBE_CLAUSE_READS.with(|count| count.set(0));
        let probe =
            probe_predicate_carrying_errors(conjunctions, &mut quiet, ProbeReads::WhetherItHeld);
        let counted = BOUND_MAP_PROBE_CLAUSE_READS.with(|count| count.get());
        let outcome = match &probe {
            Ok(Probe::DidNotHold { .. }) => Outcome::DidNotHold,
            Err(error) if error.is_rules_file_mistake() => Outcome::MistakeAtOnce,
            Err(error) if crate::rules::eval::is_unevaluatable(error) => Outcome::CarriedError,
            other => {
                disagreements.push(format!("{label}: an outcome no cell names: {other:?}"));
                continue;
            }
        };
        if counted != expected_reads {
            disagreements.push(format!(
                "{label}: clause reads: wanted {expected_reads}, got {counted}"
            ));
        }
        if outcome != expected {
            disagreements.push(format!(
                "{label}: outcome: wanted {expected:?}, got {outcome:?} ({probe:?})"
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "cells that disagreed:\n{}",
        disagreements.join("\n")
    );
    Ok(())
}

/// Each probe entry returns only the answers its reading can produce, so a caller has no arm to write
/// for a state it cannot reach: a hold on a guess is the whole-map entry's answer alone
/// (`WholeMapProbe::HeldByAssumption`), a carried error the one-object entry's alone, and the plain entry
/// returns a `Probe` with neither. Pinned on one predicate per caller shape, over a bucket entry as the
/// root with `let t = 'AWS::S3::Bucket'` bound at the root scope:
/// - `Nope exists or Type == %t`, asked whether it held: under `Evaluated` (the bound-map notice's probe)
///   the `%t` clause is read for real through the root scope and the entry HOLDS, anchored on `Type`; the
///   whole-map entry over the same predicate leaves `Type == %t` unread under `AssumedHeld` and answers a
///   hold on a guess naming that clause, and a decided hold under its `Evaluated` reading;
/// - `Owner !exists  this[ keys == parse_int('abc') ] !empty  Kind == 'k'` over the `Cfg` map: under
///   `SkippedOnAKeptEntry` (the grounding probe) the mistake is read on the probe's terms and is neutral,
///   `Kind == 'k'` fails, and the answer is "did not hold" with no error to carry; the one-object entry
///   over the same map returns the mistake;
/// - `Type == %t`, asked whether it touched (the population probe's question): the bucket entry holds
///   anchored, a queue entry does not hold and touched `Type`.
#[test]
fn each_probe_entry_answers_only_what_its_reading_can_produce() -> Result<()> {
    const BUCKET: &str = r#"{ "Type": "AWS::S3::Bucket", "Properties": { "BucketName": "b" } }"#;
    const QUEUE: &str = r#"{ "Type": "AWS::SQS::Queue", "Properties": { "QueueName": "q" } }"#;
    const DOCUMENT: &str = r#"{ "Env": "prod", "Cfg": { "Mode": "fast", "PROD": 1 } }"#;
    let rules_file = RulesFile::try_from("let t = 'AWS::S3::Bucket'\nrule r { Resources exists }")?;
    let mut disagreements = Vec::new();

    // The disjunction decided by its outside-reaching clause: the plain entry under `Evaluated`, then
    // the whole-map entry under both of its readings.
    let query = AccessQuery::try_from("Resources[ Nope exists or Type == %t ]")?;
    let conjunctions = match query.query.get(1) {
        Some(QueryPart::Filter(_, conjunctions)) => conjunctions,
        other => panic!("the query's second part is the filter, got {:?}", other),
    };
    let bucket = Rc::new(PathAwareValue::try_from(BUCKET)?);
    {
        let mut root = root_scope(&rules_file, Rc::clone(&bucket));
        let mut quiet = QuietScope {
            root: Rc::clone(&bucket),
            parent: &mut root,
            grounded: false,
            takes_the_fallback: false,
            cache: None,
        };
        let probe = probe_predicate(
            conjunctions,
            &mut quiet,
            ProbeReads::WhetherItHeld,
            ProbeReading::Evaluated,
        );
        if probe != (Probe::Held { anchored: true }) {
            disagreements.push(format!(
                "the bound-map probe under Evaluated reads `Type == %t` for real and holds anchored: got {probe:?}"
            ));
        }
    }
    let unread_clause = conjunctions
        .iter()
        .flatten()
        .nth(1)
        .expect("the disjunction has two clauses");
    for (label, reading, assumed) in [
        (
            "the whole-map probe under AssumedHeld takes the disjunction as held through `Type == %t`",
            WholeMapProbeReading::AssumedHeld,
            true,
        ),
        (
            "the whole-map probe under Evaluated reads `Type == %t` and decides the hold",
            WholeMapProbeReading::Evaluated,
            false,
        ),
    ] {
        let mut root = root_scope(&rules_file, Rc::clone(&bucket));
        let mut quiet = QuietScope {
            root: Rc::clone(&bucket),
            parent: &mut root,
            grounded: false,
            takes_the_fallback: false,
            cache: None,
        };
        let probe = probe_predicate_for_the_whole_map(
            conjunctions,
            &mut quiet,
            ProbeReads::WhetherItHeld,
            reading,
        );
        match (probe, assumed) {
            (WholeMapProbe::HeldByAssumption { unread }, true)
                if std::ptr::eq(unread, unread_clause) => {}
            (WholeMapProbe::Decided(Probe::Held { anchored: true }), false) => {}
            (other, _) => disagreements.push(format!("{label}: got {other:?}")),
        }
    }

    // The erroring clause: folded by the plain entry over a kept entry, returned by the one-object entry.
    let query = AccessQuery::try_from(
        "Cfg[ Owner !exists  this[ keys == parse_int('abc') ] !empty  Kind == 'k' ]",
    )?;
    let conjunctions = match query.query.get(1) {
        Some(QueryPart::Filter(_, conjunctions)) => conjunctions,
        other => panic!("the query's second part is the filter, got {:?}", other),
    };
    let document = Rc::new(PathAwareValue::try_from(DOCUMENT)?);
    let map = match &*document {
        PathAwareValue::Map((_, map)) => Rc::new(map.values["Cfg"].clone()),
        other => panic!("the document is a map, got {:?}", other),
    };
    {
        let mut root = root_scope(&rules_file, Rc::clone(&document));
        let mut quiet = QuietScope {
            root: Rc::clone(&map),
            parent: &mut root,
            grounded: false,
            takes_the_fallback: false,
            cache: None,
        };
        let probe = probe_predicate(
            conjunctions,
            &mut quiet,
            ProbeReads::WhetherItHeld,
            ProbeReading::SkippedOnAKeptEntry,
        );
        if !matches!(probe, Probe::DidNotHold { .. }) {
            disagreements.push(format!(
                "the grounding probe folds the mistake and `Kind == 'k'` decides against the entry: got {probe:?}"
            ));
        }
    }
    {
        let mut root = root_scope(&rules_file, Rc::clone(&document));
        let mut quiet = QuietScope {
            root: Rc::clone(&map),
            parent: &mut root,
            grounded: false,
            takes_the_fallback: true,
            cache: None,
        };
        match probe_predicate_carrying_errors(conjunctions, &mut quiet, ProbeReads::WhetherItHeld) {
            Err(error) if error.is_rules_file_mistake() => {}
            other => disagreements.push(format!(
                "the one-object probe returns the mistake as the real run would raise it: got {other:?}"
            )),
        }
    }

    // The population probe's question, asked whether it touched, over a member and a non-member.
    let query = AccessQuery::try_from("Resources[ Type == %t ]")?;
    let conjunctions = match query.query.get(1) {
        Some(QueryPart::Filter(_, conjunctions)) => conjunctions,
        other => panic!("the query's second part is the filter, got {:?}", other),
    };
    for (label, entry, expected) in [
        (
            "the population probe over a bucket: held, anchored on `Type`",
            BUCKET,
            Probe::Held { anchored: true },
        ),
        (
            "the population probe over a queue: did not hold, and touched `Type`",
            QUEUE,
            Probe::DidNotHold { touched: true },
        ),
    ] {
        let value = Rc::new(PathAwareValue::try_from(entry)?);
        let mut root = root_scope(&rules_file, Rc::clone(&value));
        let mut quiet = QuietScope {
            root: Rc::clone(&value),
            parent: &mut root,
            grounded: false,
            takes_the_fallback: false,
            cache: None,
        };
        let probe = probe_predicate(
            conjunctions,
            &mut quiet,
            ProbeReads::WhetherItTouched,
            ProbeReading::Evaluated,
        );
        if probe != expected {
            disagreements.push(format!("{label}: wanted {expected:?}, got {probe:?}"));
        }
    }
    assert!(
        disagreements.is_empty(),
        "cells that disagreed:\n{}",
        disagreements.join("\n")
    );
    Ok(())
}

/// A function call expression for `resolve_function`, at no particular position in a rules file.
fn call<'l>(name: FunctionName, parameters: &[LetValue<'l>]) -> FunctionExpr<'l> {
    FunctionExpr {
        name,
        parameters: parameters.to_vec(),
        location: FileLocation {
            line: 0,
            column: 0,
            file_name: "",
        },
    }
}

/// `resolve_function` answers one result per input, and an input the function has no answer for stays
/// in the answer as an unresolved result that names it.
///
/// Flattening the function's `Vec<Option<_>>` would drop the `int` and the missing key below, and
/// `to_lower` over three inputs would answer with one value; a comparison over that one value could
/// pass on a selection that holds two it was written to catch. A kept unresolved result fails its
/// comparison the way the bare query's does.
///
/// The missing key keeps the query's own unresolved result, path and reason included, so the report
/// reads as it does for the bare query. The `int` gets one built here: the input's path, and a reason
/// naming the function and the type it was handed.
#[test]
fn resolve_function_keeps_an_unresolved_result_for_every_input_it_cannot_handle() -> Result<()> {
    let value = PathAwareValue::try_from(
        r#"{ Ingress: [ { IpProtocol: "TCP" }, { IpProtocol: -1 }, { CidrIp: "0.0.0.0/0" } ] }"#,
    )?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let parameters = vec![LetValue::AccessClause(AccessQuery::try_from(
        "Ingress[*].IpProtocol",
    )?)];

    let function = call(FunctionName::ToLower, &parameters);
    let results = resolve_function(&function, &mut eval)?;
    assert_eq!(results.len(), 3, "one answer per input: {:?}", results);

    match &results[0] {
        QueryResult::Resolved(v) => match &**v {
            PathAwareValue::String((path, lowered)) => {
                assert_eq!(lowered, "tcp");
                assert_eq!(path.0, "/Ingress/0/IpProtocol");
            }
            other => panic!("expected the lowercased string, got {:?}", other),
        },
        other => panic!("expected a resolved value, got {:?}", other),
    }

    match &results[1] {
        QueryResult::UnResolved(ur) => {
            assert_eq!(
                ur.traversed_to.self_path().0,
                "/Ingress/1/IpProtocol",
                "the unresolved result points at the input the function could not take"
            );
            let reason = ur.reason.as_deref().unwrap_or("");
            assert!(
                reason.contains("to_lower") && reason.contains("int"),
                "the reason names the function and the type it was handed: {:?}",
                reason
            );
        }
        other => panic!("an int is not an answer to to_lower: {:?}", other),
    }

    match &results[2] {
        QueryResult::UnResolved(ur) => {
            assert_eq!(ur.remaining_query, "IpProtocol");
            assert!(
                ur.reason
                    .as_deref()
                    .unwrap_or("")
                    .contains("Could not find key IpProtocol"),
                "the query's own unresolved result is kept as it was: {:?}",
                ur
            );
        }
        other => panic!("a missing key is not an answer to to_lower: {:?}", other),
    }

    Ok(())
}

/// The reason tells a value of a type the function does not take from one it takes and still cannot
/// answer for.
///
/// `substring` answers nothing for a range outside the string, `url_decode` for bytes that are not
/// UTF-8 once decoded, and `parse_char` for an empty string; all three inputs are strings, which the
/// functions take. Saying "it is String, which the function does not take" for them would be false,
/// and a reader fixing what the report points at would look at the wrong thing.
#[rstest::rstest]
#[case::substring_end_past_the_string(
    FunctionName::Substring,
    r#"{ V: "abc" }"#,
    vec![0, 5],
    "the end 5 is past the end of the string, which is 3 characters long"
)]
#[case::substring_start_past_the_end(
    FunctionName::Substring,
    r#"{ V: "abc" }"#,
    vec![2, 1],
    "the start 2 is past the end 1"
)]
// `[0, 0)` is inside `""` and selects the empty string, so the out-of-bounds range on an empty
// string is one whose end is past its length.
#[case::substring_of_an_empty_string(
    FunctionName::Substring,
    r#"{ V: "" }"#,
    vec![0, 1],
    "the end 1 is past the end of the string, which is 0 characters long"
)]
#[case::url_decode_of_bytes_that_are_not_utf8(
    FunctionName::UrlDecode,
    r#"{ V: "%FF" }"#,
    vec![],
    "does not decode to valid UTF-8"
)]
#[case::parse_char_of_an_empty_string(
    FunctionName::ParseChar,
    r#"{ V: "" }"#,
    vec![],
    "the string is empty"
)]
#[case::to_lower_of_an_int_control(
    FunctionName::ToLower,
    r#"{ V: 7 }"#,
    vec![],
    "it is int, which the function does not take"
)]
fn resolve_function_gives_the_real_reason_for_a_value_it_cannot_answer_for(
    #[case] name: FunctionName,
    #[case] input: &str,
    #[case] extra_int_arguments: Vec<i64>,
    #[case] reason_fragment: &str,
) -> Result<()> {
    let value = PathAwareValue::try_from(input)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let mut parameters = vec![LetValue::AccessClause(AccessQuery::try_from("V")?)];
    for n in extra_int_arguments {
        parameters.push(LetValue::Value(PathAwareValue::Int((Path::root(), n))));
    }

    let function = call(name.clone(), &parameters);
    let results = resolve_function(&function, &mut eval)?;
    match results.as_slice() {
        [QueryResult::UnResolved(ur)] => {
            let reason = ur.reason.as_deref().unwrap_or("");
            assert!(
                reason.contains(reason_fragment),
                "{name}: the reason must say {:?}, got {:?}",
                reason_fragment,
                reason
            );
            assert_eq!(ur.traversed_to.self_path().0, "/V");
            assert!(
                ur.remaining_query.is_empty(),
                "a value that was found leaves no query unsatisfied, so nothing reads as a missing \
                 property: {:?}",
                ur.remaining_query
            );
        }
        other => panic!("{name} over {input} has no answer, got {:?}", other),
    }
    Ok(())
}

/// The refusal for a scalar argument says what the argument resolved to, not what type it needed.
///
/// An empty selection and a missing key both fell to the callers' type arms and were told the argument
/// had to be "a string" or "a number", for a value that was never found. Two missing keys were "2
/// values". Each shape now has its own sentence, and a single resolved value passes through. Every
/// argument here is a query over the data, so each refusal is the data's (`Unevaluatable`); the same
/// shapes from a literal list would be the author's.
#[test]
fn exactly_one_names_what_the_argument_resolved_to() -> Result<()> {
    let value = PathAwareValue::try_from(
        r#"{ Items: [ { Delim: "-" }, { Delim: "+" }, { Other: 1 }, { Other: 2 } ] }"#,
    )?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let first = AccessQuery::try_from("Items[0].Delim")?;
    let second = AccessQuery::try_from("Items[1].Delim")?;
    let third = AccessQuery::try_from("Items[2].Delim")?;
    let fourth = AccessQuery::try_from("Items[3].Delim")?;
    let all = AccessQuery::try_from("Items[*].Delim")?;
    let nothing = AccessQuery::try_from("Items[ Delim == 'x' ].Delim")?;
    let message = |values: &[QueryResult]| -> String {
        match exactly_one("join", "second", values) {
            Err(Error::Unevaluatable(message)) => message,
            other => panic!("expected the data's refusal, got {:?}", other),
        }
    };

    let one = eval.query(&first.query)?;
    assert!(
        matches!(exactly_one("join", "second", &one)?, (_, false)),
        "one resolved value passes through, and is not a literal"
    );
    let literal = vec![QueryResult::Literal(Rc::new(PathAwareValue::try_from(
        r#""-""#,
    )?))];
    assert!(
        matches!(exactly_one("join", "second", &literal)?, (_, true)),
        "one literal passes through, and says it is one"
    );

    let none = eval.query(&nothing.query)?;
    assert!(
        message(&none)
            .contains("resolved to no value (an empty selection, or a list with no elements)"),
        "an empty selection is named as such: {}",
        message(&none)
    );
    // A key holding a list with no elements expands to no values before the check, so it reaches the
    // same arm; the reason names that shape too rather than calling it an empty selection.
    let empty_list = interpolated_keys(&[QueryResult::Resolved(Rc::new(
        PathAwareValue::try_from("[]")?,
    ))]);
    assert!(
        empty_list.is_empty() && message(&empty_list).contains("a list with no elements"),
        "an expanded empty list is named as such: {:?} / {}",
        empty_list,
        message(&empty_list)
    );

    let missing = eval.query(&third.query)?;
    assert!(
        message(&missing).contains("did not resolve")
            && message(&missing).contains("Could not find key Delim"),
        "one missing key carries the query's own reason: {}",
        message(&missing)
    );

    let two_missing = eval
        .query(&third.query)?
        .into_iter()
        .chain(eval.query(&fourth.query)?)
        .collect::<Vec<_>>();
    assert!(
        message(&two_missing).contains("none of its 2 results resolved"),
        "two missing keys are not two values: {}",
        message(&two_missing)
    );

    let mixed = eval.query(&all.query)?;
    assert_eq!(mixed.len(), 4);
    assert!(
        message(&mixed).contains("got 4 results, 2 of them unresolved"),
        "a mixed selection names both counts: {}",
        message(&mixed)
    );

    let two = eval
        .query(&first.query)?
        .into_iter()
        .chain(eval.query(&second.query)?)
        .collect::<Vec<_>>();
    assert!(
        message(&two).contains("exactly one value, got 2"),
        "two values are counted as values: {}",
        message(&two)
    );

    Ok(())
}

/// A function whose every argument is a literal computes a literal, and one that read the data does not.
///
/// A result that came back `Resolved` whatever its arguments would route `parse_int("5")` and `5` to
/// different comparator arms through `is_literal`, where they could reach different verdicts for one
/// constant. The tag follows the arguments: all literal in, literal out; a query among them, resolved
/// out.
#[test]
fn resolve_function_tags_the_result_by_what_its_arguments_were() -> Result<()> {
    let value = PathAwareValue::try_from(r#"{ Port: "443" }"#)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };

    let literal = vec![LetValue::Value(PathAwareValue::try_from(r#""5""#)?)];
    let function = call(FunctionName::ParseInt, &literal);
    let results = resolve_function(&function, &mut eval)?;
    assert!(
        matches!(
            results.as_slice(),
            [QueryResult::Literal(v)] if matches!(**v, PathAwareValue::Int((_, 5)))
        ),
        "a function over a literal is a literal: {:?}",
        results
    );

    let queried = vec![LetValue::AccessClause(AccessQuery::try_from("Port")?)];
    let function = call(FunctionName::ParseInt, &queried);
    let results = resolve_function(&function, &mut eval)?;
    assert!(
        matches!(
            results.as_slice(),
            [QueryResult::Resolved(v)] if matches!(**v, PathAwareValue::Int((_, 443)))
        ),
        "a function over a query is a resolved value: {:?}",
        results
    );

    // The tag is decided from the arguments, not from the elements that came back. An empty
    // selection has no elements to read a tag from and is a query over the data, so `count` over it
    // is a resolved 0, and `join` over it with a literal delimiter is resolved too.
    let mut eval = BasicQueryTesting {
        root: Rc::new(PathAwareValue::try_from(r#"{ Items: [ { V: 1 } ] }"#)?),
        recorder: None,
    };
    let empty = vec![LetValue::AccessClause(AccessQuery::try_from(
        "Items[ V == 2 ].V",
    )?)];
    let function = call(FunctionName::Count, &empty);
    let results = resolve_function(&function, &mut eval)?;
    assert!(
        matches!(results.as_slice(), [QueryResult::Resolved(v)] if matches!(**v, PathAwareValue::Int((_, 0)))),
        "count over an empty selection is a resolved 0, not a literal: {:?}",
        results
    );
    let empty_joined = vec![
        LetValue::AccessClause(AccessQuery::try_from("Items[ V == 2 ].V")?),
        LetValue::Value(PathAwareValue::try_from(r#"",""#)?),
    ];
    let function = call(FunctionName::Join, &empty_joined);
    let results = resolve_function(&function, &mut eval)?;
    assert!(
        matches!(results.as_slice(), [QueryResult::Resolved(_)]),
        "join over an empty selection is resolved, not literal: {:?}",
        results
    );

    // A nested call of literals is a literal argument; a call with no arguments is not a literal.
    let nested = vec![LetValue::FunctionCall(FunctionExpr {
        parameters: vec![LetValue::Value(PathAwareValue::try_from("5")?)],
        name: FunctionName::ParseString,
        location: FileLocation {
            line: 0,
            column: 0,
            file_name: "",
        },
    })];
    let function = call(FunctionName::ParseInt, &nested);
    let results = resolve_function(&function, &mut eval)?;
    assert!(
        matches!(
            results.as_slice(),
            [QueryResult::Literal(v)] if matches!(**v, PathAwareValue::Int((_, 5)))
        ),
        "a function of a function of literals is a literal: {:?}",
        results
    );
    let function = call(FunctionName::Now, &[]);
    let results = resolve_function(&function, &mut eval)?;
    assert!(
        matches!(results.as_slice(), [QueryResult::Resolved(_)]),
        "now() reads nothing from the rules file and is not a literal: {:?}",
        results
    );

    // Two more cells: a filter that selects nothing, and lists that are all empty. Both are
    // queries over the data with no literal in them, so both answer Resolved whatever they count.
    let mut eval = BasicQueryTesting {
        root: Rc::new(PathAwareValue::try_from(
            r#"{ Resources: { A: { Type: "Y", Properties: { Tags: [] } }, B: { Type: "Y", Properties: { Tags: [] } } } }"#,
        )?),
        recorder: None,
    };
    let none_selected = vec![LetValue::AccessClause(AccessQuery::try_from(
        "Resources.*[ Type == 'X' ]",
    )?)];
    let function = call(FunctionName::Count, &none_selected);
    let results = resolve_function(&function, &mut eval)?;
    assert!(
        matches!(results.as_slice(), [QueryResult::Resolved(_)]),
        "count over a filter that selects nothing is resolved: {:?}",
        results
    );
    let all_empty = vec![LetValue::AccessClause(AccessQuery::try_from(
        "Resources.*.Properties.Tags",
    )?)];
    let function = call(FunctionName::Count, &all_empty);
    let results = resolve_function(&function, &mut eval)?;
    assert!(
        matches!(results.as_slice(), [QueryResult::Resolved(_)]),
        "count over lists that are all empty is resolved: {:?}",
        results
    );

    Ok(())
}

/// An argument that resolves to a list value reaches the function as that list's elements.
///
/// The results went to the function as the query produced them, and a property holding a list is one
/// result holding a `List`, so `count` over it answered 1 whatever the list held. The same one-level
/// expansion the comparison path applies (`interpolated_keys`) is applied to every argument, for a
/// resolved list and a literal one alike; a list inside a list stays one element.
#[test]
fn resolve_function_reads_a_list_valued_argument_as_its_elements() -> Result<()> {
    let value = PathAwareValue::try_from(r#"{ L: ["a", "b", "c"], Nested: [["a", "b"], ["c"]] }"#)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };

    let property = vec![LetValue::AccessClause(AccessQuery::try_from("L")?)];
    let function = call(FunctionName::Count, &property);
    let results = resolve_function(&function, &mut eval)?;
    assert!(
        matches!(
            results.as_slice(),
            [QueryResult::Resolved(v)] if matches!(**v, PathAwareValue::Int((_, 3)))
        ),
        "count of a list property is the number of its elements: {:?}",
        results
    );

    let literal = vec![LetValue::Value(PathAwareValue::try_from(
        r#"["a", "b", "c"]"#,
    )?)];
    let function = call(FunctionName::Count, &literal);
    let results = resolve_function(&function, &mut eval)?;
    assert!(
        matches!(
            results.as_slice(),
            [QueryResult::Literal(v)] if matches!(**v, PathAwareValue::Int((_, 3)))
        ),
        "count of a list literal is the number of its elements, and a literal: {:?}",
        results
    );

    let lowering = call(FunctionName::ToLower, &literal);
    let lowered = resolve_function(&lowering, &mut eval)?;
    assert_eq!(
        lowered.len(),
        3,
        "a mapping function answers once per element: {:?}",
        lowered
    );

    let nested = vec![LetValue::AccessClause(AccessQuery::try_from("Nested")?)];
    let function = call(FunctionName::Count, &nested);
    let results = resolve_function(&function, &mut eval)?;
    assert!(
        matches!(
            results.as_slice(),
            [QueryResult::Resolved(v)] if matches!(**v, PathAwareValue::Int((_, 2)))
        ),
        "one level: a list inside the list is one element: {:?}",
        results
    );

    // A query that already enumerates is left as it is: `Nested[*]` hands over the two inner lists
    // as two values, not their three elements, the way the filter path reads a projecting query.
    let enumerated = vec![LetValue::AccessClause(AccessQuery::try_from("Nested[*]")?)];
    let function = call(FunctionName::Count, &enumerated);
    let results = resolve_function(&function, &mut eval)?;
    assert!(
        matches!(
            results.as_slice(),
            [QueryResult::Resolved(v)] if matches!(**v, PathAwareValue::Int((_, 2)))
        ),
        "an enumeration's members are the values, lists included: {:?}",
        results
    );

    Ok(())
}

/// The single-map filter notice names the binding and the filter as text an author can paste back,
/// so `let x = <binding>[ <predicate> ]` built from the two renderers has to parse.
///
/// Two renderings this pins, each a parse error at exit 5 if the renderer gets it wrong: a key that
/// needs quotes written without them (`AWS::CloudFormation::Authentication exists` stops the parser at
/// the first `:` with "There were no clauses present"), and conjuncts joined with `;`, which the grammar
/// does not accept between clauses. The predicate here is the published registry rule's, which has a
/// quoted key, a negated unary, two disjunctions and a `.*` descent, so one text exercises every arm the
/// renderer has for it.
#[test]
fn a_rendered_single_map_filter_parses_back() -> Result<()> {
    let rules = "let cfn_authentication_rule = Resources.Metadata\n\
                 let skip_cfn_authentication = %cfn_authentication_rule[\n\
                 \"AWS::CloudFormation::Authentication\" exists\n\
                 Metadata.cfn_nag.rules_to_suppress not exists or\n\
                 Metadata.cfn_nag.rules_to_suppress.*.id != \"W1\"\n\
                 Metadata.guard.SuppressedRules not exists or\n\
                 Metadata.guard.SuppressedRules.* != \"CFN_AUTHENTICATION_RULE\"\n\
                 ]\n\
                 rule r when %skip_cfn_authentication !empty { %cfn_authentication_rule exists }";
    let rules_file = RulesFile::try_from(rules)?;

    let binding_of = |name: &str| -> &[QueryPart<'_>] {
        match rules_file
            .assignments
            .iter()
            .find(|each| each.var == name)
            .map(|each| &each.value)
        {
            Some(LetValue::AccessClause(query)) => query.query.as_slice(),
            other => panic!("{} should be bound by a query, got {:?}", name, other),
        }
    };
    let binding =
        query_as_written(binding_of("cfn_authentication_rule")).expect("a plain key path renders");
    let predicate = binding_of("skip_cfn_authentication")
        .iter()
        .find_map(|part| match part {
            QueryPart::Filter(_, conjunctions) => predicate_as_written(conjunctions),
            _ => None,
        })
        .expect("the skip binding carries a filter whose predicate renders");

    assert_eq!("Resources.Metadata", binding);
    assert!(
        predicate.contains("\"AWS::CloudFormation::Authentication\" exists")
            && predicate.contains("Metadata.cfn_nag.rules_to_suppress !exists or")
            && predicate.contains("!= 'W1'")
            && !predicate.contains(';'),
        "keys keep their quotes and conjuncts are not joined with `;`, got {:?}",
        predicate
    );

    let rendered = format!(
        "let x = {}[ {} ]\nrule r {{ %x !empty }}",
        binding, predicate
    );
    let reparsed = RulesFile::try_from(rendered.as_str());
    assert!(
        reparsed.is_ok(),
        "the rendered text has to parse back, got {:?} for {:?}",
        reparsed.err(),
        rendered
    );
    Ok(())
}

/// Every comparator the grammar has, in both polarities where it has two, renders to the keyword the
/// parser reads back -- `is_struct` for a map, not the variant's `is_map` -- and a variable-rooted
/// binding renders without the reserved slot the parser inserts after the root: `let m = %o.Nested`
/// prints `%o.Nested`, not the `%o[*].Nested` its parts' `Display` gives, which the engine reads as the
/// author's own wildcard. Each row is rendered, the rendered text is parsed back, and the parsed clause
/// has to equal the original -- compared as values, because the reserved slot and the authored wildcard
/// print alike.
///
/// Red when the renderer is wrong, measured by mutating it: with `IsMap` rendered as `is_map`, the
/// `Cfg is_struct` row fails at "renders as written"; with the reserved slot printed, `m` fails at "the
/// reserved slot is not printed" and would also fail the value comparison, which is the check that
/// stands when the two slots' text is the same. Before this shape the test re-parsed the SOURCE text
/// and compared the original with itself, a check that could not fail.
#[test]
fn every_comparator_and_a_variable_rooted_binding_render_so_that_they_parse_back() -> Result<()> {
    let clauses = [
        "Size == 5",
        "Size != 5",
        "Name in ['a', 'b']",
        "Name not in ['a', 'b']",
        "Size > 5",
        "Size >= 5",
        "Size < 5",
        "Size <= 5",
        "Name exists",
        "Name !exists",
        "Tags empty",
        "Tags !empty",
        "Name is_string",
        "Name !is_string",
        "Tags is_list",
        "Tags !is_list",
        "Cfg is_struct",
        "Cfg !is_struct",
        "On is_bool",
        "On !is_bool",
        "Size is_int",
        "Size !is_int",
        "Ratio is_float",
        "Ratio !is_float",
        "Gone is_null",
        "Gone !is_null",
        "this exists",
    ];
    for clause in clauses {
        let rules = format!("let x = Resources[ {} ]\nrule r {{ %x !empty }}", clause);
        let rules_file = RulesFile::try_from(rules.as_str())?;
        let predicate = match &rules_file.assignments[0].value {
            LetValue::AccessClause(query) => query
                .query
                .iter()
                .find_map(|part| match part {
                    QueryPart::Filter(_, conjunctions) => predicate_as_written(conjunctions),
                    _ => None,
                })
                .expect("the filter renders"),
            other => panic!("x should be bound by a query, got {:?}", other),
        };
        assert_eq!(clause, predicate, "the row renders as written");
        // The RENDERED text is what parses back, not the source text: a check that re-parsed the
        // source compared the original with itself and could not fail.
        let rendered = format!("let x = Resources[ {} ]\nrule r {{ %x !empty }}", predicate);
        let reparsed = RulesFile::try_from(rendered.as_str()).unwrap_or_else(|e| {
            panic!(
                "the rendered row has to parse back, got {:?} for {:?}",
                e, rendered
            )
        });
        // Structural, through the derived `PartialEq` on `LetValue`: the two texts are laid out alike,
        // so the clause positions agree and the comparison reaches the predicate itself. Together with
        // the "renders as written" assertion above this is the whole round trip; a comparison of the
        // re-parsed filter's rendering with `predicate` would follow from these two, since the
        // renderer reads only the tree.
        assert_eq!(
            rules_file.assignments[0].value, reparsed.assignments[0].value,
            "the rendered row parses back to the same clause"
        );
    }

    let rules =
        "let o = Outer\nlet m = %o.Nested\nlet n = %o[*].Nested\nrule r { %m exists %n exists }";
    let rules_file = RulesFile::try_from(rules)?;
    fn binding_of<'a, 'loc>(file: &'a RulesFile<'loc>, name: &str) -> &'a LetValue<'loc> {
        &file
            .assignments
            .iter()
            .find(|each| each.var == name)
            .expect("bound")
            .value
    }
    let rendered_of = |name: &str| -> String {
        match binding_of(&rules_file, name) {
            LetValue::AccessClause(query) => {
                query_as_written(&query.query).expect("the binding renders")
            }
            other => panic!("{} should be bound by a query, got {:?}", name, other),
        }
    };
    assert_eq!(
        "%o.Nested",
        rendered_of("m"),
        "the reserved slot is not printed"
    );
    assert_eq!(
        "%o[*].Nested",
        rendered_of("n"),
        "the author's own wildcard is"
    );
    // Both renderings parse back to the bindings they were rendered from, reserved slot and authored
    // wildcard included: `Display` prints both slots as `[*]`, so the comparison is of the parsed
    // values, not of their text.
    let rendered = format!(
        "let o = Outer\nlet m = {}\nlet n = {}\nrule r {{ %m exists %n exists }}",
        rendered_of("m"),
        rendered_of("n")
    );
    let reparsed = RulesFile::try_from(rendered.as_str()).unwrap_or_else(|e| {
        panic!(
            "the rendered bindings have to parse back, got {:?} for {:?}",
            e, rendered
        )
    });
    for name in ["m", "n"] {
        assert_eq!(
            binding_of(&rules_file, name),
            binding_of(&reparsed, name),
            "`{}` parses back to the binding it was rendered from",
            name
        );
    }
    Ok(())
}

/// The predicate renderer follows the grammar for every literal shape a filter can hold, so the text it
/// prints parses back to the same predicate: a nested filter is written out with its own predicate (not
/// the record tree's `(filter-clauses)` placeholder), a string holding a single quote is double-quoted,
/// a backslash and the closing quote are escaped the way `parse_string_inner` reads them, a regex keeps
/// its slashes with an inner `/` escaped, a map-key filter is spelled `[ keys == ... ]`, and a key that
/// is not a bare identifier is quoted -- single quotes when it holds a double quote and no single one.
///
/// A renderer that fell back to the record tree would print the nested filter as `(filter-clauses)`,
/// and one that single-quoted `it's` would print `Name == 'it's'`, a parse error at the second quote.
#[test]
fn every_literal_shape_in_a_predicate_renders_so_that_it_parses_back() -> Result<()> {
    let rules = "let m = Resources.Metadata\n\
                 let x = %m[\n\
                 Tags[ Key == 'env' ] exists\n\
                 Name == \"it's\"\n\
                 Path == 'a\\\\b'\n\
                 Arn == /arn:aws\\/x/\n\
                 \"odd key\" exists\n\
                 \"he said \\\"hi\\\"\" exists\n\
                 Labels[ keys == 'Name' ] !empty\n\
                 ]\n\
                 rule r { %x !empty }";
    let rules_file = RulesFile::try_from(rules)?;
    let x = rules_file
        .assignments
        .iter()
        .find(|each| each.var == "x")
        .expect("x is bound");
    let predicate = match &x.value {
        LetValue::AccessClause(query) => query
            .query
            .iter()
            .find_map(|part| match part {
                QueryPart::Filter(_, conjunctions) => predicate_as_written(conjunctions),
                _ => None,
            })
            .expect("the filter renders"),
        other => panic!("x should be bound by a query, got {:?}", other),
    };

    assert_eq!(
        "Tags[ Key == 'env' ] exists \
         Name == \"it's\" \
         Path == 'a\\\\b' \
         Arn == /arn:aws\\/x/ \
         \"odd key\" exists \
         'he said \"hi\"' exists \
         Labels[ keys == 'Name' ] !empty",
        predicate
    );

    let rendered = format!(
        "let m = Resources.Metadata\nlet x = %m[ {} ]\nrule r {{ %x !empty }}",
        predicate
    );
    let reparsed = RulesFile::try_from(rendered.as_str()).unwrap_or_else(|e| {
        panic!(
            "the rendered text has to parse back, got {:?} for {:?}",
            e, rendered
        )
    });
    let reparsed_x = reparsed
        .assignments
        .iter()
        .find(|each| each.var == "x")
        .expect("x is bound after the round trip");
    // Compared structurally with the positions zeroed on both sides, not through `LetValue`'s
    // `Display`, which prints every filter as `(filter-clauses)` and so compared two placeholders, and
    // not as re-rendered text, which a renderer that rewrites a clause to another valid clause would
    // reproduce. The positions have to be ignored because the source is laid out over several lines
    // and the rendered text over one, so every clause sits at a different line and column.
    fn filter_of<'loc>(value: &LetValue<'loc>) -> Conjunctions<GuardClause<'loc>> {
        match value {
            LetValue::AccessClause(query) => query
                .query
                .iter()
                .find_map(|part| match part {
                    QueryPart::Filter(_, conjunctions) => Some(without_positions(conjunctions)),
                    _ => None,
                })
                .expect("x is bound by a query holding a filter"),
            other => panic!("x should be bound by a query, got {:?}", other),
        }
    }
    assert_eq!(
        filter_of(&x.value),
        filter_of(&reparsed_x.value),
        "the round trip has to give back the same predicate"
    );
    Ok(())
}

/// A predicate with every source position zeroed, so two parses of the same text laid out differently
/// compare equal on everything but where the clauses sat. Walks every place a position is stored:
/// access clauses, rule references, calls, nested blocks and their assignments, `when` conditions, the
/// filters and map-key filters inside queries, and function calls on either side of a comparison.
fn without_positions<'loc>(
    conjunctions: &Conjunctions<GuardClause<'loc>>,
) -> Conjunctions<GuardClause<'loc>> {
    conjunctions
        .iter()
        .map(|disjunction| disjunction.iter().map(clause_without_positions).collect())
        .collect()
}

fn no_position<'loc>() -> FileLocation<'loc> {
    FileLocation {
        line: 0,
        column: 0,
        file_name: "",
    }
}

fn clause_without_positions<'loc>(clause: &GuardClause<'loc>) -> GuardClause<'loc> {
    match clause {
        GuardClause::Clause(gac) => GuardClause::Clause(access_clause_without_positions(gac)),
        GuardClause::NamedRule(rule) => {
            let mut rule = rule.clone();
            rule.location = no_position();
            GuardClause::NamedRule(rule)
        }
        GuardClause::ParameterizedNamedRule(call) => {
            let mut call = call.clone();
            call.named_rule.location = no_position();
            call.parameters = call
                .parameters
                .iter()
                .map(let_value_without_positions)
                .collect();
            GuardClause::ParameterizedNamedRule(call)
        }
        GuardClause::BlockClause(block) => {
            let mut block = block.clone();
            block.location = no_position();
            block.query = query_without_positions(&block.query);
            block.block = block_without_positions(&block.block);
            GuardClause::BlockClause(block)
        }
        GuardClause::WhenBlock(conditions, block) => GuardClause::WhenBlock(
            conditions
                .iter()
                .map(|disjunction| {
                    disjunction
                        .iter()
                        .map(when_clause_without_positions)
                        .collect()
                })
                .collect(),
            block_without_positions(block),
        ),
    }
}

fn when_clause_without_positions<'loc>(clause: &WhenGuardClause<'loc>) -> WhenGuardClause<'loc> {
    match clause {
        WhenGuardClause::Clause(gac) => {
            WhenGuardClause::Clause(access_clause_without_positions(gac))
        }
        WhenGuardClause::NamedRule(rule) => {
            let mut rule = rule.clone();
            rule.location = no_position();
            WhenGuardClause::NamedRule(rule)
        }
        WhenGuardClause::ParameterizedNamedRule(call) => {
            let mut call = call.clone();
            call.named_rule.location = no_position();
            call.parameters = call
                .parameters
                .iter()
                .map(let_value_without_positions)
                .collect();
            WhenGuardClause::ParameterizedNamedRule(call)
        }
    }
}

fn block_without_positions<'loc>(
    block: &Block<'loc, GuardClause<'loc>>,
) -> Block<'loc, GuardClause<'loc>> {
    Block {
        assignments: block
            .assignments
            .iter()
            .map(|assignment| LetExpr {
                var: assignment.var.clone(),
                value: let_value_without_positions(&assignment.value),
            })
            .collect(),
        conjunctions: without_positions(&block.conjunctions),
    }
}

fn access_clause_without_positions<'loc>(gac: &GuardAccessClause<'loc>) -> GuardAccessClause<'loc> {
    let mut gac = gac.clone();
    gac.access_clause.location = no_position();
    gac.access_clause.query = query_without_positions(&gac.access_clause.query);
    gac.access_clause.compare_with = gac
        .access_clause
        .compare_with
        .as_ref()
        .map(let_value_without_positions);
    gac
}

fn query_without_positions<'loc>(query: &AccessQuery<'loc>) -> AccessQuery<'loc> {
    let mut query = query.clone();
    query.query = query
        .query
        .iter()
        .map(|part| match part {
            QueryPart::Filter(name, conjunctions) => {
                QueryPart::Filter(name.clone(), without_positions(conjunctions))
            }
            QueryPart::MapKeyFilter(name, clause) => QueryPart::MapKeyFilter(
                name.clone(),
                MapKeyFilterClause {
                    comparator: clause.comparator,
                    compare_with: let_value_without_positions(&clause.compare_with),
                    location: no_position(),
                },
            ),
            other => other.clone(),
        })
        .collect();
    query
}

fn let_value_without_positions<'loc>(value: &LetValue<'loc>) -> LetValue<'loc> {
    match value {
        LetValue::Value(literal) => LetValue::Value(literal.clone()),
        LetValue::AccessClause(query) => LetValue::AccessClause(query_without_positions(query)),
        LetValue::FunctionCall(call) => {
            let mut call = call.clone();
            call.location = no_position();
            call.parameters = call
                .parameters
                .iter()
                .map(let_value_without_positions)
                .collect();
            LetValue::FunctionCall(call)
        }
    }
}

/// A refusal's marker is an undecidable kind: a clause fails closed on it as on any other marker, and the
/// capture cut (`ShapeNotes::rebind_to_markers`) reads the `refused` flag alone, never the other
/// undecidables.
#[test]
fn a_refusal_is_an_undecidable_kind_and_the_decided_kinds_are_not() {
    assert!(UnResolvedKind::Undecidable { refused: true }.is_undecidable());
    assert!(UnResolvedKind::Undecidable { refused: false }.is_undecidable());
    assert!(!UnResolvedKind::Absent.is_undecidable());
    assert!(!UnResolvedKind::EmptyEnumeration.is_undecidable());
    assert!(UnResolvedKind::Undecidable { refused: true }.is_refusal());
    assert!(!UnResolvedKind::Undecidable { refused: false }.is_refusal());
    assert!(!UnResolvedKind::Absent.is_refusal());
    assert!(!UnResolvedKind::EmptyEnumeration.is_refusal());
}

/// The `refused` bit is set where a refusal is built and clear where a value nobody could decide is: the
/// bit a filter loop cuts its captures on (`refusal_markers_in`) is checked here at its producers, not
/// only end to end. `to_refusal_result` sets it; `to_undecidable_result` and the marker the key filter
/// files for a map it could not decide clear it.
///
/// The consumers of the bit are pinned in this file, with a `refused: false` and a `refused: true` case
/// each, by the rstest suites `undecidable_reason_reads_the_kind_alone` and
/// `a_function_refuses_an_undecidable_argument_in_the_operators_words`. The key filter's marker is built
/// inside the key-filter arm of the walk, so it is reached through a key filter whose right-hand side
/// resolves to nothing (`Names` is absent), the shape that arm answers with that marker.
#[test]
fn the_producers_of_an_undecidable_marker_set_the_refused_bit_as_documented() -> Result<()> {
    let cfg = cfg_of_a_one_resource_document()?;
    for (producer, results, refused) in [
        (
            "to_refusal_result",
            to_refusal_result(Rc::clone(&cfg), "why".to_string(), &[])?,
            true,
        ),
        (
            "to_undecidable_result",
            to_undecidable_result(Rc::clone(&cfg), "why".to_string(), &[])?,
            false,
        ),
    ] {
        assert_eq!(1, results.len(), "{producer} builds one marker");
        match &results[0] {
            QueryResult::UnResolved(unresolved) => {
                assert_eq!(
                    UnResolvedKind::Undecidable { refused },
                    unresolved.kind,
                    "{producer} sets `refused` to {refused}"
                );
                assert_eq!(refused, unresolved.kind.is_refusal(), "{producer}");
                assert!(
                    unresolved.kind.is_undecidable(),
                    "{} is undecidable",
                    producer
                );
                assert_eq!(Some("why"), unresolved.reason.as_deref(), "{producer}");
                assert_eq!(
                    "/Resources/Cfg",
                    unresolved.traversed_to.self_path().0.as_str(),
                    "{producer} stands at the value it was built for"
                );
            }
            other => panic!("{} builds an unresolved marker, not {:?}", producer, other),
        }
    }

    // The key filter's marker for a map it could not decide: `Names` is nowhere, so the right-hand side
    // resolves to nothing and the map is answered with an undecidable marker that is not a refusal.
    let document = PathAwareValue::try_from(r#"{ "Cfg": { "M": { "PROD": 1 } } }"#)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(document),
        recorder: None,
    };
    let query = AccessQuery::try_from("Cfg.M[ keys == Names[*].Name ]")?.query;
    let results = eval.query(&query)?;
    let kinds: Vec<UnResolvedKind> = results
        .iter()
        .filter_map(|result| match result {
            QueryResult::UnResolved(unresolved) => Some(unresolved.kind),
            QueryResult::Resolved(_) | QueryResult::Literal(_) => None,
        })
        .collect();
    assert_eq!(
        vec![UnResolvedKind::Undecidable { refused: false }],
        kinds,
        "the key filter files one undecidable marker for the map, with `refused` clear, among {results:?}"
    );
    Ok(())
}

/// A cut of a capture (`truncate_variable_capture`) takes back the reading's own appends only under a
/// measurement, whether the reading's first append to the name came before the length was read or is the
/// loop's own: the undo point is at most the length read, so the roll-back at the reading's end still
/// leaves the real run's keys. Outside a measurement the cut goes down to the length read.
#[test]
fn a_truncate_under_a_measurement_cuts_the_readings_appends_only() -> Result<()> {
    let rules_file = RulesFile::try_from("let sel = Cfg\nrule r { Cfg exists }")?;
    let value = Rc::new(PathAwareValue::try_from(r#"{ "Cfg": { "A": 1 } }"#)?);
    let mut root = root_scope(&rules_file, Rc::clone(&value));
    let key = |name: &str| -> Result<QueryResult> {
        Ok(QueryResult::Resolved(Rc::new(PathAwareValue::try_from(
            format!("\"{name}\"").as_str(),
        )?)))
    };
    // The captures of an assignment being resolved.
    root.resolving_assignments.insert("sel");
    // The real run files two keys under `x`.
    root.add_variable_capture("x", key("A")?)?;
    root.add_variable_capture("x", key("B")?)?;
    assert_eq!(2, root.variable_capture_len("x"), "the real run's two keys");
    // A reading starts. A loop reads the length, appends one key (the reading's FIRST append to the
    // name, logged at length 2), is refused, cuts back to the length it read and pushes the marker.
    root.set_measurement(Measurement::Quiet);
    let len = root.variable_capture_len("x");
    assert_eq!(2, len, "the mark is the real run's length");
    root.add_variable_capture("x", key("C")?)?;
    assert_eq!(3, root.variable_capture_len("x"), "the reading's append");
    root.truncate_variable_capture("x", len)?;
    assert_eq!(
        2,
        root.variable_capture_len("x"),
        "the cut takes back the reading's own append"
    );
    root.add_variable_capture("x", key("M")?)?;
    // A second loop of the same reading: its length is read after the reading's first append.
    let later = root.variable_capture_len("x");
    assert_eq!(3, later);
    root.add_variable_capture("x", key("D")?)?;
    root.truncate_variable_capture("x", later)?;
    assert_eq!(
        3,
        root.variable_capture_len("x"),
        "the cut leaves the reading's earlier marker"
    );
    // The reading ends: the roll-back truncates to the logged length, the real run's two keys.
    root.set_measurement(Measurement::Off);
    assert_eq!(
        2,
        root.variable_capture_len("x"),
        "the real run's keys stand after the roll-back"
    );
    // The real run's own cut goes down to the length it read.
    root.add_variable_capture("x", key("E")?)?;
    root.truncate_variable_capture("x", 2)?;
    assert_eq!(2, root.variable_capture_len("x"));
    root.truncate_variable_capture("x", 1)?;
    assert_eq!(
        1,
        root.variable_capture_len("x"),
        "a cut below the real run's keys is the caller's"
    );
    Ok(())
}

/// The map at `/Resources/Cfg` of a one-resource document, walked by hand so the value carries that path.
fn cfg_of_a_one_resource_document() -> Result<Rc<PathAwareValue>> {
    let value = PathAwareValue::try_from(r#"{ Resources: { Cfg: { x: 1 } } }"#)?;
    let cfg = match &value {
        PathAwareValue::Map((_, root)) => match root.values.get("Resources") {
            Some(PathAwareValue::Map((_, resources))) => match resources.values.get("Cfg") {
                Some(cfg) => Rc::new(cfg.clone()),
                None => panic!("the document has Resources.Cfg"),
            },
            _ => panic!("the document has a Resources map"),
        },
        _ => panic!("the document is a map"),
    };
    assert_eq!("/Resources/Cfg", cfg.self_path().0.as_str());
    Ok(cfg)
}

/// `undecidable_reason` reads the marker's kind and nothing else: the reason for the undecidable kind,
/// a refusal's or a key filter's (the recorded one, or the path when none was recorded), `None` for a
/// value the document lacks and for an enumeration over an empty collection. The binary arms branch on
/// this `Option` with no catch-all, so a non-undecidable unresolved value is a decided failure because
/// the helper said so, not because a wildcard arm absorbed it.
#[rstest::rstest]
#[case::absent_is_decided(UnResolvedKind::Absent, Some("why"), None)]
#[case::empty_enumeration_is_decided(UnResolvedKind::EmptyEnumeration, Some("why"), None)]
#[case::undecidable_with_a_reason(
    UnResolvedKind::Undecidable { refused: false },
    Some("why"),
    Some("why")
)]
#[case::refused_with_a_reason(
    UnResolvedKind::Undecidable { refused: true },
    Some("why"),
    Some("why")
)]
#[case::undecidable_without_a_reason_names_the_path(
    UnResolvedKind::Undecidable { refused: false },
    None,
    Some("the selection at /Resources/Cfg[L:0,C:0] could not be decided")
)]
#[case::refused_without_a_reason_names_the_path(
    UnResolvedKind::Undecidable { refused: true },
    None,
    Some("the selection at /Resources/Cfg[L:0,C:0] could not be decided")
)]
fn undecidable_reason_reads_the_kind_alone(
    #[case] kind: UnResolvedKind,
    #[case] reason: Option<&str>,
    #[case] expected: Option<&str>,
) -> Result<()> {
    let unresolved = UnResolved {
        traversed_to: cfg_of_a_one_resource_document()?,
        remaining_query: "[ keys NOT IN %missing ]".to_string(),
        reason: reason.map(str::to_string),
        kind,
    };
    assert_eq!(
        expected.map(str::to_string),
        crate::rules::eval::undecidable_reason(&unresolved),
        "{:?} with reason {:?}",
        kind,
        reason
    );
    Ok(())
}

/// The function dispatch refuses an undecidable argument entry through the one reader of the marker, so a
/// marker recorded without a reason is reported in the operators' words, naming the path, and not in a
/// text of the dispatch's own.
///
/// The dispatch matched the marker's kind itself and fell back to "a selection the function was given
/// could not be decided", where the operators say "the selection at <path> could not be decided" for the
/// same marker; it reads through `undecidable_reason` now. A recorded reason comes through as it is, a
/// refusal's marker is read as a key filter's, a decided unresolved entry (a value the document lacks) is
/// not a refusal, and the marker is found among decided entries of the same argument and in a later
/// argument.
#[rstest::rstest]
#[case::without_a_reason_names_the_path(
    UnResolvedKind::Undecidable { refused: false },
    None,
    Some("the selection at /Resources/Cfg[L:0,C:0] could not be decided")
)]
#[case::with_a_reason_carries_it(
    UnResolvedKind::Undecidable { refused: false },
    Some("why"),
    Some("why")
)]
#[case::a_refusal_carries_it(
    UnResolvedKind::Undecidable { refused: true },
    Some("why"),
    Some("why")
)]
#[case::a_decided_absence_is_no_refusal(UnResolvedKind::Absent, Some("why"), None)]
fn a_function_refuses_an_undecidable_argument_in_the_operators_words(
    #[case] kind: UnResolvedKind,
    #[case] reason: Option<&str>,
    #[case] expected: Option<&str>,
) -> Result<()> {
    let marker = QueryResult::UnResolved(UnResolved {
        traversed_to: cfg_of_a_one_resource_document()?,
        remaining_query: "[ keys NOT IN %missing ]".to_string(),
        reason: reason.map(str::to_string),
        kind,
    });
    let decided = QueryResult::Resolved(Rc::new(PathAwareValue::try_from(r#""a""#)?));
    let expected = expected.map(str::to_string);
    assert_eq!(
        expected,
        undecidable_argument_reason(&[vec![marker.clone()]]),
        "the marker alone"
    );
    assert_eq!(
        expected,
        undecidable_argument_reason(&[vec![decided.clone(), marker.clone()]]),
        "the marker after a decided entry of the same argument"
    );
    assert_eq!(
        expected,
        undecidable_argument_reason(&[vec![decided], vec![marker]]),
        "the marker in a later argument"
    );
    assert_eq!(
        None,
        undecidable_argument_reason(&[vec![]]),
        "no marker, no refusal"
    );
    Ok(())
}

/// The kind the pass-over refusal names is read from the entry the predicate tested: a map, a list and
/// a null each have their own, a scalar has none, and the kinds are worded in the order map, list, null.
#[test]
fn entry_kinds_are_read_from_the_value_and_worded_in_order() -> Result<()> {
    let document = PathAwareValue::try_from(r#"{"M": {"a": 1}, "L": ["a"], "N": null, "S": "s"}"#)?;
    let PathAwareValue::Map((_, entries)) = &document else {
        panic!("the document is a map");
    };
    let kind_of = |key: &str| EntryKinds::of(&entries.values[key]);
    assert_eq!("map-valued", kind_of("M").named());
    assert_eq!("list-valued", kind_of("L").named());
    assert_eq!("null", kind_of("N").named());
    assert!(kind_of("S").is_empty(), "a scalar has no kind");
    assert_eq!("", kind_of("S").named());
    assert!(kind_of("M").holds_a_member());
    assert!(kind_of("L").holds_a_member());
    assert!(!kind_of("N").holds_a_member(), "a null alone is no member");
    let m_and_l = kind_of("L").with(kind_of("M"));
    assert_eq!("map-valued or list-valued", m_and_l.named());
    assert_eq!(
        "map-valued, list-valued or null",
        kind_of("N").with(m_and_l).named()
    );
    assert_eq!(
        "map-valued or null",
        kind_of("N").with(kind_of("M")).named()
    );
    assert_eq!(
        "list-valued or null",
        kind_of("N").with(kind_of("L")).named()
    );
    Ok(())
}

// `CaptureFrames` on its own: a store of strings, the frame calls in the order the loops make them, and
// what the store reads at each step. The rules under test are the ones the loop sites rely on: a
// nested begin/end pair moves the depth and parks nothing until the outermost entry ends; `close` parks
// a segment still running and appends every parked slice back in loop order; `cut` reads the
// ABSOLUTE start of a parked slice (its live start plus what the frames of its home already held parked)
// against a mark taken on the same scale, so an earlier entry's slice survives a later entry's cut, and
// a slice that crosses the mark keeps what lies below it; an entry's end removes a name the entry made
// and the close puts it back; what an entry hands up into `merged` is parked with it;
// `insert_below_segment` files a result the entry's end leaves in place; with no frame open the calls
// change nothing and the insert declines.
fn a_capture_of(text: &str) -> QueryResult {
    QueryResult::Resolved(Rc::new(
        PathAwareValue::try_from(format!("\"{text}\"").as_str()).expect("a string value"),
    ))
}

fn texts_of(results: &[QueryResult]) -> Vec<String> {
    results
        .iter()
        .map(|result| match result {
            QueryResult::Resolved(value) => match &**value {
                PathAwareValue::String((_, text)) => text.clone(),
                other => format!("{other:?}"),
            },
            other => format!("{other:?}"),
        })
        .collect()
}

fn texts_under(store: &CaptureStore<'_>, name: &str) -> Vec<String> {
    store
        .get(name)
        .map(|results| texts_of(results))
        .unwrap_or_default()
}

#[test]
fn nested_begins_park_only_when_the_outermost_entry_ends() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("x").or_default().push(a_capture_of("a"));
    frames.begin_segment(&store, &merged);
    store.entry("x").or_default().push(a_capture_of("b"));
    assert!(
        frames.end_segment(&mut store, &mut merged).is_empty(),
        "the inner end moves the depth and parks nothing"
    );
    assert_eq!(vec!["a", "b"], texts_under(&store, "x"));
    assert_eq!(vec!["x"], frames.end_segment(&mut store, &mut merged));
    assert!(
        texts_under(&store, "x").is_empty(),
        "the outermost end parks both appends"
    );
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["a", "b"], texts_under(&store, "x"));
}

#[test]
fn close_with_a_segment_still_running_parks_it_and_appends_every_slice_back_in_loop_order() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("x").or_default().push(a_capture_of("a"));
    frames.end_segment(&mut store, &mut merged);
    frames.begin_segment(&store, &merged);
    store.entry("x").or_default().push(a_capture_of("b"));
    frames.begin_segment(&store, &merged);
    store.entry("y").or_default().push(a_capture_of("c"));
    assert_eq!(1, frames.parked_len(CaptureHome::Captured, "x"));
    let changed = frames.close(&mut store, &mut merged);
    assert!(changed.contains(&"x") && changed.contains(&"y"));
    assert_eq!(vec!["a", "b"], texts_under(&store, "x"));
    assert_eq!(vec!["c"], texts_under(&store, "y"));
    assert_eq!(0, frames.parked_len(CaptureHome::Captured, "x"));
    assert_eq!(0, frames.parked_len(CaptureHome::Captured, "y"));
}

#[test]
fn a_parked_slice_at_or_above_the_mark_goes_with_a_cut_and_one_below_it_stays() {
    let kept = |len: usize| -> Vec<String> {
        let mut frames = CaptureFrames::default();
        let mut store: CaptureStore<'static> = HashMap::new();
        let mut merged: CaptureStore<'static> = HashMap::new();
        store
            .entry("x")
            .or_default()
            .extend([a_capture_of("k1"), a_capture_of("k2")]);
        frames.open(CaptureHome::Captured, 0, &store, &merged, true);
        frames.begin_segment(&store, &merged);
        store.entry("x").or_default().push(a_capture_of("a"));
        frames.end_segment(&mut store, &mut merged);
        frames.cut(CaptureHome::Captured, &mut store, "x", len);
        frames.close(&mut store, &mut merged);
        texts_under(&store, "x")
    };
    assert_eq!(
        vec!["k1", "k2", "a"],
        kept(3),
        "a slice parked at 2 is below a mark of 3"
    );
    assert_eq!(
        vec!["k1", "k2"],
        kept(2),
        "a slice parked at 2 is at a mark of 2 and goes"
    );
    assert_eq!(
        vec!["k1"],
        kept(1),
        "a cut below the live length takes the live prefix down to it"
    );
    assert!(kept(0).is_empty(), "a cut to 0 takes everything");
}

#[test]
fn a_cut_lowers_a_running_segments_start_so_the_entry_parks_what_it_appended_after_it() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    store
        .entry("x")
        .or_default()
        .extend([a_capture_of("k1"), a_capture_of("k2")]);
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    // The cut, as the owner makes it.
    assert!(frames.cut(CaptureHome::Captured, &mut store, "x", 1));
    assert_eq!(vec!["k1"], texts_under(&store, "x"));
    store.entry("x").or_default().push(a_capture_of("a"));
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(
        vec!["k1"],
        texts_under(&store, "x"),
        "the append after the cut is this entry's and is parked at its end"
    );
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["k1", "a"], texts_under(&store, "x"));
}

#[test]
fn a_cut_in_the_other_home_leaves_the_frame_alone() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("x").or_default().push(a_capture_of("a"));
    frames.end_segment(&mut store, &mut merged);
    // The other home's store, the one its owner would hand in with the cut.
    let mut assignments: CaptureStore<'static> = HashMap::new();
    assert!(!frames.cut(CaptureHome::Assignment, &mut assignments, "x", 0));
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["a"], texts_under(&store, "x"));
}

#[test]
fn a_result_filed_below_the_segment_survives_the_entrys_end() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("x").or_default().push(a_capture_of("a"));
    assert!(frames.insert_below_segment(&mut store, "x", a_capture_of("key")));
    assert_eq!(vec!["key", "a"], texts_under(&store, "x"));
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(
        vec!["key"],
        texts_under(&store, "x"),
        "the entry's own append is parked, the key filed below the segment stays"
    );
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["key", "a"], texts_under(&store, "x"));
}

#[test]
fn a_mark_counts_the_parked_slices_so_a_later_entrys_cut_leaves_an_earlier_entrys_slice_alone() {
    // The F5a shape: entry 1 parks [a]; under entry 2 a clause binds fresh and is refused. Its mark is
    // taken on the absolute scale (the live length plus what is parked), so the cut back to it drops
    // entry 2's own bind and nothing of entry 1's. Read against the live length alone the mark was 0,
    // the same base as entry 1's slice, and the cut took entry 1's keys with it.
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("x").or_default().push(a_capture_of("a"));
    frames.end_segment(&mut store, &mut merged);
    frames.begin_segment(&store, &merged);
    let mark = texts_under(&store, "x").len() + frames.parked_len(CaptureHome::Captured, "x");
    assert_eq!(1, mark, "the mark is past entry 1's parked slice");
    store.entry("x").or_default().push(a_capture_of("b"));
    // The owner's cut, as `truncate_variable_capture` makes it.
    assert!(frames.cut(CaptureHome::Captured, &mut store, "x", mark));
    assert!(
        texts_under(&store, "x").is_empty(),
        "entry 2's own bind is cut"
    );
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(
        vec!["a"],
        texts_under(&store, "x"),
        "entry 1's slice survives the cut"
    );
}

#[test]
fn a_parked_slice_that_crosses_the_mark_keeps_what_lies_below_it_and_the_prefix_survives() {
    // `x` holds `k` before the loop. Entry 1 binds `a`, the clause marks (at 2, past `k` and `a`), and
    // binds `b`; its end parks `[a, b]` at 1. Entry 2 binds `c` and is refused: the cut back to 2 must
    // take `b` and `c` and leave `k` and `a`. Kept WHOLE, the parked slice counted 2 against the live
    // store, which was cut to nothing, and `k`, bound before the loop, was gone; with the resources in
    // the other order (the refusal first, nothing parked) `k` stayed.
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    store.entry("x").or_default().push(a_capture_of("k"));
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("x").or_default().push(a_capture_of("a"));
    let mark = texts_under(&store, "x").len() + frames.parked_len(CaptureHome::Captured, "x");
    assert_eq!(2, mark);
    store.entry("x").or_default().push(a_capture_of("b"));
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(vec!["k"], texts_under(&store, "x"));
    frames.begin_segment(&store, &merged);
    store.entry("x").or_default().push(a_capture_of("c"));
    assert!(frames.cut(CaptureHome::Captured, &mut store, "x", mark));
    assert_eq!(
        vec!["k"],
        texts_under(&store, "x"),
        "the capture bound before the loop survives entry 2's cut"
    );
    assert_eq!(
        1,
        frames.parked_len(CaptureHome::Captured, "x"),
        "entry 1's slice keeps `a`, below the mark, and loses `b`"
    );
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["k", "a"], texts_under(&store, "x"));
}

#[test]
fn a_cut_answers_whether_the_live_entry_shrank() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let merged: CaptureStore<'static> = HashMap::new();
    store
        .entry("x")
        .or_default()
        .extend([a_capture_of("k1"), a_capture_of("k2")]);
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    assert!(
        !frames.cut(CaptureHome::Captured, &mut store, "x", 2),
        "a cut at the live length changes nothing"
    );
    assert!(
        !frames.cut(CaptureHome::Captured, &mut store, "y", 0),
        "a name the store does not hold"
    );
    assert!(frames.cut(CaptureHome::Captured, &mut store, "x", 1));
    assert_eq!(vec!["k1"], texts_under(&store, "x"));
}

/// The name an entry's work made (absent when its segment began) is removed when the segment ends and
/// comes back at the close. `split_off` leaves the name behind with an empty `Vec`, and the readers that
/// decide whether a name is bound ask `contains_key`, so under entry 2 the name entry 1 made read as
/// bound (a capture key shadowing a `let` of the same name, in the order where the capturing entry came
/// first). No rules file reaches the shadowing: the parser refuses a `let t` beside a filter capture
/// `t` ("Variable t is both assigned and declared as a filter capture"), so the row is this one, at the
/// frames' own API.
#[test]
fn an_entrys_end_removes_a_name_the_entry_made_and_the_close_puts_it_back() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    // `e` stood in the store, empty, before the loop: it was there, and stays.
    store.entry("e").or_default();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("t").or_default().push(a_capture_of("prod"));
    merged.entry("m").or_default().push(a_capture_of("up"));
    let changed = frames.end_segment(&mut store, &mut merged);
    assert!(changed.contains(&"t") && changed.contains(&"m"));
    assert!(
        !store.contains_key("t"),
        "entry 1 made `t`; the next entry must not read it as bound"
    );
    assert!(!merged.contains_key("m"));
    assert!(
        store.contains_key("e"),
        "a name that stood before the loop stays"
    );
    frames.begin_segment(&store, &merged);
    assert!(!store.contains_key("t"));
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["prod"], texts_under(&store, "t"));
    assert_eq!(vec!["up"], texts_under(&merged, "m"));
    assert!(store.contains_key("e"));
}

#[test]
fn a_name_whose_every_slice_a_cut_took_stands_empty_after_the_loop_as_a_cut_left_it() {
    // Entry 1 makes `t` and its end parks `[prod]` and removes the name; entry 2's refusal cuts `t` back
    // to a mark taken before the loop (0), which takes the parked slice. After the loop `t` is bound to
    // nothing, the shape a cut left before the frames, so a reader after the loop finds what it found.
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("t").or_default().push(a_capture_of("prod"));
    frames.end_segment(&mut store, &mut merged);
    assert!(!store.contains_key("t"));
    frames.begin_segment(&store, &merged);
    assert!(!frames.cut(CaptureHome::Captured, &mut store, "t", 0));
    assert_eq!(0, frames.parked_len(CaptureHome::Captured, "t"));
    frames.end_segment(&mut store, &mut merged);
    let changed = frames.close(&mut store, &mut merged);
    assert!(store.contains_key("t"));
    assert!(texts_under(&store, "t").is_empty());
    assert!(
        changed.contains(&"t"),
        "the name put back is a changed name, as its removal was: an owner counting generations moves"
    );
}

#[test]
fn what_an_entry_hands_up_into_merged_is_parked_with_it_and_appended_back_at_the_close() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    merged.entry("t").or_default().push(a_capture_of("prod"));
    assert_eq!(
        vec!["prod"],
        texts_under(&merged, "t"),
        "readable under its own entry"
    );
    frames.end_segment(&mut store, &mut merged);
    frames.begin_segment(&store, &merged);
    assert!(
        texts_under(&merged, "t").is_empty(),
        "the next entry does not read what the first handed up"
    );
    merged.entry("t").or_default().push(a_capture_of("dev"));
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(
        vec!["prod", "dev"],
        texts_under(&merged, "t"),
        "the union after the loop"
    );
}

#[test]
fn a_loop_run_for_a_let_the_outer_entry_forced_leaves_its_keys_below_the_outer_segment() {
    // The outer loop's entry 1 is running (depth 0); it forces a `let` whose filter loops (a frame at
    // depth 1) and binds `b` below its own segments, as the own-key bind does. At the inner close the
    // keys go below the OUTER segment, so entry 1's end parks nothing of them and entry 2 reads them;
    // filed inside entry 1's segment they were parked with it and read empty under entry 2.
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("t").or_default().push(a_capture_of("own"));
    frames.open(CaptureHome::Captured, 1, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    assert!(frames.insert_below_segment(&mut store, "b", a_capture_of("R1")));
    frames.end_segment(&mut store, &mut merged);
    frames.begin_segment(&store, &merged);
    assert!(frames.insert_below_segment(&mut store, "b", a_capture_of("R2")));
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(
        vec!["R1", "R2"],
        texts_under(&store, "b"),
        "the let's keys, in loop order"
    );
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(
        vec!["R1", "R2"],
        texts_under(&store, "b"),
        "the outer entry's end parks its own `t` and leaves the let's `b` in place"
    );
    assert!(texts_under(&store, "t").is_empty());
    frames.begin_segment(&store, &merged);
    assert_eq!(
        vec!["R1", "R2"],
        texts_under(&store, "b"),
        "readable under the next entry"
    );
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["R1", "R2"], texts_under(&store, "b"));
    assert_eq!(vec!["own"], texts_under(&store, "t"));
}

#[test]
fn with_no_frame_open_the_calls_change_nothing_and_the_insert_declines() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.begin_segment(&store, &merged);
    store.entry("x").or_default().push(a_capture_of("a"));
    assert!(frames.end_segment(&mut store, &mut merged).is_empty());
    assert!(!frames.insert_below_segment(&mut store, "x", a_capture_of("key")));
    assert!(frames.close(&mut store, &mut merged).is_empty());
    assert_eq!(vec!["a"], texts_under(&store, "x"));
}

#[test]
fn a_bind_below_the_segment_from_a_begin_inside_it_is_filed_below_the_loops_segment_whatever_the_depth(
) {
    // The list-wildcard loop's element is running (depth 1); the element's filter begins again, which
    // opens nothing (depth 2), and binds the member's key below the segment. The key belongs to the loop
    // that expanded the list, so it is filed below the loop's segment at depth 2 as it would be at depth
    // 1: the element's end leaves it, and the next element's continuation reads it. An insert declined
    // past depth 1 would append the key inside the element's segment and park it with it, so
    // `Tags[*][ t | ... ].Sub[ Name IN %t[*].Value ]` would read an empty `%t` under the second tag
    // where `Tags[ t | ... ]` reads both. Whose key a bind is, the loop's or the entry's own, is the owner's
    // call (`OwnKeyFiling`), pinned at the rules level beside this.
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    frames.begin_segment(&store, &merged);
    assert!(
        frames.insert_below_segment(&mut store, "t", a_capture_of("prod")),
        "a bind below the segment at depth 2 is filed below the loop's segment"
    );
    store.entry("t").or_default().push(a_capture_of("own"));
    assert!(
        frames.end_segment(&mut store, &mut merged).is_empty(),
        "the inner end parks nothing"
    );
    assert_eq!(
        vec!["t"],
        frames.end_segment(&mut store, &mut merged),
        "the element's end parks its own append and leaves the key"
    );
    assert_eq!(vec!["prod"], texts_under(&store, "t"));
    frames.begin_segment(&store, &merged);
    frames.begin_segment(&store, &merged);
    assert!(frames.insert_below_segment(&mut store, "t", a_capture_of("dev")));
    assert_eq!(
        vec!["prod", "dev"],
        texts_under(&store, "t"),
        "the next element reads the keys held so far"
    );
    frames.end_segment(&mut store, &mut merged);
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["prod", "dev", "own"], texts_under(&store, "t"));
}

#[test]
fn a_frame_with_no_segment_running_declines_the_insert_and_its_own_segment_takes_it() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    assert!(
        !frames.insert_below_segment(&mut store, "x", a_capture_of("key")),
        "a frame open with no segment running files nothing below"
    );
    assert!(texts_under(&store, "x").is_empty());
    frames.begin_segment(&store, &merged);
    assert!(
        frames.insert_below_segment(&mut store, "x", a_capture_of("key")),
        "at depth 1 the loop that opened the segment files below it"
    );
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(vec!["key"], texts_under(&store, "x"));
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["key"], texts_under(&store, "x"));
}

#[test]
fn a_let_forced_from_a_begin_inside_the_running_segment_still_leaves_its_keys_below_the_outer_segment(
) {
    // The forced `let`'s loop is opened while the outer entry's work sits at depth 2 (a filter run for one
    // value forced it). Its keys still go below the OUTER segment at its close, whatever depth the outer
    // frame has reached: the `let` is memoised and every later entry reads it.
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    frames.begin_segment(&store, &merged);
    store.entry("t").or_default().push(a_capture_of("own"));
    frames.open(CaptureHome::Captured, 1, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    assert!(frames.insert_below_segment(&mut store, "b", a_capture_of("R1")));
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["R1"], texts_under(&store, "b"));
    assert!(
        frames.end_segment(&mut store, &mut merged).is_empty(),
        "the inner end of the outer frame parks nothing"
    );
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(
        vec!["R1"],
        texts_under(&store, "b"),
        "the outer entry's end parks its own `t` and leaves the let's `b` in place"
    );
    assert!(texts_under(&store, "t").is_empty());
    frames.begin_segment(&store, &merged);
    assert_eq!(
        vec!["R1"],
        texts_under(&store, "b"),
        "readable under the next entry"
    );
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["own"], texts_under(&store, "t"));
}

#[test]
fn a_let_forced_by_an_entry_leaves_its_merged_keys_below_the_outer_segment_too() {
    // The forced `let`'s predicate holds a nested block that hands a key up into `merged` under the
    // let's entry; the let's loop parks it with that entry and appends it back at its close. Appended
    // back INSIDE the forcing entry's segment, it was parked again with the forcing entry and the
    // entries after it read the memoised let's merged key empty; it goes below the outer segment, as
    // the let's captured keys do.
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    merged.entry("t").or_default().push(a_capture_of("own"));
    frames.open(CaptureHome::Captured, 1, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    merged.entry("m").or_default().push(a_capture_of("k1"));
    frames.end_segment(&mut store, &mut merged);
    assert!(
        texts_under(&merged, "m").is_empty(),
        "parked with the let's first entry"
    );
    frames.begin_segment(&store, &merged);
    merged.entry("m").or_default().push(a_capture_of("k2"));
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(
        vec!["k1", "k2"],
        texts_under(&merged, "m"),
        "appended back at the let's close, in loop order"
    );
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(
        vec!["k1", "k2"],
        texts_under(&merged, "m"),
        "the forcing entry's end parks its own `t` and leaves the let's merged `m` in place"
    );
    assert!(texts_under(&merged, "t").is_empty());
    frames.begin_segment(&store, &merged);
    assert_eq!(
        vec!["k1", "k2"],
        texts_under(&merged, "m"),
        "readable under the next entry"
    );
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["own"], texts_under(&merged, "t"));
    assert_eq!(vec!["k1", "k2"], texts_under(&merged, "m"));
}

#[test]
fn a_let_forced_while_the_owner_writes_nothing_records_no_opened_lengths() {
    // The owner says whether it writes captures at the open (`writes_captures`); the frames read no
    // measurement of their own. A frame opened while nothing is written has nothing to move: its keys
    // stay where the entry appended them, the outer segment's starts are not moved, and the entry's end
    // parks them with its own. Opened while the owner writes (the companion test above), the same frame
    // moves the let's keys below the outer segment, under a measurement as in the real run. A frame that
    // read `Measurement::Off` here would miss that a block built for the reading writes without an undo
    // log, so inside a measured `when` it would park a forced let's keys with the forcing entry and read
    // the memoised let empty under every later resource where the real run reads it full.
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    frames.open(CaptureHome::Captured, 1, &store, &merged, false);
    frames.begin_segment(&store, &merged);
    store.entry("b").or_default().push(a_capture_of("R1"));
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(
        vec!["R1"],
        texts_under(&store, "b"),
        "the let's key is back in the live store at the close"
    );
    let outer_start_for_b = frames.frames[0]
        .segment
        .as_ref()
        .and_then(|starts| starts.get("b").copied());
    assert_eq!(
        None, outer_start_for_b,
        "no start was moved for a name the outer segment never saw"
    );
    frames.end_segment(&mut store, &mut merged);
    assert!(
        texts_under(&store, "b").is_empty(),
        "parked with the forcing entry: nothing was written to move"
    );
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["R1"], texts_under(&store, "b"));
}

/// A reading's undo log clones a frame's segment starts once per frame: the first touch under a frame
/// records them (`ReadingUndo::note_frame_starts`, through `CaptureFrames::starts_record`), a second
/// touch under the same frame clones nothing, an ask for an outer frame that does not exist clones
/// nothing, and a touch under a newly opened frame records that frame once. Counted through
/// `CAPTURE_FRAME_STARTS_CLONES`.
#[test]
fn a_second_touch_of_a_logged_name_clones_no_segment_starts() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    store.entry("x").or_default().push(a_capture_of("k"));
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    let mut undo = ReadingUndo::default();
    let clones = || CAPTURE_FRAME_STARTS_CLONES.with(|count| count.get());
    CAPTURE_FRAME_STARTS_CLONES.with(|count| count.set(0));
    undo.note_frame_starts(&frames, false);
    assert_eq!(
        1,
        clones(),
        "the first touch under the frame records its starts"
    );
    undo.note_frame_starts(&frames, false);
    assert_eq!(
        1,
        clones(),
        "a second touch under the same frame clones nothing: the index is checked before the record is taken"
    );
    undo.note_frame_starts(&frames, true);
    assert_eq!(
        1,
        clones(),
        "no outer frame exists: nothing to record, nothing cloned"
    );
    frames.open(CaptureHome::Captured, 1, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    undo.note_frame_starts(&frames, false);
    assert_eq!(
        2,
        clones(),
        "a touch under a newly opened frame records that frame once"
    );
    undo.note_frame_starts(&frames, true);
    assert_eq!(
        2,
        clones(),
        "the outer frame is already recorded: nothing cloned"
    );
    assert_eq!(2, undo.frame_starts.len(), "one record per frame touched");
    frames.close(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
}

#[test]
fn a_readings_roll_back_puts_every_touched_name_back_as_it_stood() {
    // The log keeps each name whole at its first touch, so inserts below the real run's keys, appends and
    // cuts inside the reading are all undone exactly; a name the reading created is removed.
    let mut undo = ReadingUndo::default();
    let mut resolved: HashMap<&'static str, Vec<QueryResult>> = HashMap::new();
    let mut shapes: HashMap<&'static str, (RhsEnumeration, PassedOn)> = HashMap::new();
    let mut entry_sets: HashMap<&'static str, Rc<FunctionEntries>> = HashMap::new();
    let mut captures: CaptureStore<'static> = HashMap::new();
    captures
        .entry("x")
        .or_default()
        .extend([a_capture_of("k1"), a_capture_of("k2")]);
    // The reading touches `x` three ways: an insert below the real run's keys, an append, a cut.
    undo.note_touched("x", captures.get("x").cloned());
    captures
        .get_mut("x")
        .unwrap()
        .insert(0, a_capture_of("below"));
    undo.note_touched("x", captures.get("x").cloned());
    captures.get_mut("x").unwrap().push(a_capture_of("after"));
    captures.get_mut("x").unwrap().truncate(2);
    assert_eq!(vec!["below", "k1"], texts_under(&captures, "x"));
    // And creates `y`.
    undo.note_touched("y", captures.get("y").cloned());
    captures.entry("y").or_default().push(a_capture_of("new"));
    let mut frames = CaptureFrames::default();
    let mut failed = HashMap::new();
    let mut put_back = undo.roll_back(
        &mut resolved,
        &mut shapes,
        &mut entry_sets,
        &mut failed,
        &mut captures,
        &mut frames,
    );
    put_back.sort_unstable();
    assert_eq!(vec!["x", "y"], put_back);
    assert_eq!(
        vec!["k1", "k2"],
        texts_under(&captures, "x"),
        "the real run's list, whatever the reading did to it"
    );
    assert!(
        !captures.contains_key("y"),
        "a name the reading created is gone"
    );
    assert!(
        undo.roll_back(
            &mut resolved,
            &mut shapes,
            &mut entry_sets,
            &mut failed,
            &mut captures,
            &mut frames
        )
        .is_empty(),
        "a second roll-back has nothing to put back"
    );
}

/// A scope that counts the segment calls it forwards to the one beneath it and, when asked, refuses the
/// own-key bind: the way to drive an entry loop out through the `?` between its predicate and its walk.
struct SegmentsCounted<'scope, 'value, 'loc: 'value> {
    inner: &'scope mut dyn EvalContext<'value, 'loc>,
    begins: usize,
    ends: usize,
    refuses_the_key_bind: bool,
}

impl<'scope, 'value, 'loc: 'value> RecordTracer<'value> for SegmentsCounted<'scope, 'value, 'loc> {
    fn start_record(&mut self, context: &str) -> Result<()> {
        self.inner.start_record(context)
    }
    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.inner.end_record(context, record)
    }
}

impl<'scope, 'value, 'loc: 'value> EvalContext<'value, 'loc>
    for SegmentsCounted<'scope, 'value, 'loc>
{
    fn begin_capture_entry(&mut self) {
        self.begins += 1;
        self.inner.begin_capture_entry()
    }
    fn end_capture_entry(&mut self) {
        self.ends += 1;
        self.inner.end_capture_entry()
    }
    fn end_capture_entry_detached(&mut self) -> EntryCaptures<'value> {
        self.ends += 1;
        self.inner.end_capture_entry_detached()
    }
    fn refile_captures(&mut self, captures: EntryCaptures<'value>) {
        self.inner.refile_captures(captures)
    }
    fn add_variable_capture_key_below_the_entry(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        if self.refuses_the_key_bind {
            return Err(Error::IncompatibleError(format!(
                "the bind of `{variable_name}` is refused here"
            )));
        }
        self.inner
            .add_variable_capture_key_below_the_entry(variable_name, key)
    }
    fn open_capture_frame(&mut self) {
        self.inner.open_capture_frame()
    }
    fn close_capture_frame(&mut self) {
        self.inner.close_capture_frame()
    }
    fn has_deprecation_site(&mut self, kind: DeprecationKind, site: &FileLocation<'_>) -> bool {
        self.inner.has_deprecation_site(kind, site)
    }
    fn has_quiet_filter_site(
        &mut self,
        kind: DeprecationKind,
        site: &FileLocation<'_>,
        text: &str,
    ) -> bool {
        self.inner.has_quiet_filter_site(kind, site, text)
    }
    fn has_quiet_record_at(&mut self, kind: DeprecationKind, site: &FileLocation<'_>) -> bool {
        self.inner.has_quiet_record_at(kind, site)
    }
    fn record_quiet_filter_site(
        &mut self,
        kind: DeprecationKind,
        site: &FileLocation<'_>,
        text: &str,
    ) {
        self.inner.record_quiet_filter_site(kind, site, text)
    }
    fn variable_binding_source(&mut self, name: &str) -> Option<BindingSource<'value, 'loc>> {
        self.inner.variable_binding_source(name)
    }
    fn quiet_record_key_step(
        &mut self,
        variable_name: &str,
        hops_left: usize,
    ) -> crate::rules::eval_context::QuietRecordKey {
        self.inner.quiet_record_key_step(variable_name, hops_left)
    }
    fn root_quiet_record_key(
        &mut self,
        hops_left: usize,
    ) -> crate::rules::eval_context::QuietRecordKey {
        self.inner.root_quiet_record_key(hops_left)
    }
    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult>> {
        self.inner.query(query)
    }
    fn find_parameterized_rule(
        &mut self,
        rule_name: &str,
    ) -> Result<&'value ParameterizedRule<'loc>> {
        self.inner.find_parameterized_rule(rule_name)
    }
    fn root(&mut self) -> Rc<PathAwareValue> {
        self.inner.root()
    }
    fn document_root(&mut self) -> Rc<PathAwareValue> {
        self.inner.document_root()
    }
    fn query_start(&self) -> QueryStart {
        self.inner.query_start()
    }
    fn in_predicate(&self) -> bool {
        self.inner.in_predicate()
    }
    fn empty_selection(&self) -> Option<Rc<EmptySelection>> {
        self.inner.empty_selection()
    }
    fn reads_beside_the_map(&self) -> bool {
        self.inner.reads_beside_the_map()
    }
    fn fallback_root(&mut self) -> Rc<PathAwareValue> {
        self.inner.fallback_root()
    }
    fn is_top_level_alias(&self, variable_name: &str, merged: MergedKeys) -> bool {
        self.inner.is_top_level_alias(variable_name, merged)
    }
    fn rule_status(
        &mut self,
        rule_name: &'value str,
        role: crate::rules::eval::ClauseRole,
    ) -> Result<Status> {
        self.inner.rule_status(rule_name, role)
    }
    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult>> {
        self.inner.resolve_variable(variable_name)
    }
    fn literal_binding(&self, variable_name: &str) -> Option<Vec<Rc<PathAwareValue>>> {
        self.inner.literal_binding(variable_name)
    }
    fn variable_binding_query(
        &mut self,
        variable_name: &str,
        merged: MergedKeys,
    ) -> Option<&'value AccessQuery<'loc>> {
        self.inner.variable_binding_query(variable_name, merged)
    }
    fn variable_shape(
        &mut self,
        variable_name: &str,
        merged: MergedKeys,
    ) -> (RhsEnumeration, PassedOn) {
        self.inner.variable_shape(variable_name, merged)
    }
    fn variable_lists_keys(&self, variable_name: &str, merged: MergedKeys) -> bool {
        self.inner.variable_lists_keys(variable_name, merged)
    }
    fn query_with_shape(
        &mut self,
        query: &'value [QueryPart<'loc>],
    ) -> Result<(Vec<QueryResult>, RhsEnumeration, PassedOn)> {
        self.inner.query_with_shape(query)
    }
    fn note_query_grounding(&mut self, query: &'value [QueryPart<'loc>], results: &[QueryResult]) {
        self.inner.note_query_grounding(query, results)
    }
    fn projection_member_keys(
        &mut self,
        variable_name: &str,
        merged: MergedKeys,
    ) -> Result<Option<Rc<ProjectionKeys>>> {
        self.inner.projection_member_keys(variable_name, merged)
    }
    fn add_variable_capture(
        &mut self,
        variable_name: &'value str,
        result: QueryResult,
    ) -> Result<()> {
        self.inner.add_variable_capture(variable_name, result)
    }
    fn variable_capture_len(&self, variable_name: &str) -> usize {
        self.inner.variable_capture_len(variable_name)
    }
    fn truncate_variable_capture(&mut self, variable_name: &'value str, len: usize) -> Result<()> {
        self.inner.truncate_variable_capture(variable_name, len)
    }
    fn reset_captures(&mut self) {
        self.inner.reset_captures()
    }
    fn binding_is_a_capture(&mut self, variable_name: &str, merged: MergedKeys) -> bool {
        self.inner.binding_is_a_capture(variable_name, merged)
    }
    fn resolve_variable_from_nested_block(
        &mut self,
        variable_name: &'value str,
        unbound: UnboundName,
    ) -> Result<Vec<QueryResult>> {
        self.inner
            .resolve_variable_from_nested_block(variable_name, unbound)
    }
    fn add_merged_capture(
        &mut self,
        variable_name: &'value str,
        result: QueryResult,
    ) -> Result<()> {
        self.inner.add_merged_capture(variable_name, result)
    }
    fn add_variable_capture_index(&mut self, name: &str, index: Rc<PathAwareValue>) -> Result<()> {
        self.inner.add_variable_capture_index(name, index)
    }
    fn record_deprecation(&mut self, notice: String) {
        self.inner.record_deprecation(notice)
    }
    fn record_deprecation_once(
        &mut self,
        kind: DeprecationKind,
        site: &FileLocation<'_>,
        notice: String,
    ) -> bool {
        self.inner.record_deprecation_once(kind, site, notice)
    }
    fn predicate_regexes(
        &self,
        site: &FileLocation<'_>,
    ) -> Rc<crate::rules::eval_context::CompiledRegexes> {
        self.inner.predicate_regexes(site)
    }
    fn set_measurement(&mut self, mode: Measurement) {
        self.inner.set_measurement(mode)
    }
    fn measurement(&self) -> Measurement {
        self.inner.measurement()
    }
    fn when_is_settled(
        &self,
        site: &FileLocation<'loc>,
        direction: MoveDirection,
        bindings: Option<&BTreeSet<BindingId<'value>>>,
    ) -> bool {
        self.inner.when_is_settled(site, direction, bindings)
    }
    fn when_has_settled_measurements(
        &self,
        site: &FileLocation<'loc>,
        direction: MoveDirection,
    ) -> bool {
        self.inner.when_has_settled_measurements(site, direction)
    }
    fn settle_when(
        &mut self,
        site: &FileLocation<'loc>,
        direction: MoveDirection,
        bindings: Option<BTreeSet<BindingId<'value>>>,
    ) {
        self.inner.settle_when(site, direction, bindings)
    }
    fn binding_owners(&self, variable_name: &str) -> Option<BTreeSet<BindingId<'value>>> {
        self.inner.binding_owners(variable_name)
    }
    fn document_binding_memo(
        &self,
    ) -> Option<Rc<std::cell::RefCell<super::DocumentBindingMemo<'value>>>> {
        self.inner.document_binding_memo()
    }
    fn resolving_a_binding(&self) -> bool {
        self.inner.resolving_a_binding()
    }
    fn within_parameterized_call(&self) -> bool {
        self.inner.within_parameterized_call()
    }
    fn function_chain(&mut self, name: &str) -> Option<FunctionChain<'value>> {
        self.inner.function_chain(name)
    }
    fn function_result_entries(&mut self, name: &str) -> Option<Result<Rc<FunctionEntries>>> {
        self.inner.function_result_entries(name)
    }
    fn record_warning(
        &mut self,
        site: &FileLocation<'_>,
        argument: &str,
        map: &str,
        notice: String,
    ) {
        self.inner.record_warning(site, argument, map, notice)
    }
    fn record_capture_warning(&mut self, site: &FileLocation<'_>, capture: &str, notice: String) {
        self.inner.record_capture_warning(site, capture, notice)
    }
    fn record_unraised_refusal(
        &mut self,
        site: &FileLocation<'_>,
        context: &str,
        verdict: crate::rules::UnraisedVerdict,
        refusals: &[String],
    ) {
        self.inner
            .record_unraised_refusal(site, context, verdict, refusals)
    }
    fn variable_is_resolved(&self, variable_name: &str) -> bool {
        self.inner.variable_is_resolved(variable_name)
    }
    fn data_file_name(&self) -> Option<&'value str> {
        self.inner.data_file_name()
    }
    fn case_label(&self) -> Option<&str> {
        self.inner.case_label()
    }
}

/// The filter of `query` with its position: the one part an entry loop is driven with.
fn the_filter_of<'q, 'loc>(
    query: &'q [QueryPart<'loc>],
) -> (
    usize,
    &'q Option<String>,
    &'q Conjunctions<GuardClause<'loc>>,
) {
    query
        .iter()
        .enumerate()
        .find_map(|(index, part)| match part {
            QueryPart::Filter(name, conjunctions) => Some((index, name, conjunctions)),
            _ => None,
        })
        .expect("the query holds a filter")
}

#[test]
fn the_entry_closure_ends_its_segment_on_the_exit_that_refuses_the_key_bind() -> Result<()> {
    // The entry's predicate holds, the mark is taken, and the own-key bind answers `Err`: the closure
    // leaves through that `?`. The segment begun for the entry has to be ended on that exit too; left
    // running, the frame's depth stayed one too high and the next begin under it opened nothing.
    let query = AccessQuery::try_from("Resources.*[ x | Kind == 'k' ]")?.query;
    let (index, name, conjunctions) = the_filter_of(&query);
    let entry = Rc::new(PathAwareValue::try_from(r#"{ "Kind": "k" }"#)?);
    let mut beneath = BasicQueryTesting {
        root: Rc::clone(&entry),
        recorder: None,
    };
    let mut counted = SegmentsCounted {
        inner: &mut beneath,
        begins: 0,
        ends: 0,
        refuses_the_key_bind: true,
    };
    let mut scope = ValueScope {
        root: Rc::clone(&entry),
        parent: &mut counted,
        in_predicate: true,
        this_is_the_population: false,
        root_from: RootProvenance::of(&query),
        empty_selection: None,
    };
    let mut shape = ShapeNotes::default();
    let walked = check_and_delegate_noting(
        conjunctions,
        name.as_deref(),
        None,
        OwnKeyFiling::BelowTheLoop,
    )(
        index + 1,
        &query,
        Rc::clone(&entry),
        Rc::clone(&entry),
        &mut scope,
        QueryStart::Document,
        false,
        None,
        &mut shape,
    );
    assert!(
        walked.is_err(),
        "the refused bind leaves the closure through its `?`"
    );
    assert_eq!(
        (1, 1),
        (counted.begins, counted.ends),
        "the segment begun for the entry is ended on that exit"
    );
    Ok(())
}

#[test]
fn the_member_loop_ends_its_segment_on_the_exit_that_refuses_the_key_bind() -> Result<()> {
    // The same exit in the list member loop: the member's predicate holds, its bind answers `Err`.
    let query = AccessQuery::try_from("Items[*][ x | Kind == 'k' ]")?.query;
    let (index, name, conjunctions) = the_filter_of(&query);
    let member = PathAwareValue::try_from(r#"{ "Kind": "k" }"#)?;
    let mut beneath = BasicQueryTesting {
        root: Rc::new(member.clone()),
        recorder: None,
    };
    let mut counted = SegmentsCounted {
        inner: &mut beneath,
        begins: 0,
        ends: 0,
        refuses_the_key_bind: true,
    };
    let mut shape = ShapeNotes::default();
    let selected = select_list_members(
        name,
        conjunctions,
        index,
        &query,
        &[member],
        &mut counted,
        QueryStart::Document,
        false,
        None,
        &mut shape,
    );
    assert!(
        selected.is_err(),
        "the refused bind leaves the loop through its `?`"
    );
    assert_eq!(
        (1, 1),
        (counted.begins, counted.ends),
        "the segment begun for the member is ended on that exit"
    );
    Ok(())
}

#[test]
fn the_exit_that_refuses_the_key_bind_under_another_entry_leaves_that_entrys_segment_running(
) -> Result<()> {
    // The entry closure run for one value under ANOTHER loop's entry (the filter after a key over a
    // one-object map): the outer segment is running at depth 1 on the root's frame, the inner begin
    // raises the depth to 2 and opens nothing, and the refused bind leaves through the `?`. The guard's
    // drop ends the inner begin alone, so the depth is back at 1 and the outer entry's own end still
    // parks what that entry appended. Left inflated, the outer end took the depth to 1 and parked
    // nothing, and the next entry read the outer entry's captures as held so far.
    let rules_file = RulesFile::try_from("rule r { Resources.*[ x | Kind == 'k' ] !empty }")?;
    let entry = Rc::new(PathAwareValue::try_from(r#"{ "Kind": "k" }"#)?);
    let mut root = root_scope(&rules_file, Rc::clone(&entry));
    let depth_of = |root: &RootScope<'_, '_>| root.capture_frames.frames.last().map(|f| f.depth);
    root.open_capture_frame();
    root.begin_capture_entry();
    root.add_variable_capture("outer", QueryResult::Resolved(Rc::clone(&entry)))?;
    assert_eq!(
        Some(1),
        depth_of(&root),
        "the outer entry's segment is running"
    );
    let query = AccessQuery::try_from("Resources.*[ x | Kind == 'k' ]")?.query;
    let (index, name, conjunctions) = the_filter_of(&query);
    {
        let mut counted = SegmentsCounted {
            inner: &mut root,
            begins: 0,
            ends: 0,
            refuses_the_key_bind: true,
        };
        let mut scope = ValueScope {
            root: Rc::clone(&entry),
            parent: &mut counted,
            in_predicate: true,
            this_is_the_population: false,
            root_from: RootProvenance::of(&query),
            empty_selection: None,
        };
        let mut shape = ShapeNotes::default();
        let walked = check_and_delegate_noting(
            conjunctions,
            name.as_deref(),
            None,
            OwnKeyFiling::BelowTheLoop,
        )(
            index + 1,
            &query,
            Rc::clone(&entry),
            Rc::clone(&entry),
            &mut scope,
            QueryStart::Document,
            false,
            None,
            &mut shape,
        );
        assert!(
            walked.is_err(),
            "the refused bind leaves the closure through its `?`"
        );
        assert_eq!((1, 1), (counted.begins, counted.ends));
    }
    assert_eq!(
        Some(1),
        depth_of(&root),
        "the depth is back at the outer entry's after the error exit"
    );
    root.end_capture_entry();
    assert_eq!(
        Some(0),
        depth_of(&root),
        "the outer entry's end is the matching one"
    );
    assert!(
        !root.captured.contains_key("outer"),
        "the outer entry's end parks what the outer entry appended"
    );
    root.close_capture_frame();
    assert_eq!(1, root.captured.get("outer").map_or(0, Vec::len));
    Ok(())
}

/// A block built for a measured reading writes its captures with no undo log, so a `let` one of its
/// loop's entries forces has its keys moved below the forcing entry's segment, as in the real run: the
/// owner tells the frames it writes (`writes_captures`), with the test its own `add_variable_capture`
/// uses. The frames read `Measurement::Off` for themselves before, and such a block parked the let's
/// keys with the first resource: `%b` read empty under every later one inside the measured `when` where
/// the real run read it full. The loop is driven by hand: the body's frame and its first entry, the
/// let's own frame one let deeper under it, the let's key bound there, the let's frame closed, the entry
/// ended.
#[test]
fn a_block_built_under_a_measurement_files_a_forced_lets_keys_below_the_forcing_entrys_segment(
) -> Result<()> {
    let rules_file = RulesFile::try_from(
        "rule r {\n  let bs = Resources[ b | Type == 'X' ]\n  Resources exists\n}",
    )?;
    let value = Rc::new(PathAwareValue::try_from(
        r#"{ "Resources": { "A": { "Type": "X" } } }"#,
    )?);
    let mut root = root_scope(&rules_file, Rc::clone(&value));
    root.set_measurement(Measurement::Quiet);
    let block = &rules_file.guard_rules[0].block;
    let mut scope = block_scope(block, Rc::clone(&value), &mut root);
    assert!(
        scope.built_under_measurement,
        "the block is the reading's own"
    );
    scope.open_capture_frame();
    scope.begin_capture_entry();
    scope.resolving_let = 1;
    scope.open_capture_frame();
    scope.begin_capture_entry();
    scope.add_variable_capture("b", a_capture_of("A"))?;
    scope.end_capture_entry();
    scope.close_capture_frame();
    scope.resolving_let = 0;
    scope.end_capture_entry();
    assert_eq!(
        vec!["A"],
        texts_under(&scope.captured, "b"),
        "the forcing entry's end leaves the let's key for the next entry"
    );
    scope.close_capture_frame();
    assert_eq!(vec!["A"], texts_under(&scope.captured, "b"));
    Ok(())
}

/// A block that existed before the measurement writes only the captures of a `let` the reading resolves,
/// and logs them. Those keys go below the forcing entry's segment as the real run's do, so the measured
/// reading reads the let's key under the next entry, and the roll-back at the reading's end puts the
/// name's list back as it stood before the reading, whatever the reading did to it. Before, the log kept
/// a length and truncated to it, so the keys were kept inside the segment to protect it, parked with the
/// first entry, and the measured reading read the let empty under every later one.
#[test]
fn a_logging_readings_forced_let_files_below_the_segment_and_its_roll_back_is_exact() -> Result<()>
{
    let rules_file = RulesFile::try_from(
        "rule r {\n  let bs = Resources[ b | Type == 'X' ]\n  Resources exists\n}",
    )?;
    let value = Rc::new(PathAwareValue::try_from(
        r#"{ "Resources": { "A": { "Type": "X" } } }"#,
    )?);
    let mut root = root_scope(&rules_file, Rc::clone(&value));
    let block = &rules_file.guard_rules[0].block;
    let mut scope = block_scope(block, Rc::clone(&value), &mut root);
    assert!(
        !scope.built_under_measurement,
        "the block existed before the reading"
    );
    // The real run's key.
    scope
        .captured
        .entry("b")
        .or_default()
        .push(a_capture_of("real"));
    scope.parent.set_measurement(Measurement::Quiet);
    scope.open_capture_frame();
    scope.begin_capture_entry();
    scope.resolving_let = 1;
    scope.open_capture_frame();
    scope.begin_capture_entry();
    scope.add_variable_capture("b", a_capture_of("R1"))?;
    scope.end_capture_entry();
    scope.close_capture_frame();
    scope.resolving_let = 0;
    scope.end_capture_entry();
    assert_eq!(
        vec!["real", "R1"],
        texts_under(&scope.captured, "b"),
        "the measured reading reads the let's key under the next entry, as the real run does"
    );
    scope.close_capture_frame();
    scope.set_measurement(Measurement::Off);
    assert_eq!(
        vec!["real"],
        texts_under(&scope.captured, "b"),
        "the roll-back puts the real run's list back"
    );
    Ok(())
}

/// A block that existed before the measurement files a forced `let`'s OWN-KEY bind below the running
/// segment under a logging reading as it does under the real run, and logs the name: the key a one-value
/// filter binds while the block's `let` is being resolved is read under the next entry in both readings,
/// and the roll-back puts the real run's list back. A logging reading that appended the key instead
/// parked it with the entry, so a rule-body `let` resolved first inside a measured reading read only the
/// current member's key where the real run read every member's.
#[test]
fn a_logging_readings_forced_let_files_its_own_key_bind_below_the_segment_as_the_real_run_does(
) -> Result<()> {
    let rules_file = RulesFile::try_from(
        "rule r {\n  let bs = Resources[ b | Type == 'X' ]\n  Resources exists\n}",
    )?;
    let value = Rc::new(PathAwareValue::try_from(
        r#"{ "Resources": { "A": { "Type": "X" } } }"#,
    )?);
    let key = |text: &str| -> Rc<PathAwareValue> {
        Rc::new(PathAwareValue::try_from(format!("\"{text}\"").as_str()).expect("a string value"))
    };
    // The two readings, run the same way: the let's own loop (its frame opened while the let is being
    // resolved, so the frame is at the let's depth and an append there is the entry's), its first entry's
    // segment running, a one-value filter's own-key bind made below that segment, the entry ended; what
    // the next entry reads is what stands in the store then.
    let read_under_the_next_entry = |measurement: Measurement| -> Result<Vec<String>> {
        let mut root = root_scope(&rules_file, Rc::clone(&value));
        let block = &rules_file.guard_rules[0].block;
        let mut scope = block_scope(block, Rc::clone(&value), &mut root);
        assert!(!scope.built_under_measurement);
        scope
            .captured
            .entry("b")
            .or_default()
            .push(a_capture_of("real"));
        scope.parent.set_measurement(measurement);
        scope.resolving_let = 1;
        scope.open_capture_frame();
        scope.begin_capture_entry();
        scope.add_variable_capture_key_below_the_entry("b", key("A"))?;
        scope.end_capture_entry();
        let under_the_next_entry = texts_under(&scope.captured, "b");
        scope.close_capture_frame();
        scope.resolving_let = 0;
        if measurement != Measurement::Off {
            assert_eq!(
                1, scope.reading_undo.records_taken,
                "the logging reading recorded the name once"
            );
            scope.set_measurement(Measurement::Off);
            assert_eq!(
                vec!["real"],
                texts_under(&scope.captured, "b"),
                "the roll-back puts the real run's list back"
            );
        }
        Ok(under_the_next_entry)
    };
    let real = read_under_the_next_entry(Measurement::Off)?;
    let measured = read_under_the_next_entry(Measurement::Quiet)?;
    assert_eq!(
        vec!["real", "A"],
        real,
        "the real run reads the let's key under the next entry"
    );
    assert_eq!(
        real, measured,
        "the logging reading reads the same keys as the real run"
    );
    Ok(())
}

/// The undo log is handed a name's list once per reading, at the first touch, however many entries write
/// or cut the name afterwards: n appends under a measurement hand it one clone and leave the roll-back
/// exact. A clone on every write handed it the growing list n times for the one record it keeps.
#[test]
fn the_undo_log_records_a_touched_name_once_however_many_entries_write_it() -> Result<()> {
    let rules_file = RulesFile::try_from(
        "rule r {\n  let bs = Resources[ b | Type == 'X' ]\n  Resources exists\n}",
    )?;
    let value = Rc::new(PathAwareValue::try_from(
        r#"{ "Resources": { "A": { "Type": "X" } } }"#,
    )?);
    let mut root = root_scope(&rules_file, Rc::clone(&value));
    let block = &rules_file.guard_rules[0].block;
    let mut scope = block_scope(block, Rc::clone(&value), &mut root);
    scope
        .captured
        .entry("b")
        .or_default()
        .push(a_capture_of("real"));
    scope.parent.set_measurement(Measurement::Quiet);
    scope.resolving_let = 1;
    for entry in ["R1", "R2", "R3", "R4"] {
        scope.add_variable_capture("b", a_capture_of(entry))?;
    }
    scope.truncate_variable_capture("b", 3)?;
    scope.add_variable_capture("c", a_capture_of("other"))?;
    assert_eq!(
        2, scope.reading_undo.records_taken,
        "one list handed in per touched name: `b` over four appends and a cut, `c` once"
    );
    scope.resolving_let = 0;
    scope.set_measurement(Measurement::Off);
    assert_eq!(vec!["real"], texts_under(&scope.captured, "b"));
    assert!(
        !scope.captured.contains_key("c"),
        "a name the reading created is removed"
    );
    assert_eq!(
        0, scope.reading_undo.records_taken,
        "the roll-back drains the records"
    );
    Ok(())
}

/// A refusal raised from a member's walk leaves no capture frame open behind it: the list filter's loop
/// opens its frame through the guard that closes it on every way out (`CaptureFrameGuard`), the error's
/// included, so after the clause the scope holds no frame and `variable_capture_len`, which counts the
/// parked slices too, agrees with the live store. A frame left open past its loop kept the member's
/// slice parked: the capture read short (the refusal's marker missing from `%i`) while its length still
/// counted the slice, and every later frame of the rule nested under the stale one. The clause runs on
/// the rule body's own scope, since a body's loops open their frames on the block that owns the body's
/// captures and never on the root (`BlockScope::open_capture_frame`); a reading of the root's frames
/// after a whole-file evaluation measures nothing of them.
#[test]
fn a_refusal_raised_under_a_list_filters_member_leaves_no_frame_open() -> Result<()> {
    use crate::rules::eval::{eval_rule_clause, ClauseRole};

    const RULES: &str = "rule r {\n  List[ i | Kind == 'k' ].Sub[*][ s | R1 !exists ] !empty\n}";
    const LIST_REFUSED: &str = r#"{
        "List": [
            { "Kind": "k", "Sub": { "R1": { "Ref": "P" }, "P": { "Kind": "k" }, "Q": { "Kind": "k" } } },
            { "Kind": "k" }
        ]
    }"#;
    let rules_file = RulesFile::try_from(RULES)?;
    let value = Rc::new(PathAwareValue::try_from(LIST_REFUSED)?);
    let mut root = root_scope(&rules_file, Rc::clone(&value));
    let block = &rules_file.guard_rules[0].block;
    let mut scope = block_scope(block, Rc::clone(&value), &mut root);
    let clause = &block.conjunctions[0][0];
    // The first member's `Sub` holds the key its filter's predicate names (`R1`), so the wildcard filter
    // over it is refused, and the refusal leaves the list loop through the member's walk.
    let walked = eval_rule_clause(clause, &mut scope, ClauseRole::Assertion);
    assert!(
        !matches!(walked, Ok(Status::PASS)),
        "the clause is refused, never passed: {:?}",
        walked
    );
    assert!(
        scope.capture_frames.frames.is_empty(),
        "the member loop's frame is closed on the error's way out"
    );
    let live = scope.captured.get("i").map_or(0, Vec::len);
    assert_eq!(
        live,
        scope.variable_capture_len("i"),
        "no slice of `i` is left parked in a frame: the live store is the whole capture"
    );
    assert_eq!(
        1, live,
        "`%i` holds the refusal's marker alone, as the cut left it"
    );
    Ok(())
}

/// A measured reading that files a forced `let`'s keys below the running segment moves the segment's start
/// for that name on a frame that belongs to the REAL run and is older than the reading; the roll-back puts
/// the capture list back and the start back with it (`ReadingUndo::note_frame_starts`), or the entry's end
/// parks fewer of the entry's OWN appends under that name and they stay live under the next entry. The row
/// models the real run's loop (its frame and its first entry's segment open before the reading), a Quiet
/// reading inside the entry that resolves one of the block's `let`s and files two keys of `b` below the
/// segment, the reading's end, the entry's own append of `b`, and the entry's end: the own append is parked,
/// the next entry reads `b` as it stood when the loop began, and the close appends the own append back.
/// With the start left where the reading moved it, the end parked nothing of the one own append (it parks
/// only past the start) and the next entry read it.
#[test]
fn a_measured_readings_filing_below_leaves_the_entrys_own_appends_parked_at_its_end() -> Result<()>
{
    let rules_file = RulesFile::try_from(
        "rule r {\n  let bs = Resources[ b | Type == 'X' ]\n  Resources exists\n}",
    )?;
    let value = Rc::new(PathAwareValue::try_from(
        r#"{ "Resources": { "A": { "Type": "X" }, "C": { "Type": "X" } } }"#,
    )?);
    let key = |text: &str| -> Rc<PathAwareValue> {
        Rc::new(PathAwareValue::try_from(format!("\"{text}\"").as_str()).expect("a string value"))
    };
    let mut root = root_scope(&rules_file, Rc::clone(&value));
    let block = &rules_file.guard_rules[0].block;
    let mut scope = block_scope(block, Rc::clone(&value), &mut root);
    assert!(!scope.built_under_measurement);
    // The real run's loop: its frame and its first entry's segment, with `b` absent.
    scope.open_capture_frame();
    scope.begin_capture_entry();
    // A `when` measured inside the entry resolves the block's `let` under the reading: two keys of `b`
    // filed below the segment, logged, and taken back at the reading's end.
    scope.parent.set_measurement(Measurement::Quiet);
    scope.resolving_let = 1;
    scope.add_variable_capture_key_below_the_entry("b", key("A"))?;
    scope.add_variable_capture_key_below_the_entry("b", key("C"))?;
    scope.resolving_let = 0;
    scope.set_measurement(Measurement::Off);
    assert!(
        !scope.captured.contains_key("b"),
        "the roll-back removed the reading's `b`: {:?}",
        scope.captured
    );
    // The entry's own append under the same name, then the entry's end.
    scope.add_variable_capture("b", a_capture_of("own"))?;
    scope.end_capture_entry();
    assert!(
        texts_under(&scope.captured, "b").is_empty(),
        "the entry's own append is parked at its end, whatever the reading filed and took back: {:?}",
        scope.captured
    );
    scope.begin_capture_entry();
    assert!(
        texts_under(&scope.captured, "b").is_empty(),
        "the next entry reads `b` as it stood when the loop began: {:?}",
        scope.captured
    );
    scope.end_capture_entry();
    scope.close_capture_frame();
    assert_eq!(
        vec!["own"],
        texts_under(&scope.captured, "b"),
        "the close appends the first entry's own append back"
    );
    Ok(())
}

#[test]
fn a_name_an_own_key_bind_filed_below_the_segment_and_a_refusal_emptied_is_absent_under_the_next_entry(
) {
    // Entry 1 binds its own key `x` below the running segment (which lists `x` among the segment's
    // starts from then on), and is then refused with its mark taken BEFORE the bind: the cut takes the
    // key and leaves `x` empty. "Absent when the segment began" has to be read from what the store held
    // at the begin, not from the starts: read from the starts, `x` counted as standing before the entry,
    // stayed present and empty, and read as bound under entry 2 by an entry that never bound it.
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    let mark = texts_under(&store, "x").len() + frames.parked_len(CaptureHome::Captured, "x");
    assert_eq!(0, mark, "the clause marks before the bind");
    assert!(frames.insert_below_segment(&mut store, "x", a_capture_of("k")));
    assert!(frames.cut(CaptureHome::Captured, &mut store, "x", mark));
    assert!(
        texts_under(&store, "x").is_empty(),
        "the refusal's cut takes the key"
    );
    let changed = frames.end_segment(&mut store, &mut merged);
    assert!(changed.contains(&"x"));
    assert!(
        !store.contains_key("x"),
        "entry 1 made `x` and holds nothing of it: the next entry reads it absent"
    );
    frames.begin_segment(&store, &merged);
    assert!(!store.contains_key("x"));
    frames.end_segment(&mut store, &mut merged);
    let changed = frames.close(&mut store, &mut merged);
    assert!(store.contains_key("x") && texts_under(&store, "x").is_empty());
    assert!(changed.contains(&"x"));
}

#[test]
fn a_forced_lets_capture_cut_to_nothing_reads_alike_under_later_entries_in_both_spellings() {
    // The forced `let`'s capture `b`, cut to nothing by a refusal, in the two shapes a `let` takes: its
    // filter opens a frame of its own (a collection: the keys are put back at the inner close and moved
    // below the outer segment, which moves nothing for an empty name), or it opens none (one object: the
    // owner files the key below the outer segment directly). Both read ABSENT under the outer loop's next
    // entry and present-but-empty after the loop. One shape read present-and-empty under the next entry
    // and the other absent, so a memoised `let` left two traces for one document.
    let under_the_next_entry = |with_an_inner_frame: bool| -> (bool, bool, Vec<String>) {
        let mut frames = CaptureFrames::default();
        let mut store: CaptureStore<'static> = HashMap::new();
        let mut merged: CaptureStore<'static> = HashMap::new();
        frames.open(CaptureHome::Captured, 0, &store, &merged, true);
        frames.begin_segment(&store, &merged);
        if with_an_inner_frame {
            frames.open(CaptureHome::Captured, 1, &store, &merged, true);
            frames.begin_segment(&store, &merged);
            store.entry("b").or_default().push(a_capture_of("R1"));
            frames.cut(CaptureHome::Captured, &mut store, "b", 0);
            frames.end_segment(&mut store, &mut merged);
            frames.close(&mut store, &mut merged);
        } else {
            assert!(frames.insert_below_segment(&mut store, "b", a_capture_of("R1")));
            frames.cut(CaptureHome::Captured, &mut store, "b", 0);
        }
        frames.end_segment(&mut store, &mut merged);
        let present_under_the_next_entry = store.contains_key("b");
        frames.begin_segment(&store, &merged);
        frames.end_segment(&mut store, &mut merged);
        frames.close(&mut store, &mut merged);
        (
            present_under_the_next_entry,
            store.contains_key("b"),
            texts_under(&store, "b"),
        )
    };
    let with_an_inner_frame = under_the_next_entry(true);
    let without = under_the_next_entry(false);
    assert_eq!(
        with_an_inner_frame, without,
        "the two spellings leave the same trace"
    );
    assert_eq!(
        (false, true, Vec::<String>::new()),
        without,
        "absent under the next entry, present and empty after the loop"
    );
}

/// The frames' answer to F1 at the owner: a block's generation for a name moves when the name is put
/// back empty at the close, as it moved when the entry's end removed it. `document_level_site` hands
/// "absent" and "present, empty" one id at one generation, so without the bump a `when` settled on the
/// name under the last entry stayed settled after the loop.
#[test]
fn a_name_put_back_empty_at_the_close_moves_the_blocks_generation() -> Result<()> {
    let rules_file = RulesFile::try_from("rule r {\n  Resources exists\n}")?;
    let value = Rc::new(PathAwareValue::try_from(
        r#"{ "Resources": { "A": { "Type": "X" } } }"#,
    )?);
    let mut root = root_scope(&rules_file, Rc::clone(&value));
    let block = &rules_file.guard_rules[0].block;
    let mut scope = block_scope(block, Rc::clone(&value), &mut root);
    scope.open_capture_frame();
    scope.begin_capture_entry();
    scope.add_variable_capture("t", a_capture_of("prod"))?;
    scope.end_capture_entry();
    assert!(
        !scope.captured.contains_key("t"),
        "entry 1's end removed the name it made"
    );
    let after_the_removal = scope.capture_generation_of("t");
    scope.begin_capture_entry();
    scope.truncate_variable_capture("t", 0)?;
    scope.end_capture_entry();
    assert_eq!(
        after_the_removal,
        scope.capture_generation_of("t"),
        "a cut that finds no live entry moves nothing"
    );
    scope.close_capture_frame();
    assert!(scope.captured.contains_key("t") && texts_under(&scope.captured, "t").is_empty());
    assert!(
        scope.capture_generation_of("t") > after_the_removal,
        "the put-back moves the generation, so a question settled under entry 2 is asked again"
    );
    Ok(())
}

/// A segment ended detaching hands its parked slices, its handed-up `merged` slices and the names it
/// made to the caller, and the frame's close appends none of them back; filed back under a segment of a
/// later frame they are that segment's, read under it alone and parked again at its end, so the two
/// frames together read as one loop that bound and walked per entry: entry 1's slice under entry 1's
/// walk, entry 2's under entry 2's, both in loop order after the close. A name a detached segment made
/// is absent between the frames and comes back with its slice. The own-key enumeration runs its
/// predicates in one frame and its walks in another (`enumerate_under_an_own_key_filter`); this is the
/// frames' half of that hand-over.
#[test]
fn a_segment_ended_detaching_travels_to_another_frames_segment_and_reads_there_alone() {
    // Every read of a total below is cross-checked against the frames (`ParkedTotalResum`).
    #[cfg(debug_assertions)]
    let _resum = ParkedTotalResum::on();
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    store.entry("k").or_default().push(a_capture_of("before"));
    // The predicates' frame: two entries, each binding `t` and handing `m` up, both detached.
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("t").or_default().push(a_capture_of("prod"));
    merged.entry("m").or_default().push(a_capture_of("up1"));
    let (changed, first) = frames.end_segment_detaching(&mut store, &mut merged);
    assert!(changed.contains(&"t") && changed.contains(&"m"));
    assert!(!first.is_empty());
    assert!(
        !store.contains_key("t") && !merged.contains_key("m"),
        "entry 1 made `t` and `m`; entry 2 must not read them"
    );
    assert_eq!(
        0,
        frames.parked_len(CaptureHome::Captured, "t"),
        "a detached slice is not parked: the running total follows it out"
    );
    frames.begin_segment(&store, &merged);
    store.entry("t").or_default().push(a_capture_of("dev"));
    let (_, second) = frames.end_segment_detaching(&mut store, &mut merged);
    assert!(!second.is_empty());
    assert_eq!(0, frames.parked_len(CaptureHome::Captured, "t"));
    frames.close(&mut store, &mut merged);
    assert!(
        !store.contains_key("t") && !merged.contains_key("m"),
        "the close puts back nothing of what was detached: {:?} {:?}",
        store,
        merged
    );
    assert_eq!(0, frames.parked_len(CaptureHome::Captured, "t"));
    assert_eq!(vec!["before"], texts_under(&store, "k"));
    // The walks' frame: each entry's captures filed back under its own segment.
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    let changed = CaptureFrames::refile(&mut store, &mut merged, first);
    assert!(changed.contains(&"t") && changed.contains(&"m"));
    assert_eq!(vec!["prod"], texts_under(&store, "t"));
    assert_eq!(vec!["up1"], texts_under(&merged, "m"));
    frames.end_segment(&mut store, &mut merged);
    assert!(
        !store.contains_key("t") && !merged.contains_key("m"),
        "parked again with entry 1's walk"
    );
    frames.begin_segment(&store, &merged);
    CaptureFrames::refile(&mut store, &mut merged, second);
    assert_eq!(
        vec!["dev"],
        texts_under(&store, "t"),
        "under entry 2's walk, entry 2's tag alone"
    );
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(
        2,
        frames.parked_len(CaptureHome::Captured, "t"),
        "both walks' slices parked in the walks' frame"
    );
    frames.close(&mut store, &mut merged);
    assert_eq!(
        0,
        frames.parked_len(CaptureHome::Captured, "t"),
        "the close appended them back: nothing parked"
    );
    assert_eq!(vec!["prod", "dev"], texts_under(&store, "t"));
    assert_eq!(vec!["up1"], texts_under(&merged, "m"));
    // An end that parks nothing hands back nothing, and an empty hand-over files nothing.
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    let (changed, nothing) = frames.end_segment_detaching(&mut store, &mut merged);
    assert!(changed.is_empty() && nothing.is_empty());
    assert!(CaptureFrames::refile(&mut store, &mut merged, nothing).is_empty());
    frames.close(&mut store, &mut merged);
    assert_eq!(vec!["prod", "dev"], texts_under(&store, "t"));
    assert_eq!(0, frames.parked_len(CaptureHome::Captured, "t"));
}

/// A file-level `let` whose query fails is resolved ONCE per evaluation, as a `let` that resolves is: over
/// `let cs = Cfg.*[ Kind == 'zz' or Tags[ t | Key == 'Env' ] !empty  Sub.R1 == %nope ]` the own-key loop
/// decides `C` (its tag captured under `t`) and ends at `A` on the unresolved variable; four reads of
/// `%cs` at the root raise that error four times, each the same variant with the same text, while the
/// query runs once (`ASSIGNMENT_RESOLUTIONS`) and the let's capture store holds `C`'s tag once. Without
/// the memo of the failure every read ran the loop again and appended the tag again: four reads, four
/// copies of "test".
#[test]
fn a_failing_let_runs_once_and_its_captures_are_appended_once_however_often_it_is_read(
) -> Result<()> {
    const FILE: &str =
        "let cs = Cfg.*[ Kind == 'zz' or Tags[ t | Key == 'Env' ] !empty  Sub.R1 == %nope ]\nrule r {\n  %cs !empty or Cfg exists\n}";
    const DOC: &str = r#"{ "Cfg": { "Kind": "zz",
        "C": { "Tags": [ { "Key": "Env", "Value": "test" } ], "Sub": { "P": "pc" } },
        "A": { "Tags": [ { "Key": "Env", "Value": "prod" } ], "Sub": { "R1": 1, "P": 5 } },
        "B": { "Tags": [ { "Key": "Env", "Value": "dev" } ], "Sub": { "R1": 1, "P": 6 } } } }"#;
    let rules_file = RulesFile::try_from(FILE)?;
    let value = Rc::new(PathAwareValue::try_from(DOC)?);
    let mut root = root_scope(&rules_file, Rc::clone(&value));
    ASSIGNMENT_RESOLUTIONS.with(|count| count.set(0));
    let mut raised = Vec::new();
    for _ in 0..4 {
        match root.resolve_variable("cs") {
            Ok(values) => panic!(
                "the let resolves to {} values; its loop ends on `%nope`",
                values.len()
            ),
            Err(error) => raised.push(error),
        }
    }
    let first = raised[0].to_string();
    for (reading, error) in raised.iter().enumerate() {
        assert!(
            matches!(error, Error::MissingValue(_)),
            "read {}: the unresolved variable's own error, not {:?}",
            reading,
            error
        );
        assert_eq!(
            first,
            error.to_string(),
            "read {}: the same error text",
            reading
        );
    }
    assert_eq!(
        1,
        ASSIGNMENT_RESOLUTIONS.with(|count| count.get()),
        "the failing let's query ran once for four reads"
    );
    // The store holds tag MAPS (`{ Key, Value }`), so the tag is read through its `Value`.
    let tags: Vec<String> = root
        .assignment_captures
        .get("t")
        .map(|results| {
            results
                .iter()
                .map(|result| match result {
                    QueryResult::Resolved(tag) => match &**tag {
                        PathAwareValue::Map((_, map)) => match map.values.get("Value") {
                            Some(PathAwareValue::String((_, text))) => text.clone(),
                            other => format!("{other:?}"),
                        },
                        other => format!("{other:?}"),
                    },
                    other => format!("{other:?}"),
                })
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        vec!["test"],
        tags,
        "the decided entry's tag is in the let's store once"
    );
    Ok(())
}

/// The running parked total of a home is the sum over ALL its open frames: with two frames of one home,
/// each holding a parked slice of `t`, the total reads both; the inner frame's close appends its slice
/// back and the total falls to the outer frame's share; the outer frame's close leaves nothing parked.
#[test]
fn the_parked_total_of_a_home_falls_back_to_the_outer_frames_share_when_the_inner_one_closes() {
    // Every read of a total below is cross-checked against the frames (`ParkedTotalResum`).
    #[cfg(debug_assertions)]
    let _resum = ParkedTotalResum::on();
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("t").or_default().push(a_capture_of("outer"));
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(1, frames.parked_len(CaptureHome::Captured, "t"));
    frames.begin_segment(&store, &merged);
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("t").or_default().push(a_capture_of("inner"));
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(
        2,
        frames.parked_len(CaptureHome::Captured, "t"),
        "the total counts both frames' slices"
    );
    frames.close(&mut store, &mut merged);
    assert_eq!(
        1,
        frames.parked_len(CaptureHome::Captured, "t"),
        "the inner frame's close appended its slice back; the outer frame's share stays"
    );
    assert_eq!(vec!["inner"], texts_under(&store, "t"));
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(
        2,
        frames.parked_len(CaptureHome::Captured, "t"),
        "the outer entry's end parked the appended slice as its own"
    );
    frames.close(&mut store, &mut merged);
    assert_eq!(0, frames.parked_len(CaptureHome::Captured, "t"));
    assert_eq!(vec!["outer", "inner"], texts_under(&store, "t"));
}

/// The running parked total of a home stays in step with the frames through every way a slice moves: a
/// park (up), a cut at or above the mark (down by what the cut took), a detaching end (down by what was
/// handed out), a close (down by what was appended back), across two frames of one home. This test holds
/// the debug build's read-time re-sum on (a `ParkedTotalResum` guard; the flag is off by default), so
/// every read of the total here recomputes it from the frames (`CaptureFrames::debug_check_total`, run at
/// each close too) and each step is both the expected value and that cross-check; the re-sum's visits are
/// counted on the check's own counter (`PARKED_TOTAL_RESUM_VISITS`: two slices parked, two visited per
/// read, and none on the production counter `CAPTURE_FRAME_SLICES_VISITED`), and a read with the guard
/// dropped visits none.
#[test]
fn a_park_a_cut_a_detach_and_a_close_each_keep_the_parked_total_in_step_with_the_frames() {
    // The dedicated cell for the read-time re-sum: on for this test's reads, off at the guard's drop.
    #[cfg(debug_assertions)]
    let resum = ParkedTotalResum::on();
    #[cfg(debug_assertions)]
    let visits = || PARKED_TOTAL_RESUM_VISITS.with(|count| count.get());
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("t").or_default().push(a_capture_of("outer"));
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(
        1,
        frames.parked_len(CaptureHome::Captured, "t"),
        "one slice parked"
    );
    frames.begin_segment(&store, &merged);
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("t").or_default().push(a_capture_of("inner-a"));
    store.entry("t").or_default().push(a_capture_of("inner-b"));
    frames.end_segment(&mut store, &mut merged);
    assert_eq!(
        3,
        frames.parked_len(CaptureHome::Captured, "t"),
        "both frames' slices"
    );
    #[cfg(debug_assertions)]
    {
        PARKED_TOTAL_RESUM_VISITS.with(|count| count.set(0));
        CAPTURE_FRAME_SLICES_VISITED.with(|count| count.set(0));
        frames.parked_len(CaptureHome::Captured, "t");
        assert_eq!(
            (2, 0),
            (
                visits(),
                CAPTURE_FRAME_SLICES_VISITED.with(|count| count.get())
            ),
            "with the re-sum on, a read visits the two parked slices on the check's counter and none on the production one"
        );
    }
    // A cut back to the mark 2 on the absolute scale: the inner slice began at 1 and crosses the mark,
    // so one of its two results goes; the outer slice, below the mark, stands.
    assert!(
        !frames.cut(CaptureHome::Captured, &mut store, "t", 2),
        "nothing of `t` is in the live store to truncate"
    );
    assert_eq!(
        2,
        frames.parked_len(CaptureHome::Captured, "t"),
        "the cut took one result"
    );
    // A second inner entry whose captures are handed out at its end.
    frames.begin_segment(&store, &merged);
    store.entry("t").or_default().push(a_capture_of("inner-c"));
    let (_, detached) = frames.end_segment_detaching(&mut store, &mut merged);
    assert_eq!(1, detached.parked.len(), "one slice handed out");
    assert_eq!(
        2,
        frames.parked_len(CaptureHome::Captured, "t"),
        "the handed-out slice is not parked"
    );
    frames.close(&mut store, &mut merged);
    assert_eq!(
        1,
        frames.parked_len(CaptureHome::Captured, "t"),
        "the inner frame's close appended its slice back; the outer frame's share stays"
    );
    assert_eq!(vec!["inner-a"], texts_under(&store, "t"));
    frames.end_segment(&mut store, &mut merged);
    frames.close(&mut store, &mut merged);
    assert_eq!(
        0,
        frames.parked_len(CaptureHome::Captured, "t"),
        "nothing parked after the last close"
    );
    assert_eq!(vec!["outer", "inner-a"], texts_under(&store, "t"));
    #[cfg(debug_assertions)]
    {
        drop(resum);
        frames.open(CaptureHome::Captured, 0, &store, &merged, true);
        frames.park("t", 0, vec![a_capture_of("later")]);
        PARKED_TOTAL_RESUM_VISITS.with(|count| count.set(0));
        assert_eq!(1, frames.parked_len(CaptureHome::Captured, "t"));
        assert_eq!(
            0,
            visits(),
            "with the guard dropped, a read visits no slice"
        );
        frames.close(&mut store, &mut merged);
    }
}

/// A name a cut emptied out of the frames is listed by the home's running total alone if the cut's
/// accounting left the total standing, and no per-name check at the close meets it (the popped frame holds
/// no slice of it). The close re-checks every name the total still lists, and when it pops the home's
/// LAST frame it asserts the total table empty: a total planted to stand after a cut took every slice
/// (the shape of a cut under-counting what it took) trips the last-frame check. A debug assertion, so the
/// test runs only in a build that has it.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "closed with a running parked total left for")]
fn a_total_left_standing_after_a_cut_emptied_the_name_trips_the_last_frames_close() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.park("t", 0, vec![a_capture_of("a"), a_capture_of("b")]);
    frames.cut(CaptureHome::Captured, &mut store, "t", 0);
    assert_eq!(0, frames.parked_len(CaptureHome::Captured, "t"));
    // The plant: the total lists `t` though no frame holds a slice of it.
    frames.parked_lens[home_index(CaptureHome::Captured)].insert("t", 1);
    frames.close(&mut store, &mut merged);
}

/// A name a detaching end drained out of the frame is listed by the home's running total alone if the
/// detach's accounting left the total standing (the shape of a detach under-counting what it handed
/// out): the last frame's close trips on it. A debug assertion, so the test runs only in a build that
/// has it.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "closed with a running parked total left for")]
fn a_total_left_standing_after_a_detach_drained_the_name_trips_the_last_frames_close() {
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.begin_segment(&store, &merged);
    store.entry("t").or_default().push(a_capture_of("a"));
    let (_, detached) = frames.end_segment_detaching(&mut store, &mut merged);
    assert_eq!(1, detached.parked.len(), "the slice was handed out");
    assert_eq!(0, frames.parked_len(CaptureHome::Captured, "t"));
    // The plant: the total lists `t` though the detach drained it out of the frame.
    frames.parked_lens[home_index(CaptureHome::Captured)].insert("t", 1);
    frames.close(&mut store, &mut merged);
}

/// A cut visits the parked slices of its own name alone, from the back of that name's list, and stops at
/// the first slice below the mark, so the slices it visits do not grow with what the frame holds: over N
/// segments of one frame, each parking one slice of `t` (two results) and one of `x` (one result), a cut of
/// `x` to a mark inside its last slice visits exactly one slice at N = 2, 8 and 32, whatever `t` holds,
/// and a cut of `t` to a mark inside its second-to-last slice visits exactly two (the last slice goes whole,
/// the one before it is truncated and the walk stops there); the slices below the mark stand untouched. The
/// visits are `CAPTURE_FRAME_SLICES_VISITED`, the count the per-entry work test reads.
#[test]
fn a_cut_visits_the_slices_of_its_own_name_alone_and_stops_below_the_mark() {
    let visits = || CAPTURE_FRAME_SLICES_VISITED.with(|count| count.get());
    for entries in [2usize, 8, 32] {
        let mut frames = CaptureFrames::default();
        let mut store: CaptureStore<'static> = HashMap::new();
        let mut merged: CaptureStore<'static> = HashMap::new();
        frames.open(CaptureHome::Captured, 0, &store, &merged, true);
        // Entry k parks `t` at the absolute start 2k (two results) and `x` at k (one result).
        for entry in 0..entries {
            frames.park(
                "t",
                2 * entry,
                vec![
                    a_capture_of(&format!("t{entry}a")),
                    a_capture_of(&format!("t{entry}b")),
                ],
            );
            frames.park("x", entry, vec![a_capture_of(&format!("x{entry}"))]);
        }
        assert_eq!(2 * entries, frames.parked_len(CaptureHome::Captured, "t"));
        assert_eq!(entries, frames.parked_len(CaptureHome::Captured, "x"));
        // `x` cut to the mark just below its last slice: that slice goes whole, the walk stops at the one
        // before it, and none of `t`'s slices are visited.
        CAPTURE_FRAME_SLICES_VISITED.with(|count| count.set(0));
        frames.cut(CaptureHome::Captured, &mut store, "x", entries - 1);
        assert_eq!(
            if entries > 1 { 2 } else { 1 },
            visits(),
            "N={entries}: a cut of `x` visits its last slice and stops at the one before it"
        );
        assert_eq!(entries - 1, frames.parked_len(CaptureHome::Captured, "x"));
        assert_eq!(
            2 * entries,
            frames.parked_len(CaptureHome::Captured, "t"),
            "N={entries}: `t` untouched"
        );
        // `t` cut to a mark inside its second-to-last slice: the last slice goes whole, the one before it is
        // truncated to its first result, and the walk stops there.
        CAPTURE_FRAME_SLICES_VISITED.with(|count| count.set(0));
        frames.cut(CaptureHome::Captured, &mut store, "t", 2 * entries - 3);
        assert_eq!(
            2,
            visits(),
            "N={entries}: the last slice goes whole, the one before it is truncated, and the walk stops"
        );
        assert_eq!(
            2 * entries - 3,
            frames.parked_len(CaptureHome::Captured, "t")
        );
        frames.close(&mut store, &mut merged);
        let mut expected: Vec<String> = Vec::new();
        for entry in 0..entries - 2 {
            expected.push(format!("t{entry}a"));
            expected.push(format!("t{entry}b"));
        }
        expected.push(format!("t{}a", entries - 2));
        assert_eq!(
            expected,
            texts_under(&store, "t"),
            "N={entries}: the slices below the mark stand whole; the one crossing it keeps its first result"
        );
    }
}

/// A slice parked out of start order trips the debug check `park` keeps for `cut`'s back-to-front stop: a
/// slice of `t` beginning at 2 after one that ends at 6. The check is a debug assertion, so the test runs
/// only in a build that has it; a release test build has no check to trip and leaves the test out.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "begins before the previous one ends")]
fn a_slice_parked_before_the_previous_ones_end_trips_the_order_check() {
    let mut frames = CaptureFrames::default();
    let store: CaptureStore<'static> = HashMap::new();
    let merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.park("t", 5, vec![a_capture_of("a")]);
    frames.park("t", 2, vec![a_capture_of("b")]);
}

/// An error absorbed under a NESTED loop leaves the outer frame's depth where the outer entry began: the
/// nested loop closes its own frame on its way out with its segment still running (the close ends it),
/// and the outer entry's segment is ended by the guard the `?` drops (`CaptureSegment`), so the next
/// outer entry begins a real segment whose end parks its own appends, and nothing bound under the first
/// entry, in the outer loop or the nested one, is read under the second. A depth left one too high would
/// make the second entry's begin open nothing and its end park nothing, the cross-entry leak the frames
/// remove; the two frames' closes then append every slice back in loop order.
#[test]
fn an_absorbed_error_under_a_nested_loop_leaves_the_depth_where_the_outer_entry_began() -> Result<()>
{
    let rules_file = RulesFile::try_from("rule r {\n  Resources exists\n}")?;
    let value = Rc::new(PathAwareValue::try_from(
        r#"{ "Resources": { "A": { "Type": "X" } } }"#,
    )?);
    let mut root = root_scope(&rules_file, Rc::clone(&value));
    let block = &rules_file.guard_rules[0].block;
    let mut scope = block_scope(block, Rc::clone(&value), &mut root);
    // The outer loop's frame; entry 1 runs under the guard every entry loop uses.
    scope.open_capture_frame();
    {
        let mut entry_one = CaptureSegment::begin(&mut scope);
        entry_one.add_variable_capture("t", a_capture_of("one"))?;
        // A nested loop under entry 1: its frame, its entry's segment, a capture bound there, and then
        // the error on the way out, which closes the nested frame with the segment still running.
        entry_one.open_capture_frame();
        entry_one.begin_capture_entry();
        entry_one.add_variable_capture("u", a_capture_of("inner"))?;
        entry_one.close_capture_frame();
        // The `?` leaves entry 1's work here: the guard drops and ends entry 1's segment, which parks
        // `u` too (the nested frame's close had appended it back under entry 1).
    }
    assert!(
        !scope.captured.contains_key("t") && !scope.captured.contains_key("u"),
        "entry 1's captures, the nested loop's included, are parked: {:?}",
        scope.captured
    );
    // Entry 2 begins a REAL segment (the depth is back where the outer entry began): what it appends is
    // parked at its end. With the depth left one too high the begin would open nothing and the end
    // would park nothing, and `t` would read as [two] under the loop's next entry.
    scope.begin_capture_entry();
    scope.add_variable_capture("t", a_capture_of("two"))?;
    scope.end_capture_entry();
    assert!(
        !scope.captured.contains_key("t"),
        "entry 2's end parked its own append, so its segment was a real one: {:?}",
        scope.captured
    );
    scope.close_capture_frame();
    assert_eq!(vec!["one", "two"], texts_under(&scope.captured, "t"));
    assert_eq!(vec!["inner"], texts_under(&scope.captured, "u"));
    Ok(())
}

/// What a later entry reads for a memoised `let`'s capture that a refusal cut to nothing and the entry's
/// end removed: the empty selection a declared capture that captured nothing gets, at the root
/// (`capture_sources` names the capture's assignment) and in a block (`capture_names` declares it), never
/// an unresolved-variable error and never a stale value. The `let`'s own result stays memoised.
#[test]
fn a_declared_capture_absent_from_the_store_reads_as_an_empty_selection_at_both_scopes(
) -> Result<()> {
    let rules_file = RulesFile::try_from(
        "let bs = Resources[ b | Type == 'X' ]\nrule r {\n  let cs = Resources[ c | Type == 'X' ]\n  Resources exists\n}",
    )?;
    let value = Rc::new(PathAwareValue::try_from(
        r#"{ "Resources": { "A": { "Type": "X" } } }"#,
    )?);
    let mut root = root_scope(&rules_file, Rc::clone(&value));
    // The real run resolves the let: its key `b` is captured and the result memoised.
    assert_eq!(1, root.resolve_variable("bs")?.len());
    assert_eq!(1, root.resolve_variable("b")?.len(), "the key, as captured");
    // The shape a refusal's cut and the entry's end leave for the later entries: the name gone.
    root.assignment_captures.remove("b");
    let read = root.resolve_variable("b")?;
    assert!(
        read.is_empty(),
        "an empty selection, not an error: {:?}",
        read
    );
    assert!(
        root.variable_is_resolved("bs"),
        "the let's own result is still memoised"
    );
    let block = &rules_file.guard_rules[0].block;
    let mut scope = block_scope(block, Rc::clone(&value), &mut root);
    assert_eq!(1, scope.resolve_variable("cs")?.len());
    assert_eq!(1, scope.resolve_variable("c")?.len());
    scope.captured.remove("c");
    let read = scope.resolve_variable("c")?;
    assert!(
        read.is_empty(),
        "the block's declared capture, absent: an empty selection, not an error: {:?}",
        read
    );
    Ok(())
}

/// The kind a unary report carries describes the sentence the report prints, not the record it was
/// built from. A refused read recorded over a resolved value reports a sentence that names a path and
/// the refusal and keeps the record's kind; one recorded over an unresolved value prints the value the
/// query traversed to into its sentence, and that sentence is no refusal whatever the record says: it
/// carries a template value, which the console's refusal bound would print whole. The composed sentence
/// is also no member of the registry, which holds the exact texts the producers registered: a text that
/// contains a registered refusal is not one.
#[test]
fn a_unary_report_over_a_traversed_value_is_no_refusal_whatever_the_record_says() -> Result<()> {
    let refusal_text = String::from(
        "`[*]` then the filter read one object that has no `Sid`, the key the predicate compares, and kept nothing; refused in both polarities",
    );
    // The registry registers under a live root scope only; this test raises outside any evaluation,
    // so it holds a root scope of its own for the test's span instead of leaving the text on the thread.
    let registry_rules = RulesFile::try_from("rule r { Resources exists }")?;
    let _registry_scope = root_scope_for(
        &registry_rules,
        Rc::new(PathAwareValue::try_from("{ Resources: { A: 1 } }")?),
        None,
    );
    assert!(is_refusal(&refuse(refusal_text.clone())));
    let value = "v".repeat(2048);
    let traversed = Rc::new(PathAwareValue::try_from(
        format!("{{ Tags: {{ Env: '{value}' }} }}").as_str(),
    )?);
    let record = |from: QueryResult| EventRecord {
        context: String::from("Resources.*.Properties.Tags[*][ Key == 'Env' ].Value EXISTS"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::Unary(
            UnaryValueCheck {
                comparison: (CmpOperator::Exists, false),
                value: ValueCheck {
                    status: Status::FAIL,
                    message: Some(refusal_text.clone()),
                    custom_message: None,
                    from,
                    refusal: true,
                },
            },
        ))),
        children: vec![],
    };
    let report_of = |records: &[EventRecord<'_>]| -> Messages {
        let clauses = report_all_failed_clauses_for_rules(records);
        match clauses.as_slice() {
            [ClauseReport::Clause(clause)] => clause.get_message(),
            other => panic!("one clause report for one record, got {}", other.len()),
        }
    };

    let over_a_value = report_of(&[record(QueryResult::UnResolved(UnResolved {
        traversed_to: Rc::clone(&traversed),
        remaining_query: String::from("Value"),
        reason: None,
        kind: UnResolvedKind::Absent,
    }))]);
    let sentence = over_a_value.error_message.clone().unwrap_or_default();
    assert!(
        sentence.contains(&value) && sentence.contains(&refusal_text),
        "the sentence carries the traversed value and the refusal: {}",
        sentence
    );
    assert!(
        !over_a_value.refusal,
        "a sentence that carries a traversed value is no refusal, whatever the record said"
    );
    assert!(
        !is_refusal(&Error::Unevaluatable(sentence.clone())),
        "a text that contains a registered refusal is not a member of the registry"
    );

    let over_a_path = report_of(&[record(QueryResult::Resolved(Rc::clone(&traversed)))]);
    let sentence = over_a_path.error_message.clone().unwrap_or_default();
    assert!(
        !sentence.contains(&value) && sentence.contains(&refusal_text),
        "the sentence names a path and the refusal, and no value: {}",
        sentence
    );
    assert!(
        over_a_path.refusal,
        "a sentence that interpolates no value keeps the record's kind"
    );
    Ok(())
}

/// One clause site is one line, counting DISTINCT refusal TEXTS and the verdicts that met them
/// (`record_unraised_refusal`, `SiteWarning::also_unraised`): the same text reported again (the next
/// value a block evaluates the clause over, the same `let`) adds no refusal, a different text is counted
/// as a second refused read, and the verdict clause counts the evaluations each way once both ways were
/// met, so one refusal met beside a pass and beside an absence is one refusal and the verdict wording
/// does not depend on which came first; the texts are named in the order the site MET them, numbered, so
/// the same two texts met in the other order are named in the other order; a rendering that ordered the
/// texts by their sort order would name them alike for both orders, and one that named the first alone
/// would leave the second a count. The fourth verdict, a value that matches a denied entry, and the fifth,
/// a value of another kind (a pair the comparator refused on kinds), each have their own wording.
#[test]
fn a_sites_line_counts_distinct_refusal_texts_and_the_verdicts_that_met_them() -> Result<()> {
    let rules_file = RulesFile::try_from("rule r { Resources exists }")?;
    let mut root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }")?),
    );
    let site = FileLocation {
        file_name: "rules.guard",
        line: 1,
        column: 10,
    };
    use crate::rules::UnraisedVerdict;
    let first = vec![String::from("the first refusal")];
    let second = vec![String::from("the second refusal")];
    // The line ends with the clause's position; a scope built with no data file and no case names no
    // input after it.
    const AT: &str = " The clause is at Location[file:rules.guard, line:1, column:10].";
    root.record_unraised_refusal(&site, "Y IN %x", UnraisedVerdict::Passed, &first);
    root.record_unraised_refusal(&site, "Y IN %x", UnraisedVerdict::Passed, &first);
    let after_the_repeat: Vec<String> = root.warnings().cloned().collect();
    assert_eq!(after_the_repeat.len(), 1, "one site, one line");
    assert_eq!(
        after_the_repeat[0],
        crate::utils::writer::warning(format_args!(
            "Y IN %x passed by a value that holds, so the refused read among its other values was not \
             raised by it; the refusal is reported here instead: the first refusal.{AT}"
        )),
        "the same text twice: one refusal, one verdict, no count; the position ends the line"
    );
    root.record_unraised_refusal(&site, "Y IN %x", UnraisedVerdict::DecidedByAbsence, &second);
    let after_the_second: Vec<String> = root.warnings().cloned().collect();
    assert_eq!(after_the_second.len(), 1, "still one line");
    assert_eq!(
        after_the_second[0],
        crate::utils::writer::warning(format_args!(
            "Y IN %x passed by a value that holds on 2 evaluations and was decided by a value the \
             document lacks on 1 evaluation, so the 2 refused reads among its other values were not \
             raised by it; they are reported here instead: (1) the first refusal (2) the second \
             refusal.{AT}"
        )),
        "a second distinct text and the other verdict: both counted, both texts named in the order met"
    );
    // The third verdict, with its own wording.
    root.record_unraised_refusal(&site, "Y IN %x", UnraisedVerdict::DecidedByMismatch, &first);
    let after_the_mismatch: Vec<String> = root.warnings().cloned().collect();
    assert_eq!(
        after_the_mismatch[0],
        crate::utils::writer::warning(format_args!(
            "Y IN %x passed by a value that holds on 2 evaluations and was decided by a value the \
             document lacks on 1 evaluation and was decided by a value that does not match on 1 \
             evaluation, so the 2 refused reads among its other values were not raised by it; they are \
             reported here instead: (1) the first refusal (2) the second refusal.{AT}"
        )),
        "a value that does not match is the third counted way"
    );
    // The fourth verdict, the negated comparators' no, with its own wording.
    root.record_unraised_refusal(
        &site,
        "Y IN %x",
        UnraisedVerdict::DecidedByCollision,
        &first,
    );
    let after_the_collision: Vec<String> = root.warnings().cloned().collect();
    assert_eq!(
        after_the_collision[0],
        crate::utils::writer::warning(format_args!(
            "Y IN %x passed by a value that holds on 2 evaluations and was decided by a value the \
             document lacks on 1 evaluation and was decided by a value that does not match on 1 \
             evaluation and was decided by a value that matches a denied value on 1 evaluation, so the \
             2 refused reads among its other values were not raised by it; they are reported here \
             instead: (1) the first refusal (2) the second refusal.{AT}"
        )),
        "a value that matches a denied value is the fourth counted way"
    );
    // The fifth verdict, a pair the comparator refused on kinds, with its own wording.
    root.record_unraised_refusal(&site, "Y IN %x", UnraisedVerdict::DecidedByKinds, &first);
    let after_the_kinds: Vec<String> = root.warnings().cloned().collect();
    assert_eq!(
        after_the_kinds[0],
        crate::utils::writer::warning(format_args!(
            "Y IN %x passed by a value that holds on 2 evaluations and was decided by a value the \
             document lacks on 1 evaluation and was decided by a value that does not match on 1 \
             evaluation and was decided by a value that matches a denied value on 1 evaluation and was \
             decided by a value of another kind on 1 evaluation, so the 2 refused reads among its other \
             values were not raised by it; they are reported here instead: (1) the first refusal (2) the \
             second refusal.{AT}"
        )),
        "a value of another kind is the fifth counted way"
    );
    // The other order of the same three reports: the same counts, and the text met first ("the second
    // refusal", which sorts after "the first refusal") is named first.
    let rules_file = RulesFile::try_from("rule r { Resources exists }")?;
    let mut other = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }")?),
    );
    other.record_unraised_refusal(&site, "Y IN %x", UnraisedVerdict::DecidedByAbsence, &second);
    other.record_unraised_refusal(&site, "Y IN %x", UnraisedVerdict::Passed, &first);
    other.record_unraised_refusal(&site, "Y IN %x", UnraisedVerdict::Passed, &first);
    let the_other_order: Vec<String> = other.warnings().cloned().collect();
    assert_eq!(
        the_other_order.len(),
        1,
        "one site, one line in the other order too"
    );
    assert_eq!(
        the_other_order[0],
        crate::utils::writer::warning(format_args!(
            "Y IN %x passed by a value that holds on 2 evaluations and was decided by a value the \
             document lacks on 1 evaluation, so the 2 refused reads among its other values were not \
             raised by it; they are reported here instead: (1) the second refusal (2) the first \
             refusal.{AT}"
        )),
        "the verdict counts do not depend on the order; the texts are named in the order met"
    );
    Ok(())
}

/// A refusal text quoting a document key that holds a line feed and an ESC is written into the
/// refused-read line as ONE `Warning:`-prefixed line with the two characters as their escapes (`\n`,
/// `\u{1b}`): the text is escaped once, at the one point the line builder writes it in
/// (`unraised_refusal_notice`), as the clause and the file name beside it are. A key holding either would
/// otherwise split the line (its second half with no prefix, read as failure text) or open a terminal
/// escape sequence; a debug build's `writer::warning` asserts that no such character reached the body, so
/// a builder that wrote the text in raw fails this cell by that assertion.
#[test]
fn a_refusal_text_holding_a_line_feed_and_an_escape_is_one_prefixed_line() -> Result<()> {
    let site = FileLocation {
        file_name: "rules.guard",
        line: 1,
        column: 10,
    };
    let rules_file = RulesFile::try_from("rule r { Resources exists }")?;
    let mut root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }")?),
    );
    let refusal = vec![String::from(
        "the key `a\nb\u{1b}]c` could not be read as the predicate asks",
    )];
    root.record_unraised_refusal(
        &site,
        "Y IN %x",
        crate::rules::UnraisedVerdict::Passed,
        &refusal,
    );
    let lines: Vec<String> = root.warnings().cloned().collect();
    assert_eq!(1, lines.len(), "one line, got {lines:?}");
    let line = &lines[0];
    assert_eq!(
        (true, false, false, true),
        (
            line.starts_with("Warning: "),
            line.contains('\n'),
            line.contains('\u{1b}'),
            line.contains("`a\\nb\\u{1b}]c`"),
        ),
        "prefixed, holding no line feed and no ESC, the key written with its escapes: {line:?}"
    );
    Ok(())
}

/// The twin's undecidable-pair sentence escapes a long key and bounds it on an ESCAPE BOUNDARY
/// (`escaped_template_part`): the bound holds on the printed text and no escape is cut in half. A key of
/// 255 characters, an ESC and a tail prints the 255 and cuts at the ESC, whose six-character escape does
/// not fit, counting the five source characters left out (nothing of the ESC is printed, raw or half
/// escaped); a key of 256 bidi overrides, eight printed characters each, prints 32 of them and counts the
/// 224 left out, where a cut by source characters before the escape printed all 256 at eight times the
/// bound.
#[test]
fn the_twins_undecidable_sentence_cuts_a_key_on_an_escape_boundary() -> Result<()> {
    use crate::rules::eval_context::{undecidable_pair_text, LONGEST_TEMPLATE_PART_IN_A_REFUSAL};
    let error = crate::rules::errors::Error::UndecidableComparison(String::from("undecidable"));
    let key = format!(
        "{}\u{1b}tail",
        "k".repeat(LONGEST_TEMPLATE_PART_IN_A_REFUSAL - 1)
    );
    let text = undecidable_pair_text(&key, &[], &error);
    assert_eq!(
        (true, false, false, false),
        (
            text.contains(&format!(
                "{}...[5 more characters cut]",
                "k".repeat(LONGEST_TEMPLATE_PART_IN_A_REFUSAL - 1)
            )),
            text.contains('\u{1b}'),
            text.contains("\\u{1b}"),
            text.contains("k\\...["),
        ),
        "the ESC that does not fit is left out whole, the tail counted with it: {text:?}"
    );
    let bidi = "\u{202e}".repeat(LONGEST_TEMPLATE_PART_IN_A_REFUSAL);
    let text = undecidable_pair_text(&bidi, &[], &error);
    assert_eq!(
        (32, true, false),
        (
            text.matches("\\u{202e}").count(),
            text.contains("...[224 more characters cut]"),
            text.contains('\u{202e}'),
        ),
        "a key of bidi overrides is bounded on what is printed: {text:?}"
    );
    Ok(())
}

/// The refusal registry is one set per live root scope, not one per thread: a refusal raised with no
/// root scope alive registers nothing; a refusal registered under one scope is still a refusal while a
/// second scope lives on the same thread and after that second scope drops (the second scope's drop
/// removes its own set only); `reset_root`, which builds the new scope before the old one drops, leaves
/// the new scope a live, empty set of its own and takes the old scope's refusals with the old scope.
#[test]
fn a_refusal_lives_with_its_own_root_scope_and_a_scopeless_refuse_registers_nothing() -> Result<()>
{
    let rules_file = RulesFile::try_from("rule r { Resources exists }")?;
    let root = Rc::new(PathAwareValue::try_from("{ Resources: { A: 1 } }")?);
    let outside = refuse(String::from("a refusal raised with no root scope alive"));
    assert!(
        !is_refusal(&outside),
        "a refusal raised with no root scope alive is dropped, not kept for the next scope"
    );
    let first = root_scope_for(&rules_file, Rc::clone(&root), None);
    let first_refusal = refuse(String::from("the first scope's refusal"));
    assert!(
        is_refusal(&first_refusal),
        "registered under the first scope"
    );
    let second_text = String::from("the second scope's refusal");
    {
        let _second = root_scope_for(&rules_file, Rc::clone(&root), None);
        let second_refusal = refuse(second_text.clone());
        assert!(
            is_refusal(&second_refusal) && is_refusal(&first_refusal),
            "both scopes alive: each one's refusal is a refusal"
        );
    }
    assert!(
        is_refusal(&first_refusal),
        "the first scope's refusal survives the second scope's drop"
    );
    assert!(
        !is_refusal(&Error::Unevaluatable(second_text)),
        "the second scope's refusal went with the second scope"
    );
    let reset = first.reset_root(Rc::clone(&root));
    assert!(
        !is_refusal(&Error::Unevaluatable(String::from(
            "the first scope's refusal"
        ))),
        "the old scope's refusals go with the old scope's drop inside `reset_root`"
    );
    let under_the_reset_scope = refuse(String::from("a refusal under the reset scope"));
    assert!(
        is_refusal(&under_the_reset_scope),
        "the reset scope has a live set of its own"
    );
    drop(reset);
    assert!(
        !is_refusal(&under_the_reset_scope),
        "the reset scope's refusals go with its drop"
    );
    Ok(())
}

/// A template part is cut only where the cut shortens it. The marker a cut writes costs about thirty
/// characters, so a path or a name a few characters over `LONGEST_TEMPLATE_PART_IN_A_REFUSAL` would render
/// LONGER cut than whole: a 260-character path renders whole with its location, as `Path`'s `Display`
/// renders it; a 300-character one is cut, carries the marker and renders in fewer characters than its
/// text. The same for a name through `template_part`: a 258-character key renders whole and a 300-character
/// one is cut and shorter.
#[test]
fn a_part_a_little_over_the_bound_renders_whole_and_a_long_one_is_cut_shorter() {
    let bound = LONGEST_TEMPLATE_PART_IN_A_REFUSAL;
    let a_little_over = Path(format!("/{}", "a".repeat(bound + 3)), Location::new(7, 3));
    assert_eq!(
        bound + 4,
        a_little_over.0.chars().count(),
        "the fixture is 260 characters"
    );
    assert_eq!(
        a_little_over.to_string(),
        template_path(&a_little_over),
        "a 260-character path renders whole, with its location: a cut would make it longer"
    );
    let long = Path(format!("/{}", "b".repeat(299)), Location::new(1, 1));
    let shown = template_path(&long);
    assert!(
        shown.contains("...[") && shown.contains(" more characters cut]..."),
        "a 300-character path is cut and marked: {}",
        shown
    );
    assert!(
        shown.chars().count() < long.0.chars().count(),
        "the cut rendering ({}) is shorter than the path text (300)",
        shown.chars().count()
    );
    let key_a_little_over = "k".repeat(bound + 2);
    assert_eq!(
        key_a_little_over,
        template_part(&key_a_little_over),
        "a 258-character key renders whole: a cut would make it longer"
    );
    let long_key = "k".repeat(300);
    let cut_key = template_part(&long_key);
    assert!(
        cut_key.ends_with(" more characters cut]") && cut_key.chars().count() < 300,
        "a 300-character key is cut at its end and shorter: {}",
        cut_key
    );
}

/// The middle cut of a path, exact at both cut points over multi-byte characters and over a long leaf: the
/// head is the path's first `LONGEST_TEMPLATE_PART_IN_A_REFUSAL / 2` characters, the tail its last as many,
/// the marker between them names the characters cut, and the location follows whole, joined to the text the
/// way `Display` joins it (`Path::shown_with_location`), so the rendering equals the pieces of
/// `path.to_string()` around the cut. An accented letter as the last kept head character and an emoji as
/// the first cut one, an emoji as the first kept tail character and an accented letter as the last cut one,
/// and a 300-character leaf segment, whose END the tail keeps (its last characters before the location)
/// while its start goes to the marker.
#[test]
fn a_paths_middle_cut_keeps_whole_characters_at_both_ends_and_a_long_leafs_end() {
    let half = LONGEST_TEMPLATE_PART_IN_A_REFUSAL / 2;
    let expected = |path: &Path| -> String {
        let chars: Vec<char> = path.0.chars().collect();
        let head: String = chars[..half].iter().collect();
        let tail: String = chars[chars.len() - half..].iter().collect();
        let location = &path.to_string()[path.0.len()..];
        format!(
            "{head}...[{} more characters cut]...{tail}{location}",
            chars.len() - 2 * half
        )
    };
    // 127 ASCII characters, then `é` as the 128th (the last kept head character), then an emoji as the
    // 129th (the first cut), filler, `ü` as the last cut character, an emoji as the first kept tail
    // character, and 127 more to the end: 400 characters in all.
    let at_the_head_cut = {
        let mut text = String::from("/");
        text.push_str(&"a".repeat(126));
        text.push('\u{e9}');
        text.push('\u{1F600}');
        text.push_str(&"m".repeat(400 - 128 - 1 - 2 - 127));
        text.push('\u{fc}');
        text.push('\u{1F600}');
        text.push_str(&"z".repeat(127));
        Path(text, Location::new(12, 5))
    };
    assert_eq!(
        400,
        at_the_head_cut.0.chars().count(),
        "the fixture is 400 characters"
    );
    let shown = template_path(&at_the_head_cut);
    assert_eq!(
        expected(&at_the_head_cut),
        shown,
        "the accented letter is the head's last character and the emoji after it is cut whole"
    );
    assert!(
        shown.starts_with(&format!("/{}\u{e9}...[", "a".repeat(126))),
        "the head ends in the accented letter: {}",
        shown
    );
    assert!(
        shown.contains(&format!("]...\u{1F600}{}", "z".repeat(127))),
        "the tail begins with the emoji and the accented letter before it is cut whole: {}",
        shown
    );
    let long_leaf = Path(
        format!("/Resources/R/Properties/{}", "L".repeat(300)),
        Location::new(3, 9),
    );
    let shown = template_path(&long_leaf);
    assert_eq!(
        expected(&long_leaf),
        shown,
        "a 300-character leaf: the head keeps the top of the document, the tail the leaf's end"
    );
    assert!(
        shown.ends_with(&format!("{}[L:3,C:9]", "L".repeat(half))),
        "the tail is the leaf's last {} characters, then the location: {}",
        half,
        shown
    );
    assert!(
        shown.starts_with("/Resources/R/Properties/LLLL"),
        "the head keeps the document's top and the leaf's start: {}",
        shown
    );
}

/// `Path`'s `Display` is its text shown with its location through the one joining,
/// `Path::shown_with_location`, so a refusal's path rendered whole or cut (`template_path`) and a path
/// rendered anywhere else carry the location the same way: for a path with a location, `to_string()`
/// equals `shown_with_location` given the path's own text.
#[test]
fn a_paths_display_is_its_text_shown_with_its_location() {
    let path = Path("/Resources/B/Properties".to_string(), Location::new(4, 7));
    assert_eq!(path.to_string(), path.shown_with_location(&path.0));
    assert_eq!(
        "/Resources/B/Properties[L:4,C:7]",
        path.to_string(),
        "the text, then the location in brackets"
    );
}

/// The cut begins at the first length where it shortens the part, and that length is read off the
/// marker's own text, so a change to the marker moves the boundary with it: an end cut keeps
/// `LONGEST_TEMPLATE_PART_IN_A_REFUSAL` characters and writes `...[N more characters cut]`, a middle cut
/// keeps as many and writes `...[N more characters cut]...` between its halves, and either is made only
/// where the kept characters plus the marker are fewer than the whole. A part one character under that
/// length renders whole, a part at it is cut and shorter; the same for a path, with its location kept out
/// of the count; and a path of accented letters one character under the length renders whole though its
/// BYTES are twice the bound, since characters decide.
#[test]
fn the_cut_begins_at_the_first_length_where_it_shortens_the_part() {
    let bound = LONGEST_TEMPLATE_PART_IN_A_REFUSAL;
    let end_marker = |cut: usize| format!("...[{cut} more characters cut]").chars().count();
    let middle_marker = |cut: usize| format!("...[{cut} more characters cut]...").chars().count();
    let first_cut_part = (bound + 1..)
        .find(|&total| bound + end_marker(total - bound) < total)
        .expect("a part long enough is cut");
    let first_cut_path = (bound + 1..)
        .find(|&total| bound + middle_marker(total - bound) < total)
        .expect("a path long enough is cut");
    let whole_part = "p".repeat(first_cut_part - 1);
    assert_eq!(
        whole_part,
        template_part(&whole_part),
        "a part of {} characters renders whole: its cut would be as long",
        first_cut_part - 1
    );
    let cut_part = "p".repeat(first_cut_part);
    let shown = template_part(&cut_part);
    assert!(
        shown.ends_with(" more characters cut]") && shown.chars().count() < first_cut_part,
        "a part of {} characters is cut and shorter: {}",
        first_cut_part,
        shown
    );
    let whole_path = Path(
        format!("/{}", "q".repeat(first_cut_path - 2)),
        Location::new(2, 3),
    );
    assert_eq!(
        whole_path.to_string(),
        template_path(&whole_path),
        "a path of {} characters renders whole with its location",
        first_cut_path - 1
    );
    let cut_path = Path(
        format!("/{}", "q".repeat(first_cut_path - 1)),
        Location::new(2, 3),
    );
    let shown = template_path(&cut_path);
    assert!(
        shown.contains(" more characters cut]...")
            && shown.ends_with("[L:2,C:3]")
            && shown.chars().count() < cut_path.to_string().chars().count(),
        "a path of {} characters is cut, shorter, and keeps its location: {}",
        first_cut_path,
        shown
    );
    let accented = Path("\u{e9}".repeat(first_cut_path - 1), Location::new(5, 1));
    assert!(
        accented.0.len() > 2 * bound,
        "the fixture's bytes are past twice the bound"
    );
    assert_eq!(
        accented.to_string(),
        template_path(&accented),
        "a path of {} accented letters renders whole: characters decide, not bytes",
        first_cut_path - 1
    );
}
