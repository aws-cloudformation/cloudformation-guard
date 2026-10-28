use super::*;
use crate::rules::exprs::*;
use crate::rules::path_value::*;
use pretty_assertions::assert_eq;
use std::convert::TryFrom;

/// The sentence a record's failed condition alone joins, through the join every arm ships
/// (`join_rule_refusals` over `condition_refusals`): the cells that read the condition's join go through
/// production code and not a copy of it.
fn sentence_and_whether_refusals_joined(
    message: &str,
    children: &[EventRecord<'_>],
    slot: SentenceSlot,
) -> (String, Option<SentenceParts>) {
    join_rule_refusals(
        message,
        condition_refusals(children),
        Vec::new(),
        Vec::new(),
        slot,
    )
}

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
    /// The frames of the runs open under this double (`EvalContext::refusal_frames`): kept as a root
    /// scope keeps them, so a run under the double pushes and pops here and a fold under it ranks by the
    /// frames a cell plants, where a double that dropped them ranked every token 0 whatever ran.
    pub(crate) refusal_frames: RefusalFrames,
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
    fn rule_status(
        &mut self,
        _: &str,
        _: crate::rules::eval::ClauseRole,
    ) -> Result<crate::rules::Judged> {
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
    /// Dropped with the other notices.
    fn pend_scalar_filter_notice(
        &mut self,
        _: crate::rules::errors::RefusalToken,
        _: &FileLocation<'_>,
        _: &str,
        _: String,
        _: crate::rules::MarkerBinding,
    ) {
    }
    fn undecided_member_read(
        &mut self,
        _: crate::rules::errors::RefusalToken,
        _: Option<&str>,
        _: crate::rules::eval::ClauseRole,
        _: &FileLocation<'_>,
    ) {
    }
    fn undecided_reads_decided(
        &mut self,
        _: &FileLocation<'_>,
        _: crate::rules::UndecidedReadsDecision,
    ) {
    }
    fn held_raises_failed_closed(&mut self, _: &[String]) {}
    fn held_fails_mark(&self) -> u64 {
        0
    }
    fn held_fails_judged(&mut self, _: u64, _: Option<&[crate::rules::RefusedRead]>) {}
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
    fn resolving_binding(&self) -> crate::rules::MarkerBinding {
        crate::rules::MarkerBinding::Clause
    }
    fn within_parameterized_call(&self) -> bool {
        false
    }
    /// The double's own stack (`refusal_frames`), kept as a root scope keeps its: a run under this
    /// double pushes and pops here, so a fold under it ranks by the frames the run and a cell planted.
    /// A double that answered an empty stack and dropped every push ranked every token 0 under a run,
    /// the pair rule as released, whatever the run had opened.
    fn refusal_frames(&self) -> RefusalFrames {
        self.refusal_frames.clone()
    }
    fn refusal_frames_mut(&mut self) -> &mut RefusalFrames {
        &mut self.refusal_frames
    }
    /// Binds no variables, so nothing here is on a chain to a function's result.
    fn function_chain(&mut self, _: &str) -> Option<FunctionChain<'value>> {
        None
    }
    fn function_result_entries(&mut self, _: &str) -> Option<Result<Rc<FunctionEntries>>> {
        None
    }
    fn record_warning(&mut self, _: &FileLocation<'_>, _: &str, _: &str, _: String) {}
    fn record_capture_warning(&mut self, _: &FileLocation<'_>, _: &str, _: String) -> bool {
        false
    }
    fn record_unraised_refusal(
        &mut self,
        _: &FileLocation<'_>,
        _: &str,
        _: crate::rules::UnraisedVerdict,
        _: &[String],
    ) {
    }
    fn open_absorbed_frame(&mut self) {}
    fn close_absorbed_frame(&mut self) -> Vec<crate::rules::AbsorbedRaise<'loc>> {
        Vec::new()
    }
    fn note_absorbed_raise(
        &mut self,
        _: &str,
        _: &FileLocation<'loc>,
        _: &[String],
        _: crate::rules::RaiseKind,
    ) {
    }
    fn absorbed_frame_mark(&self) -> usize {
        0
    }
    fn truncate_absorbed_frame(&mut self, _: usize) -> Vec<crate::rules::AbsorbedRaise<'loc>> {
        Vec::new()
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
            refusal_frames: RefusalFrames::default(),
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
            refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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

/// The control file of the two per-rule status tests: two rules meant to answer differently, so a
/// reader that reports one value for every name cannot pass either test.
const CONTROL_RULES: &str = "rule first { Cfg.Items exists }\nrule second { Cfg.Items[*].V == 9 }";

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
/// The two statuses are the run's own, read off the `RuleCheck` records the run wrote
/// (`recorded_rule_status`), so the equality is about one run. `RootScope::rule_status` would evaluate
/// the rule AGAIN, bare (its memo is filled only by references met inside a run, never by the top-level
/// run), and a second evaluation can agree with itself for reasons of its own; its own control is the
/// test after this one, so a regression in `rule_status` does not turn this test red under the wrong
/// name.
#[test]
fn one_variable_rooted_clause_answers_the_same_in_two_rules() -> Result<()> {
    let rules = "let l = Cfg.Items.*\n\
                 rule first { %l[ V == 1 ] !empty }\n\
                 rule second { %l[ V == 1 ] !empty }";

    // The instrument first, on a file whose two rules are meant to differ. Without this the equality
    // below is also satisfied by the records reporting one value for every name, which is the shape of
    // a test that cannot fail. The reader is the one the equality uses: the run's own `RuleCheck`
    // records answer PASS and FAIL by name.
    {
        let control_file = RulesFile::try_from(CONTROL_RULES)?;
        let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(ITEMS)?)?;
        let mut scope = root_scope(&control_file, Rc::new(value));
        crate::rules::eval::eval_rules_file(&control_file, &mut scope, None)?;
        let top = scope.reset_recorder().extract();
        assert_eq!(
            (Status::PASS, Status::FAIL),
            (
                recorded_rule_status(&top, "first"),
                recorded_rule_status(&top, "second")
            ),
            "the run's own records have to report two different answers for one file, or the equality \
             below witnesses nothing"
        );
    }

    let rules_file = RulesFile::try_from(rules)?;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(ITEMS)?)?;
    let mut scope = root_scope(&rules_file, Rc::new(value));
    let whole = crate::rules::eval::eval_rules_file(&rules_file, &mut scope, None)?;

    let top = scope.reset_recorder().extract();
    let first = recorded_rule_status(&top, "first");
    let second = recorded_rule_status(&top, "second");

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

/// The bare per-rule status tells a passing rule from a decided failing one.
///
/// The control for `RootScope::rule_status` that `one_variable_rooted_clause_answers_the_same_in_two_rules`
/// carried before it was a test of its own: that test's equality reads the run's records, so this reader
/// is no premise of it, and a regression here turns only this test red. `rule_status` evaluates the rule
/// itself (its memo is filled only by references met inside a run), a bare drive with one record
/// around each, on a scope no file run has touched: `drive_bare` resets the recorder itself, and a scope
/// a file ran on carries state the run left behind (the memos such as `resolved_variables`, which a
/// recorder reset does not clear). The judged answers whole, basis included: `second`'s FAIL is a
/// comparison that answered no, a decided no, so an answer that read it as resting on an undecidable
/// would fail here too.
#[test]
fn the_bare_per_rule_status_tells_a_pass_from_a_decided_fail() -> Result<()> {
    let control_file = RulesFile::try_from(CONTROL_RULES)?;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(ITEMS)?)?;
    let mut scope = root_scope(&control_file, Rc::new(value));
    assert_eq!(
        (
            crate::rules::Judged::Pass,
            crate::rules::Judged::Fail(crate::rules::FailBasis::Decided)
        ),
        (
            scope.drive_bare(|scope| {
                scope.rule_status("first", crate::rules::eval::ClauseRole::Assertion)
            })?,
            scope.drive_bare(|scope| {
                scope.rule_status("second", crate::rules::eval::ClauseRole::Assertion)
            })?
        ),
        "the bare per-rule status (`rule_status`) has to judge `first` Judged::Pass and `second` \
         Judged::Fail(FailBasis::Decided); anything else means it answers these two rules otherwise"
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
    fn rule_status(
        &mut self,
        _: &str,
        _: crate::rules::eval::ClauseRole,
    ) -> Result<crate::rules::Judged> {
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
    fn pend_scalar_filter_notice(
        &mut self,
        _: crate::rules::errors::RefusalToken,
        _: &FileLocation<'_>,
        _: &str,
        _: String,
        _: crate::rules::MarkerBinding,
    ) {
        todo!()
    }
    fn undecided_member_read(
        &mut self,
        _: crate::rules::errors::RefusalToken,
        _: Option<&str>,
        _: crate::rules::eval::ClauseRole,
        _: &FileLocation<'_>,
    ) {
        todo!()
    }
    fn undecided_reads_decided(
        &mut self,
        _: &FileLocation<'_>,
        _: crate::rules::UndecidedReadsDecision,
    ) {
        todo!()
    }
    fn held_raises_failed_closed(&mut self, _: &[String]) {
        todo!()
    }
    fn held_fails_mark(&self) -> u64 {
        todo!()
    }
    fn held_fails_judged(&mut self, _: u64, _: Option<&[crate::rules::RefusedRead]>) {
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
    fn resolving_binding(&self) -> crate::rules::MarkerBinding {
        todo!()
    }
    fn within_parameterized_call(&self) -> bool {
        todo!()
    }
    fn refusal_frames(&self) -> RefusalFrames {
        todo!()
    }
    fn refusal_frames_mut(&mut self) -> &mut RefusalFrames {
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
    fn record_capture_warning(&mut self, _: &FileLocation<'_>, _: &str, _: String) -> bool {
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
    fn open_absorbed_frame(&mut self) {
        todo!()
    }
    fn close_absorbed_frame(&mut self) -> Vec<crate::rules::AbsorbedRaise<'loc>> {
        todo!()
    }
    fn note_absorbed_raise(
        &mut self,
        _: &str,
        _: &FileLocation<'loc>,
        _: &[String],
        _: crate::rules::RaiseKind,
    ) {
        todo!()
    }
    fn absorbed_frame_mark(&self) -> usize {
        todo!()
    }
    fn truncate_absorbed_frame(&mut self, _: usize) -> Vec<crate::rules::AbsorbedRaise<'loc>> {
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
        refusal_frames: RefusalFrames::default(),
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
/// What this reads: `main`'s own `RuleCheck` record in the tree the run wrote
/// (`reset_recorder().extract()`, `recorded_rule_status`), so the two statuses are the run's own verdicts
/// and no rule is evaluated a second time to produce them. `rule_status` after the run would evaluate
/// `main` AGAIN, bare: its memo is filled only by references met inside a run, never by the top-level
/// run, so an earlier form of this test checked a second evaluation and not the run's verdict.
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
            // The run's own verdict for `main`, read off the record tree the run wrote.
            let top = scope.reset_recorder().extract();
            per_case.push((shape, order, recorded_rule_status(&top, "main")));
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

/// The status a top-level rule's own `RuleCheck` record holds in an extracted record tree: the run's
/// verdict, read where the run wrote it, never a second evaluation. The one reader of its kind;
/// `eval_tests.rs` imports it. Rules may share a name (a rules file admits it), so every match is collected:
/// exactly one is required, a miss panics naming the rules the tree holds, and a second record of the name
/// panics naming how many there are, so the answer is never the first of several.
pub(crate) fn recorded_rule_status(top: &EventRecord<'_>, rule_name: &str) -> Status {
    let held: Vec<(&str, Status)> = top
        .children
        .iter()
        .filter_map(|child| match &child.container {
            Some(RecordType::RuleCheck(NamedStatus { name, status, .. })) => Some((*name, *status)),
            _ => None,
        })
        .collect();
    let matches: Vec<Status> = held
        .iter()
        .filter(|(name, _)| *name == rule_name)
        .map(|(_, status)| *status)
        .collect();
    match matches.as_slice() {
        [status] => *status,
        [] => panic!(
            "no rule named {} in the record tree; it holds {:?}",
            rule_name,
            held.iter().map(|(name, _)| *name).collect::<Vec<_>>()
        ),
        several => panic!(
            "{} records of the rule named {} in the record tree: {:?}",
            several.len(),
            rule_name,
            several
        ),
    }
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
/// key name): an object. The first spec has no scalar entry on purpose, so the walk stands. A scalar
/// `replicas` beside the sub-maps, with none of them holding the key the predicate names, makes the spec
/// one object to the slot after `%s`, which tests the predicate on the spec itself as `spec[*][ f ]`
/// does; the notice classifies the map from its keys before it probes anything, so a one-object spec
/// pays no probe, no re-walk and no entry read on any of the twelve evaluations, and no notice goes out
/// (the fifth row pins that, with the rule's status: the spec is selected and the clause passes). The
/// second spec keeps its scalar and is mixed: its sub-maps hold the key, so the slot refuses the filter
/// where the literal does and tests the spec as one object otherwise, and the notice returns for it at
/// the same classification, with the same zero cost. The filter sits inside a type block that matches twelve buckets, so the clause is
/// evaluated twelve times. The predicates:
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
///   map-valued fields each carry one too, with a scalar `replicas` beside them: a mixed map, refused
///   where the literal is and one object otherwise. The notice returns at the classification, so
///   nothing is probed, re-walked or announced on any of the twelve evaluations: (0, 0, 0, 0).
/// - `%s[ securityContext !exists ] !empty` over a `spec` of `replicas`, `selector` and `template`, no
///   sub-map holding the key: one object, tested whole and selected (the rule PASSes), and the same
///   (0, 0, 0, 0).
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
        "{buckets}spec:\n  selector:\n    matchLabels:\n      app: a\n  template:\n    \
         metadata:\n      labels:\n        app: a\n  strategy:\n    type: Recreate\n"
    );
    let carrying = format!(
        "{buckets}spec:\n  replicas: 3\n  securityContext:\n    securityContext: {{}}\n  selector:\n    \
         securityContext:\n      runAsNonRoot: true\n"
    );
    let one_object = format!(
        "{buckets}spec:\n  replicas: 3\n  selector:\n    matchLabels:\n      app: a\n  template:\n    \
         metadata:\n      labels:\n        app: a\n"
    );
    // (probes, re-walks, entry probes, notices) over the twelve evaluations, and the rule's status where
    // the row's silence is a selection (`None` where only the counts are the row's point).
    type Counts = (usize, usize, usize, usize);
    let rows: [(&str, &str, &str, Counts, Option<Status>); 7] = [
        (
            "a positive predicate that did not hold on the object: one probe, no re-walk, then the recorded quiet verdict on the other eleven evaluations",
            &object,
            "let s = spec\nrule r { AWS::S3::Bucket { %s[ securityContext exists ] empty } }",
            (1, 0, 0, 0),
            None,
        ),
        (
            "an absence check spelled with a leading `not`, held on the object: announced once as a lost selection, as the `!exists` spelling is",
            &object,
            "let s = spec\nrule r { AWS::S3::Bucket { %s[ not securityContext exists ] !empty } }",
            (1, 1, 0, 1),
            None,
        ),
        (
            "the `not` spelling over a mixed spec (a scalar beside sub-maps that hold the key): classified before any probe, nothing probed, re-walked or announced",
            &carrying,
            "let s = spec\nrule r { AWS::S3::Bucket { %s[ not securityContext exists ] empty } }",
            (0, 0, 0, 0),
            None,
        ),
        (
            "an absence check over the same mixed spec: classified before any probe, nothing probed, re-walked or announced",
            &carrying,
            "let s = spec\nrule r { AWS::S3::Bucket { %s[ securityContext !exists ] empty } }",
            (0, 0, 0, 0),
            None,
        ),
        (
            "an absence check over a one-object spec (a scalar `replicas` beside sub-maps none of which holds the key): tested whole and selected, the rule passes, nothing probed, re-walked or announced",
            &one_object,
            "let s = spec\nrule r { AWS::S3::Bucket { %s[ securityContext !exists ] !empty } }",
            (0, 0, 0, 0),
            Some(Status::PASS),
        ),
        (
            "the control: an absence check held on the object, announced once as a lost selection",
            &object,
            "let s = spec\nrule r { AWS::S3::Bucket { %s[ securityContext !exists ] !empty } }",
            (1, 1, 0, 1),
            None,
        ),
        (
            "the common idiom over a collection, `%r[ Type == 'AWS::S3::Bucket' ]` with `let r = Resources`, inside the type block: one probe, then the recorded quiet verdict on the other eleven evaluations",
            &object,
            "let r = Resources\nrule r { AWS::S3::Bucket { %r[ Type == 'AWS::S3::Bucket' ] !empty } }",
            (1, 0, 0, 0),
            None,
        ),
    ];
    for (label, doc, rules, expected, expected_status) in rows {
        BOUND_MAP_FILTER_PROBES.with(|probes| probes.set(0));
        BOUND_MAP_FILTER_REWALKS.with(|rewalks| rewalks.set(0));
        BOUND_MAP_ENTRY_PROBES.with(|probes| probes.set(0));
        let rules_file = RulesFile::try_from(rules)?;
        let value =
            PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(doc).unwrap())?;
        let mut scope = root_scope(&rules_file, Rc::new(value));
        let status = crate::rules::eval::eval_rules_file(&rules_file, &mut scope, None)?;
        if let Some(expected_status) = expected_status {
            assert_eq!(expected_status, status, "{label}: the rule's status");
        }
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
/// capture cut (`ShapeNotes::rebind_to_markers`) reads the `refusal` token alone, never the other
/// undecidables.
#[test]
fn a_refusal_is_an_undecidable_kind_and_the_decided_kinds_are_not() {
    assert!(UnResolvedKind::Undecidable {
        refusal: Some(crate::rules::errors::RefusalToken::minted(7)),
        carried: None,
    }
    .is_undecidable());
    assert!(UnResolvedKind::Undecidable {
        refusal: None,
        carried: None
    }
    .is_undecidable());
    assert!(!UnResolvedKind::Absent.is_undecidable());
    assert!(!UnResolvedKind::EmptyEnumeration.is_undecidable());
    assert!(UnResolvedKind::Undecidable {
        refusal: Some(crate::rules::errors::RefusalToken::minted(7)),
        carried: None,
    }
    .is_refusal());
    assert!(!UnResolvedKind::Undecidable {
        refusal: None,
        carried: None
    }
    .is_refusal());
    assert!(!UnResolvedKind::Absent.is_refusal());
    assert!(!UnResolvedKind::EmptyEnumeration.is_refusal());
}

/// The refusal token is opaque: the marker's kind prints as its two facts and never the token's count, so
/// two evaluations of one rules file dump the same record for the same verdicts, and an error rebuilt from
/// its text (`Error::repeated`) carries no token, so a later read of a failed assignment flags no entry.
/// The type's field is private and it has no public constructor (the crate-private `minted` is this
/// crate's), so code outside the evaluator names it in a pattern and nothing else.
#[test]
fn the_refusal_token_is_opaque_in_the_dump_and_dropped_by_a_rebuilt_error() {
    let token = crate::rules::errors::RefusalToken::minted(7);
    assert_eq!(
        "Undecidable { refused: true }",
        format!(
            "{:?}",
            UnResolvedKind::Undecidable {
                refusal: Some(token),
                carried: None,
            }
        )
    );
    assert_eq!(
        "Undecidable { refused: false }",
        format!(
            "{:?}",
            UnResolvedKind::Undecidable {
                refusal: None,
                carried: None
            }
        )
    );
    let rebuilt =
        crate::rules::errors::Error::UndecidableComparison("why".to_string(), Some(token))
            .repeated();
    assert!(
        matches!(&rebuilt, crate::rules::errors::Error::UndecidableComparison(reason, None) if reason == "why"),
        "a rebuilt error keeps the text and drops the token: {:?}",
        rebuilt
    );
}

/// Two markers of one refusal read alike though their tokens were minted apart, and a refused marker
/// reads apart from a plain one: `UnResolvedKind::reading` is the kind's name and whether it is a
/// refusal, what `Debug` prints, never the count. Pinned on two tokens minted in one run, the two markers
/// a derived equality told apart with identical prints on both sides; the kind offers no `==` outside test
/// builds, and the test-build `==` is this reading, so a comparison of two markers compares nothing else.
#[test]
fn two_markers_of_one_refusal_read_alike_whatever_their_tokens_count() {
    let first = UnResolvedKind::Undecidable {
        refusal: Some(mint_refusal_token()),
        carried: None,
    };
    let second = UnResolvedKind::Undecidable {
        refusal: Some(mint_refusal_token()),
        carried: None,
    };
    let plain = UnResolvedKind::Undecidable {
        refusal: None,
        carried: None,
    };
    assert_eq!(("Undecidable", true), first.reading());
    assert_eq!(first.reading(), second.reading());
    assert_eq!(("Undecidable", false), plain.reading());
    assert_ne!(first.reading(), plain.reading());
    assert_eq!(("Absent", false), UnResolvedKind::Absent.reading());
    assert_eq!(
        ("EmptyEnumeration", false),
        UnResolvedKind::EmptyEnumeration.reading()
    );
    assert_ne!(
        UnResolvedKind::Absent.reading(),
        UnResolvedKind::EmptyEnumeration.reading()
    );
    assert_ne!(first.reading(), UnResolvedKind::Absent.reading());
    // `Debug` is written through `reading`, so the whole dump of a kind is a rendering of its reading
    // and nothing else: the kind's name alone for the two decided kinds, the name with the refusal flag
    // for a marker. Pinned on every variant, a plain marker carrying a token for an enclosing run
    // among them (`carried` is transport, not a fact about the entry, and renders as a plain marker), so
    // a `Debug` that grew a field the reading does not hold (a token's count, say) goes red here.
    let carrying = UnResolvedKind::Undecidable {
        refusal: None,
        carried: Some(mint_refusal_token()),
    };
    assert_eq!(("Undecidable", false), carrying.reading());
    for kind in [
        first,
        plain,
        carrying,
        UnResolvedKind::Absent,
        UnResolvedKind::EmptyEnumeration,
    ] {
        let (name, refused) = kind.reading();
        let rendering = match kind {
            UnResolvedKind::Undecidable { .. } => format!("{} {{ refused: {} }}", name, refused),
            UnResolvedKind::Absent | UnResolvedKind::EmptyEnumeration => name.to_string(),
        };
        assert_eq!(
            rendering,
            format!("{:?}", kind),
            "`Debug` is the reading's rendering and nothing more"
        );
    }
}

/// The token's `Debug` form names the type and no count, on the token itself and through an
/// `Error::UndecidableComparison` that carries it: a consumer that prints an error with `{:?}` reads nothing
/// the private field withholds.
#[test]
fn the_refusal_tokens_debug_form_holds_no_count() {
    let token = crate::rules::errors::RefusalToken::minted(7);
    assert_eq!("RefusalToken(..)", format!("{:?}", token));
    let error = crate::rules::errors::Error::UndecidableComparison("why".to_string(), Some(token));
    let printed = format!("{:?}", error);
    assert!(
        printed.contains("RefusalToken(..)"),
        "the error names the token's type: {}",
        printed
    );
    assert!(
        !printed.chars().any(|c| c.is_ascii_digit()),
        "the error's debug form holds no count: {}",
        printed
    );
}

/// A plain marker that carries a token (`to_undecidable_result` with the token of the raise that ended a run
/// the refusal was minted before) reads plain for its own entry and hands the token on: `is_refusal` is
/// false, so the filter loop whose walk returned it cuts no captures on a token minted BEFORE the walk
/// (`refusal_markers_in` leaves it out, read against a frame opened after the minting) and cuts them on
/// one minted DURING the walk (the frame opened before it), while `refusal`, what the error a clause
/// raises over the marker copies, is the carried token, so the run enclosing the one that built the
/// marker reads it against its own start. The marker prints as a plain one (`refused: false`) and is equal
/// to a plain marker carrying nothing: the token is transport, not a fact about the entry. A refused
/// marker's `refusal` is its own token, never a carried one, and is read whenever it was minted.
#[test]
fn a_plain_marker_carrying_a_token_reads_plain_and_hands_the_token_on() -> Result<()> {
    let cfg = cfg_of_a_one_resource_document()?;
    let before_the_minting = RefusalFrame::open();
    let token = mint_refusal_token();
    let after_the_minting = RefusalFrame::open();
    let carrying = to_undecidable_result(Rc::clone(&cfg), "why".to_string(), &[], Some(token))?;
    let plain = to_undecidable_result(Rc::clone(&cfg), "why".to_string(), &[], None)?;
    let refused = to_refusal_result(Rc::clone(&cfg), "why".to_string(), &[], token)?;
    let kind_of = |results: &[QueryResult]| match results {
        [QueryResult::UnResolved(unresolved)] => unresolved.kind,
        other => panic!("one undecidable marker was expected, not {:?}", other),
    };
    let (carrying_kind, plain_kind, refused_kind) =
        (kind_of(&carrying), kind_of(&plain), kind_of(&refused));
    assert!(
        !carrying_kind.is_refusal() && carrying_kind.is_undecidable(),
        "a carrying marker is plain for its own entry: {:?}",
        carrying_kind
    );
    assert_eq!(
        Some(token),
        carrying_kind.refusal(),
        "a carrying marker hands the token on through `refusal`"
    );
    assert_eq!(
        None,
        plain_kind.refusal(),
        "a plain marker hands no token on"
    );
    assert_eq!(
        Some(token),
        refused_kind.refusal(),
        "a refused marker's token is its own"
    );
    assert_eq!(
        "Undecidable { refused: false }",
        format!("{carrying_kind:?}"),
        "the carried token is not printed"
    );
    assert_eq!(
        plain_kind, carrying_kind,
        "a carrying marker is equal to a plain one"
    );
    assert_ne!(
        refused_kind, carrying_kind,
        "a carrying marker is not a refused one"
    );
    assert!(
        refusal_markers_in(&carrying, &after_the_minting).is_empty(),
        "the capture cut leaves a carrying marker alone where its token predates the walk: {:?}",
        carrying
    );
    // The frame's eligibility bit is its whole test: a token minted before the frame opened cannot mark
    // its entry and ranks below any in-run token in the folds (`eligible` reads `minted_inside`); one
    // minted after it opened can. Read as the binding-range half alone, the older token ranked above a
    // later in-run token a binding range excluded, and a nested run's marker carried it up.
    assert_eq!(
        (true, false),
        (
            before_the_minting.eligible(token),
            after_the_minting.eligible(token)
        ),
        "a frame reads a token minted after it opened as eligible and one minted before it as not"
    );
    assert_eq!(
        1,
        refusal_markers_in(&carrying, &before_the_minting).len(),
        "the capture cut reads a carrying marker whose token was minted during the walk: {carrying:?}"
    );
    assert_eq!(
        1,
        refusal_markers_in(&refused, &after_the_minting).len(),
        "the capture cut reads a refused marker whenever its token was minted: {refused:?}"
    );
    Ok(())
}

/// The refusal token is set where a refusal is built and absent where a value nobody could decide is: the
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
            to_refusal_result(
                Rc::clone(&cfg),
                "why".to_string(),
                &[],
                crate::rules::errors::RefusalToken::minted(7),
            )?,
            true,
        ),
        (
            "to_undecidable_result",
            to_undecidable_result(Rc::clone(&cfg), "why".to_string(), &[], None)?,
            false,
        ),
    ] {
        assert_eq!(1, results.len(), "{producer} builds one marker");
        match &results[0] {
            QueryResult::UnResolved(unresolved) => {
                assert!(
                    matches!(unresolved.kind, UnResolvedKind::Undecidable { .. }),
                    "{producer} builds an undecidable marker, not {:?}",
                    unresolved.kind
                );
                assert_eq!(
                    refused,
                    unresolved.kind.is_refusal(),
                    "{producer} sets the refusal token to {refused}"
                );
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
        refusal_frames: RefusalFrames::default(),
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
        vec![UnResolvedKind::Undecidable { refusal: None, carried: None }],
        kinds,
        "the key filter files one undecidable marker for the map, with `refusal` None, among {results:?}"
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
    UnResolvedKind::Undecidable { refusal: None, carried: None },
    Some("why"),
    Some("why")
)]
#[case::refused_with_a_reason(
    UnResolvedKind::Undecidable {
        refusal: Some(crate::rules::errors::RefusalToken::minted(7)),
        carried: None,
    },
    Some("why"),
    Some("why")
)]
#[case::undecidable_without_a_reason_names_the_path(
    UnResolvedKind::Undecidable { refusal: None, carried: None },
    None,
    Some("the selection at /Resources/Cfg[L:0,C:0] could not be decided")
)]
#[case::refused_without_a_reason_names_the_path(
    UnResolvedKind::Undecidable {
        refusal: Some(crate::rules::errors::RefusalToken::minted(7)),
        carried: None,
    },
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
    UnResolvedKind::Undecidable { refusal: None, carried: None },
    None,
    Some("the selection at /Resources/Cfg[L:0,C:0] could not be decided")
)]
#[case::with_a_reason_carries_it(
    UnResolvedKind::Undecidable { refusal: None, carried: None },
    Some("why"),
    Some("why")
)]
#[case::a_refusal_carries_it(
    UnResolvedKind::Undecidable {
        refusal: Some(crate::rules::errors::RefusalToken::minted(7)),
        carried: None,
    },
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

/// `undecidable_argument` folds every entry of every argument by the pair rule
/// (`eval::undecidable_pair_among`, `keep_latest_refusal_else_first`): a refusal's marker anywhere among
/// the arguments gives the error its reason AND its token (the latest-minted refusal's where several
/// stand among the arguments), in either argument order and beside a decided entry; two plain markers
/// keep the first reason with no token; a decided entry alone refuses nothing.
/// Before, the first marker of either kind was the error with its own token alone, so a plain marker in the
/// first argument hid the refusal in the second: the error carried no token and the filter predicate run
/// that ended on it left its entry plain, while the arguments reversed left it refused.
#[test]
fn a_function_refuses_the_refusals_pair_whichever_argument_holds_it() -> Result<()> {
    use crate::rules::errors::RefusalToken;
    let marker = |reason: &str, refusal: Option<RefusalToken>| -> Result<QueryResult> {
        Ok(QueryResult::UnResolved(UnResolved {
            traversed_to: cfg_of_a_one_resource_document()?,
            remaining_query: String::new(),
            reason: Some(reason.to_string()),
            kind: UnResolvedKind::Undecidable {
                refusal,
                carried: None,
            },
        }))
    };
    let plain = marker("budget", None)?;
    let refused = marker("refused", Some(RefusalToken::minted(7)))?;
    let decided = QueryResult::Resolved(Rc::new(PathAwareValue::try_from(r#""a""#)?));
    let pair = |args: &[Vec<QueryResult>]| -> Option<(String, Option<RefusalToken>)> {
        match undecidable_argument(args, RefusalFrames::default()) {
            Some(crate::rules::errors::Error::UndecidableComparison(reason, token)) => {
                Some((reason, token))
            }
            Some(other) => panic!("the refusal is an UndecidableComparison, not {:?}", other),
            None => None,
        }
    };
    let the_refusal = Some(("refused".to_string(), Some(RefusalToken::minted(7))));
    assert_eq!(
        the_refusal,
        pair(&[vec![plain.clone()], vec![refused.clone()]]),
        "the plain marker in the first argument, the refusal in the second"
    );
    assert_eq!(
        the_refusal,
        pair(&[vec![refused.clone()], vec![plain.clone()]]),
        "the refusal in the first argument, the plain marker in the second"
    );
    assert_eq!(
        the_refusal,
        pair(&[vec![decided.clone(), plain.clone(), refused.clone()]]),
        "a decided entry, then the plain marker, then the refusal, in one argument"
    );
    assert_eq!(
        Some(("budget".to_string(), None)),
        pair(&[vec![plain.clone()], vec![plain]]),
        "two plain markers keep the first reason with no token"
    );
    assert_eq!(
        None,
        pair(&[vec![decided]]),
        "a decided entry alone refuses nothing"
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
fn a_result_filed_below_the_segment_survives_the_end_of_the_entry() {
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
fn a_mark_counts_the_parked_slices_so_a_cut_by_a_later_entry_leaves_the_slice_of_an_earlier_entry_alone(
) {
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
fn the_end_of_an_entry_removes_a_name_the_entry_made_and_the_close_puts_it_back() {
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
    ) -> Result<crate::rules::Judged> {
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
    fn pend_scalar_filter_notice(
        &mut self,
        token: crate::rules::errors::RefusalToken,
        site: &FileLocation<'_>,
        reason: &str,
        notice: String,
        binding: crate::rules::MarkerBinding,
    ) {
        self.inner
            .pend_scalar_filter_notice(token, site, reason, notice, binding)
    }
    fn undecided_member_read(
        &mut self,
        token: crate::rules::errors::RefusalToken,
        reason: Option<&str>,
        role: crate::rules::eval::ClauseRole,
        at: &FileLocation<'_>,
    ) {
        self.inner.undecided_member_read(token, reason, role, at)
    }
    fn undecided_reads_decided(
        &mut self,
        at: &FileLocation<'_>,
        decision: crate::rules::UndecidedReadsDecision,
    ) {
        self.inner.undecided_reads_decided(at, decision)
    }
    fn held_raises_failed_closed(&mut self, sites: &[String]) {
        self.inner.held_raises_failed_closed(sites)
    }
    fn held_fails_mark(&self) -> u64 {
        self.inner.held_fails_mark()
    }
    fn held_fails_judged(&mut self, since: u64, rests_on: Option<&[crate::rules::RefusedRead]>) {
        self.inner.held_fails_judged(since, rests_on)
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
    fn resolving_binding(&self) -> crate::rules::MarkerBinding {
        self.inner.resolving_binding()
    }
    fn within_parameterized_call(&self) -> bool {
        self.inner.within_parameterized_call()
    }
    fn refusal_frames(&self) -> RefusalFrames {
        self.inner.refusal_frames()
    }
    fn refusal_frames_mut(&mut self) -> &mut RefusalFrames {
        self.inner.refusal_frames_mut()
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
    fn record_capture_warning(
        &mut self,
        site: &FileLocation<'_>,
        capture: &str,
        notice: String,
    ) -> bool {
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
    fn open_absorbed_frame(&mut self) {
        self.inner.open_absorbed_frame()
    }
    fn close_absorbed_frame(&mut self) -> Vec<crate::rules::AbsorbedRaise<'loc>> {
        self.inner.close_absorbed_frame()
    }
    fn note_absorbed_raise(
        &mut self,
        clause: &str,
        site: &FileLocation<'loc>,
        reads: &[String],
        kind: crate::rules::RaiseKind,
    ) {
        self.inner.note_absorbed_raise(clause, site, reads, kind)
    }
    fn absorbed_frame_mark(&self) -> usize {
        self.inner.absorbed_frame_mark()
    }
    fn truncate_absorbed_frame(&mut self, mark: usize) -> Vec<crate::rules::AbsorbedRaise<'loc>> {
        self.inner.truncate_absorbed_frame(mark)
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
        refusal_frames: RefusalFrames::default(),
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
        refusal_frames: RefusalFrames::default(),
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
fn the_exit_that_refuses_the_key_bind_under_another_entry_leaves_the_segment_of_that_entry_running(
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
fn a_block_built_under_a_measurement_files_a_forced_lets_keys_below_the_segment_of_the_forcing_entry(
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
fn a_measured_readings_filing_below_leaves_the_own_appends_of_the_entry_parked_at_its_end(
) -> Result<()> {
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
    // Every read of a total below is cross-checked against the frames: the re-sum is on by default in a
    // debug build (`PARKED_TOTAL_RESUM`), so no guard is held here.
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
    // Every read of a total below is cross-checked against the frames: the re-sum is on by default in a
    // debug build (`PARKED_TOTAL_RESUM`), so no guard is held here.
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
/// handed out), a close (down by what was appended back), across two frames of one home. The debug
/// build's re-sum is on by default and this test holds it on through a `ParkedTotalResum` guard as well (a
/// statement of what the cells rely on, not a change of setting), so every read of the total here
/// recomputes it from the frames (`CaptureFrames::debug_check_total`, run at each close too) and each step
/// is both the expected value and that cross-check; the re-sum's visits are counted on the check's own
/// counter (`PARKED_TOTAL_RESUM_VISITS`: two slices parked, two visited per read, and none on the
/// production counter `CAPTURE_FRAME_SLICES_VISITED`), and a read after the guard's drop, with the thread
/// back at its default, re-sums the one parked slice.
#[test]
fn a_park_a_cut_a_detach_and_a_close_each_keep_the_parked_total_in_step_with_the_frames() {
    // The dedicated cells for the read-time re-sum: held on for this test's reads (the default in a debug
    // build); the guard's drop puts the default back, which the tail block reads.
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
            1,
            visits(),
            "with the guard dropped the thread is back at its default, on, so a read re-sums the one parked slice"
        );
        frames.close(&mut store, &mut merged);
    }
}

/// A name a cut emptied out of the frames is listed by the home's running total alone if the cut's
/// accounting left the total standing, and no per-name check at the close meets it (the popped frame holds
/// no slice of it: the per-name re-sum at a close, on by default in a debug build, covers the names the
/// popped frame still holds, and the cut emptied `t` out of this one). What catches it is the O(1) check
/// every debug build makes when the close pops the home's LAST frame, that the total table is empty: a
/// total planted to stand after a cut took every slice (the shape of a cut under-counting what it took)
/// trips it. A debug assertion, so the test runs only in a build that has it.
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

/// A park with no frame open trips the debug check `park` keeps before its early return: the caller has
/// already split the results off the live store, so with no frame to hold them they would be gone with no
/// signal. No evaluator path reaches it (`end_segment` returns first with no frame); the check guards a
/// caller that would. A debug assertion, so the test runs only in a build that has it.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "parked with no frame open")]
fn a_park_with_no_frame_open_trips_the_frame_check() {
    let mut frames = CaptureFrames::default();
    frames.park("t", 0, vec![a_capture_of("a")]);
}

/// A park with no frame open COUNTS nothing: the running total is read after the park and is still
/// empty, since `park` returns before the increment when no frame holds the slice (a slice dropped but
/// counted would leave a total the frames disagree with, the drift the re-sum exists to catch). In a
/// debug build the check above fires first, so the park runs under `catch_unwind` and the cell reads the
/// total afterwards, the same reading a release build gives with no panic.
#[test]
fn a_park_with_no_frame_open_counts_nothing_in_the_running_total() {
    let mut frames = CaptureFrames::default();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        frames.park("t", 0, vec![a_capture_of("a")]);
    }));
    assert_eq!(
        cfg!(debug_assertions),
        outcome.is_err(),
        "a debug build trips the frame check, a release build parks nothing and goes on"
    );
    assert_eq!(
        0,
        frames.parked_len(CaptureHome::Captured, "t"),
        "nothing was parked, so nothing is counted"
    );
}

/// A `ParkedTotalResum` guard puts back the setting it found: the thread's default is ON; an `off()` guard
/// (a measurement test's) holds it off, an `on()` guard nested inside it holds it on and at its drop puts
/// back the outer scope's OFF, not the thread's default, and the outer guard's drop puts back the default.
#[cfg(debug_assertions)]
#[test]
fn a_nested_resum_guard_restores_the_outer_scopes_setting_at_its_drop() {
    let on = || PARKED_TOTAL_RESUM.with(|on| on.get());
    assert!(on(), "on before any guard: the debug build's default");
    let outer = ParkedTotalResum::off();
    assert!(!on(), "off under the outer `off()` guard");
    {
        let _inner = ParkedTotalResum::on();
        assert!(on(), "on under the inner `on()` guard");
    }
    assert!(
        !on(),
        "the inner guard's drop puts back the outer scope's OFF, not the thread's default"
    );
    drop(outer);
    assert!(
        on(),
        "the outer guard's drop puts back the thread's default, on"
    );
}

/// A stale total under a STILL-OPEN outer frame trips the per-name re-sum at the inner frame's close while
/// a test holds the re-sum on: the inner frame holds one slice of `t`, the total is planted one higher, and
/// the inner close's cross-check of `t` (not the last-frame check, since the outer frame of the home stays
/// open) reports the disagreement. A debug assertion, so the test runs only in a build that has it.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "the running parked total of `t` and the frames disagree")]
fn a_stale_total_under_a_still_open_outer_frame_trips_the_inner_closes_re_sum() {
    let _resum = ParkedTotalResum::on();
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.park("t", 0, vec![a_capture_of("a")]);
    *frames.parked_lens[home_index(CaptureHome::Captured)]
        .get_mut("t")
        .expect("the park listed `t`") += 1;
    frames.close(&mut store, &mut merged);
}

/// A drift found at an inner frame's close panics ONCE: the outer frame's close runs during the unwind
/// (a guard's drop closes frames on the way out of a panicking test), and its checks stand aside while the
/// panic is in flight, so the process survives and the inner message is the one reported. Here the outer
/// close runs from a drop, as `CaptureFrameGuard::drop` runs it, with a stale total that both the per-name
/// re-sum (the guard is on) and the last-frame check would trip. A debug assertion, so the test runs only
/// in a build that has it.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "the running parked total of `t` and the frames disagree")]
fn a_drift_found_at_an_inner_close_panics_once_though_the_outer_frame_closes_during_the_unwind() {
    struct ClosesOnDrop<'a> {
        frames: &'a mut CaptureFrames<'static>,
        store: &'a mut CaptureStore<'static>,
        merged: &'a mut CaptureStore<'static>,
    }
    impl Drop for ClosesOnDrop<'_> {
        fn drop(&mut self) {
            self.frames.close(self.store, self.merged);
        }
    }
    let _resum = ParkedTotalResum::on();
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.park("t", 0, vec![a_capture_of("a")]);
    *frames.parked_lens[home_index(CaptureHome::Captured)]
        .get_mut("t")
        .expect("the park listed `t`") += 1;
    let closer = ClosesOnDrop {
        frames: &mut frames,
        store: &mut store,
        merged: &mut merged,
    };
    // The inner close panics on the drift; the drop of `closer` then closes the outer frame while the
    // panic unwinds, and must not panic again.
    closer.frames.close(closer.store, closer.merged);
}

/// The SHORT total: the outer frame holds a slice of two results of `t`, the inner frame one of one, and the
/// total is planted at two, short by one. The inner close takes its one result off the total (two to one,
/// a take the total covers) and then re-sums: the frames hold two, the total one, the disagreement is
/// reported. The outer frame's close then runs during the unwind and takes its two results off a total of
/// one, which reaches the "short of what is taken" check `unpark_len` keeps; it stands aside while the
/// panic is in flight, so the test panics ONCE (a second panic would abort the whole test binary). The
/// twin of the too-high plant above, for the check that plant never reaches. A debug assertion, so the
/// test runs only in a build that has it.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "the running parked total of `t` and the frames disagree")]
fn a_short_total_found_at_an_inner_close_panics_once_though_the_outer_close_takes_from_it_during_the_unwind(
) {
    struct ClosesOnDrop<'a> {
        frames: &'a mut CaptureFrames<'static>,
        store: &'a mut CaptureStore<'static>,
        merged: &'a mut CaptureStore<'static>,
    }
    impl Drop for ClosesOnDrop<'_> {
        fn drop(&mut self) {
            self.frames.close(self.store, self.merged);
        }
    }
    let _resum = ParkedTotalResum::on();
    let mut frames = CaptureFrames::default();
    let mut store: CaptureStore<'static> = HashMap::new();
    let mut merged: CaptureStore<'static> = HashMap::new();
    frames.open(CaptureHome::Captured, 0, &store, &merged, true);
    frames.park("t", 0, vec![a_capture_of("a"), a_capture_of("b")]);
    frames.open(CaptureHome::Captured, 2, &store, &merged, true);
    frames.park("t", 2, vec![a_capture_of("c")]);
    // The plant: the total reads two for the three results the frames hold.
    *frames.parked_lens[home_index(CaptureHome::Captured)]
        .get_mut("t")
        .expect("the parks listed `t`") = 2;
    let closer = ClosesOnDrop {
        frames: &mut frames,
        store: &mut store,
        merged: &mut merged,
    };
    closer.frames.close(closer.store, closer.merged);
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
    // Bare drives of the `let`s, whose filters write one record per entry: one record around each.
    // The real run resolves the let: its key `b` is captured and the result memoised.
    assert_eq!(
        1,
        root.drive_bare(|scope| scope.resolve_variable("bs"))?.len()
    );
    assert_eq!(
        1,
        root.drive_bare(|scope| scope.resolve_variable("b"))?.len(),
        "the key, as captured"
    );
    // The shape a refusal's cut and the entry's end leave for the later entries: the name gone.
    root.assignment_captures.remove("b");
    let read = root.drive_bare(|scope| scope.resolve_variable("b"))?;
    assert!(
        read.is_empty(),
        "an empty selection, not an error: {:?}",
        read
    );
    assert!(
        root.variable_is_resolved("bs"),
        "the let's own result is still memoised"
    );
    // The block scope borrows the root, so it cannot reset the recorder itself: the tracker is cleared
    // of the root's `Harness` record first, and `drive_under_a_harness_record` (what `drive_bare` runs
    // after its reset) encloses the three drives in one `Harness` record, so a `?` inside leaves no
    // record open behind the error it returns.
    let _ = root.reset_recorder();
    let block = &rules_file.guard_rules[0].block;
    let mut scope = block_scope(block, Rc::clone(&value), &mut root);
    let read = drive_under_a_harness_record(&mut scope, |scope| {
        assert_eq!(1, scope.resolve_variable("cs")?.len());
        assert_eq!(1, scope.resolve_variable("c")?.len());
        scope.captured.remove("c");
        scope.resolve_variable("c")
    })?;
    assert!(
        read.is_empty(),
        "the block's declared capture, absent: an empty selection, not an error: {:?}",
        read
    );
    Ok(())
}

/// The author's `<< >>` message a block check carries (`BlockCheck::custom_message`: a `not` over a reference
/// that failed closed, an access clause's own block-shaped record) reaches the structured report's
/// `custom_message` for every block record kind the report builder reads (`BlockGuardCheck`,
/// `GuardClauseBlockCheck`, `TypeCheck`, `WhenCheck`), beside the record's own sentence and flag; a record
/// with none reads `None`, as before. Rows "BG", "GC", "TC", "WC", one per kind, each a childless FAIL
/// record with a message, and "GC-none" the control with no author's message.
#[test]
fn a_block_checks_authors_message_reaches_the_structured_report_for_every_record_kind() {
    const AUTHORS: &str = "the author's own words on the clause";
    const SENTENCE: &str = "the record's own sentence";
    let block = |custom_message: Option<&str>| BlockCheck {
        status: Status::FAIL,
        at_least_one_matches: false,
        raised: false,
        message: Some(SENTENCE.to_string()),
        refusal: true,
        custom_message: custom_message.map(str::to_string),
        gate_mark: false,
        frame_reads: Vec::new(),
    };
    let record = |container: RecordType<'static>| EventRecord {
        context: String::from("rule/clause"),
        container: Some(container),
        children: vec![],
    };
    let messages_of = |records: &[EventRecord<'_>]| -> (Option<String>, Option<String>, bool) {
        let clauses = report_all_failed_clauses_for_rules(records);
        match clauses.as_slice() {
            [ClauseReport::Block(block)] => (
                block.messages.custom_message.clone(),
                block.messages.error_message.clone(),
                block.messages.refusal,
            ),
            other => panic!("one block report for one record, got {}", other.len()),
        }
    };
    for (label, container) in [
        ("BG", RecordType::BlockGuardCheck(block(Some(AUTHORS)))),
        (
            "GC",
            RecordType::GuardClauseBlockCheck(block(Some(AUTHORS))),
        ),
        (
            "TC",
            RecordType::TypeCheck(TypeBlockCheck {
                type_name: "AWS::S3::Bucket",
                block: block(Some(AUTHORS)),
            }),
        ),
        ("WC", RecordType::WhenCheck(block(Some(AUTHORS)))),
    ] {
        assert_eq!(
            (Some(AUTHORS.to_string()), Some(SENTENCE.to_string()), true),
            messages_of(&[record(container)]),
            "({label}) the block check's author's message, sentence and flag reach the report"
        );
    }
    assert_eq!(
        (None, Some(SENTENCE.to_string()), true),
        messages_of(&[record(RecordType::GuardClauseBlockCheck(block(None)))]),
        "(GC-none) a block check with no author's message reports none"
    );
}

/// An access clause's block record with a message is reported by the report builder unless one of the
/// clause's OWN per-value records reports (`an_own_value_check_reports`), and after its children: (i) a
/// FAILING own-context child (a dependent-rule value check under the clause's context): the block is
/// suppressed and the child reports alone; (ii) a reporting child from ANOTHER context (a `let`'s key
/// filter recorded under no clause): the child first, then the block with its author's message; (iii) a
/// named reference's record (a `not` that failed closed) holding the referenced rule's `RuleCheck`: the
/// rule's report first, then the block, the order the call spelling writes; (iv) an own-context child
/// that is a `Success` prints nothing, so the block is NOT suppressed. The clause and value contexts are
/// built by the writer's helpers (`eval::access_clause_block_context`, `eval::access_clause_value_context`),
/// never spelled here.
#[test]
fn an_access_clauses_block_report_is_suppressed_only_by_an_own_value_check_that_reports() {
    use crate::rules::exprs::{GuardClause, RuleClause, RulesFile};
    use crate::rules::{ClauseCheck, MissingValueCheck, NamedStatus};
    const AUTHORS: &str = "the author's own words on the clause";
    const SENTENCE: &str = "the record's own sentence";
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("a rules file");
    let gac = match rules_file.guard_rules[0].block.conjunctions[0][0] {
        RuleClause::Clause(GuardClause::Clause(ref gac)) => gac,
        ref other => panic!("an access clause, got {:?}", other),
    };
    let block_context = crate::rules::eval::access_clause_block_context(gac);
    let value_context = crate::rules::eval::access_clause_value_context(gac);
    let block = BlockCheck {
        status: Status::FAIL,
        at_least_one_matches: false,
        raised: false,
        message: Some(SENTENCE.to_string()),
        refusal: true,
        custom_message: Some(AUTHORS.to_string()),
        gate_mark: false,
        frame_reads: Vec::new(),
    };
    let child = |context: &str, container: RecordType<'static>| EventRecord {
        context: context.to_string(),
        container: Some(container),
        children: vec![],
    };
    let failing = |context: &str| {
        child(
            context,
            RecordType::ClauseValueCheck(ClauseCheck::DependentRule(MissingValueCheck {
                rule: "helper",
                status: Status::FAIL,
                message: None,
                custom_message: None,
                failure: None,
            })),
        )
    };
    let success = child(
        &value_context,
        RecordType::ClauseValueCheck(ClauseCheck::Success),
    );
    let rule_run = child(
        "check",
        RecordType::RuleCheck(NamedStatus {
            name: "check",
            status: Status::FAIL,
            message: None,
            slot: crate::rules::CustomSlot::Evaluator,
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        }),
    );
    /// The kinds of the reports, in order: `B` a block carrying the author's message, `C` a clause
    /// report, `R` a rule report.
    fn shape(reports: &[ClauseReport<'_>]) -> String {
        reports
            .iter()
            .map(|report| match report {
                ClauseReport::Block(block) => match block.messages.custom_message.as_deref() {
                    Some(AUTHORS) => 'B',
                    _ => 'b',
                },
                ClauseReport::Clause(_) => 'C',
                ClauseReport::Rule(_) => 'R',
                ClauseReport::Disjunctions(_) => 'D',
            })
            .collect()
    }
    for (label, context, children, expected) in [
        (
            "(i) an own-context failing child suppresses the block",
            block_context.as_str(),
            vec![failing(&value_context)],
            "C",
        ),
        (
            "(ii) a reporting child of another context: the child, then the block",
            block_context.as_str(),
            vec![failing("")],
            "CB",
        ),
        (
            "(iii) a named reference's record over the rule's run: the rule, then the block",
            "not check",
            vec![rule_run.clone()],
            "RB",
        ),
        (
            "(iv) an own-context success prints nothing and suppresses nothing",
            block_context.as_str(),
            vec![success.clone()],
            "B",
        ),
        (
            "(v) an own-context success beside a reporting child of another context: the child, then the block (a reading by the children's kind suppressed the block here)",
            block_context.as_str(),
            vec![success.clone(), failing("")],
            "CB",
        ),
    ] {
        let record = EventRecord {
            context: context.to_string(),
            container: Some(RecordType::GuardClauseBlockCheck(block.clone())),
            children,
        };
        assert_eq!(
            expected,
            shape(&report_all_failed_clauses_for_rules(std::slice::from_ref(
                &record
            ))),
            "{label}"
        );
    }
}

/// The writer's two contexts for an access clause differ by the one shared prefix the reader strips
/// (`eval::ACCESS_CLAUSE_BLOCK_CONTEXT_PREFIX`): a drift between them would make every access clause's
/// block record look like one with no per-value child, and every raised clause print its reason twice.
#[test]
fn the_access_clauses_block_and_value_contexts_differ_by_the_shared_prefix() {
    use crate::rules::exprs::{GuardClause, RuleClause, RulesFile};
    // The `let` is what makes the file evaluable below: an undeclared variable is a rules-file error,
    // and the real evaluation's `expect` would panic on it instead of writing the record this cell reads.
    let rules_file =
        RulesFile::try_from("let allowed = ['T']\nrule r { some Resources.*.Type IN %allowed }")
            .expect("a rules file");
    let gac = match rules_file.guard_rules[0].block.conjunctions[0][0] {
        RuleClause::Clause(GuardClause::Clause(ref gac)) => gac,
        ref other => panic!("an access clause, got {:?}", other),
    };
    let block_context = crate::rules::eval::access_clause_block_context(gac);
    let value_context = crate::rules::eval::access_clause_value_context(gac);
    assert_eq!(
        Some(value_context.as_str()),
        block_context.strip_prefix(crate::rules::eval::ACCESS_CLAUSE_BLOCK_CONTEXT_PREFIX),
        "the block context is the prefix and then the value context"
    );
    assert!(
        !value_context.is_empty() && !value_context.starts_with('#'),
        "the value context is the clause as written: {}",
        value_context
    );
    // The writer USES the helpers: a real evaluation's record tree holds the clause's block record under
    // the block context and, under it, a value's record under the value context; a writer spelling either
    // text by hand would drift from the reader without this read.
    let mut root = root_scope(
        &rules_file,
        Rc::new(
            PathAwareValue::try_from(r#"{ "Resources": { "R": { "Type": "T" } } }"#)
                .expect("a document"),
        ),
    );
    crate::rules::eval::eval_rules_file(&rules_file, &mut root, None).expect("an evaluation");
    let tree = root.reset_recorder().extract();
    fn find<'r>(record: &'r EventRecord<'_>, context: &str) -> Option<&'r EventRecord<'r>> {
        if record.context == context {
            return Some(record);
        }
        record
            .children
            .iter()
            .find_map(|child| find(child, context))
    }
    let block = find(&tree, &block_context)
        .expect("the clause's block record, under the writer's block context");
    assert!(
        block
            .children
            .iter()
            .any(|child| child.context == value_context),
        "a value's record under the clause's block record carries the writer's value context: {:?}",
        block
            .children
            .iter()
            .map(|child| child.context.as_str())
            .collect::<Vec<_>>()
    );
}

/// The root scope's hold machine for the in-predicate scalar-filter notice, cell by cell
/// (`pend_scalar_filter_notice`, `undecided_member_read`, `undecided_reads_decided`,
/// `held_raises_failed_closed`, and `record_unraised_refusal`'s drop of a raise decided past): (1) held,
/// confirmed by a filter-role read with the marker's own sentence, read by a clause and FAILED there: one
/// notice, and a second hold on the same token for the same site adds none (once per site); (2) a clause
/// DECIDED without the marker withdraws its read and keeps the hold confirmed, so a later reader that fails
/// writes it; (3) a raise at a clause's site is written when that site fails a rule closed, not when another
/// site does, and a nameless call writes every raise; (4) an unconfirmed hold a clause reads is dropped and
/// never written, by that clause or a later one; (5) a raise at one site is not erased by a later read at
/// another site that is then decided without the marker; (6) the refused-read line written for the raise's
/// site as decided past drops the raise, so a later fail-closed writes nothing; (7) two tokens held at one
/// site are written first-minted first, so the site keeps the first's text; (8) a filter-role read with
/// another sentence confirms nothing. A strict FAIL is settled by the rule's verdict (`held_fails_judged`):
/// written when the rule FAILs, withdrawn when it does not, and dropped by the refused-read line a
/// disjunct writes for the clause (6b), as a raise is by its fold, and the line drops the readers of the
/// holds it names alone (6c): another hold read at the same site keeps its FAIL, whether the line names
/// the hold by its reason, by the token of a registered text, or drops a raised reader (6d); two holds
/// pended at one filter site, the later minted first, write one notice, the first minted of those left
/// standing, so a line naming one of them leaves the other's text (6c, one site); (14) the count of
/// marked FAILs advances only when a call marks one. The store's bound: (9) a hold whose
/// marker no binding produced (`MarkerBinding::Clause`) stays through an unrelated cleanup, a reader
/// decided without it, a FAIL the rule passed past and a raise decided past (a later clause of the rule
/// may still read the marker), and goes at the rule boundary (`reset_captures`), while a file-level
/// assignment's hold (`RootAssignment`; rows (2) and (5), which need a second reader) outlives it; (10) a
/// second hold for one token merges into the first, keeping its confirmation and its RAISED reader for
/// the fold to write, where a replacement reset both. The rule-level settlement: (11) a nested rule's
/// judgment (`held_fails_mark`, then `held_fails_judged` since it) withdraws the FAILs marked since its
/// mark alone, so the enclosing rule's earlier FAIL is written by the enclosing rule's own FAIL; (12) a
/// FAIL whose reads do not name the hold (by sentence or by token) withdraws its FAIL and writes nothing,
/// where one that names it by token writes it. (13) the boundary reads the binding's KIND: a block
/// `let`'s hold (`BlockLet`) goes at the boundary as a clause's own does; a file-level assignment's is
/// kept and keeps no reader entry across it, so a FAIL left unsettled at the boundary is not written by
/// the next rule's judgment; a re-pend keeps the greater binding.
#[test]
fn the_held_scalar_filter_notice_is_written_only_where_its_reader_moved_the_verdict() {
    use crate::rules::errors::RefusalToken;
    use crate::rules::eval::ClauseRole;
    use crate::rules::exprs::RulesFile;
    use crate::rules::{EvalContext, UndecidedReadsDecision, UnraisedVerdict};
    const BODY: &str = "the member is now undecided (held notice";
    let at = |line: u32| FileLocation {
        line,
        column: 1,
        file_name: "rules.guard",
    };
    let (filter_site, clause_a, clause_b) = (at(5), at(10), at(20));
    let rules_file = RulesFile::try_from("rule r { Other exists }").expect("a rules file");
    let scope = || {
        root_scope(
            &rules_file,
            Rc::new(PathAwareValue::try_from(r#"{ "Other": "o" }"#).expect("a document")),
        )
    };
    let notices = |root: &RootScope<'_, '_>| -> Vec<String> {
        root.deprecations()
            .filter(|notice| notice.contains(BODY))
            .cloned()
            .collect()
    };
    // A clause's own marker (`pend`: its reader withdrawn or written; the hold goes at the rule boundary,
    // `reset_captures`), a block `let`'s (`pend_block`: the same lifetime, its readers inside the rule)
    // and a file-level assignment's (`pend_let`: kept past the boundary for the next rule's reader).
    let pend = |root: &mut RootScope<'_, '_>, token: RefusalToken, tag: &str| {
        root.pend_scalar_filter_notice(
            token,
            &filter_site,
            "R",
            format!("{BODY} {tag})"),
            crate::rules::MarkerBinding::Clause,
        );
    };
    let pend_block = |root: &mut RootScope<'_, '_>, token: RefusalToken, tag: &str| {
        root.pend_scalar_filter_notice(
            token,
            &filter_site,
            "R",
            format!("{BODY} {tag})"),
            crate::rules::MarkerBinding::BlockLet,
        );
    };
    let pend_let = |root: &mut RootScope<'_, '_>, token: RefusalToken, tag: &str| {
        root.pend_scalar_filter_notice(
            token,
            &filter_site,
            "R",
            format!("{BODY} {tag})"),
            crate::rules::MarkerBinding::RootAssignment,
        );
    };
    let confirm = |root: &mut RootScope<'_, '_>, token: RefusalToken| {
        root.undecided_member_read(token, Some("R"), ClauseRole::Filter, &filter_site);
    };
    let read = |root: &mut RootScope<'_, '_>, token: RefusalToken, site: &FileLocation<'_>| {
        root.undecided_member_read(token, Some("R"), ClauseRole::Assertion, site);
    };
    // A top-level rule's judgment over every FAIL marked in the scope (mark 0): a FAIL resting on the
    // read `R` (the holds `R` names are written), or any other verdict (the FAILs are withdrawn).
    let rests_on_r: Vec<crate::rules::RefusedRead> = vec![("R".to_string(), None)];
    let judged_fail = |root: &mut RootScope<'_, '_>| root.held_fails_judged(0, Some(&rests_on_r));
    let judged_pass = |root: &mut RootScope<'_, '_>| root.held_fails_judged(0, None);
    let t1 = RefusalToken::minted(1);
    let t2 = RefusalToken::minted(2);

    // (1) held, confirmed, read, FAILED, the rule judged FAIL: written once; once per site. A FAIL alone
    // writes nothing until the rule is judged.
    let mut root = scope();
    root.allow_repend();
    pend(&mut root, t1, "one");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    assert_eq!(0, notices(&root).len(), "(1) a FAIL waits for the rule");
    judged_fail(&mut root);
    assert_eq!(
        1,
        notices(&root).len(),
        "(1) written once: {:?}",
        notices(&root)
    );
    pend(&mut root, t1, "again");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    judged_fail(&mut root);
    assert_eq!(
        1,
        notices(&root).len(),
        "(1) once per site: {:?}",
        notices(&root)
    );
    assert!(
        notices(&root)[0].contains("one)"),
        "(1) the first text stays"
    );

    // (2) DECIDED keeps a memoized binding's hold confirmed for the next reader; so does a FAIL the rule
    // passed past.
    let mut root = scope();
    pend_let(&mut root, t1, "two");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Decided);
    judged_fail(&mut root);
    assert_eq!(
        0,
        notices(&root).len(),
        "(2) decided without the marker writes nothing"
    );
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    judged_pass(&mut root);
    assert_eq!(
        0,
        notices(&root).len(),
        "(2) a FAIL the rule passed past writes nothing"
    );
    read(&mut root, t1, &clause_b);
    root.undecided_reads_decided(&clause_b, UndecidedReadsDecision::Failed);
    judged_fail(&mut root);
    assert_eq!(
        1,
        notices(&root).len(),
        "(2) the next reader that fails writes it"
    );

    // (3) a raise is written where ITS site fails a rule closed, not where another does; a rule's FAIL
    // leaves a raise alone (its fold settles it).
    let mut root = scope();
    pend(&mut root, t1, "three");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Raised);
    root.held_raises_failed_closed(&[clause_b.to_string()]);
    judged_fail(&mut root);
    assert_eq!(
        0,
        notices(&root).len(),
        "(3) another site's fail-closed, or the rule's FAIL, writes nothing for a raise"
    );
    root.held_raises_failed_closed(&[clause_a.to_string()]);
    assert_eq!(
        1,
        notices(&root).len(),
        "(3) the raise's own site writes it"
    );

    // (4) an unconfirmed hold a clause reads is dropped.
    let mut root = scope();
    pend(&mut root, t1, "four");
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    judged_fail(&mut root);
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_b);
    root.undecided_reads_decided(&clause_b, UndecidedReadsDecision::Failed);
    judged_fail(&mut root);
    assert_eq!(
        0,
        notices(&root).len(),
        "(4) nothing confirmed it, nothing is written"
    );

    // (5) a raise at A survives a read at B decided without the marker (a memoized binding's hold, the
    // one shape with two readers).
    let mut root = scope();
    pend_let(&mut root, t1, "five");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Raised);
    read(&mut root, t1, &clause_b);
    root.undecided_reads_decided(&clause_b, UndecidedReadsDecision::Decided);
    root.held_raises_failed_closed(&[clause_a.to_string()]);
    assert_eq!(
        1,
        notices(&root).len(),
        "(5) the raise at A is kept past B's read"
    );

    // (6) the decided-past line for the raise's site drops the raise.
    let mut root = scope();
    pend(&mut root, t1, "six");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Raised);
    root.record_unraised_refusal(
        &clause_a,
        "Other exists",
        UnraisedVerdict::DecidedBySiblingClause,
        &["R".to_string()],
    );
    root.held_raises_failed_closed(&[clause_a.to_string()]);
    assert_eq!(
        0,
        notices(&root).len(),
        "(6) a raise decided past writes nothing"
    );
    // (6b) the same line for a strict FAIL a disjunct passed past.
    let mut root = scope();
    pend(&mut root, t1, "six-b");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    root.record_unraised_refusal(
        &clause_a,
        "Other exists",
        UnraisedVerdict::PassedBySiblingClause,
        &["R".to_string()],
    );
    judged_fail(&mut root);
    assert_eq!(
        0,
        notices(&root).len(),
        "(6b) a FAIL decided past writes nothing when the rule fails on something else"
    );

    // (6c) two filter sites, one reading clause (two holds, each pended at a filter site of its own and
    // read by the one clause `clause_a`, each with its own marker):
    // the refused-read line written for one hold's read drops THAT hold's reader alone, so the other
    // hold's FAIL is still written when the rule fails on it, whichever hold the line names (the same
    // document in both orders). The two holds are pended at sites of their own, so each FAIL that is
    // written is a notice of its own. Before the narrowing there is no notice in both orders
    // (the line having dropped both readers), and a line that drops no reader gives two notices.
    let rests_on_both: Vec<crate::rules::RefusedRead> =
        vec![("R1".to_string(), None), ("R2".to_string(), None)];
    for (decided_past, written_tag) in [("R2", "h1)"), ("R1", "h2)")] {
        let mut root = scope();
        for (index, (token, reason, tag)) in [(t1, "R1", "h1"), (t2, "R2", "h2")]
            .iter()
            .copied()
            .enumerate()
        {
            // Each hold at a site of its own (a notice is kept once per site), so a hold that is wrongly
            // kept or wrongly dropped changes how many notices are written, not only which text.
            let hold_site = at(5 + index as u32);
            root.pend_scalar_filter_notice(
                token,
                &hold_site,
                reason,
                format!("{BODY} {tag})"),
                crate::rules::MarkerBinding::Clause,
            );
            root.undecided_member_read(token, Some(reason), ClauseRole::Filter, &hold_site);
            root.undecided_member_read(token, Some(reason), ClauseRole::Assertion, &clause_a);
        }
        root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
        root.record_unraised_refusal(
            &clause_a,
            "Other exists",
            UnraisedVerdict::PassedBySiblingClause,
            &[decided_past.to_string()],
        );
        root.held_fails_judged(0, Some(&rests_on_both));
        let written = notices(&root);
        assert_eq!(
            1,
            written.len(),
            "(6c) the hold the line did not name is written (line names {decided_past}): {written:?}"
        );
        assert!(
            written[0].contains(written_tag),
            "(6c) the other hold's text (line names {}): {:?}",
            decided_past,
            written
        );
    }

    // (6c, one site) the production shape: both holds pended at the SAME filter site (one clause run over
    // two resources, the site being the filter's). A notice is kept once per (kind, site), so the FAILs
    // left standing write ONE notice, the first minted of them. The later-minted hold (t2) is pended
    // FIRST, so a store that kept the first pended would write `h2` where the first minted writes `h1`.
    // The rows: the line naming neither hold (both readers stand: `h1`), naming R1 (its reader is
    // dropped, only R2's stands: `h2`) and naming R2 (only R1's stands: `h1`), so the narrowing is read
    // at a site the two holds share. Red when the store keeps a notice per hold
    // (two notices), when the first pended is the one kept (`h2` on the first row), when a line drops
    // both readers (no notice on the second and third rows), and when a line drops no reader (`h1` on
    // the second row).
    let one_site = at(5);
    for (decided_past, written_tag) in [(None, "h1)"), (Some("R1"), "h2)"), (Some("R2"), "h1)")] {
        let mut root = scope();
        for (token, reason, tag) in [(t2, "R2", "h2"), (t1, "R1", "h1")] {
            root.pend_scalar_filter_notice(
                token,
                &one_site,
                reason,
                format!("{BODY} {tag})"),
                crate::rules::MarkerBinding::Clause,
            );
            root.undecided_member_read(token, Some(reason), ClauseRole::Filter, &one_site);
            root.undecided_member_read(token, Some(reason), ClauseRole::Assertion, &clause_a);
        }
        root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
        if let Some(named) = decided_past {
            root.record_unraised_refusal(
                &clause_a,
                "Other exists",
                UnraisedVerdict::PassedBySiblingClause,
                &[named.to_string()],
            );
        }
        root.held_fails_judged(0, Some(&rests_on_both));
        let written = notices(&root);
        assert_eq!(
            1,
            written.len(),
            "(6c, one site) one notice for one site (line names {decided_past:?}): {written:?}"
        );
        assert!(
            written[0].contains(written_tag),
            "(6c, one site) the hold written (line names {:?}): {:?}",
            decided_past,
            written
        );
    }

    // (6d) the same two holds as (6c) with the line named the other ways: by a REGISTERED text that does not
    // contain either hold's reason but is the sentence its hold's token was minted for (the narrowing
    // then reads the text's registered token), and with the readers RAISED rather than FAILED, ended by
    // the fail-closed write of the raise's site rather than by the rule's judgment. Each row drops the
    // named hold's reader alone, so the other hold's notice is the one written. The holds are pended at
    // sites of their own, as in (6c), so a notice is written per hold left standing. Before the
    // token path the by-token rows give two notices (neither hold named, so neither reader
    // dropped), and before the narrowing every row gives no notice.
    const WRAPS: [&str; 2] = [
        "the wrap around the first refused read",
        "the wrap around the second refused read",
    ];
    // (the readers are raised, the line names the hold by its token, the index of the hold named)
    let rows: [(bool, bool, usize); 6] = [
        (false, true, 0),
        (false, true, 1),
        (true, false, 0),
        (true, false, 1),
        (true, true, 0),
        (true, true, 1),
    ];
    for (raised, by_token, named) in rows {
        let mut root = scope();
        let tokens = if by_token {
            [register_refusal(WRAPS[0]), register_refusal(WRAPS[1])]
        } else {
            [t1, t2]
        };
        for (index, (token, reason)) in tokens.iter().copied().zip(["R1", "R2"]).enumerate() {
            // Each hold at a site of its own, as in (6c).
            let hold_site = at(5 + index as u32);
            root.pend_scalar_filter_notice(
                token,
                &hold_site,
                reason,
                format!("{BODY} h{})", index + 1),
                crate::rules::MarkerBinding::Clause,
            );
            root.undecided_member_read(token, Some(reason), ClauseRole::Filter, &hold_site);
            root.undecided_member_read(token, Some(reason), ClauseRole::Assertion, &clause_a);
        }
        let line = if by_token {
            WRAPS[named].to_string()
        } else {
            ["R1", "R2"][named].to_string()
        };
        if raised {
            root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Raised);
            root.record_unraised_refusal(
                &clause_a,
                "Other exists",
                UnraisedVerdict::DecidedBySiblingClause,
                &[line],
            );
            root.held_raises_failed_closed(&[clause_a.to_string()]);
        } else {
            root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
            root.record_unraised_refusal(
                &clause_a,
                "Other exists",
                UnraisedVerdict::PassedBySiblingClause,
                &[line],
            );
            root.held_fails_judged(0, Some(&rests_on_both));
        }
        let written = notices(&root);
        let other_tag = format!("h{})", 2 - named);
        assert_eq!(
            1,
            written.len(),
            "(6d) only the hold the line did not name is written (raised {raised}, by token {by_token}, \
             hold named {named}): {written:?}"
        );
        assert!(
            written[0].contains(&other_tag),
            "(6d) the other hold's text (raised {}, by token {}, hold named {}): {:?}",
            raised,
            by_token,
            named,
            written
        );
    }

    // (7) two tokens at one site: first-minted first.
    let mut root = scope();
    pend(&mut root, t2, "second");
    pend(&mut root, t1, "first");
    confirm(&mut root, t1);
    confirm(&mut root, t2);
    read(&mut root, t1, &clause_a);
    read(&mut root, t2, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    judged_fail(&mut root);
    let written = notices(&root);
    assert_eq!(1, written.len(), "(7) one notice at the site: {written:?}");
    assert!(
        written[0].contains("first)"),
        "(7) the first-minted text: {:?}",
        written
    );

    // (8) a filter-role read with another sentence confirms nothing.
    let mut root = scope();
    pend(&mut root, t1, "eight");
    root.undecided_member_read(t1, Some("not R"), ClauseRole::Filter, &filter_site);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    judged_fail(&mut root);
    assert_eq!(
        0,
        notices(&root).len(),
        "(8) another sentence confirms nothing"
    );

    // (9) the store's bound is the RULE boundary (`reset_captures`): a clause's own hold stays through
    // an unrelated cleanup before its first outer read, through a reader decided without it, a FAIL the
    // rule passed past and a raise decided past (a later clause of the rule may read the marker through a
    // capture or a call's argument), and goes at the rule's end; a file-level assignment's hold outlives
    // the boundary.
    let mut root = scope();
    pend(&mut root, t1, "nine");
    confirm(&mut root, t1);
    root.record_unraised_refusal(
        &clause_b,
        "Other exists",
        UnraisedVerdict::DecidedBySiblingClause,
        &["Q".to_string()],
    );
    judged_pass(&mut root);
    assert_eq!(
        1,
        root.held_scalar_filter_notices(),
        "(9) a confirmed, unread hold waits for its reader through an unrelated cleanup"
    );
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Decided);
    assert_eq!(
        1,
        root.held_scalar_filter_notices(),
        "(9) a reader decided without the marker leaves the hold for a later reader"
    );
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    judged_pass(&mut root);
    assert_eq!(
        1,
        root.held_scalar_filter_notices(),
        "(9) a FAIL the rule passed past leaves the hold"
    );
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Raised);
    root.record_unraised_refusal(
        &clause_a,
        "Other exists",
        UnraisedVerdict::DecidedBySiblingClause,
        &["R".to_string()],
    );
    assert_eq!(
        1,
        root.held_scalar_filter_notices(),
        "(9) a raise decided past leaves the hold"
    );
    root.reset_captures();
    assert_eq!(
        (0, 0),
        (root.held_scalar_filter_notices(), notices(&root).len()),
        "(9) the rule's end drops a clause's own hold; nothing was written"
    );
    let mut root = scope();
    pend_let(&mut root, t1, "nine-let");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Decided);
    root.reset_captures();
    assert_eq!(
        1,
        root.held_scalar_filter_notices(),
        "(9) a file-level assignment's hold outlives the rule boundary for the next rule's reader"
    );
    assert_eq!(0, notices(&root).len(), "(9) nothing was written");

    // (10) a re-pend of one token merges: the confirmation and the RAISED reader at A are kept, so the
    // fold around A writes it; replaced whole, the hold read unconfirmed and the fold found no raise.
    let mut root = scope();
    root.allow_repend();
    pend(&mut root, t1, "ten");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Raised);
    pend(&mut root, t1, "ten again");
    assert_eq!(
        1,
        root.held_scalar_filter_notices(),
        "(10) one hold per token"
    );
    root.held_raises_failed_closed(&[clause_a.to_string()]);
    let written = notices(&root);
    assert_eq!(
        1,
        written.len(),
        "(10) the raise survived the re-pend and is written: {written:?}"
    );
    assert!(
        written[0].contains("ten again)"),
        "(10) the later notice text is the one written: {:?}",
        written
    );
    assert_eq!(
        0,
        root.held_scalar_filter_notices(),
        "(10) written and dropped"
    );

    // (11) a nested rule's judgment settles the FAILs marked since ITS mark alone: the enclosing rule's
    // FAIL at A, marked before the nested rule opened, survives the nested rule's pass and is written when
    // the enclosing rule's FAIL rests on the read.
    let mut root = scope();
    pend_let(&mut root, t1, "eleven");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    let nested = root.held_fails_mark();
    read(&mut root, t1, &clause_b);
    root.undecided_reads_decided(&clause_b, UndecidedReadsDecision::Failed);
    root.held_fails_judged(nested, None);
    assert_eq!(
        0,
        notices(&root).len(),
        "(11) the nested pass withdraws B and writes nothing"
    );
    judged_fail(&mut root);
    assert_eq!(
        1,
        notices(&root).len(),
        "(11) A's FAIL, marked before the nested rule, is written by the enclosing rule"
    );

    // (12) a FAIL that rests on OTHER reads moved nothing for this hold: withdrawn; the hold goes at the
    // rule boundary (`reset_captures`).
    let mut root = scope();
    pend(&mut root, t1, "twelve");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    let other: Vec<crate::rules::RefusedRead> = vec![("another read".to_string(), None)];
    root.held_fails_judged(0, Some(&other));
    assert_eq!(
        (0, 1),
        (notices(&root).len(), root.held_scalar_filter_notices()),
        "(12) a FAIL resting on other reads writes nothing and withdraws the FAIL; the hold waits for the rule's end"
    );
    root.reset_captures();
    assert_eq!(
        0,
        root.held_scalar_filter_notices(),
        "(12) the rule's end drops it"
    );
    // The same FAIL naming the hold by its TOKEN writes it.
    let mut root = scope();
    pend(&mut root, t1, "twelve-token");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    let by_token: Vec<crate::rules::RefusedRead> = vec![("another read".to_string(), Some(t1))];
    root.held_fails_judged(0, Some(&by_token));
    assert_eq!(
        1,
        notices(&root).len(),
        "(12) a read carrying the hold's token names it"
    );

    // (13) the boundary reads the binding's KIND: a block `let`'s hold (a rule body's, a type block's
    // per-resource, a called rule's body's) has every reader inside its rule and goes at the boundary as
    // a clause's own does, where a flag read as "any binding" kept a type block's N holds alive to the
    // scope's end; a file-level assignment's hold is kept, and keeps NO reader entry across the
    // boundary, so a FAIL a rule left unsettled at a shared site is not written by the next rule's
    // judgment. A re-pend keeps the greater binding.
    let mut root = scope();
    pend_block(&mut root, t1, "thirteen-block");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Decided);
    root.reset_captures();
    assert_eq!(
        (0, 0),
        (root.held_scalar_filter_notices(), notices(&root).len()),
        "(13) a block `let`'s hold goes at the rule boundary; nothing was written"
    );
    let mut root = scope();
    pend_let(&mut root, t1, "thirteen-root");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    root.reset_captures();
    assert_eq!(
        1,
        root.held_scalar_filter_notices(),
        "(13) a file-level assignment's hold is kept past the boundary"
    );
    judged_fail(&mut root);
    assert_eq!(
        (0, 1),
        (notices(&root).len(), root.held_scalar_filter_notices()),
        "(13) the FAIL left unsettled at the boundary is not carried into the next rule's judgment: nothing written, the hold confirmed for a reader"
    );
    read(&mut root, t1, &clause_b);
    root.undecided_reads_decided(&clause_b, UndecidedReadsDecision::Failed);
    judged_fail(&mut root);
    assert_eq!(
        1,
        notices(&root).len(),
        "(13) the next rule's own FAIL on the kept hold is written"
    );
    let mut root = scope();
    root.allow_repend();
    pend_block(&mut root, t1, "thirteen-merge");
    pend_let(&mut root, t1, "thirteen-merge again");
    confirm(&mut root, t1);
    root.reset_captures();
    assert_eq!(
        1,
        root.held_scalar_filter_notices(),
        "(13) a re-pend keeps the greater binding: the hold outlives the boundary"
    );

    // (14) the FAIL count advances once, on the first FAIL a call actually marks: a Failed decision at a
    // site where no hold has a `Read` entry marks nothing and leaves the count alone, while a store that
    // holds a reader elsewhere is walked. A count that moves on the call that marks nothing, or
    // by the number of FAILs a call marks instead of by one, fails here.
    // TWO holds are read at `clause_a`, so one Failed call marks two FAILs: the count advances once for
    // the call (`+1 per call that marks`), not once per FAIL marked (`+2`), which a single hold cannot
    // tell apart.
    let mut root = scope();
    pend(&mut root, t1, "fourteen");
    confirm(&mut root, t1);
    read(&mut root, t1, &clause_a);
    pend(&mut root, t2, "fourteen, a second hold");
    confirm(&mut root, t2);
    read(&mut root, t2, &clause_a);
    let before = root.held_fails_mark();
    root.undecided_reads_decided(&clause_b, UndecidedReadsDecision::Failed);
    assert_eq!(
        before,
        root.held_fails_mark(),
        "(14) a FAIL decided where no hold is read marks nothing"
    );
    root.undecided_reads_decided(&clause_a, UndecidedReadsDecision::Failed);
    assert_eq!(
        before + 1,
        root.held_fails_mark(),
        "(14) one call that marks two FAILs advances the count once"
    );
}

/// A unary report keeps the kind of the record it was built from (`ValueCheck::refusal`) and, for a
/// refusal's record, bounds what its sentence quotes from the template, as the comparison reports do. A
/// refused read recorded over an unresolved value prints the value the query traversed to into its
/// sentence cut at the template-part bound with the marker, the refusal whole beside it, and the report
/// is the refusal the record says it is, so the console prints the sentence whole with its remedy; it
/// used to be written as no refusal whatever the record said, the value unbounded, and the console cut
/// the sentence at `LONGEST_RECORDED_MESSAGE` with the remedy among what was cut. A refused read over a
/// resolved value names the value's path, which a key of three thousand characters used to print whole;
/// now the path is cut and marked too. The composed sentence is no member of the registry, which holds
/// the exact texts the producers registered: a text that contains a registered refusal is not one.
#[test]
fn a_unary_report_keeps_the_records_kind_and_bounds_what_it_quotes() -> Result<()> {
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

    const CUT_MARKER: &str = " more characters cut]";

    let over_a_value = report_of(&[record(QueryResult::UnResolved(UnResolved {
        traversed_to: Rc::clone(&traversed),
        remaining_query: String::from("Value"),
        reason: None,
        kind: UnResolvedKind::Absent,
    }))]);
    let sentence = over_a_value.error_message.clone().unwrap_or_default();
    assert_eq!(
        (true, true, false, true, true),
        (
            sentence.contains("property [Value] is missing. Value traversed to [Path="),
            sentence.contains(&refusal_text),
            sentence.contains(&value),
            sentence.contains(CUT_MARKER),
            sentence.chars().count() < 4096,
        ),
        "the sentence names the missing key, carries the refusal whole and the traversed value cut and \
         marked, under the whole-line bound: {sentence}"
    );
    assert!(
        over_a_value.refusal,
        "the report keeps the record's kind over a traversed value: the value is bounded, so the console \
         prints the sentence whole with the refusal's remedy"
    );
    assert!(
        !is_refusal(&Error::Unevaluatable(sentence.clone())),
        "a text that contains a registered refusal is not a member of the registry"
    );

    let over_a_path = report_of(&[record(QueryResult::Resolved(Rc::clone(&traversed)))]);
    let sentence = over_a_path.error_message.clone().unwrap_or_default();
    assert_eq!(
        (false, true, false),
        (
            sentence.contains(&value),
            sentence.contains(&refusal_text),
            sentence.contains(CUT_MARKER),
        ),
        "the sentence names a short path whole and the refusal, and no value: {sentence}"
    );
    assert!(
        over_a_path.refusal,
        "a sentence that interpolates a path keeps the record's kind"
    );

    // The control for the resolved arm's bound: a value whose path holds a key of three thousand
    // characters, which the sentence used to quote whole inside a refusal printed whole.
    let long_key = "k".repeat(3000);
    let under_a_long_key = Rc::new(PathAwareValue::Int((
        Path::new(format!("/Resources/{long_key}"), 1, 1),
        1,
    )));
    let over_a_long_path = report_of(&[record(QueryResult::Resolved(under_a_long_key))]);
    let sentence = over_a_long_path.error_message.clone().unwrap_or_default();
    // A path is cut in its MIDDLE (`template_path`: the head keeps the top of the document, the tail the
    // leaf segment), so the kept `k`s stand in two runs around the marker, their count the bound less
    // the `/Resources/` head; an end cut kept them in one run.
    let kept_path = sentence
        .split("/Resources/")
        .nth(1)
        .and_then(|rest| rest.split("[L:1,C:1]").next())
        .unwrap_or_default();
    assert_eq!(
        (false, true, true, true, true),
        (
            sentence.contains(&long_key),
            kept_path.matches('k').count() == LONGEST_TEMPLATE_PART_IN_A_REFUSAL - 11
                && kept_path.starts_with('k')
                && kept_path.ends_with('k')
                && kept_path.contains(CUT_MARKER),
            sentence.contains(CUT_MARKER),
            sentence.contains(&refusal_text),
            sentence.chars().count() < 4096,
        ),
        "the long key's path is cut at the template-part bound and marked, the refusal whole beside it, \
         under the whole-line bound: {sentence}"
    );
    assert!(
        over_a_long_path.refusal,
        "the record's kind is kept over the bounded path"
    );
    Ok(())
}

/// The sentence the comparison report writes for an unresolved right-hand operand reads the OPERAND
/// (`names_a_refused_read`: the marker's kind, `UnResolvedKind::is_refusal`), as the left-hand arm does,
/// and not the record's `refusal` flag. A right-hand value the evaluator REFUSED to read prints "the value
/// to compare to could not be read" with the refusal's text and no traversed value, keeps the record's
/// kind and stays under the whole-line bound. The control, an absent right-hand value with no refusal
/// beside it, keeps the released rendering: `property [<remaining query>] to compare to is missing. Value
/// traversed to [<value>]`, the key named and the value quoted whole, with no marker. (The only writer of
/// an unresolved right-hand operand sets the flag from that operand's own kind, so the two readings agree
/// on every record written today; the operand is read so the sentence cannot depend on how a writer sets
/// the flag.)
#[test]
fn a_comparison_report_names_a_refused_right_hand_read_as_unread() -> Result<()> {
    const THE_MISSING_TO: &str =
        "property [Missing] to compare to is missing. Value traversed to [Path=";
    const COULD_NOT_BE_READ: &str = "the value to compare to could not be read";
    const CUT_MARKER: &str = " more characters cut]";
    let refusal_text = String::from(
        "`[*]` then the filter read one object that has no `Sid`, the key the predicate compares, and kept nothing; refused in both polarities",
    );
    let value = "v".repeat(2048);
    let properties = Rc::new(PathAwareValue::try_from(
        format!("{{ A: 1, Pad: '{value}' }}").as_str(),
    )?);
    let left = Rc::new(PathAwareValue::Int((
        Path::new(String::from("/Resources/R/Properties/A"), 1, 1),
        1,
    )));
    let record = |to: UnResolved, message: Option<String>, refusal: bool| EventRecord {
        context: String::from("Resources.R.Properties.A != Resources.R.Properties.Missing"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(
            ComparisonClauseCheck {
                comparison: (CmpOperator::Eq, true),
                from: QueryResult::Resolved(Rc::clone(&left)),
                to: Some(QueryResult::UnResolved(to)),
                message,
                custom_message: None,
                status: Status::FAIL,
                refusal,
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
    // A right-hand value the evaluator refused to read: the marker's kind says so.
    let refused = report_of(&[record(
        UnResolved {
            traversed_to: Rc::clone(&properties),
            remaining_query: String::new(),
            reason: Some(refusal_text.clone()),
            kind: UnResolvedKind::Undecidable {
                refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                carried: None,
            },
        },
        Some(refusal_text.clone()),
        true,
    )]);
    let sentence = refused.error_message.clone().unwrap_or_default();
    assert_eq!(
        (true, false, true, false, true),
        (
            sentence.contains(COULD_NOT_BE_READ),
            sentence.contains("to compare to is missing"),
            sentence.contains(&refusal_text),
            sentence.contains(&value),
            sentence.chars().count() < 4096,
        ),
        "a refused right-hand read is named as one, with the refusal and no traversed value: {sentence}"
    );
    assert!(refused.refusal, "the record's kind is kept");

    // The control: an absent right-hand value with no refusal beside it, as released.
    let plain = report_of(&[record(
        UnResolved {
            traversed_to: Rc::clone(&properties),
            remaining_query: String::from("Missing"),
            reason: None,
            kind: UnResolvedKind::Absent,
        },
        None,
        false,
    )]);
    let sentence = plain.error_message.clone().unwrap_or_default();
    assert_eq!(
        (true, false, true, false),
        (
            sentence.contains(THE_MISSING_TO),
            sentence.contains(COULD_NOT_BE_READ),
            sentence.contains(&value),
            sentence.contains(CUT_MARKER),
        ),
        "an absent key with no refusal beside it keeps the released sentence, the value whole: {sentence}"
    );
    assert!(!plain.refusal, "no refusal, as recorded");
    Ok(())
}

/// A refusal's report sentence ESCAPES what it quotes from the template and bounds the PRINTED form
/// (`bounded_value_for_refusal` through `template_part`): the console writes the sentence as it
/// is, so a value of 256 bidi overrides, cut by source characters, printed every one of them raw at eight
/// times the bound, and the four values a comparison's sentence can quote passed the whole-line bound
/// again. Now each bidi override prints as its escape, each quoted value stops at the bound on an escape
/// boundary with the marker counting the source characters left out (the two string values here each
/// print the opening quote and 31 escapes, 249 characters, and leave 226 out), no raw override reaches the
/// sentence, and the sentence stays under the whole-line bound. The control, the same record as no
/// refusal, keeps the released unbounded rendering with the overrides as they are.
#[test]
fn a_refusals_report_sentence_escapes_and_bounds_what_it_prints() -> Result<()> {
    let bidi = "\u{202e}".repeat(LONGEST_TEMPLATE_PART_IN_A_REFUSAL);
    let value = Rc::new(PathAwareValue::String((
        Path::new(String::from("/Resources/R/Properties/Tags/Env"), 1, 1),
        bidi.clone(),
    )));
    let record = |refusal: bool| EventRecord {
        context: String::from("Resources.R.Properties.Tags.Env != Resources.R.Properties.Tags.Env"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(
            ComparisonClauseCheck {
                comparison: (CmpOperator::Eq, true),
                from: QueryResult::Resolved(Rc::clone(&value)),
                to: Some(QueryResult::Resolved(Rc::clone(&value))),
                message: Some(String::from("refused")),
                custom_message: None,
                status: Status::FAIL,
                refusal,
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
    let sentence = report_of(&[record(true)]).error_message.unwrap_or_default();
    assert_eq!(
        (false, 62, 2, true),
        (
            sentence.contains('\u{202e}'),
            sentence.matches("\\u{202e}").count(),
            sentence.matches("...[226 more characters cut]").count(),
            sentence.chars().count() < 4096,
        ),
        "each quoted value prints its overrides escaped, 31 of them, and the count left out; no raw \
         override; under the whole-line bound: {sentence:?}"
    );
    let released = report_of(&[record(false)])
        .error_message
        .unwrap_or_default();
    assert_eq!(
        (true, 0),
        (
            released.contains(&bidi),
            released.matches("more characters cut]").count(),
        ),
        "a record that is no refusal keeps the unbounded rendering, as released"
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

/// The announced-capture set holds a reason only where its warning was recorded. `refuse_unbound_capture`
/// keys the reason it refuses with into the root's set (`EvalContext::announced_capture_refusals`). That
/// set is read by the refused-read line `RootScope::record_unraised_refusal` writes for a comparison
/// (`eval::judged_binary_operation`). A reason is keyed only when `announce_unbound_capture` reached a
/// scope that wrote the warning (`record_capture_warning` says so), so the line leaves a refusal off
/// exactly where the warning channel names it. Over `Rules[0][ r | Action == 'allow' ]` at a scalar: a root evaluating
/// (measurement off) records one warning and the set holds the reason; the same shape under a `Quiet`
/// measurement records nothing and the set stays empty; a `QuietScope` over a root, whose
/// `record_capture_warning` drops the line, leaves the set empty too. Before, the set was filled whatever
/// the scope did with the line, so a refusal first met under a probe or a measurement was keyed as
/// announced with no line anywhere, and a decided clause that met its marker named it nowhere. No
/// evaluation-level cell exists for that omission: every memo a quiet probe or a measured reading writes is
/// taken back before the real run reads it (`ReadingUndo`, `DocumentBindingMemo`), so no rules file and
/// template reach a decided clause holding a marker whose refusal was keyed under a probe alone, and this
/// unit cell pins the invariant the refused-read line rests on instead.
#[test]
fn a_capture_refusal_is_in_the_announced_set_only_where_its_warning_was_recorded() -> Result<()> {
    let rules_file = RulesFile::try_from("rule r { Rules[0][ r | Action == 'allow' ] !empty }")?;
    let access = AccessQuery::try_from("Rules[0][ r | Action == 'allow' ]")?;
    let query = access.query.as_slice();
    // The filter is found by its kind, not by position: `Rules[0]` parses as a key and an index part
    // before the filter, and the index was once folded into the key.
    let conjunctions = query
        .iter()
        .find_map(|part| match part {
            QueryPart::Filter(_, conjunctions) => Some(conjunctions),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the query holds a filter part, got {:?}", query));
    let current = Rc::new(PathAwareValue::try_from("{ a: 1 }")?);
    let reason = capture_not_bound_reason("r", CaptureSite::OneValue, 1, query, &current);
    let announced_in = |root: &RootScope<'_, '_>| -> (bool, usize) {
        let set = root
            .announced_capture_refusals()
            .expect("a root scope owns the announced set");
        let keyed = set.borrow().contains(&reason);
        (keyed, root.warnings().count())
    };

    // Evaluating: the line is recorded, the reason keyed as announced.
    let mut evaluating = root_scope(&rules_file, Rc::clone(&current));
    refuse_unbound_capture(
        CaptureSite::OneValue,
        "r",
        conjunctions,
        1,
        query,
        &current,
        &mut evaluating,
        true,
    )?;
    assert_eq!(
        (true, 1),
        announced_in(&evaluating),
        "evaluating: the reason is keyed as announced and one warning stands"
    );

    // Under a measurement: nothing is recorded, so the reason is not keyed as announced.
    let mut measured = root_scope(&rules_file, Rc::clone(&current));
    measured.set_measurement(Measurement::Quiet);
    refuse_unbound_capture(
        CaptureSite::OneValue,
        "r",
        conjunctions,
        1,
        query,
        &current,
        &mut measured,
        true,
    )?;
    assert_eq!(
        (false, 0),
        announced_in(&measured),
        "under a measurement: no warning stands, so the reason is not keyed as announced"
    );

    // From a quiet probe: the scope drops the line, so the reason is not keyed as announced.
    let mut probed = root_scope(&rules_file, Rc::clone(&current));
    {
        let mut quiet = QuietScope {
            root: Rc::clone(&current),
            parent: &mut probed,
            grounded: false,
            takes_the_fallback: false,
            cache: None,
        };
        refuse_unbound_capture(
            CaptureSite::OneValue,
            "r",
            conjunctions,
            1,
            query,
            &current,
            &mut quiet,
            true,
        )?;
    }
    assert_eq!(
        (false, 0),
        announced_in(&probed),
        "from a quiet probe: no warning stands, so the reason is not keyed as announced"
    );

    // Outside a filter predicate's query (`in_predicate` false) the refusal is the clause's error, and the
    // same three scopes key the reason as announced exactly where their warning was recorded: the line the
    // refused-read writer would add for this reason is left off only where a warning names it.
    let mut evaluating_outside = root_scope(&rules_file, Rc::clone(&current));
    let refused = refuse_unbound_capture(
        CaptureSite::OneValue,
        "r",
        conjunctions,
        1,
        query,
        &current,
        &mut evaluating_outside,
        false,
    );
    assert!(
        refused.is_err(),
        "outside a predicate the refusal is raised"
    );
    assert_eq!(
        (true, 1),
        announced_in(&evaluating_outside),
        "evaluating, outside a predicate: the reason is keyed as announced and one warning stands"
    );

    let mut measured_outside = root_scope(&rules_file, Rc::clone(&current));
    measured_outside.set_measurement(Measurement::Quiet);
    let refused = refuse_unbound_capture(
        CaptureSite::OneValue,
        "r",
        conjunctions,
        1,
        query,
        &current,
        &mut measured_outside,
        false,
    );
    assert!(
        refused.is_err(),
        "outside a predicate the refusal is raised"
    );
    assert_eq!(
        (false, 0),
        announced_in(&measured_outside),
        "under a measurement, outside a predicate: no warning stands, so the reason is not keyed"
    );

    let mut probed_outside = root_scope(&rules_file, Rc::clone(&current));
    {
        let mut quiet = QuietScope {
            root: Rc::clone(&current),
            parent: &mut probed_outside,
            grounded: false,
            takes_the_fallback: false,
            cache: None,
        };
        let refused = refuse_unbound_capture(
            CaptureSite::OneValue,
            "r",
            conjunctions,
            1,
            query,
            &current,
            &mut quiet,
            false,
        );
        assert!(
            refused.is_err(),
            "outside a predicate the refusal is raised"
        );
    }
    assert_eq!(
        (false, 0),
        announced_in(&probed_outside),
        "from a quiet probe, outside a predicate: no warning stands, so the reason is not keyed"
    );
    Ok(())
}

/// The test that keeps a capture's refusal off the refused-read line (`is_capture_not_bound_reason`) reads
/// the one builder's text (`capture_not_bound_reason`) round trip, and reads a text that holds one of its
/// phrases alone, or the phrases out of order, as not that reason: the two are one text in two places.
#[test]
fn the_capture_reason_test_reads_the_builders_text_round_trip() -> Result<()> {
    let query = AccessQuery::try_from("Rules[0][ r | Action == 'allow' ]")?.query;
    let current = PathAwareValue::try_from("{ a: 1 }")?;
    let reason = capture_not_bound_reason("r", CaptureSite::OneValue, 1, &query, &current);
    assert!(
        is_capture_not_bound_reason(&reason),
        "the builder's own text is read as the capture's reason: {}",
        reason
    );
    let this_site = capture_not_bound_reason("r", CaptureSite::This, 0, &query, &current);
    assert!(
        is_capture_not_bound_reason(&this_site),
        "the `this` site's text too: {}",
        this_site
    );
    for (label, text) in [
        (
            "the opening phrase alone",
            "Query Rules[0] declares the capture `r` after this",
        ),
        (
            "the closing phrase alone",
            "a key named x; a capture is bound by a filter over a named collection, or over a list",
        ),
        (
            "the phrases out of order",
            "a capture is bound by a filter over a named collection, or over a list; Query Rules[0] declares the capture `r`",
        ),
        ("another refusal's sentence", "`[*]` handed the map at path /Resources on as one object"),
    ] {
        assert!(
            !is_capture_not_bound_reason(text),
            "{} is not the capture's reason: {}",
            label,
            text
        );
    }
    Ok(())
}

/// The value a refusal's record quotes (`bounded_value_for_refusal`) renders its PATH as every refusal renders
/// a path (`template_path`: a backslash as written, controls as their escapes, the location appended
/// whole) and its VALUE as a quoted template part (`template_part`: the backslash doubled, as a quoted key
/// is): a path segment `a\b` prints `a\b` here and in the refusal's own path sentence alike, where the
/// part rule printed it `a\\b` in one place and `a\b` in the other, and a value holding a line feed and a
/// backslash prints `x\ny\\z` once-escaped. The location rides on the path, as `Path`'s `Display` carries
/// it.
#[test]
fn a_refusals_quoted_value_renders_its_path_as_a_path_and_its_value_as_a_part() {
    let value = PathAwareValue::String((
        Path::new("/Cfg/a\\b".to_string(), 3, 9),
        "x\ny\\z".to_string(),
    ));
    let rendered = bounded_value_for_refusal(&value);
    assert_eq!(
        rendered, "Path=/Cfg/a\\b[L:3,C:9] Value=\"x\\ny\\\\z\"",
        "the path keeps its one backslash and its location, the value is escaped once"
    );
    assert_eq!(
        rendered.matches("Path=/Cfg/a\\b[").count(),
        1,
        "the path reads as `template_path` renders it: {}",
        rendered
    );
    assert!(
        !rendered.contains("a\\\\b"),
        "the path's backslash is not doubled: {}",
        rendered
    );
}

/// `registers_wrap`, the one rule both wrap sites read (`rhs_undecided`, `key_filter::outcome_of`), on
/// its truth table: a plain refusal's wrap is registered whatever token it carries; a numbered text's
/// wrap is registered only when NO token carries the refusal for it (the release build's fail-closed
/// answer where the sites' debug assertions say the invariant was broken); a text that is no refusal's
/// registers nothing, numbered or not, token or none. Read here because at each site the assertion
/// panics on the one input where the branch matters, so a test through the sites cannot tell the rule
/// from a site that registers every refusal's wrap.
#[test]
fn a_wrap_is_registered_for_a_plain_refusal_and_for_a_numbered_text_with_no_token_alone() {
    let token = Some(mint_refusal_token());
    for (refused, numbered, token, expected) in [
        (true, false, None, true),
        (true, false, token, true),
        (true, true, None, true),
        (true, true, token, false),
        (false, false, None, false),
        (false, false, token, false),
        (false, true, None, false),
        (false, true, token, false),
    ] {
        assert_eq!(
            registers_wrap(refused, numbered, token),
            expected,
            "registers_wrap({}, {}, {:?})",
            refused,
            numbered,
            token
        );
    }
}

/// A function's reason for a value it had no answer for (`no_answer_for`, through
/// `general_no_answer_reason`) bounds its one template-derived part, the path, where it is written: a
/// value at a path of a thousand characters names its path as `template_path` renders it (cut in its
/// middle, both ends kept, the location whole) and never whole, so the reason reaches the key filter's
/// marker (`UnResolvedRhs::did_not_resolve_reason`) and a record's lead (`eval::Lead::Absence`) bounded,
/// where it was once bounded only where the key filter embedded it and reached a lead whole.
#[test]
fn a_functions_no_answer_reason_bounds_its_path_where_it_is_written() {
    // A list, a kind `parse_int` does not take: the one way a value reaches `no_answer_for` through
    // `parse_int` (a string it cannot parse leaves through the function's own `Err`, never here).
    let long = "k".repeat(1000);
    let value = Rc::new(PathAwareValue::List((
        Path::new(format!("/Cfg/{long}/Name"), 2, 4),
        vec![],
    )));
    let result = no_answer_for(
        &FunctionName::ParseInt,
        &[vec![QueryResult::Resolved(Rc::clone(&value))]],
        Some(0),
    );
    let QueryResult::UnResolved(unresolved) = &result else {
        panic!("a value the function had no answer for is an unresolved result");
    };
    let reason = unresolved.reason.clone().unwrap_or_default();
    let expected_path = template_path(value.self_path());
    assert!(
        expected_path.contains("more characters cut]...") && expected_path.ends_with("[L:2,C:4]"),
        "the control: a thousand-character path is cut in its middle with its location whole: {}",
        expected_path
    );
    assert_eq!(
        reason,
        format!(
            "parse_int has no answer for the value at {expected_path}: it is array, which the function \
             does not take"
        ),
        "the reason names the path as `template_path` renders it"
    );
    assert!(
        !reason.contains(&long),
        "the path is never whole: {}",
        reason
    );
}

/// `bounded_lead`, the record's net under the source bounds (`eval::Lead::into_text`): a lead of bounded
/// parts, wider than one part, passes through unchanged (nothing is cut a second time); a lead holding a
/// raw control is escaped once, and a second pass over the escaped lead changes nothing; a raw lead past
/// `LONGEST_LEAD_IN_A_RECORD` printed characters is cut at its end with the count cut.
#[test]
fn the_records_lead_net_cuts_nothing_bounded_and_escapes_once() {
    // The widest lead a retrieval writes: the three-part "Attempting to retrieve from key K but type is
    // not an struct type at path P, Type = T, Value = V" reason with every part at its maximum (a key
    // and a value each cut at the part bound, a path cut in its middle), the longest type name among
    // them; a lead of bounded parts of that width passes through unchanged, so the net's width cannot
    // sit between a real lead's width and the console's bound and cut such a lead a second time.
    let widest_part = "k".repeat(1000);
    let bounded = format!(
        "Attempting to retrieve from key {} but type is not an struct type at path {}, Type = {}, \
         Value = {}",
        marker_part(&widest_part),
        template_path(&Path::new(format!("/Cfg/{widest_part}/Tags"), 1, 1)),
        "String",
        marker_part(&format!("{:?}", "v".repeat(1000)))
    );
    assert_eq!(
        bounded_lead(&bounded),
        bounded,
        "a lead of bounded parts passes through unchanged ({} chars)",
        bounded.chars().count()
    );
    assert!(
        bounded.chars().count() < LONGEST_LEAD_IN_A_RECORD,
        "the widest three-part lead is under the net's width: {} chars",
        bounded.chars().count()
    );
    let once = bounded_lead("key \u{1b}x");
    assert_eq!(once, "key \\u{1b}x", "a raw control is escaped once");
    assert_eq!(bounded_lead(&once), once, "an escaped lead is unchanged");
    let too_long = "r".repeat(LONGEST_LEAD_IN_A_RECORD + 500);
    let cut = bounded_lead(&too_long);
    assert!(
        cut.starts_with(&"r".repeat(LONGEST_LEAD_IN_A_RECORD))
            && cut.ends_with("...[500 more characters cut]")
            && cut.chars().count() < too_long.len(),
        "a raw lead past the net's width is cut at its end with the count: {} chars",
        cut.chars().count()
    );
}

/// The twin's undecidable-pair sentence escapes a long key and bounds it on an ESCAPE BOUNDARY
/// (`template_part`): the bound holds on the printed text and no escape is cut in half. A key of
/// 255 characters, an ESC and a forty-character tail prints the 255 and cuts at the ESC, whose
/// six-character escape does not fit, counting the 41 source characters left out (nothing of the ESC is
/// printed, raw or half escaped); a key of 256 bidi overrides, eight printed characters each, prints 32
/// of them and counts the 224 left out, where a cut by source characters before the escape printed all
/// 256 at eight times the bound. The tail is long so that the cut shortens the text: a cut that would
/// print longer than the escaped text whole is not made (`whole_unless_the_cut_is_shorter`, the rule
/// every template part is bounded under), so a four-character tail would print whole with its escape.
#[test]
fn the_twins_undecidable_sentence_cuts_a_key_on_an_escape_boundary() -> Result<()> {
    use crate::rules::eval_context::{undecidable_pair_text, LONGEST_TEMPLATE_PART_IN_A_REFUSAL};
    let error = crate::rules::errors::Error::undecidable(String::from("undecidable"));
    let key = format!(
        "{}\u{1b}{}",
        "k".repeat(LONGEST_TEMPLATE_PART_IN_A_REFUSAL - 1),
        "t".repeat(40)
    );
    let text = undecidable_pair_text(&key, &[], &error);
    assert_eq!(
        (true, false, false, false),
        (
            text.contains(&format!(
                "{}...[41 more characters cut]",
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
fn a_paths_middle_cut_keeps_whole_characters_at_both_ends_and_the_end_of_a_long_leaf() {
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
    assert_eq!(
        "/Resources/B/Properties[L:4,C:7]",
        path.to_string(),
        "the text, then the location in brackets"
    );
    assert_eq!(
        "/Resources/B/Pr...[cut]...erties[L:4,C:7]",
        path.shown_with_location("/Resources/B/Pr...[cut]...erties"),
        "a shown text takes the same location the same way"
    );
}

/// The clause table's example of a cut path is read out of `docs/CLAUSES.md` itself and compared with what
/// `template_path` renders for the documented input (a 300-character resource name under `/Resources/`,
/// above `/Properties/Tags`, at line 3 column 9): the marker's count and the kept head and tail around
/// it, so the document cannot say one count while the code cuts another. The document abbreviates the
/// 128 kept characters at each end to `RRRR`, so the comparison reads the marker and the ends, not the
/// abbreviated run. The callout's four boundary figures (a name whole through 283 and cut from 284, a
/// path's text whole through 286 and cut from 287) are parsed out of the same sentence and compared with
/// the boundaries computed off the markers, so a figure cannot drift from the code.
#[test]
fn the_clause_tables_example_of_a_cut_path_reads_what_template_path_renders() {
    // Read at run time from the repository beside the crate, as `guard/tests/docs_pinned_by.rs` reads the
    // documents, with the same escape: a crate packaged without `docs/` sets `GUARD_DOCS_ABSENT=1` and this
    // check is skipped with a line on stderr, where an `include_str!` would fail to compile the test binary.
    let clauses_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/CLAUSES.md");
    let clauses = match std::fs::read_to_string(clauses_path) {
        Ok(text) => text,
        Err(e) if std::env::var("GUARD_DOCS_ABSENT").as_deref() == Ok("1") => {
            eprintln!(
                "GUARD_DOCS_ABSENT=1: {clauses_path} is not readable ({e}); the cut-path example is not checked here"
            );
            return;
        }
        Err(e) => panic!(
            "{} is readable (set GUARD_DOCS_ABSENT=1 for a crate packaged without docs/): {}",
            clauses_path, e
        ),
    };
    let clauses = clauses.as_str();
    const LEAD_IN: &str = "a refusal path reads `";
    let start = clauses
        .find(LEAD_IN)
        .expect("the clause table carries the cut-path example")
        + LEAD_IN.len();
    let documented =
        &clauses[start..start + clauses[start..].find('`').expect("the example is closed")];
    let rendered = template_path(&Path(
        format!("/Resources/{}/Properties/Tags", "R".repeat(300)),
        Location::new(3, 9),
    ));
    let marker_of = |text: &str| -> String {
        let open = text.find("...[").expect("a middle cut marker");
        let close = text[open..].find("]...").expect("the marker closes") + open + "]...".len();
        text[open..close].to_string()
    };
    assert_eq!(
        marker_of(rendered.as_str()),
        marker_of(documented),
        "the document's marker names the count the code cuts: {documented} against {rendered}"
    );
    assert!(
        documented.starts_with("/Resources/RRRR") && rendered.starts_with("/Resources/RRRR"),
        "both keep the top of the document and the start of the name"
    );
    assert!(
        documented.ends_with("RRRR/Properties/Tags[L:3,C:9]")
            && rendered.ends_with("RRRR/Properties/Tags[L:3,C:9]"),
        "both keep the name's last letters, the leaf segments and the location"
    );
    // The same callout states the boundary lengths; they are parsed out of the sentence and compared
    // with the boundaries computed off the markers, as `the_cut_begins_at_the_first_length_where_it_shortens_the_part`
    // computes them, so the sentence cannot say one figure while the markers decide another.
    // Anchored by the one phrase that opens the figures sentence and sliced to its closing parenthesis,
    // both found on character boundaries, so a multi-byte character anywhere in the paragraph cannot
    // make the slice panic and a reworded neighbour cannot move the figures out of it.
    const FIGURES_LEAD_IN: &str = "the figures are pinned at the boundary lengths, a name of ";
    let figures_start = clauses
        .find(FIGURES_LEAD_IN)
        .expect("the clause table states the boundary lengths")
        + FIGURES_LEAD_IN.len();
    let figures_end = figures_start
        + clauses[figures_start..]
            .find(')')
            .expect("the figures sentence closes its parenthesis");
    let figures = &clauses[figures_start..figures_end];
    // The four figures are read in sequence from a cursor that moves past each one, since the lead-ins
    // repeat (" whole and one of " follows the name's figure and the path's).
    let mut cursor = 0usize;
    let mut number_after = |lead_in: &str| -> usize {
        let rest = &figures[cursor..];
        let at = match lead_in.is_empty() {
            true => 0,
            false => {
                rest.find(lead_in).unwrap_or_else(|| {
                    panic!("the figures sentence carries `{}`: {}", lead_in, figures)
                }) + lead_in.len()
            }
        };
        let digits: String = rest[at..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        cursor += at + digits.len();
        digits
            .parse()
            .unwrap_or_else(|_| panic!("a number follows `{}`: {}", lead_in, figures))
    };
    let stated = (
        number_after(""),
        number_after(" characters left whole and one of "),
        number_after(" cut, a path's text of "),
        number_after(" whole and one of "),
    );
    let bound = LONGEST_TEMPLATE_PART_IN_A_REFUSAL;
    let first_cut_part = (bound + 1..)
        .find(|&total| bound + end_cut_marker(total - bound).chars().count() < total)
        .expect("a part long enough is cut");
    let first_cut_path = (bound + 1..)
        .find(|&total| bound + middle_cut_marker(total - bound).chars().count() < total)
        .expect("a path long enough is cut");
    assert_eq!(
        (
            first_cut_part - 1,
            first_cut_part,
            first_cut_path - 1,
            first_cut_path
        ),
        stated,
        "the clause table's boundary figures (name whole, name cut, path whole, path cut) are the markers': {figures}"
    );
}

/// The cut begins at the first length where it shortens the part, and that length is read off the
/// marker's own text through the helpers the cuts write with (`end_cut_marker`, `middle_cut_marker`), so a
/// change to a marker moves the boundary with it: an end cut keeps `LONGEST_TEMPLATE_PART_IN_A_REFUSAL`
/// characters and writes the end marker, a middle cut keeps as many and writes the middle marker between
/// its halves, and either is made only where the kept characters plus the marker are fewer than the whole.
/// A part one character under that length renders whole, a part at it is cut and shorter; the same for a
/// path, with its location kept out of the count; and a path of accented letters one character under the
/// length renders whole though its BYTES are twice the bound, since characters decide. The lengths the
/// constant's doc states (whole through 283 and cut from 284 for a name, 286 and 287 for a path's text)
/// are pinned here against the computed boundary, as is the clause table's example of a cut path (a
/// 300-character resource name under `/Resources/` and above `/Properties/Tags`: 327 characters, 128 kept
/// at each end, 71 cut), so the documents' figures cannot drift from the markers.
#[test]
fn the_cut_begins_at_the_first_length_where_it_shortens_the_part() {
    let bound = LONGEST_TEMPLATE_PART_IN_A_REFUSAL;
    let end_marker = |cut: usize| end_cut_marker(cut).chars().count();
    let middle_marker = |cut: usize| middle_cut_marker(cut).chars().count();
    let first_cut_part = (bound + 1..)
        .find(|&total| bound + end_marker(total - bound) < total)
        .expect("a part long enough is cut");
    let first_cut_path = (bound + 1..)
        .find(|&total| bound + middle_marker(total - bound) < total)
        .expect("a path long enough is cut");
    assert_eq!(
        (284, 287),
        (first_cut_part, first_cut_path),
        "the documented boundaries: a name is cut from 284 characters, a path's text from 287"
    );
    let documented = Path(
        format!("/Resources/{}/Properties/Tags", "R".repeat(300)),
        Location::new(3, 9),
    );
    assert_eq!(
        format!(
            "/Resources/{}{}{}/Properties/Tags[L:3,C:9]",
            "R".repeat(bound / 2 - "/Resources/".len()),
            middle_cut_marker(327 - bound),
            "R".repeat(bound - bound / 2 - "/Properties/Tags".len())
        ),
        template_path(&documented),
        "the clause table's example: 327 characters, 128 kept at each end, 71 cut"
    );
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

/// The boundary search of `numbered_refusal_parts` tries every occurrence of the next marker, the
/// overlapping ones too: in `(1) A (2) (2) B` the only split that leaves a registered part before it is
/// the second ` (2) `, which starts one character after the first. Resuming the search after the whole
/// marker skipped it and read the text as no refusal's.
#[test]
fn numbered_refusal_parts_finds_a_boundary_that_overlaps_the_previous_one() -> Result<()> {
    // The registry is the root scope's: the two parts are registered under a scope alive for the test.
    let rules_file = RulesFile::try_from("rule r { Resources exists }")?;
    let _root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }")?),
    );
    let _a = register_refusal("A (2)");
    let _b = register_refusal("B");
    assert_eq!(
        numbered_refusal_parts("(1) A (2) (2) B"),
        Some(vec!["A (2)", "B"])
    );
    assert_eq!(
        numbered_refusal_parts("(1) A (2) (2) C"),
        None,
        "a part nobody registered is no refusal's, overlapping boundary or not"
    );
    Ok(())
}

fn an_absorbed_raise<'loc>() -> crate::rules::AbsorbedRaise<'loc> {
    crate::rules::AbsorbedRaise {
        clause: "Type == 'x'".to_string(),
        site: no_position(),
        reads: vec!["a read the clause could not make".to_string()],
        kind: crate::rules::RaiseKind::Raised,
    }
}

/// A predicate that answered with no error leaves nothing in its frame, and settling the empty frame is
/// silent in a debug and a release build alike.
///
/// It reads red if the helper asserts on an empty frame.
#[test]
fn settling_the_empty_frame_of_an_answered_predicate_is_silent() {
    let answered: Result<Status> = Ok(Status::PASS);
    settle_predicate_frame(Vec::new(), &answered);
}

/// A predicate that ended in an error may leave raises in its frame: the entry of the raise the reader
/// turns into the entry's marker. Settling drops them with no panic, since the clause that reads the
/// marker reports the refusal itself.
///
/// It reads red if the debug assertion also fires on an error.
#[test]
fn settling_the_frame_of_a_predicate_that_raised_drops_it_without_a_panic() {
    let raised: Result<Status> = Err(Error::unanswerable_from(
        false,
        "a refused read".to_string(),
    ));
    settle_predicate_frame(vec![an_absorbed_raise(), an_absorbed_raise()], &raised);
}

/// A predicate that answered with no error and still left an entry in its frame is a path the invariant
/// does not allow: a debug build trips the assertion where it happens. A debug assertion, so the test
/// runs only in a build that has it.
///
/// It reads red (no panic) if the Ok arm drops the frame without the assertion.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "a filter predicate answered and left 1 absorbed raise(s) in its frame")]
fn settling_a_non_empty_frame_of_an_answered_predicate_trips_the_assertion() {
    let answered: Result<Status> = Ok(Status::FAIL);
    settle_predicate_frame(vec![an_absorbed_raise()], &answered);
}

/// A rule report's own message is read for the JUnit failure only where no check under the rule says
/// anything (`get_message_with_rule_records`): a rule with a check that carries a text keeps the clause's
/// messages alone, a rule with only silent checks (a block with empty messages) answers with its own
/// record, the author's text in `custom_message` and the evaluator's sentence and a refusal's in
/// `error_message` (flagged for the refusal), and `get_message` is unchanged in every row.
///
/// Fails when the rule's own text is added beside a clause's, when a silent rule answers nothing,
/// when a text lands in the other slot, or when `get_message` starts to carry the rule's text.
#[test]
fn a_rule_reports_its_own_message_only_where_its_checks_say_nothing() {
    fn block(custom: Option<&str>, error: Option<&str>) -> ClauseReport<'static> {
        ClauseReport::Block(GuardBlockReport {
            context: "ctx".to_string(),
            messages: Messages {
                custom_message: custom.map(str::to_string),
                error_message: error.map(str::to_string),
                location: None,
                refusal: false,
                parts: None,
            },
            unresolved: None,
        })
    }
    fn rule(
        slot: crate::rules::CustomSlot,
        checks: Vec<ClauseReport<'static>>,
    ) -> ClauseReport<'static> {
        ClauseReport::Rule(RuleReport {
            name: "check",
            messages: Messages {
                custom_message: Some("the rule's own".to_string()),
                error_message: None,
                location: None,
                refusal: false,
                parts: None,
            },
            checks,
            custom_slot: slot,
            ..Default::default()
        })
    }
    use crate::rules::CustomSlot;
    let texts = |messages: Vec<Messages>| -> Vec<(Option<String>, Option<String>, bool)> {
        messages
            .into_iter()
            .map(|each| (each.custom_message, each.error_message, each.refusal))
            .collect()
    };
    let own = |custom: Option<&str>, error: Option<&str>, refusal: bool| {
        (
            custom.map(str::to_string),
            error.map(str::to_string),
            refusal,
        )
    };
    assert_eq!(
        vec![own(Some("the rule's own"), None, false)],
        texts(rule(CustomSlot::Author, vec![]).get_message_with_rule_records()),
        "no check: the author's body in the author's slot"
    );
    assert_eq!(
        vec![own(None, Some("the rule's own"), false)],
        texts(rule(CustomSlot::Evaluator, vec![]).get_message_with_rule_records()),
        "no check: the evaluator's sentence in the evaluator's slot"
    );
    let ClauseReport::Rule(mut displaced) = rule(CustomSlot::Author, vec![]) else {
        unreachable!("rule() builds a rule report");
    };
    displaced.messages.error_message = Some("the displaced sentence".to_string());
    displaced.messages.refusal = true;
    assert_eq!(
        vec![own(
            Some("the rule's own"),
            Some("the displaced sentence"),
            true
        )],
        texts(ClauseReport::Rule(displaced).get_message_with_rule_records()),
        "no check, a body that displaced the rule's refusal: both texts, the flag the sentence's"
    );
    assert_eq!(
        vec![own(None, Some("the rule's own"), true)],
        texts(rule(CustomSlot::Refusal, vec![]).get_message_with_rule_records()),
        "no check: a refusal's sentence in the evaluator's slot, flagged"
    );
    assert_eq!(
        vec![own(None, None, false)],
        texts(rule(CustomSlot::Evaluator, vec![block(None, None)]).get_message()),
        "get_message is unchanged: the silent check's messages, not the rule's"
    );
    assert_eq!(
        vec![own(Some("the rule's own"), None, false)],
        texts(
            rule(CustomSlot::Author, vec![block(Some("  "), Some(""))])
                .get_message_with_rule_records()
        ),
        "a check that says nothing (blank texts) leaves the rule to speak"
    );
    assert_eq!(
        vec![own(None, Some("the clause's"), false)],
        texts(
            rule(CustomSlot::Author, vec![block(None, Some("the clause's"))])
                .get_message_with_rule_records()
        ),
        "a check with a text speaks for the rule: the rule's own is not added beside it"
    );
}

/// Reading the messages of a call chain walks each rule's subtree once: a rule asks whether its checks say
/// anything of the messages it just collected, not of a second walk, so a chain of four rules, each calling
/// the one before and each holding a record text, runs `messages_of_checks` four times (the depth plus
/// one) and the answer is the innermost rule's own record. Fails when the count reads more than four (a
/// walk to ask whether the rule speaks for itself and a second to collect, which doubles at every level and
/// reads 22 for this chain), or when the answer is not the innermost rule's own text.
#[test]
fn reading_the_messages_of_a_call_chain_walks_each_level_once() {
    fn rule_over(name: &'static str, checks: Vec<ClauseReport<'static>>) -> ClauseReport<'static> {
        ClauseReport::Rule(RuleReport {
            name,
            messages: Messages {
                custom_message: Some(format!("the record of {name}")),
                error_message: None,
                location: None,
                refusal: false,
                parts: None,
            },
            checks,
            custom_slot: crate::rules::CustomSlot::Evaluator,
            ..Default::default()
        })
    }
    let innermost = rule_over("r0", vec![]);
    let chain = ["r1", "r2", "r3"]
        .iter()
        .copied()
        .fold(innermost, |inner, name| rule_over(name, vec![inner]));
    MESSAGE_WALKS.with(|walks| walks.set(0));
    let messages = chain.get_message_with_rule_records();
    let walks = MESSAGE_WALKS.with(|walks| walks.get());
    assert_eq!(
        4, walks,
        "four rules, each walked once: the depth plus one, not a count that doubles at every level"
    );
    assert_eq!(
        vec![Some("the record of r0".to_string())],
        messages
            .into_iter()
            .map(|each| each.error_message)
            .collect::<Vec<_>>(),
        "the innermost rule's own record is the answer: its text sits in the evaluator's slot"
    );
}

/// The record tree writes the sentence a call body displaced under `displaced_message` and nothing for its
/// kind, and writes no key at all for a record that displaced nothing.
///
/// Fails when the key is missing for a record that displaced a sentence, when the kind is
/// written, or when the key is written as `null` for a record that displaced nothing.
#[test]
fn the_record_tree_writes_a_displaced_sentence_and_not_its_kind() {
    use crate::rules::{CustomSlot, NamedStatus};
    let displaced = NamedStatus {
        name: "check",
        status: Status::FAIL,
        message: Some("the body".to_string()),
        slot: CustomSlot::Author,
        displaced: Some((CustomSlot::Refusal, "the rule's own sentence".to_string())),
        frame_reads: Vec::new(),
        ended_by_error: false,
    };
    let written = serde_json::to_value(&displaced).expect("the record serializes");
    assert_eq!(
        Some("the rule's own sentence"),
        written
            .get("displaced_message")
            .and_then(|text| text.as_str()),
        "the sentence is written beside the body: {}",
        written
    );
    // The exact key set, so a kind written under any other key reads red, not only one spelled "Refusal".
    let keys = |value: &serde_json::Value| -> Vec<String> {
        let mut keys: Vec<String> = value
            .as_object()
            .expect("the record serializes as an object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    };
    assert_eq!(
        vec!["displaced_message", "message", "name", "status"],
        keys(&written),
        "the sentence is written and its kind is not: {}",
        written
    );
    let nothing = NamedStatus {
        displaced: None,
        ..displaced
    };
    let written = serde_json::to_value(nothing).expect("the record serializes");
    assert_eq!(
        vec!["message", "name", "status"],
        keys(&written),
        "no key for a record that displaced nothing: {}",
        written
    );
}

/// A sentence registered many times under one live run lists one token: the newest, which the run owns,
/// so the newest overall and the newest the run owns are the same token and twenty registrations leave
/// exactly it.
///
/// Fails when the list grows with the number of registrations, or when the token kept is not the
/// newest minted (a cut that keeps the oldest token the run owns).
#[test]
fn a_sentence_registered_many_times_under_one_run_lists_a_bounded_number_of_tokens() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let mut root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    let text = "the read of `S` is refused (many times)";
    let (listed, newest) = with_refusal_frame(&mut root, RefusalFrame::open(), |_| {
        let mut newest = register_refusal(text);
        for _ in 1..20 {
            newest = register_refusal(text);
        }
        (registered_tokens_in_any_live_registry(text), newest)
    });
    assert_eq!(
        vec![newest],
        listed,
        "twenty registrations left exactly the newest token listed"
    );
}

/// A text carries one token per run that owns one: a run that raised a sentence keeps reading the token it
/// registered for it when a binding resolved inside the run registers the same sentence again, and a
/// second run opened INSIDE the binding's query reads the token its own raise carries. The cell opens an
/// outer run through `with_refusal_frame`, registers the sentence, opens a resolution of a binding whose
/// scope was built before the run, opens an inner run inside the resolution and writes through each of the
/// registry's three writers with a token minted after the inner run opened (so the inner run owns it and
/// the outer run does not). Inside the inner run the registry answers the inner run's token and the
/// inner frame reads it as its own; the two writers that hand the token on with a marker
/// (`ensure_registered`, `ensure_registered_wrap`) return the token they were handed, which is the inner
/// run's own. Once the inner run has closed, the outer run is answered its own token again and its frame
/// reads it as its own. Inside the inner run the registry lists both tokens, read there and not after the
/// run closed, since a live run owns each. Ownership is asked of the live frames (`owns_token`), which sees
/// the open resolution that excludes the inner token from the outer run, and the text read at the end of
/// the inner run (`ended_with_its_token`, which the predicate's wrapper calls while the run is live)
/// answers the inner run's token. With both runs closed, a write of the sentence leaves one token listed.
///
/// Fails when the registry answers the outer run's token to the inner run (the write was
/// skipped, or the read took the first token listed), answers the inner run's to the outer
/// run, drops one of the two tokens while a live run owns it, when an `ensure_` writer returns
/// a token other than the marker's, when a writer hands back a token the outer run owns, or
/// when the list keeps both tokens after both runs closed.
#[test]
fn a_run_opened_inside_a_binding_reads_its_own_token_beside_the_enclosing_runs_for_every_writer() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let mut root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    // The binding's scope is built before the outer run opens.
    let owner_built = next_scope_event();
    for writer in [
        "register_refusal",
        "ensure_registered",
        "ensure_registered_wrap",
    ] {
        let text = format!("the read of `S` is refused ({})", writer);
        let outer = RefusalFrame::open();
        let (run_token, inner_token, returned, inner_read, outer_read, listed) =
            with_refusal_frame(&mut root, outer, |ctx| {
                let run_token = register_refusal(&text);
                let _resolving = BindingResolution::open(owner_built);
                let inner = RefusalFrame::open();
                let (inner_token, returned, inner_read, listed) =
                    with_refusal_frame(ctx, inner, |inner_ctx| {
                        let minted_inside_the_binding = mint_refusal_token();
                        let (inner_token, returned) = match writer {
                            "register_refusal" => {
                                let minted = register_refusal(&text);
                                (minted, minted)
                            }
                            "ensure_registered" => (
                                minted_inside_the_binding,
                                ensure_registered(&text, Some(minted_inside_the_binding)),
                            ),
                            _ => (
                                minted_inside_the_binding,
                                ensure_registered_wrap(&text, Some(minted_inside_the_binding)),
                            ),
                        };
                        let read =
                            token_of_registered(&text, &crate::rules::eval::no_frame_ranking);
                        // The ownership the answers rest on, asked of the live frames themselves (an open
                        // resolution excludes the inner token from the outer run, which `minted_inside`
                        // alone does not see): the inner run owns what it minted and not the older token,
                        // the outer run the reverse.
                        assert!(
                            owns_token(&inner, inner_token)
                                && !owns_token(&outer, inner_token)
                                && owns_token(&outer, run_token)
                                && !owns_token(&inner, run_token),
                            "{}: premise: each run owns its own token and not the other's",
                            writer
                        );
                        assert!(
                            returned != run_token
                                && owns_token(&inner, returned)
                                && !owns_token(&outer, returned),
                            "{}: the writer hands back a token only the inner run owns",
                            writer
                        );
                        assert!(
                            inner.minted_inside(read).is_some(),
                            "{}: the inner frame reads the answer as minted inside its run",
                            writer
                        );
                        // The text read at the run's end, while the run is live: the settling the
                        // predicate's wrapper does (`ended_with_its_token`) for a raise with no token.
                        let ending = match ended_with_its_token(
                            &*inner_ctx,
                            Err(Error::UndecidableComparison(text.clone(), None)),
                        ) {
                            Err(Error::UndecidableComparison(_, token)) => token,
                            other => panic!("{}: the raise ends the run: {:?}", writer, other),
                        };
                        assert_eq!(
                            Some(inner_token),
                            ending,
                            "{}: the token ending the inner run is its own",
                            writer
                        );
                        // Both tokens are listed while the inner run is live, read INSIDE it: the list
                        // holds the outer run's token and the inner run's because a live run owns each.
                        let listed = registered_tokens_in_any_live_registry(&text).len();
                        (inner_token, returned, read, listed)
                    });
                let outer_read = token_of_registered(&text, &crate::rules::eval::no_frame_ranking);
                assert!(
                    outer.minted_inside(outer_read).is_some() && owns_token(&outer, run_token),
                    "{}: the outer frame reads the answer as minted inside its run",
                    writer
                );
                (
                    run_token,
                    inner_token,
                    returned,
                    inner_read,
                    outer_read,
                    listed,
                )
            });
        assert_eq!(
            Some(inner_token),
            inner_read,
            "{}: the inner run is answered the token its own raise carries",
            writer
        );
        assert_eq!(
            Some(run_token),
            outer_read,
            "{}: the outer run is answered its own token once the inner run is closed",
            writer
        );
        assert_eq!(
            2, listed,
            "{}: both tokens are listed while the inner run is live and each run owns one",
            writer
        );
        assert!(
            returned == inner_token,
            "{} returns the token the inner run owns",
            writer
        );
        // Both runs closed: the next write of the sentence cuts the list to one token.
        let _ = register_refusal(&text);
        assert_eq!(
            1,
            registered_tokens_in_any_live_registry(&text).len(),
            "{}: with no live run, a write leaves the newest token alone",
            writer
        );
    }
}

/// An outer run that registered a sentence several times, and a run opened inside a binding's query that
/// registered it several times more, each keep the NEWEST token they own and no other: the list holds
/// exactly two tokens, the outer run's newest and the inner run's newest, and the outer run, read INSIDE
/// itself once the inner run has closed, is answered its newest own token. A cut that kept each run's
/// oldest owned token would list two tokens as well and answer the outer run a token older than its
/// newest, which the folds that rank by minting (`later_token`) would read differently.
///
/// Fails when the list holds a token other than the outer run's newest and the inner run's newest,
/// holds more or fewer than two, or when the outer run is answered an older token of its own.
#[test]
fn an_outer_and_a_binding_nested_run_each_keep_the_newest_token_they_registered() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let mut root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    // The binding's scope is built before the outer run opens.
    let owner_built = next_scope_event();
    let text = "the read of `S` is refused (outer then nested)";
    let outer = RefusalFrame::open();
    with_refusal_frame(&mut root, outer, |ctx| {
        let mut outer_newest = register_refusal(text);
        for _ in 0..3 {
            outer_newest = register_refusal(text);
        }
        assert_eq!(
            vec![outer_newest],
            registered_tokens_in_any_live_registry(text),
            "premise: with one run live, the outer run's newest is the one token listed"
        );
        let _resolving = BindingResolution::open(owner_built);
        let inner = RefusalFrame::open();
        let inner_newest = with_refusal_frame(ctx, inner, |_| {
            let mut inner_newest = register_refusal(text);
            for _ in 0..3 {
                inner_newest = register_refusal(text);
            }
            let listed = registered_tokens_in_any_live_registry(text);
            assert!(
                listed.len() == 2
                    && listed.contains(&outer_newest)
                    && listed.contains(&inner_newest),
                "inside the inner run exactly two tokens are listed, each run's newest: {:?}",
                listed
            );
            assert_eq!(
                Some(inner_newest),
                token_of_registered(text, &crate::rules::eval::no_frame_ranking),
                "inside the inner run the inner run's newest token answers"
            );
            inner_newest
        });
        assert!(
            owns_token(&inner, inner_newest) && !owns_token(&outer, inner_newest),
            "premise: the inner run's newest is the binding's, which the outer run does not own"
        );
        // The inner run has closed; the outer run reads from INSIDE itself.
        assert_eq!(
            Some(outer_newest),
            token_of_registered(text, &crate::rules::eval::no_frame_ranking),
            "the outer run is answered its newest own token once the inner run is closed"
        );
    });
}

/// A frame planted with `RefusalFrames::push` is a stack the form that asks the frames
/// (`token_of_registered_under`) reads and the form that asks the live runs (`token_of_registered`) does
/// not. A text holds two tokens, the outer run's and the token of a run opened inside a binding's query,
/// both runs live: a stack planted with the outer run alone answers the outer run's token through the
/// frames form; the live runs' form answers the inner run's; a stack planted with both runs answers the
/// inner run's; a stack planted with none answers the later by minting, the one fallback ordering.
///
/// Fails when the frames form answers by the live runs (the outer-only stack answers the inner
/// run's token), when a planted stack owns neither token and answers the later one, or when
/// the empty stack answers an earlier token.
#[test]
fn a_planted_stack_is_asked_for_its_own_token_beside_the_live_runs() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let mut root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    let owner_built = next_scope_event();
    let text = "the read of `S` is refused (planted stack)";
    let outer = RefusalFrame::open();
    with_refusal_frame(&mut root, outer, |ctx| {
        let outer_token = register_refusal(text);
        let _resolving = BindingResolution::open(owner_built);
        let inner = RefusalFrame::open();
        with_refusal_frame(ctx, inner, |_| {
            let inner_token = register_refusal(text);
            assert_eq!(
                2,
                registered_tokens_in_any_live_registry(text).len(),
                "premise: both tokens are listed while both runs are live"
            );
            let mut outer_only = RefusalFrames::default();
            outer_only.push(outer);
            let mut both = RefusalFrames::default();
            both.push(outer);
            both.push(inner);
            assert_eq!(
                Some(outer_token),
                token_of_registered_under(text, &outer_only),
                "a stack planted with the outer run alone is answered the outer run's token"
            );
            assert_eq!(
                Some(inner_token),
                token_of_registered(text, &outer_only.ranking()),
                "the form that asks the live runs answers by them, whatever ranking it is handed"
            );
            assert_eq!(
                Some(inner_token),
                token_of_registered_under(text, &both),
                "a stack planted with both runs is answered the inner run's token"
            );
            assert_eq!(
                Some(inner_token),
                token_of_registered_under(text, &RefusalFrames::default()),
                "a stack planted with no run owns neither token and is answered the later by minting"
            );
        });
    });
}

/// A token carried with a refused read never displaces the token the live run reads as its own
/// (`eval::latest_token_of`). The run `R` raised the sentence itself (its own token), and a run nested in
/// a binding's query, closed since, raised it again (a token `R` does not own: the binding's range
/// excludes it); a basis read carrying that nested token, for the same sentence, is folded with the
/// registry's answer under the run's ranking, so the run's own token wins. A read whose text no registry
/// holds keeps the token it carries, and a read carrying none takes the registry's.
///
/// Fails when the carried nested token wins outright (the raise then carries a token the run
/// reads as minted before its own, and its entry reads PLAIN where it read REFUSED), when the
/// token-only read loses its carried token, or when the token-less read answers none.
#[test]
fn a_carried_token_never_displaces_the_token_the_live_run_owns() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let mut root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    // The binding's scope is built before the run opens.
    let owner_built = next_scope_event();
    let text = "the read of `S` is refused (a carried token beside the run's own)";
    let outer = RefusalFrame::open();
    with_refusal_frame(&mut root, outer, |ctx| {
        let run_token = register_refusal(text);
        let nested_token = {
            let _resolving = BindingResolution::open(owner_built);
            let inner = RefusalFrame::open();
            with_refusal_frame(ctx, inner, |_| register_refusal(text))
        };
        assert!(
            owns_token(&outer, run_token) && !owns_token(&outer, nested_token),
            "premise: the run owns its own token and not the nested run's, whose binding has closed"
        );
        let ranking = crate::rules::eval::ranking_under(ctx.refusal_frames());
        let carried = vec![(text.to_string(), Some(nested_token))];
        assert_eq!(
            Some(run_token),
            crate::rules::eval::latest_token_of(&carried, &ranking),
            "a read carrying the nested run's token answers the run's own"
        );
        let token_less = vec![(text.to_string(), None)];
        assert_eq!(
            Some(run_token),
            crate::rules::eval::latest_token_of(&token_less, &ranking),
            "a read carrying none answers the registry's token for the run"
        );
        let token_only = vec![("a read no registry holds".to_string(), Some(nested_token))];
        assert_eq!(
            Some(nested_token),
            crate::rules::eval::latest_token_of(&token_only, &ranking),
            "a read no registry holds keeps the token it carries"
        );
    });
}

/// A text no live run owns a token of answers its NEWEST token whatever ranking the reader is handed: one
/// fallback by minting everywhere (`token_of_registered`, `token_standing_for`, `ensure_registered`). The
/// ranking of a stack (`RefusalFrame::eligible`) and ownership (`owns_token`) differ for a token an open
/// binding resolution excluded: the run owned the older token, a token minted inside the open resolution
/// was the newest, and once both runs and the resolution have closed a stack planted with the run ranks the
/// older above the newest (the newest is outside it by the closed binding's range). The reader is handed
/// that ranking with no live run to own either token, and answers the newest; a fallback by the ranking
/// answered the older, so a reader by the token and a reader by the text could differ.
///
/// Fails when the answer is the older token.
#[test]
fn a_text_no_live_run_owns_answers_its_newest_whatever_ranking_it_is_handed() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let mut root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    let owner_built = next_scope_event();
    let text = "the read of `S` is refused (the newest, whatever the ranking)";
    let run = RefusalFrame::open();
    let (older, newest) = with_refusal_frame(&mut root, run, |_| {
        let older = register_refusal(text);
        let newest = {
            let _resolving = BindingResolution::open(owner_built);
            register_refusal(text)
        };
        (older, newest)
    });
    let mut planted = RefusalFrames::default();
    planted.push(run);
    assert!(
        run.eligible(older) && !run.eligible(newest),
        "premise: the planted stack ranks the older token above the newest"
    );
    assert_eq!(
        2,
        registered_tokens_in_any_live_registry(text).len(),
        "premise: both tokens stay listed after the run closed, until the next write"
    );
    assert_eq!(
        Some(newest),
        token_of_registered(text, &planted.ranking()),
        "with no live run to own either token, the newest answers whatever the ranking prefers"
    );
    // The wrap writer reads the same registry list and returns the same answer, so the marker it
    // builds carries the token a reader of the text answers.
    assert_eq!(
        newest,
        ensure_registered_wrap(text, None),
        "the wrap writer's returned token is the newest, the answer `token_of_registered` gave"
    );
}

/// The token a comparison raise carries, in the strict role and the plain one alike
/// (`eval::raised_token_of`), is the pair rule over the marker's own token and the one recovered from the
/// registry, under the run's ranking, built INSIDE the run (the shape the raise sites see, where the
/// registry and the ranking name the same run): the run owns the older token and the newest was minted
/// inside an open binding resolution (excluded), the registry asked inside the run recovers the run's token,
/// and the raise carries it where the marker carried the excluded one. The pair rule alone agrees with the
/// registry: handed both tokens in either order it answers the run's. Taken as `token.or(recovered)` the
/// marker's excluded token beat the run-owned recovered one.
///
/// Fails when the registry asked inside the run does not recover the run's token, or when
/// `raised_token_of` answers the excluded (newest) token (the marker's wins by argument
/// position and not by the pair rule under the ranking).
#[test]
fn a_raise_carries_the_token_the_run_owns_whether_it_was_recovered_or_carried() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let mut root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    let owner_built = next_scope_event();
    let text = "the read of `S` is refused (the raise's own token against the recovered one)";
    let run = RefusalFrame::open();
    with_refusal_frame(&mut root, run, |ctx| {
        let owned = register_refusal(text);
        let excluded = {
            let _resolving = BindingResolution::open(owner_built);
            register_refusal(text)
        };
        assert!(
            owns_token(&run, owned) && !owns_token(&run, excluded) && excluded.later_than(owned),
            "premise: the run owns the first token and excludes the later one"
        );
        let ranking = crate::rules::eval::ranking_under(ctx.refusal_frames());
        let recovered = token_of_registered_under(text, &ctx.refusal_frames());
        assert_eq!(
            Some(owned),
            recovered,
            "premise: the registry, asked inside the run, recovers the run's token"
        );
        assert_eq!(
            (Some(owned), Some(owned), Some(owned)),
            (
                crate::rules::eval::raised_token_of(Some(excluded), recovered, &ranking),
                crate::rules::eval::raised_token_of(Some(excluded), Some(owned), &ranking),
                crate::rules::eval::raised_token_of(Some(owned), Some(excluded), &ranking),
            ),
            "the run's token is raised whether it was recovered or carried, in either argument order"
        );
    });
    // The four raise sites take their token from this function; the rules-file cell
    // `a_predicate_with_a_gate_path_disjunct_keeps_its_entry_refused_through_a_real_evaluation` runs the gate path through a real
    // evaluation.
}

/// Tests the TEST-ONLY helpers (`FailBasis::undecidable_reads`, `or`, `live_runs_ranking`), which build or
/// join a basis with no frames in hand and read the LIVE runs' ranking; production folds hand the ranking
/// of the frames they hold (`undecidable_reads_under`, `or_under`), covered by
/// `a_basis_keeps_the_token_the_run_reads_as_its_own_whatever_order_the_reads_arrive_in`. The helper
/// ranks the live runs' ranking, told apart from minting: the run's own token is minted FIRST and a token the run
/// excludes (minted inside a binding owned by a scope that predates the run, since resolved) LATER, and
/// the basis keeps the run's token in both orders, built over both reads and joined with `or`. A rule that
/// kept the later-minted, or the first met, answers the excluded token in one of the four.
///
/// Fails when a basis answers the excluded token.
#[test]
fn a_basis_with_no_frames_in_hand_keeps_the_token_the_live_run_owns_whatever_was_minted_last() {
    use crate::rules::FailBasis;
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let mut root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    let owner_built = next_scope_event();
    let text = "the read of `S` is refused (a basis built with no frames in hand)";
    let run = RefusalFrame::open();
    let (owned, excluded, answers) = with_refusal_frame(&mut root, run, |_| {
        let owned = mint_refusal_token();
        let excluded = {
            let _resolving = BindingResolution::open(owner_built);
            mint_refusal_token()
        };
        assert!(
            run.eligible(owned) && !run.eligible(excluded) && excluded.later_than(owned),
            "premise: the run owns the first token and excludes the later one"
        );
        let built = |a, b| {
            FailBasis::undecidable_reads(vec![
                (text.to_string(), Some(a)),
                (text.to_string(), Some(b)),
            ])
            .refused_reads()[0]
                .1
        };
        let one = |token| FailBasis::undecidable_reads(vec![(text.to_string(), Some(token))]);
        let joined = |a, b| one(a).or(one(b)).refused_reads()[0].1;
        (
            owned,
            excluded,
            vec![
                built(owned, excluded),
                built(excluded, owned),
                joined(owned, excluded),
                joined(excluded, owned),
            ],
        )
    });
    assert_eq!(
        vec![Some(owned); 4],
        answers,
        "the run's token wins in both orders, though {:?} was minted last",
        excluded
    );
}

/// A rule run recorded under a block body or a `when` body (a reference or a call written there) whose
/// failing block is silent is listed with the generic sentence in its `checks`: a parent with a message of
/// its own walks its children without the fallback and the rule arm asks for the fallback itself, so a rule
/// is never listed with empty checks, where a block arm that only extended the children would list EMPTY
/// checks there (a message-less per-value record pushes nothing).
///
/// Fails when the `RuleReport` under the block or under the condition has empty `checks`.
#[test]
fn a_rule_run_under_a_block_or_a_when_body_with_a_silent_failing_block_lists_the_generic_sentence()
{
    const GENERIC: &str =
        "the block clause failed, and none of the checks recorded under it reports why";
    let silent_block = || EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: true,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![EventRecord {
            context: String::from("GuardBlockAccessClause#2"),
            container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: false,
                message: None,
                refusal: true,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            })),
            children: vec![],
        }],
    };
    let called_rule = || EventRecord {
        context: String::from("check"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "check",
            status: Status::FAIL,
            message: None,
            slot: Default::default(),
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![silent_block()],
    };
    let parent_block = EventRecord {
        context: String::from("BlockGuardClause#1"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![called_rule()],
    };
    let parent_when = EventRecord {
        context: String::from("WhenCondition#1"),
        container: Some(RecordType::WhenCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![called_rule()],
    };
    let rule_checks = |parent: &EventRecord<'_>| -> Vec<Option<String>> {
        let mut found = Vec::new();
        for clause in report_all_failed_clauses_for_rules(std::slice::from_ref(parent)) {
            match clause {
                ClauseReport::Rule(rule) => {
                    found.extend(rule.checks.iter().map(|check| match check {
                        ClauseReport::Block(block) => block.messages.error_message.clone(),
                        other => panic!("one block report under the rule, got {:?}", other),
                    }))
                }
                other => panic!("one rule report under the parent, got {:?}", other),
            }
        }
        found
    };
    assert_eq!(
        (
            vec![Some(String::from(GENERIC))],
            vec![Some(String::from(GENERIC))],
        ),
        (rule_checks(&parent_block), rule_checks(&parent_when)),
        "a rule under a block body and under a `when` body lists the generic sentence, not empty checks"
    );
    // Parents WITH a message of their own walk their children without the fallback, so only the rule
    // arm's own `true` lists the generic sentence for the rule beneath them: these rows pin that reset.
    let with_message = |record: &EventRecord<'_>| -> EventRecord<'static> {
        // A record's `message` is always the evaluator's own sentence (the author's text is the
        // `custom_message`), and it is dropped beside entries only when one of them carries ITS error:
        // here the error the entry beneath the called rule lists, behind a head the reader knows. This is a
        // text the evaluator never writes on a record with such a child, chosen on purpose: the row pins
        // that a parent WITH a message of its own walks its children without the fallback (the rule arm
        // asks for the fallback itself), and the generic entry must tell the sentence so that no entry of
        // the parent's own is added. The cell depends on that pairing, not on the wording.
        let message = Some(format!(
            "{}{GENERIC}",
            crate::rules::eval::WHEN_UNEVALUATED_HEAD
        ));
        let container = match &record.container {
            Some(RecordType::BlockGuardCheck(check)) => RecordType::BlockGuardCheck(BlockCheck {
                message,
                ..check.clone()
            }),
            Some(RecordType::WhenCheck(check)) => RecordType::WhenCheck(BlockCheck {
                message,
                ..check.clone()
            }),
            other => panic!("a block or a when parent, got {:?}", other),
        };
        EventRecord {
            context: record.context.clone(),
            container: Some(container),
            children: vec![called_rule()],
        }
    };
    assert_eq!(
        (
            vec![Some(String::from(GENERIC))],
            vec![Some(String::from(GENERIC))],
        ),
        (
            rule_checks(&with_message(&parent_block)),
            rule_checks(&with_message(&parent_when)),
        ),
        "a parent with a message of its own still lists the called rule's generic sentence"
    );
}

/// A parent with NO message of its own lists every failing child, a silent block included, beside a
/// sibling that reports: the generic sentence is dropped only where the parent has a message of its own.
/// Rows: a disjunction and a `when` condition, each with no message and two failing children (one that
/// reports "A failed", one a silent block), list both, in order; the same `when` with a message of its own
/// lists the sibling that reports (the message is for the case no child reports).
///
/// Fails when the silent block is missing from the listing (the sibling that reports made the
/// parent drop it), or when its sentence is not the generic one.
#[test]
fn a_parent_without_a_message_lists_a_silent_child_beside_a_reporting_sibling() {
    const GENERIC: &str =
        "the block clause failed, and none of the checks recorded under it reports why";
    let reporting = || EventRecord {
        context: String::from("GuardBlockAccessClause#1"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(String::from("A failed")),
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let silent = || EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![EventRecord {
            context: String::from("GuardBlockAccessClause#2"),
            container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: false,
                message: None,
                refusal: false,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            })),
            children: vec![],
        }],
    };
    let check = || BlockCheck {
        status: Status::FAIL,
        at_least_one_matches: false,
        raised: false,
        message: None,
        refusal: false,
        custom_message: None,
        gate_mark: false,
        frame_reads: Vec::new(),
    };
    let disjunction = EventRecord {
        context: String::from("Disjunction#1"),
        container: Some(RecordType::Disjunction(check())),
        children: vec![reporting(), silent()],
    };
    let when = |message: Option<&str>| EventRecord {
        context: String::from("WhenCondition#1"),
        container: Some(RecordType::WhenCheck(BlockCheck {
            message: message.map(String::from),
            raised: message.is_some(), // the fixture's records with a sentence model a raise's record
            ..check()
        })),
        children: vec![reporting(), silent()],
    };
    let messages_of = |clauses: &[ClauseReport<'_>]| -> Vec<Option<String>> {
        clauses
            .iter()
            .map(|clause| match clause {
                ClauseReport::Block(block) => block.messages.error_message.clone(),
                other => panic!("a block report, got {:?}", other),
            })
            .collect()
    };
    let both = vec![Some(String::from("A failed")), Some(String::from(GENERIC))];
    let in_a_disjunction = match report_all_failed_clauses_for_rules(&[disjunction]).as_slice() {
        [ClauseReport::Disjunctions(report)] => messages_of(&report.checks),
        other => panic!("one disjunction report, got {:?}", other),
    };
    assert_eq!(
        (both.clone(), both, vec![Some(String::from("A failed"))]),
        (
            in_a_disjunction,
            messages_of(&report_all_failed_clauses_for_rules(&[when(None)])),
            // The `when`'s sentence quotes the error the reporting sibling lists, so the sibling tells it.
            messages_of(&report_all_failed_clauses_for_rules(&[when(Some(
                &format!("{}A failed", crate::rules::eval::WHEN_UNEVALUATED_HEAD)
            ))])),
        ),
        "no message: both children listed; a message of its own: the reporting sibling alone"
    );
}

/// The walker's reading of a failed `when` condition. A RULE whose condition failed closed carries the
/// condition's explanation as its own message, which beats a silent block's generic sentence and keeps its
/// `checks` empty (the console names such a rule by its message when its checks are empty); a rule with NO
/// message lists the condition's silent block once. A type block's failed `TypeCondition` has no message
/// of its own, so its silent block is listed. A message-less block over three values that each hold the
/// same silent nested block lists the generic sentence once, not three times.
///
/// Fails when the rule with a message lists the generic sentence (or any check), when the rule
/// without one lists nothing or twice, when the type block's silent block is dropped, or when the
/// block lists three identical entries.
#[test]
fn a_failed_condition_is_walked_only_for_a_rule_without_a_message_and_generic_entries_are_not_repeated(
) {
    const GENERIC: &str =
        "the block clause failed, and none of the checks recorded under it reports why";
    let silent = || EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![EventRecord {
            context: String::from("GuardBlockAccessClause#2"),
            container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: false,
                message: None,
                refusal: false,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            })),
            children: vec![],
        }],
    };
    let gated_rule = |message: Option<&str>| EventRecord {
        context: String::from("gated"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "gated",
            status: Status::FAIL,
            message: message.map(String::from),
            slot: Default::default(),
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![EventRecord {
            context: String::from("Rule#gated/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children: vec![silent()],
        }],
    };
    let rule_messages = |record: &EventRecord<'_>| -> Vec<Option<String>> {
        match report_all_failed_clauses_for_rules(std::slice::from_ref(record)).as_slice() {
            [ClauseReport::Rule(rule)] => rule
                .checks
                .iter()
                .map(|check| match check {
                    ClauseReport::Block(block) => block.messages.error_message.clone(),
                    other => panic!("a block report under the rule, got {:?}", other),
                })
                .collect(),
            other => panic!("one rule report, got {:?}", other),
        }
    };
    // The real tree: TypeCheck(FAIL, message None) > TypeBlock(FAIL) > TypeCondition(FAIL) > the silent
    // block, so the row exercises the flag the TypeCheck arm computes (`generic_fallback && message
    // .is_none()`).
    let type_block = EventRecord {
        context: String::from("AWS::X::Y"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::X::Y",
            block: BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: false,
                message: None,
                refusal: false,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            },
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![EventRecord {
                context: String::from("TypeBlock/When"),
                container: Some(RecordType::TypeCondition(Status::FAIL)),
                children: vec![silent()],
            }],
        }],
    };
    let three_values = EventRecord {
        context: String::from("BlockGuardClause#1"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![silent(), silent(), silent()],
    };
    // The entry is kept once per CONTEXT: two silent blocks that are different clauses (different
    // contexts) are two findings, not one.
    let silent_at = |context: &str| EventRecord {
        context: String::from(context),
        ..silent()
    };
    let two_contexts = EventRecord {
        context: String::from("BlockGuardClause#1"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![
            silent_at("BlockGuardClause#2"),
            silent_at("BlockGuardClause#3"),
        ],
    };
    let listed = |record: &EventRecord<'_>| -> Vec<Option<String>> {
        report_all_failed_clauses_for_rules(std::slice::from_ref(record))
            .iter()
            .map(|clause| match clause {
                ClauseReport::Block(block) => block.messages.error_message.clone(),
                other => panic!("a block report, got {:?}", other),
            })
            .collect()
    };
    assert_eq!(
        (
            Vec::<Option<String>>::new(),
            vec![Some(String::from(GENERIC))],
            vec![Some(String::from(GENERIC))],
            vec![Some(String::from(GENERIC))],
            vec![Some(String::from(GENERIC)); 2],
        ),
        (
            rule_messages(&gated_rule(Some("the rule's condition could not be evaluated"))),
            rule_messages(&gated_rule(None)),
            listed(&type_block),
            listed(&three_values),
            listed(&two_contexts),
        ),
        "a rule with a message: empty checks; without: the silent block once; a type condition: listed; three values of one context: one entry; two contexts: two entries"
    );
}

/// A failed condition's records surface only where they carry the raise. A message-less failed rule whose
/// condition holds a DECIDED answer (a dependent rule that did not pass: the condition's own test of
/// whether the rule applies) beside a silent block lists the block's generic sentence alone, never the
/// decided answer as a finding.
///
/// Fails when the decided answer is listed as a clause report beside the block.
#[test]
fn a_failed_conditions_decided_answers_are_not_findings() {
    const GENERIC: &str =
        "the block clause failed, and none of the checks recorded under it reports why";
    let decided_no = EventRecord {
        context: String::from("gate"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::DependentRule(
            crate::rules::MissingValueCheck {
                rule: "gate",
                message: None,
                custom_message: None,
                status: Status::FAIL,
                failure: None,
            },
        ))),
        children: vec![],
    };
    let silent = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![EventRecord {
            context: String::from("GuardBlockAccessClause#2"),
            container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: false,
                message: None,
                refusal: false,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            })),
            children: vec![],
        }],
    };
    let rule = EventRecord {
        context: String::from("gated"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "gated",
            status: Status::FAIL,
            message: None,
            slot: Default::default(),
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![EventRecord {
            context: String::from("Rule#gated/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children: vec![decided_no, silent],
        }],
    };
    let kinds: Vec<Option<String>> =
        match report_all_failed_clauses_for_rules(std::slice::from_ref(&rule)).as_slice() {
            [ClauseReport::Rule(rule)] => rule
                .checks
                .iter()
                .map(|check| match check {
                    ClauseReport::Block(block) => block.messages.error_message.clone(),
                    ClauseReport::Clause(_) => Some(String::from("a clause finding")),
                    other => panic!("a block or clause report, got {:?}", other),
                })
                .collect(),
            other => panic!("one rule report, got {:?}", other),
        };
    assert_eq!(
        vec![Some(String::from(GENERIC))],
        kinds,
        "the silent block is listed once and the decided answer is not a finding"
    );
}

/// A rule that failed closed on its condition names EVERY refusal the condition met, once, in its own
/// message, and lists no checks. The condition's explanation carries the ONE error the conjunction held;
/// a condition of two disjuncts that each refuse also met the other's refusal, which the clause-error
/// records beneath the failed condition name. Rows: the second refusal is added to the message after
/// the held one's (`; the condition also met: ..`); the held refusal, which the message already carries,
/// is not repeated; `checks` stays empty for the console, which names such a rule by its message.
///
/// Fails when the message lacks the second sentence (the refusal is dropped), carries the first
/// twice, or when `checks` is not empty.
#[test]
fn a_rule_that_failed_on_its_condition_names_every_refusal_the_condition_met_once() {
    const FIRST: &str = "the read of `A` was refused";
    const SECOND: &str = "the read of `B` was refused";
    let clause_error = |sentence: &str| EventRecord {
        context: String::from("GuardAccessClause#blockA"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            // Built by the writer's own function, so a change to the wrapper's wording is caught here and
            // not hidden by a hand-copied string.
            message: Some(crate::rules::eval::clause_error_message(
                &crate::rules::errors::Error::undecidable(sentence.to_string()),
            )),
            refusal: true,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let rule = EventRecord {
        context: String::from("gated"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "gated",
            status: Status::FAIL,
            message: Some(format!(
                "The rule's condition could not be evaluated, so the rule fails rather than being treated as not applicable: {FIRST}"
            )),
            slot: crate::rules::CustomSlot::Refusal,
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![EventRecord {
            context: String::from("Rule#gated/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children: vec![clause_error(FIRST), clause_error(SECOND)],
        }],
    };
    let (message, checks) = match report_all_failed_clauses_for_rules(&[rule]).as_slice() {
        [ClauseReport::Rule(rule)] => (rule.messages.custom_message.clone(), rule.checks.len()),
        other => panic!("one rule report, got {:?}", other),
    };
    assert_eq!(
        (
            Some(format!(
                "The rule's condition could not be evaluated, so the rule fails rather than being treated as not applicable: {FIRST}; the condition also met: {SECOND}"
            )),
            0
        ),
        (message, checks),
        "the second refusal is added once and the first is not repeated; checks stay empty"
    );
}

/// A gate block over N refused body values is listed ONCE, by its own record: the gate role's marks (one
/// childless refused-body record per value, carrying the refusal's bare sentence) feed the failed
/// condition's sentence walk and are never entries. Under a message-less failed rule's condition the block's
/// record is the only check, and the console and `-o json` list it once, not once per refused value.
///
/// Fails when the rule lists three checks (a mark became an entry), or none (the block's own record
/// was replaced by nothing).
#[test]
fn a_gate_block_over_three_refused_values_is_listed_once_and_its_marks_are_never_entries() {
    let mark = |sentence: &str| EventRecord {
        context: "GuardBlockAccessClause#2".to_string(),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(sentence.to_string()),
            refusal: true,
            custom_message: None,
            gate_mark: true,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let block = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![
            mark("the read of `A` was refused"),
            mark("the read of `B` was refused"),
            mark("the read of `C` was refused"),
        ],
    };
    let rule = EventRecord {
        context: String::from("gated"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "gated",
            status: Status::FAIL,
            message: None,
            slot: Default::default(),
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![EventRecord {
            context: String::from("Rule#gated/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children: vec![block],
        }],
    };
    let listed = match report_all_failed_clauses_for_rules(&[rule]).as_slice() {
        [ClauseReport::Rule(rule)] => rule
            .checks
            .iter()
            .map(|check| match check {
                ClauseReport::Block(block) => format!(
                    "block {} :: {} refusal={}",
                    block.context,
                    block.messages.error_message.clone().unwrap_or_default(),
                    block.messages.refusal
                ),
                other => format!("other {other:?}"),
            })
            .collect::<Vec<_>>(),
        other => panic!("one rule report, got {:?}", other),
    };
    assert_eq!(
        vec![String::from(
            "block BlockGuardClause#2 :: the read of `A` was refused; the read of `B` was refused; the read of `C` was refused refusal=true"
        )],
        listed,
        "the block is listed once by its own record, which tells the three refusals once each; the marks are not entries"
    );
}

/// A STRICT-role refusal record is never taken for a gate's mark: the own-key refusal per value, and the
/// refused one-object selection beside siblings, are childless failed raised refusals with a sentence in the
/// block's own `GuardBlockAccessClause#` context, exactly the shape a mark had, and they are findings. Under
/// a block that holds one of them and nothing else, the block is listed with the refusal's sentence and the
/// refusal flag, never by "query for block clause did not retrieve any value" and never dropped.
///
/// Fails when the entry reads the retrieval sentence or the silent-block sentence, when the flag is
/// false, or when the record is not listed.
#[test]
fn a_strict_role_refusal_record_under_a_block_is_listed_with_its_sentence_and_flag() {
    const REFUSAL: &str = "the read of `Cfg` was refused, at path /Resources/R/Cfg";
    let strict_record = EventRecord {
        context: String::from("GuardBlockAccessClause#2"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(REFUSAL.to_string()),
            refusal: true,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let block = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![strict_record],
    };
    let listed: Vec<(String, bool)> = report_all_failed_clauses_for_rules(&[block])
        .iter()
        .map(|clause| match clause {
            ClauseReport::Block(block) => (
                block.messages.error_message.clone().unwrap_or_default(),
                block.messages.refusal,
            ),
            other => panic!("a block entry, got {:?}", other),
        })
        .collect();
    assert_eq!(
        vec![(REFUSAL.to_string(), true)],
        listed,
        "the strict role's refusal record is an entry with its sentence and its flag"
    );
}

/// Builds a root scope and registers the given refusal sentences, as a run does, so a cell that dedupes
/// refusals reads the registry's tokens (the path a real run takes) and not only the text match. The scope
/// lives until the end of the calling block.
macro_rules! registered_as_in_a_run {
    ($($text:expr),+ $(,)?) => {
        let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
        let _root = root_scope(
            &rules_file,
            Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
        );
        $( let _ = register_refusal($text); )+
    };
}

/// A refused body value beside a LATER value's run-ending error: the block's own record is raised with no
/// message (the error that ended the run is told elsewhere), and the earlier value's refusal is carried by
/// a gate mark. The mark is no entry. Where no parent speaks (the generic fallback is allowed) the block's
/// own entry tells the refusal, once, flagged a refusal, instead of the silent-block sentence. Where a
/// parent SPEAKS (a type block whose record carries the "bailing" sentence of the error that ended the run)
/// a marked block never displaces that sentence and lists no entry of its own: the parent's sentence stays
/// first and whole, the refusal is joined to it once, and the flag stays the plain error's.
///
/// Fails when the block is skipped or listed by the silent-block sentence under no parent, when the
/// refusal is named twice, when under the speaking parent the "bailing" sentence is missing or
/// replaced by the refusal alone, or when a child entry is listed beside it.
#[test]
fn a_refusal_a_mark_carries_beside_a_run_ending_error_is_told_once_by_the_block() {
    const REFUSAL: &str = "the read of `A` was refused, at path /Resources/A/Tags";
    const BAILING: &str = "Error a plain error during type condition evaluation, bailing";
    registered_as_in_a_run!(REFUSAL);
    let mark = || EventRecord {
        context: "GuardBlockAccessClause#2".to_string(),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(REFUSAL.to_string()),
            refusal: true,
            custom_message: None,
            gate_mark: true,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let block = || EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![mark(), mark()],
    };
    let listed = |records: &[EventRecord<'_>], fallback: bool| -> Vec<(String, bool)> {
        report_failed_clauses(records, fallback, false)
            .iter()
            .map(|clause| match clause {
                ClauseReport::Block(block) => (
                    block.messages.error_message.clone().unwrap_or_default(),
                    block.messages.refusal,
                ),
                other => panic!("a block entry, got {:?}", other),
            })
            .collect()
    };
    // No parent speaks: the generic fallback is allowed, the block tells the refusal itself.
    assert_eq!(
        vec![(REFUSAL.to_string(), true)],
        listed(&[block()], true),
        "the refusal is told once by the block's own entry, and the same refusal marked twice is one"
    );
    // A type block that speaks: TypeCheck > TypeBlock > TypeCondition > the marked block.
    let type_check = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(crate::rules::TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: true,
                message: Some(BAILING.to_string()),
                refusal: false,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            },
        })),
        children: vec![EventRecord {
            context: String::from("Type#block"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![EventRecord {
                context: String::from("Type#condition"),
                container: Some(RecordType::TypeCondition(Status::FAIL)),
                children: vec![block()],
            }],
        }],
    };
    assert_eq!(
        vec![(format!("{BAILING}{ALSO_MET}{REFUSAL}"), false)],
        listed(&[type_check], true),
        "the parent's sentence is first and whole, the refusal is joined once, the flag is the plain error's, and the block lists no entry"
    );
}

/// A refusal in a type block's failed condition is told once whichever way the block is listed: the type
/// block's `when` fails closed over two refused values, each carried by a mark beneath a block that gives
/// no entry of its own, so the type block's sentence joins both refusals (the condition of a type block is
/// read like a rule's and an inline `when`'s). Read on the REAL record tree the evaluator writes
/// (`TypeCheck` > `TypeBlock` > `TypeCondition` > the block > its marks) through
/// `report_all_failed_clauses_for_rules` under a failed rule with no sentence of its own, and through
/// `sentence_and_whether_refusals_joined` over the condition alone.
///
/// Fails when the sentence names neither refusal, one of them, or one twice; or when the walk
/// of the real tree does not descend through `TypeBlock` to the condition (the refusals are
/// lost there).
#[test]
fn a_type_blocks_failed_condition_joins_the_refusals_its_marks_carry() {
    const FIRST: &str = "the read of `A` was refused, at path /Resources/A/Tags";
    const SECOND: &str = "the read of `B` was refused, at path /Resources/B/Tags";
    let mark = |refusal: &str| EventRecord {
        context: "GuardBlockAccessClause#2".to_string(),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(refusal.to_string()),
            refusal: true,
            custom_message: None,
            gate_mark: true,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let silent_block = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![mark(FIRST), mark(SECOND), mark(FIRST)],
    };
    // The shape the evaluator writes: the type block's children are one `TypeBlock` per resource, the
    // condition one level down.
    let per_resource = vec![EventRecord {
        context: String::from("Type#block"),
        container: Some(RecordType::TypeBlock(Status::FAIL)),
        children: vec![EventRecord {
            context: String::from("Type#condition"),
            container: Some(RecordType::TypeCondition(Status::FAIL)),
            children: vec![silent_block],
        }],
    }];
    let head = "Error a plain error during type condition evaluation, bailing";
    let (text, parts) =
        sentence_and_whether_refusals_joined(head, &per_resource, SentenceSlot::Error);
    assert_eq!(
        (
            format!("{head}{ALSO_MET}{FIRST}; {SECOND}"),
            Some(format!("{FIRST}; {SECOND}"))
        ),
        (text, parts.map(|parts| parts.message().to_string())),
        "both refusals, once each, after the type block's own sentence"
    );
    // The same tree through the report walk, under a failed rule with no sentence of its own: one check,
    // the type block's joined sentence, and no entry for the block or its marks.
    let type_check = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(crate::rules::TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: true,
                message: Some(head.to_string()),
                refusal: false,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            },
        })),
        children: per_resource,
    };
    let gate = EventRecord {
        context: String::from("gate"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "gate",
            status: Status::FAIL,
            message: None,
            slot: crate::rules::CustomSlot::Evaluator,
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![type_check],
    };
    let reports = report_all_failed_clauses_for_rules(&[gate]);
    let checks: Vec<String> = match reports.as_slice() {
        [ClauseReport::Rule(rule)] => rule
            .checks
            .iter()
            .map(|check| match check {
                ClauseReport::Block(block) => {
                    block.messages.error_message.clone().unwrap_or_default()
                }
                other => panic!("a block entry, got {:?}", other),
            })
            .collect(),
        other => panic!("one rule report, got {:?}", other),
    };
    assert_eq!(
        vec![format!("{head}{ALSO_MET}{FIRST}; {SECOND}")],
        checks,
        "the real tree lists the type block once, with both refusals joined"
    );
}

/// A gate mark beside a body clause that reports the SAME refusal lists it once: the clause's own entry
/// carries it (its clause-error record wraps the same sentence the mark carries bare), so the block adds no
/// entry of its own for the mark. A mark naming a DIFFERENT refusal is the block's to tell: one extra entry.
///
/// Fails when the first row lists the refusal twice (the mark's entry beside the clause's), or when
/// the second row lists no entry for the other refusal.
#[test]
fn a_mark_beside_a_body_clause_reporting_the_same_refusal_lists_it_once() {
    const SAME: &str = "the read of `A` was refused, at path /Resources/A/Tags";
    const OTHER: &str = "the read of `B` was refused, at path /Resources/B/Tags";
    registered_as_in_a_run!(SAME, OTHER);
    let mark = |refusal: &str| EventRecord {
        context: "GuardBlockAccessClause#2".to_string(),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(refusal.to_string()),
            refusal: true,
            custom_message: None,
            gate_mark: true,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let body_clause = EventRecord {
        context: String::from("GuardAccessClause#blockA"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(crate::rules::eval::clause_error_message(
                &crate::rules::errors::Error::undecidable(SAME.to_string()),
            )),
            refusal: true,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let block = |marks: Vec<EventRecord<'static>>| {
        let mut children = vec![body_clause.clone()];
        children.extend(marks);
        EventRecord {
            context: String::from("BlockGuardClause#2"),
            container: Some(RecordType::BlockGuardCheck(BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: true,
                message: None,
                refusal: false,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            })),
            children,
        }
    };
    let texts = |marks: Vec<EventRecord<'static>>| -> Vec<String> {
        report_failed_clauses(&[block(marks)], true, false)
            .iter()
            .map(|clause| match clause {
                ClauseReport::Block(block) => {
                    block.messages.error_message.clone().unwrap_or_default()
                }
                other => panic!("a block entry, got {:?}", other),
            })
            .collect()
    };
    let same = texts(vec![mark(SAME), mark(SAME)]);
    let other = texts(vec![mark(SAME), mark(OTHER)]);
    assert_eq!(
        (1, 2, 1),
        (
            same.iter().filter(|text| text.contains(SAME)).count(),
            other.len(),
            other.iter().filter(|text| text.as_str() == OTHER).count(),
        ),
        "the same refusal is one entry; the other refusal is one entry more, alone: {same:?} / {other:?}"
    );
}

/// Every mark's refusal is told exactly once and never silently, by a parent that speaks. Two shapes in
/// which a reporter that left the marks to a parent's unwritten sentence would lose them:
/// - a type block's `when` whose condition holds a clause-error sibling entry (of the very error that stopped
///   the block, which the block's "bailing" sentence wraps too) AND a message-less child block with marks:
///   the error is told once, by the sibling (the parent's sentence is not written beside it, since an entry
///   carries its error), and the marks' refusal once, as an entry of its own after the entries beneath;
/// - a block with a message of its own over a message-less child block with marks and no entry beneath: the
///   marks are the deep ones beneath it, and its sentence joins them once.
#[test]
fn a_speaking_parent_tells_each_deep_mark_once_as_an_entry_beside_its_entries_or_joined_when_it_has_none(
) {
    use frame_sources::{block_check, mark, HELD, OTHER};
    // The sentence of a bailing type block quotes the error that stopped it, the one the clause-error
    // sibling below tells.
    let bailing = format!("Error {OTHER} during type condition evaluation, bailing");
    registered_as_in_a_run!(HELD, OTHER);
    let silent_block_over_marks = |marks: Vec<EventRecord<'static>>| EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![EventRecord {
            context: String::from("BlockGuardClause#3"),
            container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
            children: marks,
        }],
    };
    let texts = |records: &[EventRecord<'static>]| -> Vec<String> {
        report_failed_clauses(records, true, false)
            .iter()
            .map(|clause| match clause {
                ClauseReport::Block(block) => {
                    block.messages.error_message.clone().unwrap_or_default()
                }
                other => panic!("a block entry, got {:?}", other),
            })
            .collect()
    };
    // Shape one: TypeCheck{bailing} > TypeBlock > TypeCondition > [clause-error sibling, silent block over marks].
    let clause_error_sibling = EventRecord {
        context: String::from("GuardAccessClause#blockA"),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            Some(crate::rules::eval::clause_error_message(
                &crate::rules::errors::Error::undecidable(OTHER.to_string()),
            )),
            true,
            false,
        ))),
        children: vec![],
    };
    let type_check = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(crate::rules::TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(Some(bailing), false, false),
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock#S3/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![EventRecord {
                context: String::from("Type#condition"),
                container: Some(RecordType::TypeCondition(Status::FAIL)),
                children: vec![
                    clause_error_sibling,
                    silent_block_over_marks(vec![mark(HELD), mark(HELD)]),
                ],
            }],
        }],
    };
    let listed = texts(&[type_check]);
    // The type block's sentence wraps the SAME error the clause-error sibling already tells (`OTHER`), as a
    // bailing type block's does: it is not listed beside the sibling, so no error text is told twice, and
    // the marks' refusal follows as an entry of its own, once.
    assert_eq!(
        (2, 1, Some(HELD.to_string()), 1, 0),
        (
            listed.len(),
            listed.iter().filter(|text| text.contains(HELD)).count(),
            listed.last().cloned(),
            listed.iter().filter(|text| text.contains(OTHER)).count(),
            listed
                .iter()
                .filter(|text| text.contains("bailing"))
                .count(),
        ),
        "the sibling entry (the error once), then the marks' refusal alone, once: {:?}",
        listed
    );
    // Shape two: BlockGuardCheck{message} > silent block > marks.
    let speaking_block = EventRecord {
        context: String::from("BlockGuardClause#1"),
        container: Some(RecordType::BlockGuardCheck(block_check(
            Some(String::from("the block says")),
            false,
            false,
        ))),
        children: vec![silent_block_over_marks(vec![mark(HELD)])],
    };
    assert_eq!(
        vec![format!(
            "the block says{}{HELD}",
            crate::rules::eval_context::BODY_ALSO_MET
        )],
        texts(&[speaking_block]),
        "the block's own sentence joins the deep marks of its silent child block, once"
    );
}

/// A body clause whose own per-value record reports the refusal, beside a mark for the same refusal: the
/// refusal is told once. The clause's clause-error block entry is suppressed when its own per-value record
/// reports (`an_own_value_check_reports`). The per-value record of a missing block value is listed as a
/// BLOCK entry in the clause's own context (`Y`), carrying the bare refusal, so this cell asserts one block
/// entry, in that context, and no entry for the mark. The `PartsJoin::Clause` branch of `entry_texts_of`
/// (an entry built from parts, whose rendered text ends `Error = [R]` with no `: ` boundary before R) is
/// the cell `a_refusal_a_real_clause_entry_reports_is_carried_through_its_parts`.
///
/// Fails when R is listed twice (the block's own entry beside the clause's).
#[test]
fn a_refusal_a_clause_entry_reports_beside_a_mark_for_it_is_listed_once() {
    use frame_sources::{block_check, mark, HELD};
    registered_as_in_a_run!(HELD);
    let body_clause = EventRecord {
        context: String::from("GuardAccessClause#blockY"),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            Some(crate::rules::eval::clause_error_message(
                &crate::rules::errors::Error::undecidable(HELD.to_string()),
            )),
            true,
            false,
        ))),
        children: vec![EventRecord {
            context: String::from("Y"),
            container: Some(RecordType::ClauseValueCheck(
                ClauseCheck::MissingBlockValue(ValueCheck {
                    from: QueryResult::UnResolved(UnResolved {
                        traversed_to: Rc::new(
                            PathAwareValue::try_from("{ A: 1 }").expect("parses"),
                        ),
                        remaining_query: String::new(),
                        reason: Some(HELD.to_string()),
                        kind: UnResolvedKind::Undecidable {
                            refusal: Some(crate::rules::errors::RefusalToken::minted(7)),
                            carried: None,
                        },
                    }),
                    message: Some(HELD.to_string()),
                    custom_message: None,
                    status: Status::FAIL,
                    refusal: true,
                }),
            )),
            children: vec![],
        }],
    };
    let block = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![body_clause, mark(HELD)],
    };
    let entries = report_failed_clauses(&[block], true, false);
    // The per-value record of a missing block value is reported as a BLOCK entry in the clause's own context
    // (`Y`), not as a clause entry: the first form of this assertion asked for the variant and read red on a
    // report that listed the refusal once. The property is the count and the context: one entry, the
    // clause's own, naming the refusal; the block adds none.
    let listed: Vec<(String, String)> = entries
        .iter()
        .map(|entry| match entry {
            ClauseReport::Block(block) => (
                block.context.clone(),
                block.messages.error_message.clone().unwrap_or_default(),
            ),
            other => panic!("a block entry, got {:?}", other),
        })
        .collect();
    assert_eq!(
        vec![("Y".to_string(), HELD.to_string())],
        listed,
        "one entry, the clause's own per-value entry, carries the refusal, and the block adds none"
    );
}

/// A parent's own sentence is told exactly once, whatever the entries beneath it are. A child `when` with no
/// sentence lists a marks-only entry; that entry carries the marks' refusals and nothing else, so it never
/// tells the parent's sentence, which is written as the parent's own entry beside the entries:
/// - a bailing type block (a plain error that ended the run) whose only entry is a child `when`'s marks-only
///   entry: the bailing sentence once, the marks' refusal once;
/// - a block with its own refusal as its sentence over a message-less child `when` with marks: both
///   refusals once;
/// - a block with a plain error as its sentence (the evaluator's `Error {e}` wording) beside an entry that
///   names a DIFFERENT error: the sentence stays.
///
/// A parent whose text is none of the evaluator's sentences (the author's `<< >>` text) keeps the base rule
/// instead: beside entries that report it is not written
/// (`a_parent_with_a_message_drops_a_silent_child_beside_a_reporting_sibling`).
#[test]
fn a_parents_own_sentence_is_told_once_beside_the_marks_only_entry_of_a_child() {
    use frame_sources::{block_check, mark, refused_clause, type_block, when_block, HELD, OTHER};
    registered_as_in_a_run!(HELD, OTHER);
    use crate::rules::eval::{BLOCK_CLAUSE_BAILING_TAIL, TYPE_CONDITION_BAILING_TAIL};
    const PLAIN: &str = "a plain error that ended the run";
    const PLAIN_SENTENCE: &str = "a different plain error";
    let silent_block_over_a_mark = || EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![mark(HELD)],
    };
    let texts = |record: EventRecord<'static>| -> Vec<String> {
        report_failed_clauses(&[record], true, false)
            .iter()
            .map(|clause| match clause {
                ClauseReport::Block(block) => {
                    block.messages.error_message.clone().unwrap_or_default()
                }
                other => panic!("a block entry, got {:?}", other),
            })
            .collect()
    };
    let count = |listed: &[String], needle: &str| {
        listed.iter().filter(|text| text.contains(needle)).count()
    };

    let bailing = format!("Error {PLAIN}{TYPE_CONDITION_BAILING_TAIL}");
    let listed = texts(type_block(
        Some(bailing),
        &[],
        vec![when_block(None, &[], vec![silent_block_over_a_mark()])],
    ));
    assert_eq!(
        (2, 1, 1),
        (listed.len(), count(&listed, PLAIN), count(&listed, HELD)),
        "the bailing sentence once and the marks' refusal once: {:?}",
        listed
    );

    let block_with_a_refusal = EventRecord {
        context: String::from("BlockGuardClause#1"),
        container: Some(RecordType::BlockGuardCheck(block_check(
            Some(OTHER.to_string()),
            true,
            false,
        ))),
        children: vec![when_block(None, &[], vec![silent_block_over_a_mark()])],
    };
    let listed = texts(block_with_a_refusal);
    assert_eq!(
        (2, 1, 1),
        (listed.len(), count(&listed, OTHER), count(&listed, HELD)),
        "the block's own refusal once and the child's marks once: {:?}",
        listed
    );

    let block_beside_another_error = EventRecord {
        context: String::from("BlockGuardClause#1"),
        container: Some(RecordType::BlockGuardCheck(block_check(
            Some(format!("Error {PLAIN_SENTENCE}{BLOCK_CLAUSE_BAILING_TAIL}")),
            false,
            false,
        ))),
        children: vec![refused_clause(HELD)],
    };
    let listed = texts(block_beside_another_error);
    assert_eq!(
        (1, 1),
        (count(&listed, PLAIN_SENTENCE), count(&listed, HELD)),
        "the sentence stays beside an entry that names a different error: {:?}",
        listed
    );
}

/// A sentence-bearing block under a `when` condition is a record the report never visits (nothing under
/// `WhenCondition(FAIL)` is reported on its own), and the walk of the marks stops at a block with a sentence
/// of its own: the refusal its mark names is told by the entry the `when` lists for the refusals beneath it
/// (`marks_alone_entry`, which reads the condition's refusals too), once, and the converted read it names is
/// told, so the debug tripwire holds. The same shape under a `TypeCondition`, which IS walked, is the cell
/// `a_type_block_with_no_sentence_over_a_silent_block_of_two_marks_lists_each_once`.
#[test]
fn a_sentence_bearing_block_under_a_when_condition_has_its_mark_told_once() {
    use crate::rules::{RecordType, Status};
    use frame_sources::{block_check, mark, under_a_condition, when_block, HELD};
    registered_as_in_a_run!(HELD);
    let block_with_a_sentence = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(
            Some(String::from("m")),
            false,
            false,
        ))),
        children: vec![mark(HELD)],
    };
    let record = when_block(
        None,
        &[HELD],
        vec![under_a_condition(
            RecordType::WhenCondition(Status::FAIL),
            vec![block_with_a_sentence],
        )],
    );
    let listed: Vec<String> = report_all_failed_clauses_for_rules(&[record])
        .iter()
        .map(|clause| match clause {
            ClauseReport::Block(block) => block.messages.error_message.clone().unwrap_or_default(),
            other => panic!("a block entry, got {:?}", other),
        })
        .collect();
    assert_eq!(
        1,
        listed.iter().filter(|text| text.contains(HELD)).count(),
        "the refusal once: {:?}",
        listed
    );
}

/// The same shape inside a rule that has a text of its own (a call's `<< >>` body): the message-less `when`
/// writes no entry there, and the rule's sentence tells the refusal the block under the `when`'s condition
/// names, once; the debug tripwire for the `when`'s converted read holds. Nothing under a `when` condition is
/// reported on its own, and the walk of the marks stops at the block with a sentence, so only the rule's
/// sentence can tell it (`reached_deferred_refusals`).
#[test]
fn a_sentence_bearing_block_under_a_when_condition_in_a_bodied_rule_has_its_mark_told_once() {
    use crate::rules::{CustomSlot, RecordType, Status};
    use frame_sources::{block_check, mark, rule, under_a_condition, when_block, HELD};
    registered_as_in_a_run!(HELD);
    let block_with_a_sentence = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(
            Some(String::from("m")),
            false,
            false,
        ))),
        children: vec![mark(HELD)],
    };
    let record = rule(
        Some(String::from("the author's body")),
        None,
        CustomSlot::Author,
        &[],
        vec![when_block(
            None,
            &[HELD],
            vec![under_a_condition(
                RecordType::WhenCondition(Status::FAIL),
                vec![block_with_a_sentence],
            )],
        )],
    );
    let reports = report_all_failed_clauses_for_rules(&[record]);
    let (recorded, read) = texts_and_reader_messages(&reports[0]);
    let count = |texts: &[String]| {
        texts
            .iter()
            .map(|text| text.matches(HELD).count())
            .sum::<usize>()
    };
    assert_eq!(
        (1, 1),
        (count(&recorded), count(&read)),
        "the refusal once in the report and once for the readers: recorded {:?}, read {:?}",
        recorded,
        read
    );
}

/// A disjunction whose held error is a plain error (a spent regex budget: no registered refusal) beside
/// disjunct entries that already name it in their clause-error wrapper writes no sentence of its own: the
/// error is told once, by the entries. The disjunction's sentence is its head and the error it held
/// (`DISJUNCTION_UNDECIDED_HEAD`), which is stripped to read the error, as the `when` head and the rule
/// head are.
#[test]
fn a_disjunction_whose_held_error_its_entries_name_does_not_write_its_sentence_beside_them() {
    use crate::rules::eval::{DISJUNCTION_UNDECIDED_HEAD, WHEN_UNEVALUATED_HEAD};
    use frame_sources::block_check;
    const HELD_ERROR: &str = "the regex engine spent its budget";
    let entry = || EventRecord {
        context: String::from("GuardAccessClause#blockA"),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            Some(format!("Error {HELD_ERROR} when handling clause, bailing")),
            false,
            false,
        ))),
        children: vec![],
    };
    for head in [DISJUNCTION_UNDECIDED_HEAD, WHEN_UNEVALUATED_HEAD] {
        let disjunction = EventRecord {
            context: String::from("Disjunction#1"),
            container: Some(RecordType::Disjunction(block_check(
                Some(format!("{head}{HELD_ERROR}")),
                false,
                false,
            ))),
            children: vec![entry()],
        };
        let reports = report_failed_clauses(&[disjunction], true, false);
        let texts: Vec<String> = match reports.as_slice() {
            [ClauseReport::Disjunctions(report)] => report
                .checks
                .iter()
                .map(|check| match check {
                    ClauseReport::Block(block) => {
                        block.messages.error_message.clone().unwrap_or_default()
                    }
                    other => panic!("a block entry, got {:?}", other),
                })
                .collect(),
            other => panic!("one disjunction report, got {:?}", other),
        };
        assert_eq!(
            (1, 0),
            (
                texts
                    .iter()
                    .map(|text| text.matches(HELD_ERROR).count())
                    .sum::<usize>(),
                texts.iter().filter(|text| text.starts_with(head)).count()
            ),
            "the held error once, by the entry, and no sentence of the disjunction's own behind {:?}: {:?}",
            head,
            texts
        );
    }
}

/// The "bailing" tails are the writers' constants (`eval::TYPE_CONDITION_BAILING_TAIL` and its siblings): a
/// sentence built with them reads back to the error it quotes, and an entry that carries that error tells
/// the sentence, so a change of wording in the writers moves the reader with it.
#[test]
fn a_bailing_sentence_built_from_the_writers_tails_reads_back_to_its_quoted_error() {
    use crate::rules::eval::{
        BLOCK_CLAUSE_BAILING_TAIL, TYPE_BLOCK_BAILING_TAIL, TYPE_CONDITION_BAILING_TAIL,
    };
    const QUOTED: &str = "a plain error the sentence quotes";
    let entry = ClauseReport::Block(GuardBlockReport {
        context: String::from("GuardAccessClause#blockA"),
        messages: Messages {
            error_message: Some(format!("Error {QUOTED} when handling clause, bailing")),
            custom_message: None,
            location: None,
            refusal: false,
            parts: None,
        },
        unresolved: None,
    });
    let entries = [entry];
    for tail in [
        TYPE_CONDITION_BAILING_TAIL,
        TYPE_BLOCK_BAILING_TAIL,
        BLOCK_CLAUSE_BAILING_TAIL,
    ] {
        let sentence = format!("Error {QUOTED}{tail}");
        assert_eq!(
            QUOTED,
            quoted_error(&sentence),
            "the quoted error of {:?}",
            tail
        );
        assert!(
            sentence_told_by(&entries, &sentence),
            "an entry carrying the quoted error tells the sentence with the tail {:?}",
            tail
        );
        assert!(
            !sentence_told_by(&[], &sentence),
            "no entry, no telling: {:?}",
            tail
        );
    }
}

/// A sentence that gained all three groups of refusals keeps them apart: the record's own condition's refusal
/// C1 behind "the condition also met", a nested condition's N1 behind "a nested condition also met" and the
/// body's mark B1 behind "a body clause also met". The parts hold the three groups as three fields,
/// `message()` is the refusals alone with no joiner text inside, the rebuilt sentence is the stored one, and
/// the dedupe parse finds all three refusals in it.
#[test]
fn a_sentence_with_three_groups_of_refusals_keeps_them_apart() {
    use crate::rules::eval_context::{
        BODY_ALSO_MET, NESTED_ALSO_MET, RULE_FAILED_ON_AN_ERROR_HEAD,
    };
    const C1: &str = "the read of `C` was refused, at path /Resources/C/Tags";
    const N1: &str = "the read of `N` was refused, at path /Resources/N/Tags";
    const B1: &str = "the read of `B` was refused, at path /Resources/B/Tags";
    registered_as_in_a_run!(C1, N1, B1);
    let (text, parts) = rule_sentence_with(
        RULE_FAILED_ON_AN_ERROR_HEAD,
        vec![C1.to_string()],
        vec![N1.to_string()],
        vec![B1.to_string()],
        SentenceSlot::Error,
    );
    let parts = parts.expect("three refusals joined");
    assert_eq!(
        (
            format!(
                "{RULE_FAILED_ON_AN_ERROR_HEAD}{ALSO_MET}{C1}{NESTED_ALSO_MET}{N1}{BODY_ALSO_MET}{B1}"
            ),
            parts.refusals_text(),
            C1,
            N1,
            B1,
            format!("{C1}; {N1}; {B1}"),
        ),
        (
            text.clone(),
            text,
            parts.condition(),
            parts.nested(),
            parts.marks(),
            parts.message().to_string(),
        ),
        "the text, the rebuilt text, the three groups, and the refusals alone with no joiner inside"
    );
    let carried = refusals_carried_by(&parts.refusals_text());
    let (c1, n1, b1) = (
        carried.iter().any(|(text, _)| text == C1),
        carried.iter().any(|(text, _)| text == N1),
        carried.iter().any(|(text, _)| text == B1),
    );
    assert!(
        c1 && n1 && b1,
        "the parse finds all three refusals: C1 {}, N1 {}, B1 {}",
        c1,
        n1,
        b1
    );
}

/// A refusal whose own text holds a `; ` (a remedy sentence) is carried as a whole wherever it stands in a
/// joined text: first, in the middle and last, with other refusals before and after it. Fails when the parse
/// of a joined sentence reads only the suffixes after a boundary, which finds such a refusal only as the
/// last one and lets a second entry name it again.
#[test]
fn a_refusal_whose_text_holds_a_semicolon_is_carried_whole_before_and_after_others() {
    const SEMI: &str = "the object holds `Env`; write the predicate over a key it holds";
    const R2: &str = "the read of `B` was refused, at path /Resources/B/Tags";
    const R3: &str = "the read of `C` was refused, at path /Resources/C/Tags";
    registered_as_in_a_run!(SEMI, R2, R3);
    let held = |carried: &[(String, Option<crate::rules::eval_context::RefusalToken>)],
                text: &str| { carried.iter().any(|(seen, _)| seen == text) };
    for (label, joined) in [
        ("first", format!("HEAD: {SEMI}; {R2}; {R3}")),
        ("middle", format!("HEAD: {R2}; {SEMI}; {R3}")),
        ("last", format!("HEAD: {R2}; {R3}; {SEMI}")),
    ] {
        let carried = refusals_carried_by(&joined);
        assert!(
            held(&carried, SEMI) && held(&carried, R2) && held(&carried, R3),
            "{} position: all three are carried whole, SEMI {}, R2 {}, R3 {}",
            label,
            held(&carried, SEMI),
            held(&carried, R2),
            held(&carried, R3)
        );
    }
}

/// A numbered raise `(1) R1 (2) R2` is registered as its parts and never as a whole. With a `; ` inside R1 and
/// a joiner after R2, every one of R1, R2 and the refusal R3 behind the joiner is carried: the span
/// `(1) R1 (2) R2` is kept because its numbered parts are registered refusals. Fails when the span is
/// skipped for having no token of its own, which carries R1 only as a fragment and leaves R2 unrecognized
/// (told twice by the join, or dropped by the test of whether a sentence is told).
#[test]
fn a_numbered_raise_of_refusals_with_semicolons_is_carried_part_by_part() {
    const R1: &str = "the object holds `Env`; write the predicate over a key it holds";
    const R2: &str = "the read of `B` was refused, at path /Resources/B/Tags";
    const R3: &str = "the read of `C` was refused, at path /Resources/C/Tags";
    registered_as_in_a_run!(R1, R2, R3);
    let sentence = format!("HEAD: (1) {R1} (2) {R2}{ALSO_MET}{R3}");
    let carried = refusals_carried_by(&sentence);
    let held = |text: &str| carried.iter().filter(|(seen, _)| seen == text).count();
    assert_eq!(
        (1, 1, 1),
        (held(R1), held(R2), held(R3)),
        "each part of the numbered raise and the refusal behind the joiner, carried once"
    );
}

/// The dedupe side: a mark for a refusal whose text holds a `; ` is told by an entry whose text carries it
/// before another refusal, so no second entry names it. Fails when `untold_by` keeps the mark because the
/// entry's text parses the refusal only as a fragment.
#[test]
fn a_refusal_with_a_semicolon_in_an_entry_text_is_not_named_again_by_a_mark() {
    const SEMI: &str = "the object holds `Env`; write the predicate over a key it holds";
    const R2: &str = "the read of `B` was refused, at path /Resources/B/Tags";
    registered_as_in_a_run!(SEMI, R2);
    let entry = ClauseReport::Block(GuardBlockReport {
        context: String::from("Resources.*"),
        messages: Messages {
            error_message: Some(format!("HEAD: {SEMI}; {R2}")),
            custom_message: None,
            location: None,
            refusal: true,
            parts: None,
        },
        unresolved: None,
    });
    let named = |text: &str| {
        (
            text.to_string(),
            token_of_registered(text, &crate::rules::eval::no_frame_ranking),
        )
    };
    let left = untold_by(&[entry], vec![named(SEMI), named(R2)]);
    assert!(
        left.is_empty(),
        "both refusals are told by the entry, none is named again: {:?}",
        left
    );
}

/// Past the cap on inner boundaries the parse still finds the LAST refusal of a joined text by its suffix:
/// a text with more than `MAX_INNER_BOUNDARIES` inner `; ` boundaries is never recognized less than it was
/// before spans were read. Fails when the suffix candidate is dropped past the cap.
#[test]
fn a_text_with_more_inner_boundaries_than_the_cap_still_finds_its_last_refusal() {
    const LAST: &str = "the read of `Z` was refused, at path /Resources/Z/Tags";
    registered_as_in_a_run!(LAST);
    let many = (0..20)
        .map(|n| format!("filler {n}"))
        .collect::<Vec<_>>()
        .join("; ");
    let joined = format!("HEAD: {many}; {LAST}");
    let carried = refusals_carried_by(&joined);
    assert!(
        carried.iter().any(|(seen, _)| seen == LAST),
        "the last refusal after 20 inner boundaries is carried: {:?}",
        carried
            .iter()
            .map(|(text, _)| text.as_str())
            .collect::<Vec<_>>()
    );
}

/// A refusal a REAL clause entry reports (a unary check whose value check holds the refusal's sentence) is
/// carried through the entry's parts (`entry_texts_of` reads the bare evaluator message of an entry built
/// from parts, `PartsJoin::Clause`): a mark for the same refusal beside it adds no entry, and the bare
/// sentence is among the texts the entries carry.
#[test]
fn a_refusal_a_real_clause_entry_reports_is_carried_through_its_parts() {
    use frame_sources::{block_check, mark, HELD};
    registered_as_in_a_run!(HELD);
    let unary = EventRecord {
        context: String::from("Properties.Tags"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::Unary(
            UnaryValueCheck {
                comparison: (CmpOperator::Exists, false),
                value: ValueCheck {
                    from: QueryResult::UnResolved(UnResolved {
                        traversed_to: Rc::new(
                            PathAwareValue::try_from("{ A: 1 }").expect("parses"),
                        ),
                        remaining_query: String::from("Tags"),
                        reason: Some(HELD.to_string()),
                        kind: UnResolvedKind::Undecidable {
                            refusal: Some(crate::rules::errors::RefusalToken::minted(7)),
                            carried: None,
                        },
                    }),
                    message: Some(HELD.to_string()),
                    custom_message: None,
                    status: Status::FAIL,
                    refusal: true,
                },
            },
        ))),
        children: vec![],
    };
    let block = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![unary, mark(HELD)],
    };
    let entries = report_failed_clauses(&[block], true, false);
    assert_eq!(
        (1, true),
        (
            entries
                .iter()
                .filter(|entry| matches!(entry, ClauseReport::Clause(_)))
                .count(),
            entry_texts_of(&entries).iter().any(|text| text == HELD)
        ),
        "one Clause entry, no entry for the mark, and the bare sentence among the carried texts: {:?}",
        entries
    );
    assert_eq!(1, entries.len(), "the mark adds no entry beside it");
}

/// A decided answer is never a finding. A `when` inside a block body whose gate condition decided NO past a
/// refused read writes its marks under a SKIP `WhenCheck` (`WhenCondition(FAIL)` beneath it); when the
/// enclosing block then fails on a sibling clause, that decided-past read is no refusal entry of the block's.
/// A message-less FAIL child block's marks still reach the block.
///
/// Fails when an entry names the decided-past read (the descent went through the SKIP record), or
/// when the FAIL child's marks are missing.
#[test]
fn a_when_that_decided_no_past_a_refused_read_adds_no_refusal_entry_to_its_block() {
    use frame_sources::{block_check, mark, HELD, OTHER};
    registered_as_in_a_run!(HELD, OTHER);
    let mut skipped = block_check(None, false, false);
    skipped.status = Status::SKIP;
    skipped.raised = false;
    let decided_no = EventRecord {
        context: String::from("WhenBlock#2"),
        container: Some(RecordType::WhenCheck(skipped)),
        children: vec![EventRecord {
            context: String::from("WhenBlock#2/When"),
            container: Some(RecordType::WhenCondition(Status::FAIL)),
            children: vec![mark(HELD)],
        }],
    };
    let sibling = EventRecord {
        context: String::from("GuardAccessClause#blockB"),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            Some(String::from(
                "Check was not compliant as the sibling failed",
            )),
            false,
            false,
        ))),
        children: vec![],
    };
    let failing_child = EventRecord {
        context: String::from("BlockGuardClause#3"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![mark(OTHER)],
    };
    let block = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![sibling, decided_no, failing_child],
    };
    let texts: Vec<String> = report_failed_clauses(&[block], true, false)
        .iter()
        .map(|entry| match entry {
            ClauseReport::Block(block) => block.messages.error_message.clone().unwrap_or_default(),
            other => panic!("a block entry, got {:?}", other),
        })
        .collect();
    assert_eq!(
        (0, 1),
        (
            texts.iter().filter(|text| text.contains(HELD)).count(),
            texts.iter().filter(|text| text.contains(OTHER)).count(),
        ),
        "no entry for the decided-past read, one for the failing child's mark: {:?}",
        texts
    );
}

/// The second refusal of an entry that joins two is told too: a type block over a block with a sentence of
/// its own ("m") over two marks lists the block's entry "m; a body clause also met: R1; R2" (the marks are
/// refusals of the block's clauses, which no condition met) and NO second entry naming R2 (a reporter that
/// joined the marks to a parent sentence as well would list R2 again). The type block's own sentence is a
/// bailing wrapper of a plain error
/// that no entry carries, so it is written once, after the entries beneath it.
///
/// Fails when a second entry names R2, or when the block's entry misses it.
#[test]
fn a_type_blocks_condition_over_a_block_with_a_sentence_and_two_marks_tells_each_once() {
    use frame_sources::{block_check, mark, type_block, HELD, OTHER};
    registered_as_in_a_run!(HELD, OTHER);
    let block = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(
            Some(String::from("m")),
            false,
            false,
        ))),
        children: vec![mark(HELD), mark(OTHER)],
    };
    let record = type_block(
        Some(String::from(
            "Error a plain error during type condition evaluation, bailing",
        )),
        &[],
        vec![block],
    );
    let texts: Vec<String> = report_failed_clauses(&[record], true, false)
        .iter()
        .map(|entry| match entry {
            ClauseReport::Block(block) => block.messages.error_message.clone().unwrap_or_default(),
            other => panic!("a block entry, got {:?}", other),
        })
        .collect();
    assert_eq!(
        vec![
            format!(
                "m{}{HELD}; {OTHER}",
                crate::rules::eval_context::BODY_ALSO_MET
            ),
            String::from("Error a plain error during type condition evaluation, bailing"),
        ],
        texts,
        "the block's entry names both refusals once, then the bailing sentence of the type block, once"
    );
}

/// Every refusal a nested entry's text carries is recognized as told, in any position of a `; `-joined list:
/// two nested message-less blocks, the inner over two marks. The inner block lists "R1; R2" as one entry; the
/// outer block's marks are the same two, and a text parse that read only the first segment would push a
/// second entry naming R2.
///
/// Fails when two entries are listed (the second names the second refusal), or when an entry names
/// either refusal twice.
#[test]
fn a_nested_message_less_block_over_two_marks_lists_both_refusals_once() {
    use frame_sources::{block_check, mark, HELD, OTHER};
    registered_as_in_a_run!(HELD, OTHER);
    let inner = EventRecord {
        context: String::from("BlockGuardClause#3"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![mark(HELD), mark(OTHER)],
    };
    let outer = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![inner],
    };
    let texts: Vec<String> = report_failed_clauses(&[outer], true, false)
        .iter()
        .map(|entry| match entry {
            ClauseReport::Block(block) => block.messages.error_message.clone().unwrap_or_default(),
            other => panic!("a block entry, got {:?}", other),
        })
        .collect();
    assert_eq!(
        (1, 1, 1),
        (
            texts.len(),
            texts.iter().filter(|text| text.contains(HELD)).count(),
            texts.iter().filter(|text| text.contains(OTHER)).count(),
        ),
        "one entry names both refusals once: {:?}",
        texts
    );
}

/// The records of one frame source for the tripwire cells (`assert_frame_reads_told`): a failed record that
/// converted a frame whose reads are `[HELD]`, with `children`, and the sentence the record carries.
///
/// The sources are the closing records of the three `convert_condition_raise` callers: a rule's own `when`
/// (`RuleCheck`), an inline `when` (`WhenCheck`) and a type block (`TypeCheck`).
mod frame_sources {
    use crate::rules::eval_context::EventRecord;
    use crate::rules::{BlockCheck, CustomSlot, NamedStatus, RecordType, Status, TypeBlockCheck};

    pub(super) const HELD: &str = "the read of `A` was refused, at path /Resources/A/Tags";
    pub(super) const OTHER: &str = "the read of `B` was refused, at path /Resources/B/Tags";

    pub(super) fn block_check(
        message: Option<String>,
        refusal: bool,
        gate_mark: bool,
    ) -> BlockCheck {
        BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message,
            refusal,
            custom_message: None,
            gate_mark,
            frame_reads: Vec::new(),
        }
    }

    /// A refused per-clause record naming `refusal` bare, flagged a refusal.
    pub(super) fn refused_clause(refusal: &str) -> EventRecord<'static> {
        EventRecord {
            context: String::from("GuardAccessClause#blockA"),
            container: Some(RecordType::GuardClauseBlockCheck(block_check(
                Some(refusal.to_string()),
                true,
                false,
            ))),
            children: vec![],
        }
    }

    pub(super) fn mark(refusal: &str) -> EventRecord<'static> {
        EventRecord {
            context: String::from("GuardBlockAccessClause#2"),
            container: Some(RecordType::GuardClauseBlockCheck(block_check(
                Some(refusal.to_string()),
                true,
                true,
            ))),
            children: vec![],
        }
    }

    pub(super) fn under_a_condition(
        condition: RecordType<'static>,
        records: Vec<EventRecord<'static>>,
    ) -> EventRecord<'static> {
        EventRecord {
            context: String::from("condition"),
            container: Some(condition),
            children: records,
        }
    }

    /// A rule whose own `when` converted `reads`, closing with `message`, a displaced sentence if given.
    pub(super) fn rule(
        message: Option<String>,
        displaced: Option<(CustomSlot, String)>,
        slot: CustomSlot,
        reads: &[&str],
        children: Vec<EventRecord<'static>>,
    ) -> EventRecord<'static> {
        EventRecord {
            context: String::from("gated"),
            container: Some(RecordType::RuleCheck(NamedStatus {
                name: "gated",
                status: Status::FAIL,
                message,
                slot,
                displaced,
                frame_reads: reads.iter().map(|read| read.to_string()).collect(),
                // A rule whose own `when` failed ended on an error (the evaluator closes it so,
                // `judged_rule_body`): a fixture with a failed rule condition never pairs it with `false`.
                ended_by_error: children.iter().any(|child| {
                    matches!(
                        child.container,
                        Some(RecordType::RuleCondition(Status::FAIL))
                    )
                }),
            })),
            children,
        }
    }

    /// An inline `when` that converted `reads`.
    pub(super) fn when_block(
        message: Option<String>,
        reads: &[&str],
        children: Vec<EventRecord<'static>>,
    ) -> EventRecord<'static> {
        let mut check = block_check(message, false, false);
        check.frame_reads = reads.iter().map(|read| read.to_string()).collect();
        EventRecord {
            context: String::from("WhenBlock#2"),
            container: Some(RecordType::WhenCheck(check)),
            children,
        }
    }

    /// A type block that converted `reads`, closing with `message`, its children as the evaluator writes them:
    /// one `TypeBlock` per resource holding the condition.
    pub(super) fn type_block(
        message: Option<String>,
        reads: &[&str],
        condition_records: Vec<EventRecord<'static>>,
    ) -> EventRecord<'static> {
        let mut block = block_check(message, false, false);
        block.frame_reads = reads.iter().map(|read| read.to_string()).collect();
        EventRecord {
            context: String::from("TypeBlock#S3"),
            container: Some(RecordType::TypeCheck(TypeBlockCheck {
                type_name: "AWS::S3::Bucket",
                block,
            })),
            children: vec![EventRecord {
                context: String::from("TypeBlock#S3/0"),
                container: Some(RecordType::TypeBlock(Status::FAIL)),
                children: vec![under_a_condition(
                    RecordType::TypeCondition(Status::FAIL),
                    condition_records,
                )],
            }],
        }
    }
}

/// The report of a failed record, walked as the reporters walk it (`report_all_failed_clauses_for_rules`
/// under a failed rule with no sentence of its own for the block sources, the record itself for a rule), with
/// the refusal sentences registered as a run registers them. Built on a root scope so the registry holds the
/// sentences.
fn walk_a_converted_frame(record: EventRecord<'static>) {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let _root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    for text in [frame_sources::HELD, frame_sources::OTHER] {
        let _ = register_refusal(text);
    }
    let _ = report_all_failed_clauses_for_rules(&[record]);
}

/// A frame the evaluator converted into a FAIL is told by the report: the walk of the closing record finds
/// every refused read the frame held (`assert_frame_reads_told`). Five sources, each of whose reads is named
/// a different way and none of which may trip the assertion: a rule's own `when` (the read is in the rule's
/// sentence), an inline `when` (a flagged record under its condition), a type block (a gate mark under its
/// condition, through the per-resource `TypeBlock`), a nested block's entry (an entry listed beneath the
/// record carries the read), and an entry absorbed under a call with a body (the sentence the body displaced
/// carries it).
///
/// Fails when the assertion fires on a source whose read the report does name (the walk of that
/// source does not reach where the read is named).
#[test]
fn a_converted_frame_whose_reads_the_report_names_trips_nothing() {
    use crate::rules::eval::{RULE_CONDITION_UNEVALUATED_HEAD, WHEN_UNEVALUATED_HEAD};
    use crate::rules::{CustomSlot, RecordType, Status};
    use frame_sources::*;
    let sources: Vec<(&str, EventRecord<'static>)> = vec![
        (
            "a rule's own `when`: the sentence carries the read",
            rule(
                Some(format!("{RULE_CONDITION_UNEVALUATED_HEAD}{HELD}")),
                None,
                CustomSlot::Refusal,
                &[HELD],
                vec![],
            ),
        ),
        (
            "an inline `when`: a flagged record under its condition names the read",
            when_block(
                Some(format!("{WHEN_UNEVALUATED_HEAD}{OTHER}")),
                &[HELD],
                vec![under_a_condition(
                    RecordType::WhenCondition(Status::FAIL),
                    vec![refused_clause(HELD)],
                )],
            ),
        ),
        (
            "a type block: a gate mark under its per-resource condition names the read",
            type_block(
                Some(format!(
                    "Error {OTHER} during type condition evaluation, bailing"
                )),
                &[HELD],
                vec![mark(HELD)],
            ),
        ),
        (
            "a nested block's entry: an entry listed beneath the record carries the read",
            when_block(None, &[HELD], vec![refused_clause(HELD)]),
        ),
        (
            "a bailing type block with entries beneath: an entry names the read",
            type_block(
                Some(format!(
                    "Error {HELD} during type condition evaluation, bailing"
                )),
                &[HELD],
                vec![refused_clause(HELD)],
            ),
        ),
        (
            "a call's body over a silent block: the rule's sentence joins the mark's refusal",
            rule(
                Some(String::from("the author's body")),
                None,
                CustomSlot::Author,
                &[HELD],
                vec![EventRecord {
                    context: String::from("BlockGuardClause#2"),
                    container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
                    children: vec![mark(HELD)],
                }],
            ),
        ),
        (
            "an absorbed entry: the sentence a call's body displaced carries the read",
            rule(
                Some(String::from("the author's body")),
                Some((
                    CustomSlot::Refusal,
                    format!("{RULE_CONDITION_UNEVALUATED_HEAD}{HELD}"),
                )),
                CustomSlot::Author,
                &[HELD],
                vec![],
            ),
        ),
    ];
    for (label, record) in sources {
        // A panic here names the source that tripped.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            walk_a_converted_frame(record)
        }));
        assert!(result.is_ok(), "the tripwire fired on {}", label);
    }
}

/// A type block's closing record on the conversion path has no sentence (`message` None), and the caller may
/// forbid the generic fallback (its own parent speaks). The deep marks beneath it are still told: the arm
/// lists them as an entry of their own, the refusals alone, flagged refusals, and the tripwire counts them
/// told because the arm WROTE them (it compares against what the arm writes, never against what the walk
/// of the condition could have supplied).
///
/// Fails when nothing is listed for the mark (the refusal is lost), or when the tripwire fires on a
/// record whose reads the arm does write.
#[test]
fn a_type_block_with_no_sentence_lists_the_marks_beneath_it_even_when_its_parent_speaks() {
    use frame_sources::{block_check, mark, type_block, HELD};
    registered_as_in_a_run!(HELD);
    let silent_block = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![mark(HELD)],
    };
    let record = type_block(None, &[HELD], vec![silent_block]);
    let entries = report_failed_clauses(&[record], false, false);
    let texts: Vec<(String, bool)> = entries
        .iter()
        .map(|entry| match entry {
            ClauseReport::Block(block) => (
                block.messages.error_message.clone().unwrap_or_default(),
                block.messages.refusal,
            ),
            other => panic!("a block entry, got {:?}", other),
        })
        .collect();
    assert_eq!(
        vec![(HELD.to_string(), true)],
        texts,
        "the refusal alone, flagged, once"
    );
}

/// A type block with no sentence, in a rule with no text of its own (the generic fallback is on), whose
/// condition holds a silent block over two marks R1 and R2: the block's own entry is `R1; R2`, and the
/// entry the type block would write for marks no entry carries adds nothing, since both are told.
#[test]
fn a_type_block_with_no_sentence_over_a_silent_block_of_two_marks_lists_each_once() {
    use frame_sources::{block_check, mark, type_block, HELD, OTHER};
    registered_as_in_a_run!(HELD, OTHER);
    let silent_block = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![mark(HELD), mark(OTHER)],
    };
    let record = type_block(None, &[], vec![silent_block]);
    let texts: Vec<String> = report_failed_clauses(&[record], true, false)
        .iter()
        .map(|entry| match entry {
            ClauseReport::Block(block) => block.messages.error_message.clone().unwrap_or_default(),
            other => panic!("a block entry, got {:?}", other),
        })
        .collect();
    assert_eq!(
        vec![format!("{}; {}", HELD, OTHER)],
        texts,
        "one entry, both refusals once"
    );
}

/// A rule with a text of its own (a call's `<< >>` body, or the sentence the body displaced) over a type
/// block with no sentence whose condition holds a mark: the rule's text reaches the structured readers
/// (`get_message_with_rule_records_by_level`, which the `sarif` results and the `junit` failure element
/// read), the refusal is told once beside it, and the type block writes no entry for it, since an entry in
/// the rule's `checks` would make the clauses speak for the rule and drop its text.
#[test]
fn a_rules_own_text_reaches_the_structured_readers_beside_the_marks_beneath_it() {
    use crate::rules::CustomSlot;
    use frame_sources::{mark, rule, type_block, HELD};
    registered_as_in_a_run!(HELD);
    const BODY: &str = "the author's body";
    const SENTENCE: &str = "the rule's own sentence";
    let sources = vec![
        (
            "a body",
            rule(
                Some(BODY.to_string()),
                None,
                CustomSlot::Author,
                &[],
                vec![type_block(None, &[], vec![mark(HELD)])],
            ),
        ),
        (
            "a displaced sentence",
            rule(
                Some(BODY.to_string()),
                Some((CustomSlot::Evaluator, SENTENCE.to_string())),
                CustomSlot::Author,
                &[],
                vec![type_block(None, &[], vec![mark(HELD)])],
            ),
        ),
    ];
    for (label, record) in sources {
        let reports = report_all_failed_clauses_for_rules(&[record]);
        assert_eq!(1, reports.len(), "({}) one rule report", label);
        match &reports[0] {
            ClauseReport::Rule(rule) => assert!(
                rule.checks.is_empty(),
                "({}) the type block writes no entry under a rule with a text: {:?}",
                label,
                rule.checks
            ),
            other => panic!("({}) a rule report, got {:?}", label, other),
        }
        let by_level = reports[0].get_message_with_rule_records_by_level();
        assert_eq!(1, by_level.len(), "({}) one result: {:?}", label, by_level);
        let (messages, rule_level) = &by_level[0];
        let error = messages.error_message.clone().unwrap_or_default();
        assert!(
            *rule_level
                && messages.custom_message.as_deref() == Some(BODY)
                && error.matches(HELD).count() == 1,
            "({}) the rule's own record, the body present, the refusal once: {:?}",
            label,
            messages
        );
        // The mark sits under a nested type block's failed CONDITION, so it is a condition refusal joined at
        // the rule: it follows the nested-condition joiner (the rule's own condition has ALSO_MET, clause
        // marks the body joiner); nothing ended the evaluation: the sentence's head is the displaced
        // sentence, or the neutral one when there is none.
        let head = match label {
            "a displaced sentence" => SENTENCE,
            _ => crate::rules::eval_context::RULE_FAILED_HEAD,
        };
        assert!(
            error.starts_with(head)
                && error.contains(crate::rules::eval_context::NESTED_ALSO_MET)
                && !error.contains(ALSO_MET)
                && !error.contains(crate::rules::eval_context::BODY_ALSO_MET)
                && !error.contains(crate::rules::eval_context::RULE_FAILED_ON_AN_ERROR_HEAD),
            "({}) the head {:?} and the nested-condition joiner alone: {}",
            label,
            head,
            error
        );
    }
}

/// Every text a rule report lists, at every depth, and what the structured readers return for it
/// (`get_message_with_rule_records_by_level`): the texts of the records, entries and nested rules, and the
/// messages the `sarif` results and the `junit` element read.
fn texts_and_reader_messages(report: &ClauseReport<'_>) -> (Vec<String>, Vec<String>) {
    fn texts(report: &ClauseReport<'_>, out: &mut Vec<String>) {
        match report {
            ClauseReport::Rule(rule) => {
                out.extend(rule.messages.error_message.clone());
                out.extend(rule.messages.custom_message.clone());
                rule.checks.iter().for_each(|each| texts(each, out));
            }
            ClauseReport::Block(block) => {
                out.extend(block.messages.error_message.clone());
                out.extend(block.messages.custom_message.clone());
            }
            ClauseReport::Clause(_) => {
                for messages in report.get_message() {
                    out.extend(messages.error_message);
                    out.extend(messages.custom_message);
                }
            }
            ClauseReport::Disjunctions(ors) => ors.checks.iter().for_each(|each| texts(each, out)),
        }
    }
    let mut recorded = Vec::new();
    texts(report, &mut recorded);
    let mut read = Vec::new();
    for (messages, _) in report.get_message_with_rule_records_by_level() {
        read.extend(messages.error_message);
        read.extend(messages.custom_message);
    }
    (recorded, read)
}

/// A call with a `<< >>` body whose clause reports beside a type block that failed closed on a mark, and
/// beside a disjunction with an entry of its own and a mark: the rule's checks SAY something, so the rule's
/// own record is not the reader's answer, and the body is no answer: the readers return the
/// checks and not the author's body. The marks no entry names are an entry of the checks themselves (the
/// refusals alone), so every format reads each mark once and the body not at all, whether or not a mark
/// exists. Fails when the body appears because a mark does, or a mark is read twice or not at all.
#[test]
fn a_bodied_calls_marks_reach_the_readers_once_through_the_checks_when_another_check_speaks() {
    use crate::rules::CustomSlot;
    use frame_sources::{mark, refused_clause, rule, type_block, HELD, OTHER};
    registered_as_in_a_run!(HELD, OTHER);
    const BODY: &str = "the author's body";
    let disjunction_with_a_mark = EventRecord {
        context: String::from("Disjunction#2"),
        container: Some(RecordType::Disjunction(frame_sources::block_check(
            None, false, false,
        ))),
        children: vec![refused_clause(OTHER), mark(HELD)],
    };
    let shapes = vec![
        (
            "a type block that failed closed on a mark, beside a clause that reports",
            vec![
                refused_clause(OTHER),
                type_block(None, &[], vec![mark(HELD)]),
            ],
        ),
        (
            "a disjunction with an entry and a mark",
            vec![disjunction_with_a_mark],
        ),
    ];
    for (label, children) in shapes {
        let record = rule(
            Some(BODY.to_string()),
            None,
            CustomSlot::Author,
            &[],
            children,
        );
        let reports = report_all_failed_clauses_for_rules(&[record]);
        assert_eq!(1, reports.len(), "({}) one rule report", label);
        let (recorded, read) = texts_and_reader_messages(&reports[0]);
        let count = |texts: &[String], needle: &str| {
            texts
                .iter()
                .map(|text| text.matches(needle).count())
                .sum::<usize>()
        };
        assert_eq!(
            (0, 1, 1),
            (
                count(&read, BODY),
                count(&read, HELD),
                count(&recorded, HELD)
            ),
            "({}) the readers return the checks alone (no body) with the mark once, and the report records the mark once: read {:?}, recorded {:?}",
            label,
            read,
            recorded
        );
    }
}

/// A call with a body over a bailing type block (a sentence of its own) whose one resource's body holds a
/// converted inline `when` with no sentence: the `when`'s marks are told by the type block's entries, once,
/// and the debug tripwire holds. A record with a sentence tells the marks beneath it itself, so it hands
/// its children nothing to defer to the rule above, which would not see them (`marked_refusals_beneath`
/// stops at a record with a sentence).
#[test]
fn a_when_under_a_type_block_with_a_sentence_has_its_marks_told_once_under_a_bodied_call() {
    use crate::rules::CustomSlot;
    use frame_sources::{block_check, mark, rule, type_block, when_block, HELD};
    registered_as_in_a_run!(HELD);
    const BODY: &str = "the author's body";
    let silent_block = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![mark(HELD)],
    };
    // The `when` sits BESIDE the type condition, in the resource's body (the `TypeBlock`'s children), as the
    // evaluator writes a body; under the condition itself the condition's walk would already reach it.
    let mut bailing = type_block(
        Some(String::from(
            "Error a plain error that ended the run during type condition evaluation, bailing",
        )),
        &[],
        vec![],
    );
    bailing.children[0]
        .children
        .push(when_block(None, &[HELD], vec![silent_block]));
    let record = rule(
        Some(BODY.to_string()),
        None,
        CustomSlot::Author,
        &[],
        vec![bailing],
    );
    let reports = report_all_failed_clauses_for_rules(&[record]);
    let (recorded, read) = texts_and_reader_messages(&reports[0]);
    let count = |texts: &[String]| {
        texts
            .iter()
            .map(|text| text.matches(HELD).count())
            .sum::<usize>()
    };
    assert_eq!(
        (1, 1),
        (count(&recorded), count(&read)),
        "the mark once in the report and once for the readers: recorded {:?}, read {:?}",
        recorded,
        read
    );
}

/// The head of a called rule's sentence states what the record carries. A body that ended on an error
/// (`NamedStatus::ended_by_error`) reads the run-ending head whatever the refusal lists hold: over a clause
/// mark behind the body joiner, and over a refusal the rule's own condition met behind the condition joiner;
/// the same record that did not end on an error reads the plain head over the same clause mark. Fails when
/// the head is chosen from the refusal lists instead of the record's own account of the error.
#[test]
fn the_head_of_a_called_rules_sentence_follows_the_error_that_ended_the_run() {
    use crate::rules::eval_context::{
        BODY_ALSO_MET, RULE_FAILED_HEAD, RULE_FAILED_ON_AN_ERROR_HEAD,
    };
    use crate::rules::CustomSlot;
    use frame_sources::{mark, rule, under_a_condition, HELD, OTHER};
    registered_as_in_a_run!(HELD, OTHER);
    const BODY: &str = "the author's body";
    let sentence_of = |ended: bool, children: Vec<EventRecord<'static>>| -> String {
        let mut record = rule(
            Some(BODY.to_string()),
            None,
            CustomSlot::Author,
            &[],
            children,
        );
        if let Some(RecordType::RuleCheck(status)) = record.container.as_mut() {
            status.ended_by_error = ended;
        }
        let reports = report_all_failed_clauses_for_rules(&[record]);
        match &reports[0] {
            ClauseReport::Rule(rule) => rule
                .messages
                .error_message
                .clone()
                .expect("the rule's sentence is written"),
            other => panic!("a rule report is expected, got {:?}", other),
        }
    };
    // A mark of a clause in the body: a silent failed block holding the gate mark (no condition met it).
    let clause_mark = || EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(frame_sources::block_check(
            None, false, false,
        ))),
        children: vec![mark(HELD)],
    };
    let ended = sentence_of(true, vec![clause_mark()]);
    assert_eq!(
        (true, true, 1),
        (
            ended.starts_with(RULE_FAILED_ON_AN_ERROR_HEAD),
            ended.contains(BODY_ALSO_MET),
            ended.matches(HELD).count()
        ),
        "an error ended the run: the run-ending head, the clause mark behind the body joiner, once: {:?}",
        ended
    );
    let with_a_condition = sentence_of(
        true,
        vec![under_a_condition(
            RecordType::RuleCondition(Status::FAIL),
            vec![mark(OTHER)],
        )],
    );
    assert_eq!(
        (true, true, 1),
        (
            with_a_condition.starts_with(RULE_FAILED_ON_AN_ERROR_HEAD),
            with_a_condition.contains(ALSO_MET),
            with_a_condition.matches(OTHER).count()
        ),
        "an error ended the run in the rule's own condition: the run-ending head, the refusal behind the condition joiner: {:?}",
        with_a_condition
    );
    let decided = sentence_of(false, vec![clause_mark()]);
    assert_eq!(
        (true, true, 1),
        (
            decided.starts_with(RULE_FAILED_HEAD)
                && !decided.starts_with(RULE_FAILED_ON_AN_ERROR_HEAD),
            decided.contains(BODY_ALSO_MET),
            decided.matches(HELD).count()
        ),
        "no error ended the run: the plain head and the clause mark behind the body joiner: {:?}",
        decided
    );
    // A nested type block's failed condition met a refusal and the rule's own `when` did not fail: the plain
    // head, the refusal behind the nested-condition joiner.
    let nested = sentence_of(
        false,
        vec![frame_sources::type_block(None, &[], vec![mark(HELD)])],
    );
    assert_eq!(
        (true, true, false, 1),
        (
            nested.starts_with(RULE_FAILED_HEAD)
                && !nested.starts_with(RULE_FAILED_ON_AN_ERROR_HEAD),
            nested.contains(crate::rules::eval_context::NESTED_ALSO_MET),
            nested.contains(ALSO_MET),
            nested.matches(HELD).count()
        ),
        "a nested condition's refusal: the plain head, the nested-condition joiner: {:?}",
        nested
    );
}

/// A clause block whose message names a refusal R, over an inline `when` with no sentence and a mark for R,
/// under a called rule with a body: R is told once. The clause arm hands its children the rule's deferral
/// (`marks_told_above`, kept when the clause writes its own entry too), so the `when` writes no marks entry of its
/// own and the rule drops the mark the clause's message carries. Fails when the `when`'s marks entry and the
/// clause's message appear together.
#[test]
fn a_clause_block_whose_message_names_a_refusal_does_not_tell_it_again_through_a_when() {
    use crate::rules::CustomSlot;
    use frame_sources::{block_check, mark, rule, when_block, OTHER};
    registered_as_in_a_run!(OTHER);
    const BODY: &str = "the author's body";
    let clause = EventRecord {
        context: String::from("GuardBlockAccessClause#4"),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            Some(OTHER.to_string()),
            true,
            false,
        ))),
        children: vec![when_block(None, &[], vec![mark(OTHER)])],
    };
    let record = rule(
        Some(BODY.to_string()),
        None,
        CustomSlot::Author,
        &[],
        vec![clause],
    );
    let reports = report_all_failed_clauses_for_rules(&[record]);
    let (recorded, read) = texts_and_reader_messages(&reports[0]);
    let count = |texts: &[String]| {
        texts
            .iter()
            .map(|text| text.matches(OTHER).count())
            .sum::<usize>()
    };
    assert_eq!(
        (1, 1),
        (count(&recorded), count(&read)),
        "the refusal once in the report and once for the readers: recorded {:?}, read {:?}",
        recorded,
        read
    );
    // Under a rule with NO text the clause writes its own entry (its message names R) and the `when`
    // beneath it defers its marks entry: R is told once, by the clause's entry.
    let no_text = rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![EventRecord {
            context: String::from("GuardBlockAccessClause#4"),
            container: Some(RecordType::GuardClauseBlockCheck(block_check(
                Some(OTHER.to_string()),
                true,
                false,
            ))),
            children: vec![when_block(None, &[], vec![mark(OTHER)])],
        }],
    );
    let reports = report_all_failed_clauses_for_rules(&[no_text]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    assert_eq!(
        1,
        count(&recorded),
        "a rule with no text: the refusal once, not by the marks entry and the clause's message both: {:?}",
        recorded
    );
    // The same shape with an author's `<< msg >>` on the clause: the clause's own entry is never dropped
    // (its context and its text live on it); the entry beneath is the one suppressed. One entry, the
    // clause's context, the author's text present, the refusal once.
    let mut with_msg_check = block_check(Some(OTHER.to_string()), true, false);
    with_msg_check.custom_message = Some(String::from("the clause's own text"));
    let with_msg = rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![EventRecord {
            context: String::from("GuardBlockAccessClause#4"),
            container: Some(RecordType::GuardClauseBlockCheck(with_msg_check)),
            children: vec![when_block(None, &[], vec![mark(OTHER)])],
        }],
    );
    let reports = report_all_failed_clauses_for_rules(&[with_msg]);
    let entries: Vec<(String, Option<String>, Option<String>)> = match &reports[0] {
        ClauseReport::Rule(rule) => rule
            .checks
            .iter()
            .map(|entry| match entry {
                ClauseReport::Block(block) => (
                    block.context.clone(),
                    block.messages.custom_message.clone(),
                    block.messages.error_message.clone(),
                ),
                other => panic!("a block entry, got {:?}", other),
            })
            .collect(),
        other => panic!("a rule report, got {:?}", other),
    };
    assert_eq!(
        vec![(
            String::from("GuardBlockAccessClause#4"),
            Some(String::from("the clause's own text")),
            Some(OTHER.to_string())
        )],
        entries,
        "one entry: the clause's context, its author's text, the refusal once"
    );
}

/// `rule main { not check << msg >> }` that fails closed on a refusal: the called rule's run is a child of the
/// negation's clause record, its refused clause carries the same refusal the negation's sentence names, and
/// the negation's own entry (its context, the sentence and the author's `<< msg >>`) is still written after
/// the run, never dropped for repeating a refusal. Fails when the entry after the run is missing or has lost
/// the author's text.
#[test]
fn a_negation_over_a_called_rule_keeps_its_own_entry_and_its_author_text() {
    use crate::rules::CustomSlot;
    use frame_sources::{block_check, refused_clause, rule, HELD};
    registered_as_in_a_run!(HELD);
    let run = EventRecord {
        context: String::from("check"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "check",
            status: Status::FAIL,
            message: None,
            slot: CustomSlot::Evaluator,
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![refused_clause(HELD)],
    };
    let mut negation_check = block_check(
        Some(format!(
            "`not` failed only on reads it could not decide: {HELD}"
        )),
        true,
        false,
    );
    negation_check.custom_message = Some(String::from("the negation's msg"));
    let negation = EventRecord {
        context: String::from("GuardBlockAccessClause#7"),
        container: Some(RecordType::GuardClauseBlockCheck(negation_check)),
        children: vec![run],
    };
    let record = rule(None, None, CustomSlot::Evaluator, &[], vec![negation]);
    let reports = report_all_failed_clauses_for_rules(&[record]);
    let shape: Vec<String> = match &reports[0] {
        ClauseReport::Rule(main) => main
            .checks
            .iter()
            .map(|entry| match entry {
                ClauseReport::Rule(_) => String::from("R"),
                ClauseReport::Clause(_) => String::from("C"),
                ClauseReport::Disjunctions(_) => String::from("D"),
                ClauseReport::Block(block) => {
                    format!("B:{}:{:?}", block.context, block.messages.custom_message)
                }
            })
            .collect(),
        other => panic!("a rule report, got {:?}", other),
    };
    assert_eq!(
        vec![
            String::from("R"),
            String::from("B:GuardBlockAccessClause#7:Some(\"the negation's msg\")")
        ],
        shape,
        "the called rule's run, then the negation's own entry with its context and author text"
    );
}

/// An access clause whose explanation names a refusal R, over a message-less block that holds a gate mark
/// for R, under a rule with no text: R is told once, by the clause's own entry. The block's marks-only entry
/// defers (`marks_told_above` with no message of its own), as the `when`, type block and disjunction arms do, and
/// the clause's join drops what its message already carries. Fails when R appears in both the block's entry
/// and the clause's.
#[test]
fn a_message_less_block_under_a_clause_that_names_its_refusal_does_not_tell_it_again() {
    use crate::rules::CustomSlot;
    use frame_sources::{block_check, mark, rule, HELD};
    registered_as_in_a_run!(HELD);
    let block = EventRecord {
        context: String::from("BlockGuardCheck#1"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![mark(HELD)],
    };
    let clause = EventRecord {
        context: String::from("GuardBlockAccessClause#7"),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            Some(format!("the clause failed on a refused read: {HELD}")),
            true,
            false,
        ))),
        children: vec![block],
    };
    let record = rule(None, None, CustomSlot::Evaluator, &[], vec![clause]);
    let reports = report_all_failed_clauses_for_rules(&[record]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    let told: usize = recorded.iter().map(|text| text.matches(HELD).count()).sum();
    assert_eq!(
        1, told,
        "the refusal once, by the clause's entry and not by the block's entry as well: {:?}",
        recorded
    );
}

/// An access clause with a plain explanation, over a type block whose failed condition carries a mark for R
/// (a nested condition's refusal) and a message-less block that holds a gate mark for the same R (a clause
/// mark), under a rule with no text: the clause's join keeps R in the nested group only, so the sentence
/// reads `<explanation>; a nested condition also met: R` and never adds `; a body clause also met: R`.
/// Fails when the sentence names R twice.
#[test]
fn an_access_clause_joins_a_refusal_once_across_its_nested_and_clause_groups() {
    use crate::rules::CustomSlot;
    use frame_sources::{block_check, mark, rule, type_block, HELD};
    registered_as_in_a_run!(HELD);
    const EXPLANATION: &str = "the clause failed";
    let block = EventRecord {
        context: String::from("BlockGuardCheck#1"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![mark(HELD)],
    };
    let clause = EventRecord {
        context: String::from("GuardBlockAccessClause#7"),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            Some(EXPLANATION.to_string()),
            false,
            false,
        ))),
        children: vec![type_block(None, &[], vec![mark(HELD)]), block],
    };
    let record = rule(None, None, CustomSlot::Evaluator, &[], vec![clause]);
    let reports = report_all_failed_clauses_for_rules(&[record]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    assert_eq!(
        (vec![format!("{EXPLANATION}{NESTED_ALSO_MET}{HELD}")], 0),
        (
            recorded.clone(),
            recorded
                .iter()
                .filter(|text| text.contains(BODY_ALSO_MET))
                .count()
        ),
        "the refusal once, in the nested group: {:?}",
        recorded
    );
}

/// One gate mark reads the same under every record: under a type block's own failed condition it is a
/// condition refusal of THAT record (behind the condition joiner), under the failed condition of a `when`
/// nested in its body it is a NESTED condition refusal (behind the nested joiner), and in a clause of the
/// body it is a body mark. Fails when a mark under a nested `when`'s condition is grouped as the type
/// block's own, or the joined sentence words it behind the condition joiner.
#[test]
fn a_mark_under_a_nested_when_is_a_nested_condition_refusal_of_the_type_block() {
    use frame_sources::{mark, under_a_condition, when_block, HELD, OTHER};
    registered_as_in_a_run!(HELD, OTHER);
    let body = vec![
        under_a_condition(RecordType::TypeCondition(Status::FAIL), vec![mark(OTHER)]),
        when_block(
            None,
            &[],
            vec![under_a_condition(
                RecordType::WhenCondition(Status::FAIL),
                vec![mark(HELD)],
            )],
        ),
    ];
    let children = vec![EventRecord {
        context: String::from("TypeBlock#S3/0"),
        container: Some(RecordType::TypeBlock(Status::FAIL)),
        children: body,
    }];
    let texts = |found: Vec<NamedRefusal>| -> Vec<String> {
        found.into_iter().map(|(text, _)| text).collect()
    };
    let (own, nested, marks) = condition_and_clause_refusals(&children);
    let (joined, _) = join_rule_refusals(
        "head",
        own.clone(),
        nested.clone(),
        marks.clone(),
        SentenceSlot::Error,
    );
    assert_eq!(
        (
            (
                vec![OTHER.to_string()],
                vec![HELD.to_string()],
                Vec::<String>::new()
            ),
            format!("head{ALSO_MET}{OTHER}{NESTED_ALSO_MET}{HELD}")
        ),
        ((texts(own), texts(nested), texts(marks)), joined),
        "the type block's own condition mark, then the nested when's mark behind the nested joiner"
    );
}

/// A walk of the marks stops at an access clause that wrote its own entry, which told them: under a rule
/// with a text, the clause's entry carries the nested refusal and the rule's sentence does not repeat it,
/// and the walk descends through a clause with no message (which tells nothing). Fails when the rule's
/// sentence names the refusal as well, or the walk's decision is the other way round.
#[test]
fn the_marks_walk_stops_at_a_clause_that_wrote_its_own_entry() {
    use crate::rules::CustomSlot;
    use frame_sources::{block_check, mark, rule, type_block, HELD};
    registered_as_in_a_run!(HELD);
    let clause = |message: Option<&str>| EventRecord {
        context: String::from("GuardBlockAccessClause#7"),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            message.map(String::from),
            false,
            false,
        ))),
        children: vec![type_block(None, &[], vec![mark(HELD)])],
    };
    // A clause whose own per-value check reports (the context carries the `GuardAccessClause#block`
    // prefix `an_own_value_check_reports` strips, and a child in the clause's own context `Y` that prints):
    // the clause writes no entry of its own, so the walk goes on beneath it.
    let reporting = EventRecord {
        context: String::from("GuardAccessClause#blockY"),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            Some(crate::rules::eval::clause_error_message(
                &crate::rules::errors::Error::undecidable(HELD.to_string()),
            )),
            true,
            false,
        ))),
        children: vec![
            EventRecord {
                context: String::from("Y"),
                container: Some(RecordType::ClauseValueCheck(
                    ClauseCheck::MissingBlockValue(ValueCheck {
                        from: QueryResult::UnResolved(UnResolved {
                            traversed_to: Rc::new(
                                PathAwareValue::try_from("{ A: 1 }").expect("parses"),
                            ),
                            remaining_query: String::new(),
                            reason: Some(HELD.to_string()),
                            kind: UnResolvedKind::Undecidable {
                                refusal: Some(crate::rules::errors::RefusalToken::minted(7)),
                                carried: None,
                            },
                        }),
                        message: Some(HELD.to_string()),
                        custom_message: None,
                        status: Status::FAIL,
                        refusal: true,
                    }),
                )),
                children: vec![],
            },
            mark(HELD),
        ],
    };
    assert_eq!(
        (false, true, true, true),
        (
            marks_walk_descends(&clause(Some("the clause failed")), true, true),
            marks_walk_descends(&clause(Some("the clause failed")), false, false),
            marks_walk_descends(&clause(None), true, true),
            marks_walk_descends(&reporting, true, true)
        ),
        "no descent past a clause the reporter reached that wrote its entry; descent where the reporter \
         was not reached, through a clause with no message, and through one whose own check reports"
    );
    let record = rule(
        Some(String::from("The rule failed")),
        None,
        CustomSlot::Evaluator,
        &[],
        vec![clause(Some("the clause failed"))],
    );
    let reports = report_all_failed_clauses_for_rules(&[record]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    let told: Vec<&String> = recorded.iter().filter(|text| text.contains(HELD)).collect();
    assert_eq!(
        (1, true),
        (
            told.len(),
            told.iter()
                .all(|text| text.starts_with("the clause failed"))
        ),
        "the refusal once, in the clause's entry and not in the rule's sentence: {:?}",
        recorded
    );
}

/// The walk of the marks stops at a clause only where the reporter reached it and wrote its entry.
/// Shape (b): a clause C2 with a message, over a record kind the reporter ignores (a filter's predicate
/// records), over a clause C3 with a message that holds a gate mark for R. The reporter never reaches C3, so
/// C3 writes no entry, and the walk, which must not stop at C3, finds R for C2's join: R is told once, by C2.
/// Shape (a): the same C3 inside a type block's failed condition, whose clauses come through the
/// condition's filtered copy: R is told once, by C3's entry or the type block's, never twice. Fails when R
/// is told by nobody (a walk that stopped at C3 whether or not the reporter reached it) or twice.
#[test]
fn a_refusal_under_a_clause_the_reporter_does_not_reach_is_told_once_by_an_ancestor() {
    use crate::rules::CustomSlot;
    use frame_sources::{block_check, mark, rule, type_block, HELD};
    registered_as_in_a_run!(HELD);
    let clause = |context: &str, message: &str, children: Vec<EventRecord<'static>>| EventRecord {
        context: String::from(context),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            Some(message.to_string()),
            false,
            false,
        ))),
        children,
    };
    let told_of = |record: EventRecord<'static>| -> Vec<String> {
        let reports = report_all_failed_clauses_for_rules(&[record]);
        let (recorded, _) = texts_and_reader_messages(&reports[0]);
        recorded
            .into_iter()
            .filter(|text| text.contains(HELD))
            .collect()
    };
    // Shape (b).
    let c3 = clause("GuardBlockAccessClause#3", "c3 failed", vec![mark(HELD)]);
    // The ignored record is the real kind the reporter ignores, a filter's predicate records
    // (`RecordType::Filter`), not an absent container: `condition_records` treats the two differently.
    let ignored = EventRecord {
        context: String::from("a filter's predicate record"),
        container: Some(RecordType::Filter(Status::FAIL)),
        children: vec![c3],
    };
    let c2 = clause("GuardBlockAccessClause#2", "c2 failed", vec![ignored]);
    let told = told_of(rule(None, None, CustomSlot::Evaluator, &[], vec![c2]));
    assert_eq!(
        (1, true),
        (
            told.len(),
            told.iter().all(|text| text.starts_with("c2 failed"))
        ),
        "shape (b): the refusal once, in the entry of the first clause the reporter reached: {:?}",
        told
    );
    // Shape (b) with a failed called rule in place of the messaged clause: C2 > Filter > RuleCheck(FAIL) >
    // block > mark. The reporter never reaches the rule's run, so the walk goes into it (the walk is no
    // longer reached beneath the filter's record) and C2 tells R once.
    let called_run = |status: Status| EventRecord {
        context: String::from("called"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "called",
            status,
            message: None,
            slot: CustomSlot::Evaluator,
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![EventRecord {
            context: String::from("BlockGuardCheck#9"),
            container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
            children: vec![mark(HELD)],
        }],
    };
    let ignored = EventRecord {
        context: String::from("a filter's predicate record"),
        container: Some(RecordType::Filter(Status::FAIL)),
        children: vec![called_run(Status::FAIL)],
    };
    let c2 = clause("GuardBlockAccessClause#2", "c2 failed", vec![ignored]);
    let told = told_of(rule(None, None, CustomSlot::Evaluator, &[], vec![c2]));
    assert_eq!(
        (1, true),
        (
            told.len(),
            told.iter().all(|text| text.starts_with("c2 failed"))
        ),
        "a failed rule beneath an ignored kind: the refusal once, at the clause above it: {:?}",
        told
    );
    // A failed called rule beneath a record the reporter REACHES is not entered by the walk: its own run
    // reports the mark, once, and the clause's sentence does not repeat it.
    let c2 = clause(
        "GuardBlockAccessClause#2",
        "c2 failed",
        vec![called_run(Status::FAIL)],
    );
    let told = told_of(rule(None, None, CustomSlot::Evaluator, &[], vec![c2]));
    assert_eq!(
        (1, false),
        (
            told.len(),
            told.iter().any(|text| text.starts_with("c2 failed"))
        ),
        "a failed rule beneath a reached clause: the refusal once, by the rule's own run: {:?}",
        told
    );
    // Shape (a).
    let c3 = clause("GuardBlockAccessClause#3", "c3 failed", vec![mark(HELD)]);
    let in_a_condition = type_block(None, &[], vec![c3]);
    let told = told_of(rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![in_a_condition],
    ));
    assert_eq!(
        1,
        told.len(),
        "shape (a): the refusal once under a failed type block's condition: {:?}",
        told
    );
}

/// The lists cannot drift: for every failed record kind the marks walk could cross, the reporter
/// (`report_failed_clauses`) writes the entry of a messaged clause placed directly beneath it exactly when
/// `stoppable_beneath` keeps the walk stoppable there, and `reached_beneath` agrees with `stoppable_beneath`
/// for every kind but the documented exceptions. A probe clause with a message and no children is put under
/// a record of EVERY kind; its entry shows up in the report only if the reporter descends into that record
/// with the original children. The kinds and their samples are ONE list of rows (`record_kinds!`): the match
/// over `RecordType` with no `_` arm, the names and the samples are all built from the same rows, so a new
/// kind does not compile until a row is added, and a row cannot be added without its sample. The kinds the
/// reporter ignores (`FileCheck`, `Filter`, `WhenCondition` and the leaf `ClauseValueCheck`) are real
/// samples, not an absent container (`condition_records` treats the two differently); an absent container
/// is a row of its own beside them, the one shape that is no kind (the reporter ignores it, the walk goes
/// through it, and both flags fall beneath it). Three kinds are documented exceptions, and the cell asserts
/// each one's reason: beneath a failed `RuleCheck` the walk is neither stoppable nor reached, and the walk
/// does not enter a failed called rule the reporter reaches (the run tells its own marks); beneath a rule
/// or type condition the walk is not stoppable but IS reached, because the reporter descends there through
/// a filtered copy and writes the probe's entry. Fails when a kind is added to or removed from one list and
/// not the other, or an exception's reason stops holding.
#[test]
fn the_reporters_descent_and_the_walks_stoppable_flag_agree_on_every_failed_record_kind() {
    use frame_sources::block_check;
    const PROBE: &str = "the probe clause failed";
    let probe = || EventRecord {
        context: String::from("GuardBlockAccessClause#probe"),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            Some(PROBE.to_string()),
            false,
            false,
        ))),
        children: vec![],
    };
    let under = |container: Option<RecordType<'static>>| EventRecord {
        context: String::from("parent"),
        container,
        children: vec![probe()],
    };
    let named = |name: &'static str| NamedStatus {
        name,
        status: Status::FAIL,
        message: None,
        slot: crate::rules::CustomSlot::Evaluator,
        displaced: None,
        frame_reads: Vec::new(),
        ended_by_error: false,
    };
    // One row per record kind, `Variant => sample`. The rows build `variant_name` (a match over `RecordType`
    // with no `_` arm: a new kind is a compile error here until its row is added), `kind_names` and `kinds`,
    // so the three cannot differ by a kind, and a row with no sample does not parse. The two bindings are
    // named by the caller: a `let` the macro named itself would be hygienic and unreachable from here.
    macro_rules! record_kinds {
        ($names:ident, $samples:ident; $($variant:ident => $sample:expr),+ $(,)?) => {
            fn variant_name(kind: &RecordType<'_>) -> &'static str {
                match kind {
                    $(RecordType::$variant(_) => stringify!($variant),)+
                }
            }
            let $names: Vec<&str> = vec![$(stringify!($variant)),+];
            let $samples: Vec<RecordType<'static>> = vec![$(RecordType::$variant($sample)),+];
        };
    }
    record_kinds! {
        kind_names, kinds;
        FileCheck => named("file"),
        RuleCheck => named("rule"),
        RuleCondition => Status::FAIL,
        TypeCheck => TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(None, false, false),
        },
        TypeCondition => Status::FAIL,
        TypeBlock => Status::FAIL,
        Filter => Status::FAIL,
        WhenCheck => block_check(None, false, false),
        WhenCondition => Status::FAIL,
        Disjunction => block_check(None, false, false),
        BlockGuardCheck => block_check(None, false, false),
        GuardClauseBlockCheck => block_check(None, false, false),
        ClauseValueCheck => ClauseCheck::MissingBlockValue(ValueCheck {
            from: QueryResult::UnResolved(UnResolved {
                traversed_to: Rc::new(PathAwareValue::try_from("{ A: 1 }").expect("parses")),
                remaining_query: String::new(),
                reason: None,
                kind: UnResolvedKind::Undecidable {
                    refusal: None,
                    carried: None,
                },
            }),
            message: None,
            custom_message: None,
            status: Status::FAIL,
            refusal: false,
        }),
    }
    // The samples are the rows' kinds, one each: a row written twice for one kind shows up here.
    let mut names: Vec<&str> = kinds.iter().map(variant_name).collect();
    names.sort_unstable();
    names.dedup();
    let mut expected = kind_names.clone();
    expected.sort_unstable();
    assert_eq!(
        expected, names,
        "one sample per record kind, the kinds the rows name: {:?}",
        names
    );
    // `RuleCheck`: the walk does not enter a failed called rule the reporter reaches (`marks_walk_descends`
    // reads `reached`), and beneath one it enters the reporter reaches nothing, so the walk is neither
    // stoppable nor reached beneath it whatever the reporter does; `RuleCondition` and `TypeCondition`: the
    // reporter descends through a filtered copy, so the walk is reached but deliberately not stoppable there.
    // Every other kind must agree with the reporter on both flags.
    let exceptions = ["RuleCheck", "RuleCondition", "TypeCondition"];
    // The rows' kinds, and beside them the one shape that is no kind: an absent container, which the
    // reporter ignores and the walk goes through (`marks_walk_descends`), with neither flag kept beneath it.
    let mut parents: Vec<(&str, Option<RecordType<'static>>)> = kinds
        .into_iter()
        .map(|kind| (variant_name(&kind), Some(kind)))
        .collect();
    parents.push(("an absent kind", None));
    assert_eq!(
        kind_names.len() + 1,
        parents.len(),
        "one row per kind and the absent-container row"
    );
    assert!(
        marks_walk_descends(&under(None), true, true),
        "the walk goes through an absent container; the flags beneath it are the agreement's business"
    );
    let reporter_reaches = |container: Option<RecordType<'static>>| -> bool {
        let reports = report_all_failed_clauses_for_rules(&[under(container)]);
        reports.iter().any(|report| {
            let (recorded, _) = texts_and_reader_messages(report);
            recorded.iter().any(|text| text == PROBE)
        })
    };
    let disagreements: Vec<&str> = parents
        .iter()
        .filter(|(name, _)| !exceptions.contains(name))
        .filter(|(_, container)| {
            let record = under(container.clone());
            let reaches = reporter_reaches(container.clone());
            reaches != stoppable_beneath(&record, true) || reaches != reached_beneath(&record, true)
        })
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(
        Vec::<&str>::new(),
        disagreements,
        "kinds where the reporter's descent and `stoppable_beneath` or `reached_beneath` differ"
    );
    // The documented exceptions: the walk is not stoppable beneath any of them, and each one's reason holds.
    let stoppable_under_an_exception: Vec<&str> = parents
        .iter()
        .filter(|(name, _)| exceptions.contains(name))
        .filter(|(_, container)| stoppable_beneath(&under(container.clone()), true))
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(
        Vec::<&str>::new(),
        stoppable_under_an_exception,
        "the walk is not stoppable beneath a called rule or a filtered condition"
    );
    let failed_rule = under(Some(RecordType::RuleCheck(named("rule"))));
    assert_eq!(
        (false, false),
        (
            marks_walk_descends(&failed_rule, true, true),
            reached_beneath(&failed_rule, true)
        ),
        "a failed called rule the reporter reaches is not entered, and nothing beneath it is reached"
    );
    for condition in [
        RecordType::RuleCondition(Status::FAIL),
        RecordType::TypeCondition(Status::FAIL),
    ] {
        let record = under(Some(condition.clone()));
        assert_eq!(
            (true, true),
            (reporter_reaches(Some(condition)), reached_beneath(&record, true)),
            "the reporter reaches the probe through a condition's filtered copy, and the walk stays reached \
             there: {:?}",
            record.container
        );
    }
}

/// The arm of `marks_walk_descends` for a called rule, asserted directly so a rewrite to `=> true` cannot
/// survive on the reporter's dedupe alone: a failed `RuleCheck` is entered only where the reporter does not
/// reach it (`reached` false), never where it does (its own run tells the marks), and a `RuleCheck` that did
/// not fail is never entered. Fails when any of the three answers moves.
#[test]
fn the_walk_enters_a_failed_called_rule_only_where_the_reporter_does_not_reach_it() {
    use crate::rules::CustomSlot;
    let called = |status: Status| EventRecord {
        context: String::from("called"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "called",
            status,
            message: None,
            slot: CustomSlot::Evaluator,
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![],
    };
    assert_eq!(
        (false, false, true, false, false),
        (
            marks_walk_descends(&called(Status::FAIL), true, true),
            marks_walk_descends(&called(Status::FAIL), false, true),
            marks_walk_descends(&called(Status::FAIL), false, false),
            marks_walk_descends(&called(Status::PASS), false, false),
            marks_walk_descends(&called(Status::SKIP), false, false),
        ),
        "entered only when failed and not reached: not where reached (stoppable or through a condition's \
         filtered copy), never when it passed or was skipped"
    );
}

/// A mark under the evaluator's real own-condition shape, `TypeCheck > TypeBlock > TypeCondition >
/// BlockGuardCheck > mark`, is in the OWN group of the three (`refusals_by_depth`), not the nested one: a
/// check inside the record's own condition is that condition's own. A mark under a nested `when`'s condition
/// in the body is nested. Fails when the own-condition mark lands in the nested group.
#[test]
fn a_mark_under_the_real_own_condition_shape_is_in_the_own_group() {
    use frame_sources::{block_check, mark, under_a_condition, when_block, HELD};
    registered_as_in_a_run!(HELD);
    let own_condition = under_a_condition(
        RecordType::TypeCondition(Status::FAIL),
        vec![EventRecord {
            context: String::from("BlockGuardCheck#1"),
            container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
            children: vec![mark(HELD)],
        }],
    );
    let nested_when = when_block(
        None,
        &[],
        vec![under_a_condition(
            RecordType::WhenCondition(Status::FAIL),
            vec![mark(HELD)],
        )],
    );
    let children = vec![EventRecord {
        context: String::from("TypeBlock#S3/0"),
        container: Some(RecordType::TypeBlock(Status::FAIL)),
        children: vec![own_condition, nested_when],
    }];
    let groups = refusals_by_depth(&children);
    assert_eq!(
        [1, 1, 0],
        [groups[0].len(), groups[1].len(), groups[2].len()],
        "one refusal under the record's own condition, one under the nested when's, none in a clause"
    );
}

/// A type block WITH a sentence over a message-less nested `when` whose condition holds a mark for R,
/// through the reporter: the `when` writes its own refusals-only entry (a record with a sentence hands its
/// children no deferral), the type block's sentence stands alone beside it, and R is told once. On a type
/// block's or a `when`'s sentence the nested joiner (`NESTED_ALSO_MET`) is therefore written only for a
/// nested record the reporter does not reach (the next cells), never for one it reaches; a rule's sentence
/// and an access clause's entry take a reached nested record's refusals too, by deferral. Fails when R is
/// told twice, or the nested joiner reaches the type block's sentence.
#[test]
fn a_type_block_over_a_nested_when_tells_the_refusal_in_the_whens_entry_not_in_its_sentence() {
    use crate::rules::{CustomSlot, TypeBlockCheck};
    use frame_sources::{block_check, mark, rule, under_a_condition, when_block, HELD};
    registered_as_in_a_run!(HELD);
    let nested_when = when_block(
        None,
        &[],
        vec![under_a_condition(
            RecordType::WhenCondition(Status::FAIL),
            vec![mark(HELD)],
        )],
    );
    let type_block = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(Some(String::from("the type block failed")), false, false),
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock#S3/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![nested_when],
        }],
    };
    let reports = report_all_failed_clauses_for_rules(&[rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![type_block],
    )]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    let told: usize = recorded.iter().map(|text| text.matches(HELD).count()).sum();
    assert_eq!(
        (1, 0, 1),
        (
            told,
            recorded
                .iter()
                .filter(|text| text.contains(NESTED_ALSO_MET))
                .count(),
            recorded
                .iter()
                .filter(|text| text.as_str() == "the type block failed")
                .count()
        ),
        "R once (the when's entry), no nested joiner anywhere, the type block's sentence alone: {:?}",
        recorded
    );
}

/// The nested joiner on a type block's own sentence, through the reporter: `TypeCheck` (with a sentence) >
/// `TypeBlock` > `Filter` (a record kind the reporter ignores) > `WhenCheck` (no sentence, failed) >
/// `WhenCondition` > a mark for R. The `when` is never reached, so it writes no entry; the type block's walk
/// finds R in the nested group; the sentence reads `<sentence>; a nested condition also met: R`: R is told
/// once, and no entry names the `when`. The same refusal under a `when` the reporter DOES reach is told in
/// that `when`'s entry instead (`a_type_block_over_a_nested_when_tells_the_refusal_in_the_whens_entry_not_in_its_sentence`).
/// The record is an invented one, built from the record kinds the evaluator writes: no rules file was run
/// to produce this tree (the filter-predicate shape under a clause is written by the evaluator, but this
/// cell was written without a way to run the evaluator and read the tree back), so it pins the reporter,
/// not the evaluator. Fails when R is told twice or nowhere, or the sentence words it other than behind
/// the nested joiner.
#[test]
fn a_nested_when_beneath_a_kind_the_reporter_ignores_is_joined_on_the_type_blocks_sentence() {
    use crate::rules::{CustomSlot, TypeBlockCheck};
    use frame_sources::{block_check, mark, rule, under_a_condition, when_block, HELD};
    registered_as_in_a_run!(HELD);
    let nested_when = when_block(
        None,
        &[],
        vec![under_a_condition(
            RecordType::WhenCondition(Status::FAIL),
            vec![mark(HELD)],
        )],
    );
    let ignored = EventRecord {
        context: String::from("Filter#1"),
        container: Some(RecordType::Filter(Status::FAIL)),
        children: vec![nested_when],
    };
    let type_block = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(Some(String::from("the type block failed")), false, false),
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock#S3/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![ignored],
        }],
    };
    let reports = report_all_failed_clauses_for_rules(&[rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![type_block],
    )]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    let told: Vec<&String> = recorded.iter().filter(|text| text.contains(HELD)).collect();
    assert_eq!(
        vec![format!("the type block failed{NESTED_ALSO_MET}{HELD}")],
        told.into_iter().cloned().collect::<Vec<String>>(),
        "R once, on the type block's sentence behind the nested joiner, no entry for the when: {:?}",
        recorded
    );
}

/// The same shape with the nested `when` carrying a MESSAGE, the usual case for an inline `when` whose
/// condition failed closed: `TypeCheck` (with a sentence) > `TypeBlock` > `Filter` > `WhenCheck` (with a
/// sentence, failed) > `WhenCondition` > a mark for R. The reporter never reaches the `when`, so its sentence
/// is never written and tells nothing; the walk of the marks goes on beneath it (a sentence stops the walk
/// only where the reporter writes it) and finds R in the nested group; the type block's sentence reads
/// `<sentence>; a nested condition also met: R`. Fails when R is told nowhere (the walk stopped at the
/// messaged `when`), twice, or behind another joiner.
#[test]
fn a_messaged_when_beneath_a_kind_the_reporter_ignores_is_joined_on_the_type_blocks_sentence() {
    use crate::rules::{CustomSlot, TypeBlockCheck};
    use frame_sources::{block_check, mark, rule, under_a_condition, when_block, HELD};
    registered_as_in_a_run!(HELD);
    let nested_when = when_block(
        Some(String::from("the when failed")),
        &[],
        vec![under_a_condition(
            RecordType::WhenCondition(Status::FAIL),
            vec![mark(HELD)],
        )],
    );
    let ignored = EventRecord {
        context: String::from("Filter#1"),
        container: Some(RecordType::Filter(Status::FAIL)),
        children: vec![nested_when],
    };
    let type_block = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(Some(String::from("the type block failed")), false, false),
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock#S3/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![ignored],
        }],
    };
    let reports = report_all_failed_clauses_for_rules(&[rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![type_block],
    )]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    let told: Vec<&String> = recorded.iter().filter(|text| text.contains(HELD)).collect();
    assert_eq!(
        vec![format!("the type block failed{NESTED_ALSO_MET}{HELD}")],
        told.into_iter().cloned().collect::<Vec<String>>(),
        "R once, on the type block's sentence behind the nested joiner, though the when has a sentence: {:?}",
        recorded
    );
}

/// The refusal under the unreached, messaged `when` is NOT a gate mark: `TypeCheck` (with a sentence) >
/// `TypeBlock` > `Filter` > `WhenCheck` (with a sentence, failed) > `WhenCondition` > a refused comparison
/// record carrying R (`refusal: true`, a per-value check, no mark). The walk of the marks collects gate marks
/// only, the type block's own-condition walk (`condition_refusals`) reads its direct condition and
/// `TypeBlock` children only, and the `when`'s entry, which would join R, is never written: R is read by the
/// walk's deferred-record arm alone, which takes a `when` or type block the reporter never reaches as
/// deferred whatever its message (`is_deferred_condition_record` with `reached` false, read with the marks by
/// `refusals_by_depth`), and the sentence reads `<sentence>; a nested condition also met: R`.
/// The collector reaches the record because the condition's filtered copy keeps it:
/// `clause_check_carries_the_raise` answers `check.refusal` for a `Comparison`, so a refused comparison
/// record (refusal set, no gate mark) survives `condition_records` and `condition_refusals` reads its
/// message. Fails when R is told nowhere (the collector asked for a message-less record) or twice.
#[test]
fn a_refused_record_under_an_unreached_messaged_when_is_joined_on_the_type_blocks_sentence() {
    use crate::rules::{CustomSlot, TypeBlockCheck};
    use frame_sources::{block_check, rule, under_a_condition, when_block, HELD};
    registered_as_in_a_run!(HELD);
    let refused_comparison = EventRecord {
        context: String::from("Resources.A.Tags EXISTS"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(
            ComparisonClauseCheck {
                comparison: (CmpOperator::Exists, false),
                from: QueryResult::Resolved(Rc::new(PathAwareValue::Int((
                    Path::new(String::from("/Resources/A/Tags"), 1, 1),
                    1,
                )))),
                to: None,
                message: Some(HELD.to_string()),
                custom_message: None,
                status: Status::FAIL,
                refusal: true,
            },
        ))),
        children: vec![],
    };
    let nested_when = when_block(
        Some(String::from("the when failed")),
        &[],
        vec![under_a_condition(
            RecordType::WhenCondition(Status::FAIL),
            vec![refused_comparison],
        )],
    );
    let ignored = EventRecord {
        context: String::from("Filter#1"),
        container: Some(RecordType::Filter(Status::FAIL)),
        children: vec![nested_when],
    };
    let type_block = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(Some(String::from("the type block failed")), false, false),
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock#S3/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![ignored],
        }],
    };
    let reports = report_all_failed_clauses_for_rules(&[rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![type_block],
    )]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    let told: Vec<&String> = recorded.iter().filter(|text| text.contains(HELD)).collect();
    assert_eq!(
        vec![format!("the type block failed{NESTED_ALSO_MET}{HELD}")],
        told.into_iter().cloned().collect::<Vec<String>>(),
        "a refused record that is no mark, under an unreached messaged when: R once, on the type block's \
         sentence behind the nested joiner: {:?}",
        recorded
    );
}

/// The unreached record's refusals reach EVERY host, since every arm reads them with the marks
/// (`refusals_by_depth`, the one source): three hosts over the same `Filter > WhenCheck (with a sentence,
/// failed) > WhenCondition > refused comparison record carrying R`, each telling R exactly once. (a) A
/// MESSAGE-LESS type block under a rule with no text: no sentence to join R to, so the type block's
/// refusals-alone entry (`marks_alone_entry`) carries it. (b) A block WITH a sentence: its sentence joins R
/// behind the nested joiner, since R was read under a failed condition nested beneath the block and a
/// condition refusal reads the same wherever it is joined (a mark of the block's own clauses would follow
/// the body joiner). (c) A disjunction with a sentence: the same, on the disjunction's sentence. Fails when
/// any host tells R nowhere (a collector wired at some hosts only), twice, or behind the body joiner.
#[test]
fn an_unreached_whens_refusal_reaches_a_message_less_type_block_a_block_and_a_disjunction() {
    use crate::rules::CustomSlot;
    use frame_sources::{block_check, rule, type_block, under_a_condition, when_block, HELD};
    registered_as_in_a_run!(HELD);
    let unreached_when = || EventRecord {
        context: String::from("Filter#1"),
        container: Some(RecordType::Filter(Status::FAIL)),
        children: vec![when_block(
            Some(String::from("the when failed")),
            &[],
            vec![under_a_condition(
                RecordType::WhenCondition(Status::FAIL),
                vec![EventRecord {
                    context: String::from("Resources.A.Tags EXISTS"),
                    container: Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                        ComparisonClauseCheck {
                            comparison: (CmpOperator::Exists, false),
                            from: QueryResult::Resolved(Rc::new(PathAwareValue::Int((
                                Path::new(String::from("/Resources/A/Tags"), 1, 1),
                                1,
                            )))),
                            to: None,
                            message: Some(HELD.to_string()),
                            custom_message: None,
                            status: Status::FAIL,
                            refusal: true,
                        },
                    ))),
                    children: vec![],
                }],
            )],
        )],
    };
    let told_of = |host: EventRecord<'static>| -> Vec<String> {
        let reports = report_all_failed_clauses_for_rules(&[rule(
            None,
            None,
            CustomSlot::Evaluator,
            &[],
            vec![host],
        )]);
        let (recorded, _) = texts_and_reader_messages(&reports[0]);
        recorded
            .into_iter()
            .filter(|text| text.contains(HELD))
            .collect()
    };
    // (a) A message-less type block: `type_block` wraps the records in the per-resource condition shape,
    // so the filter is put under the `TypeBlock` record by hand instead, in the body position.
    let message_less_type_block = {
        let mut host = type_block(None, &[], vec![]);
        host.children = vec![EventRecord {
            context: String::from("TypeBlock#S3/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![unreached_when()],
        }];
        host
    };
    let block = EventRecord {
        context: String::from("BlockGuardCheck#1"),
        container: Some(RecordType::BlockGuardCheck(block_check(
            Some(String::from("the block failed")),
            false,
            false,
        ))),
        children: vec![unreached_when()],
    };
    let disjunction = EventRecord {
        context: String::from("Disjunction#1"),
        container: Some(RecordType::Disjunction(block_check(
            Some(String::from("the disjunction failed")),
            false,
            false,
        ))),
        children: vec![unreached_when()],
    };
    assert_eq!(
        (
            vec![HELD.to_string()],
            vec![format!("the block failed{NESTED_ALSO_MET}{HELD}")],
            vec![format!("the disjunction failed{NESTED_ALSO_MET}{HELD}")],
        ),
        (
            told_of(message_less_type_block),
            told_of(block),
            told_of(disjunction),
        ),
        "R once at each host: the type block's refusals-alone entry, the block's sentence and the \
         disjunction's sentence behind the nested joiner"
    );
}

/// A deferred record BELOW A CHECK inside a condition is a nested condition's, as a mark there is: the walk
/// counts a called rule or a `when` it enters OUTSIDE any condition as a check between, and what
/// lies under THAT check's condition is not this record's own condition's; the controls put the
/// same chains directly inside this record's own condition and read the own joiner. Two triggers
/// under a type block with a sentence, each with an
/// unreached messaged `when` (beneath a filter's predicate records) whose condition holds a mark for R: (a)
/// `TypeBlock > Filter > RuleCheck (failed, unreached) > RuleCondition > Filter > WhenCheck > WhenCondition >
/// R`, (b) `TypeBlock > Filter > WhenCheck (unreached) > WhenCondition > Filter > WhenCheck (unreached) >
/// WhenCondition > R`. Each reads R exactly once behind the nested joiner and never behind the own-condition
/// joiner. The control for each: the same deferred chain directly under the type block's OWN condition
/// (`TypeCondition > Filter > ...`), which reads R behind the own-condition joiner. Fails when a deferred
/// record is grouped by the condition flag alone (R behind the own-condition joiner on a trigger), or told
/// twice or nowhere.
#[test]
fn a_deferred_record_below_a_check_inside_a_condition_is_a_nested_conditions() {
    use crate::rules::{CustomSlot, TypeBlockCheck};
    use frame_sources::{block_check, mark, rule, under_a_condition, when_block, HELD};
    registered_as_in_a_run!(HELD);
    let behind_a_filter = |children: Vec<EventRecord<'static>>| EventRecord {
        context: String::from("Filter#1"),
        container: Some(RecordType::Filter(Status::FAIL)),
        children,
    };
    let unreached_when = |children: Vec<EventRecord<'static>>| {
        behind_a_filter(vec![when_block(
            Some(String::from("the when failed")),
            &[],
            vec![under_a_condition(
                RecordType::WhenCondition(Status::FAIL),
                children,
            )],
        )])
    };
    let unreached_called_rule = |children: Vec<EventRecord<'static>>| {
        behind_a_filter(vec![EventRecord {
            context: String::from("called"),
            container: Some(RecordType::RuleCheck(NamedStatus {
                name: "called",
                status: Status::FAIL,
                message: None,
                slot: CustomSlot::Evaluator,
                displaced: None,
                frame_reads: Vec::new(),
                ended_by_error: true,
            })),
            children: vec![under_a_condition(
                RecordType::RuleCondition(Status::FAIL),
                children,
            )],
        }])
    };
    let told_of = |type_block_children: Vec<EventRecord<'static>>| -> Vec<String> {
        let type_block = EventRecord {
            context: String::from("TypeBlock#S3"),
            container: Some(RecordType::TypeCheck(TypeBlockCheck {
                type_name: "AWS::S3::Bucket",
                block: block_check(Some(String::from("the type block failed")), false, false),
            })),
            children: vec![EventRecord {
                context: String::from("TypeBlock#S3/0"),
                container: Some(RecordType::TypeBlock(Status::FAIL)),
                children: type_block_children,
            }],
        };
        let reports = report_all_failed_clauses_for_rules(&[rule(
            None,
            None,
            CustomSlot::Evaluator,
            &[],
            vec![type_block],
        )]);
        let (recorded, _) = texts_and_reader_messages(&reports[0]);
        recorded
            .into_iter()
            .filter(|text| text.contains(HELD))
            .collect()
    };
    let own_condition = |children: Vec<EventRecord<'static>>| {
        under_a_condition(RecordType::TypeCondition(Status::FAIL), children)
    };
    let nested = format!("the type block failed{NESTED_ALSO_MET}{HELD}");
    let own = format!("the type block failed{ALSO_MET}{HELD}");
    assert_eq!(
        (
            vec![nested.clone()],
            vec![nested],
            vec![own.clone()],
            vec![own]
        ),
        (
            // (a) under an entered called rule's condition.
            told_of(vec![unreached_called_rule(vec![unreached_when(vec![
                mark(HELD),
            ])])]),
            // (b) under a nested unreached when's condition.
            told_of(vec![unreached_when(vec![unreached_when(vec![mark(
                HELD
            )])])]),
            // Controls: the same deferred chains directly under the type block's own condition.
            told_of(vec![own_condition(vec![unreached_called_rule(vec![
                unreached_when(vec![mark(HELD)]),
            ])])]),
            told_of(vec![own_condition(vec![unreached_when(vec![
                unreached_when(vec![mark(HELD)]),
            ])])]),
        ),
        "R once: behind the nested joiner under a check inside the condition, behind the own-condition joiner \
         directly under the type block's own condition"
    );
}

/// One refusal that is BOTH a nested condition's and a body clause's mark beneath a block or a disjunction is
/// told once: a block or disjunction with nothing reported beneath it joins the two groups of its refusals
/// to its sentence (or lists them alone when it has none), and a refusal in both groups stays in the
/// condition's group only (`marked_refusals_by_group`, each refusal once across the groups). The shape: a
/// filter's predicate records over an unreached messaged `when` whose condition holds a mark for R, beside a
/// body mark for R and a body mark for R2 that no condition met. Three hosts: a block with a sentence (R
/// behind the nested joiner, R2 behind the body joiner), a block without one (the refusals alone, R then R2),
/// a disjunction with a sentence (as the block with one). Fails when R is told twice (once per group), or R2
/// leaves the body joiner.
#[test]
fn a_refusal_in_both_groups_beneath_a_block_or_disjunction_is_told_once() {
    use crate::rules::CustomSlot;
    use frame_sources::{block_check, mark, rule, under_a_condition, when_block, HELD, OTHER};
    registered_as_in_a_run!(HELD, OTHER);
    let children = || {
        vec![
            EventRecord {
                context: String::from("Filter#1"),
                container: Some(RecordType::Filter(Status::FAIL)),
                children: vec![when_block(
                    Some(String::from("the when failed")),
                    &[],
                    vec![under_a_condition(
                        RecordType::WhenCondition(Status::FAIL),
                        vec![mark(HELD)],
                    )],
                )],
            },
            mark(HELD),
            mark(OTHER),
        ]
    };
    let told_of = |host: EventRecord<'static>| -> (Vec<String>, usize) {
        let reports = report_all_failed_clauses_for_rules(&[rule(
            None,
            None,
            CustomSlot::Evaluator,
            &[],
            vec![host],
        )]);
        let (recorded, _) = texts_and_reader_messages(&reports[0]);
        let r_count = recorded.iter().map(|text| text.matches(HELD).count()).sum();
        (
            recorded
                .into_iter()
                .filter(|text| text.contains(HELD))
                .collect(),
            r_count,
        )
    };
    let block = |message: Option<&str>| EventRecord {
        context: String::from("BlockGuardCheck#1"),
        container: Some(RecordType::BlockGuardCheck(block_check(
            message.map(String::from),
            false,
            false,
        ))),
        children: children(),
    };
    let disjunction = EventRecord {
        context: String::from("Disjunction#1"),
        container: Some(RecordType::Disjunction(block_check(
            Some(String::from("the disjunction failed")),
            false,
            false,
        ))),
        children: children(),
    };
    assert_eq!(
        (
            (
                vec![format!(
                    "the block failed{NESTED_ALSO_MET}{HELD}{BODY_ALSO_MET}{OTHER}"
                )],
                1
            ),
            (vec![format!("{HELD}; {OTHER}")], 1),
            (
                vec![format!(
                    "the disjunction failed{NESTED_ALSO_MET}{HELD}{BODY_ALSO_MET}{OTHER}"
                )],
                1
            ),
        ),
        (
            told_of(block(Some("the block failed"))),
            told_of(block(None)),
            told_of(disjunction),
        ),
        "R once in the condition's group, R2 behind the body joiner, at each of the three hosts"
    );
}

/// A type block WITH a sentence whose sentence an entry beneath already carries, over an unreached messaged
/// `when` with a refused comparison record carrying R: `TypeCheck` (sentence E) > `TypeBlock` > [a block with
/// the sentence E and no children, `Filter` > `WhenCheck` (with a sentence, failed) > `WhenCondition` > R].
/// The block's entry tells E, so the type block writes no sentence of its own beside the entries
/// (`sentence_told_by`), and the refusals no entry carries become the type block's refusals-alone entry
/// (`marks_alone_entry`, the `alone` value of the type block arm), which reads R through the one source
/// (`marked_refusals_beneath`): R once, E once. Fails when R is told nowhere (the sentence path is the only
/// one that reads unreached records) or twice, or E twice.
#[test]
fn an_unreached_whens_refusal_under_a_type_block_whose_sentence_an_entry_carries_is_told_once() {
    use crate::rules::{CustomSlot, TypeBlockCheck};
    use frame_sources::{block_check, rule, under_a_condition, when_block, HELD};
    registered_as_in_a_run!(HELD);
    const E: &str = "the type block failed";
    let carrying_block = EventRecord {
        context: String::from("BlockGuardCheck#1"),
        container: Some(RecordType::BlockGuardCheck(block_check(
            Some(E.to_string()),
            false,
            false,
        ))),
        children: vec![],
    };
    let unreached_when = EventRecord {
        context: String::from("Filter#1"),
        container: Some(RecordType::Filter(Status::FAIL)),
        children: vec![when_block(
            Some(String::from("the when failed")),
            &[],
            vec![under_a_condition(
                RecordType::WhenCondition(Status::FAIL),
                vec![EventRecord {
                    context: String::from("Resources.A.Tags EXISTS"),
                    container: Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                        ComparisonClauseCheck {
                            comparison: (CmpOperator::Exists, false),
                            from: QueryResult::Resolved(Rc::new(PathAwareValue::Int((
                                Path::new(String::from("/Resources/A/Tags"), 1, 1),
                                1,
                            )))),
                            to: None,
                            message: Some(HELD.to_string()),
                            custom_message: None,
                            status: Status::FAIL,
                            refusal: true,
                        },
                    ))),
                    children: vec![],
                }],
            )],
        )],
    };
    let type_block = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(Some(E.to_string()), false, false),
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock#S3/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![carrying_block, unreached_when],
        }],
    };
    let reports = report_all_failed_clauses_for_rules(&[rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![type_block],
    )]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    let told: Vec<String> = recorded
        .iter()
        .filter(|text| text.contains(HELD))
        .cloned()
        .collect();
    assert_eq!(
        (vec![HELD.to_string()], 1),
        (
            told,
            recorded.iter().filter(|text| text.as_str() == E).count()
        ),
        "R once, as the type block's refusals-alone entry beside the entry that carries its sentence; E \
         once: {:?}",
        recorded
    );
}

/// A REACHED, messaged `when` under a type block WITH a sentence: `TypeCheck` (with a sentence) > `TypeBlock`
/// > `WhenCheck` (with a sentence, failed) > `WhenCondition` > a mark for R. The reporter reaches the `when`
/// and writes its entry, which joins R behind the own-condition joiner (`ALSO_MET`: R is the `when`'s own
/// condition's); the `when` is not deferred (`is_deferred_condition_record` with `reached` true and a
/// message), so the type block's sentence stands alone, with no nested joiner, and R is told once. Fails
/// when R is told twice (the type block's sentence repeats it), nowhere, or the nested joiner appears.
#[test]
fn a_reached_messaged_when_under_a_type_block_with_a_sentence_tells_its_refusal_in_its_own_entry() {
    use crate::rules::{CustomSlot, TypeBlockCheck};
    use frame_sources::{block_check, mark, rule, under_a_condition, when_block, HELD};
    registered_as_in_a_run!(HELD);
    let nested_when = when_block(
        Some(String::from("the when failed")),
        &[],
        vec![under_a_condition(
            RecordType::WhenCondition(Status::FAIL),
            vec![mark(HELD)],
        )],
    );
    let type_block = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(Some(String::from("the type block failed")), false, false),
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock#S3/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![nested_when],
        }],
    };
    let reports = report_all_failed_clauses_for_rules(&[rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![type_block],
    )]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    let told: Vec<String> = recorded
        .iter()
        .filter(|text| text.contains(HELD))
        .cloned()
        .collect();
    assert_eq!(
        (vec![format!("the when failed{ALSO_MET}{HELD}")], 0, 1),
        (
            told,
            recorded
                .iter()
                .filter(|text| text.contains(NESTED_ALSO_MET))
                .count(),
            recorded
                .iter()
                .filter(|text| text.as_str() == "the type block failed")
                .count()
        ),
        "R once, in the reached when's own entry behind its own-condition joiner; the type block's sentence \
         alone, no nested joiner: {:?}",
        recorded
    );
}

/// The unreached-record shape of the cell above with a TYPE BLOCK in place of the `when`: `TypeCheck` (with
/// a sentence) > `TypeBlock` >
/// `Filter` > `TypeCheck` (with a sentence, failed) > `TypeBlock` > `TypeCondition` > a refused comparison
/// record carrying R (no gate mark). The nested type block is never reached, so it is a deferred record
/// whatever its message, its condition's refusals are read through its `TypeBlock` records, and the outer
/// sentence reads `<sentence>; a nested condition also met: R`, once. The cell also reads the deferral test
/// directly: a messaged failed `TypeCheck` and a messaged failed `WhenCheck` are deferred with `reached`
/// false and not deferred with `reached` true. Fails when R is told nowhere or twice, or either direct read
/// moves.
#[test]
fn a_deferred_type_block_beneath_a_kind_the_reporter_ignores_is_joined_on_the_outer_sentence() {
    use crate::rules::{CustomSlot, TypeBlockCheck};
    use frame_sources::{block_check, rule, type_block, when_block, HELD};
    registered_as_in_a_run!(HELD);
    let refused_comparison = EventRecord {
        context: String::from("Resources.A.Tags EXISTS"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(
            ComparisonClauseCheck {
                comparison: (CmpOperator::Exists, false),
                from: QueryResult::Resolved(Rc::new(PathAwareValue::Int((
                    Path::new(String::from("/Resources/A/Tags"), 1, 1),
                    1,
                )))),
                to: None,
                message: Some(HELD.to_string()),
                custom_message: None,
                status: Status::FAIL,
                refusal: true,
            },
        ))),
        children: vec![],
    };
    let nested_type_block = type_block(
        Some(String::from("the nested type block failed")),
        &[],
        vec![refused_comparison],
    );
    let messaged_when = when_block(Some(String::from("the when failed")), &[], vec![]);
    assert_eq!(
        (true, true, false, false),
        (
            is_deferred_condition_record(&nested_type_block, false),
            is_deferred_condition_record(&messaged_when, false),
            is_deferred_condition_record(&nested_type_block, true),
            is_deferred_condition_record(&messaged_when, true),
        ),
        "a messaged failed type block or when is deferred where the reporter does not reach it, and not \
         where it does"
    );
    let ignored = EventRecord {
        context: String::from("Filter#1"),
        container: Some(RecordType::Filter(Status::FAIL)),
        children: vec![nested_type_block],
    };
    let outer = EventRecord {
        context: String::from("TypeBlock#Outer"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(Some(String::from("the type block failed")), false, false),
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock#Outer/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![ignored],
        }],
    };
    let reports = report_all_failed_clauses_for_rules(&[rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![outer],
    )]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    let told: Vec<&String> = recorded.iter().filter(|text| text.contains(HELD)).collect();
    assert_eq!(
        vec![format!("the type block failed{NESTED_ALSO_MET}{HELD}")],
        told.into_iter().cloned().collect::<Vec<String>>(),
        "a deferred type block beneath a filter: R once, on the outer sentence behind the nested joiner: {:?}",
        recorded
    );
}

/// A failed CALLED RULE the reporter never reaches, with a refused record that is no gate mark under its own
/// condition and a displaced refusal sentence of its own: `<host> > Filter > RuleCheck (failed, a displaced
/// refusal sentence quoting R) > RuleCondition > a refused comparison record carrying R`. Nobody reports the
/// rule's run, the walk of the marks enters it and collects gate marks only, and the host's own-condition
/// walk reads its direct condition children only, so R and the rule's sentence would be read by nothing:
/// the entered rule is a deferred record (`is_deferred_condition_record` with `reached` false), its
/// condition's refusals and its sentence are read (`deferred_record_refusals`) and joined at the host behind
/// the nested joiner, once. Two hosts, a rule with a text and a type block with a sentence, both reading the
/// one source (`refusals_by_depth`, through `grouped_untold_refusals` and `condition_and_clause_refusals`)
/// into their sentences. Fails when R is told
/// nowhere, twice (the comparison and the quoting sentence as two), or behind another joiner.
#[test]
fn a_refused_record_under_an_unreached_called_rules_condition_is_joined_at_the_host() {
    use crate::rules::eval::RULE_CONDITION_UNEVALUATED_HEAD;
    use crate::rules::{CustomSlot, TypeBlockCheck};
    use frame_sources::{block_check, rule, under_a_condition, HELD};
    registered_as_in_a_run!(HELD);
    let unreached_called_rule = || EventRecord {
        context: String::from("Filter#1"),
        container: Some(RecordType::Filter(Status::FAIL)),
        children: vec![EventRecord {
            context: String::from("called"),
            container: Some(RecordType::RuleCheck(NamedStatus {
                name: "called",
                status: Status::FAIL,
                message: Some(String::from("the author's body")),
                slot: CustomSlot::Author,
                displaced: Some((
                    CustomSlot::Refusal,
                    format!("{RULE_CONDITION_UNEVALUATED_HEAD}{HELD}"),
                )),
                frame_reads: Vec::new(),
                ended_by_error: true,
            })),
            children: vec![under_a_condition(
                RecordType::RuleCondition(Status::FAIL),
                vec![EventRecord {
                    context: String::from("Resources.A.Tags EXISTS"),
                    container: Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                        ComparisonClauseCheck {
                            comparison: (CmpOperator::Exists, false),
                            from: QueryResult::Resolved(Rc::new(PathAwareValue::Int((
                                Path::new(String::from("/Resources/A/Tags"), 1, 1),
                                1,
                            )))),
                            to: None,
                            message: Some(HELD.to_string()),
                            custom_message: None,
                            status: Status::FAIL,
                            refusal: true,
                        },
                    ))),
                    children: vec![],
                }],
            )],
        }],
    };
    let told_of = |record: EventRecord<'static>| -> Vec<String> {
        let reports = report_all_failed_clauses_for_rules(&[record]);
        let (recorded, _) = texts_and_reader_messages(&reports[0]);
        recorded
            .into_iter()
            .filter(|text| text.contains(HELD))
            .collect()
    };
    // The host is a rule with a text: the entered rule's condition refusals reach the rule's sentence.
    let told = told_of(rule(
        Some(String::from("The rule failed")),
        None,
        CustomSlot::Evaluator,
        &[],
        vec![unreached_called_rule()],
    ));
    assert_eq!(
        vec![format!("The rule failed{NESTED_ALSO_MET}{HELD}")],
        told,
        "under a rule with a text: R once, on the rule's sentence behind the nested joiner"
    );
    // The host is a type block with a sentence: the same refusals reach the type block's sentence.
    let type_block = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(Some(String::from("the type block failed")), false, false),
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock#S3/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![unreached_called_rule()],
        }],
    };
    let told = told_of(rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![type_block],
    ));
    assert_eq!(
        vec![format!("the type block failed{NESTED_ALSO_MET}{HELD}")],
        told,
        "under a type block with a sentence: R once, on the type block's sentence behind the nested joiner"
    );
}

/// A mark under the condition of a called rule the walk enters reads behind the nested joiner, as a mark
/// under a nested `when`'s condition does: `TypeCheck` (with a sentence) > `TypeBlock` > `Filter` >
/// `RuleCheck` (failed) > `RuleCondition` > a mark for R. The reporter never reaches the called rule's run,
/// so the walk enters it; the rule's condition is NOT the type block's own condition, and the entered rule
/// counts as a check between, so R lands in the nested group and the sentence reads `<sentence>; a nested
/// condition also met: R`. Fails when R reads behind the own-condition joiner (`ALSO_MET`), is told nowhere,
/// or twice.
#[test]
fn a_mark_under_an_entered_called_rules_condition_is_joined_as_a_nested_condition() {
    use crate::rules::{CustomSlot, TypeBlockCheck};
    use frame_sources::{block_check, mark, rule, under_a_condition, HELD};
    registered_as_in_a_run!(HELD);
    let called_rule = EventRecord {
        context: String::from("called"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "called",
            status: Status::FAIL,
            message: None,
            slot: CustomSlot::Evaluator,
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: true,
        })),
        children: vec![under_a_condition(
            RecordType::RuleCondition(Status::FAIL),
            vec![mark(HELD)],
        )],
    };
    let ignored = EventRecord {
        context: String::from("Filter#1"),
        container: Some(RecordType::Filter(Status::FAIL)),
        children: vec![called_rule],
    };
    let type_block = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(Some(String::from("the type block failed")), false, false),
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock#S3/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![ignored],
        }],
    };
    let reports = report_all_failed_clauses_for_rules(&[rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![type_block],
    )]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    let told: Vec<&String> = recorded.iter().filter(|text| text.contains(HELD)).collect();
    assert_eq!(
        vec![format!("the type block failed{NESTED_ALSO_MET}{HELD}")],
        told.into_iter().cloned().collect::<Vec<String>>(),
        "R once, behind the nested joiner and not the own-condition one: {:?}",
        recorded
    );
}

/// A failed called rule inside a type block's CONDITION is reached by the reporter (through the condition's
/// filtered copy, `condition_records`) and reports its own run, so the walk of the marks does not enter it:
/// `TypeCheck` (with a sentence) > `TypeBlock` > `TypeCondition` > `RuleCheck` (failed) > a message-less
/// block > a mark for R. R is told once, by the called run's own entry (the refusals alone); the type block's
/// sentence stands alone beside it, since the condition refusal it would join is carried by that entry.
/// This cell pins the OUTPUT, not the arm: a walk that entered the reached rule would find R a second time
/// in the type block's own-condition group, but `condition_refusals` names R there already (it reads a
/// called rule's refusals through the filtered copy) and `untold_by` strips what the run's entry carries,
/// so the output reads the same either way; the arm itself is pinned by the direct `marks_walk_descends`
/// assertion in this cell and in `the_walk_enters_a_failed_called_rule_only_where_the_reporter_does_not_reach_it`.
/// Fails when R is told twice or nowhere, or the sentence does not stand alone.
#[test]
fn a_failed_called_rule_inside_a_condition_tells_its_own_marks_and_the_walk_does_not_enter_it() {
    use crate::rules::{CustomSlot, TypeBlockCheck};
    use frame_sources::{block_check, mark, rule, under_a_condition, HELD};
    registered_as_in_a_run!(HELD);
    let called_rule = EventRecord {
        context: String::from("called"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "called",
            status: Status::FAIL,
            message: None,
            slot: CustomSlot::Evaluator,
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![EventRecord {
            context: String::from("BlockGuardCheck#9"),
            container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
            children: vec![mark(HELD)],
        }],
    };
    // The walk at the rule, as the type block's walk arrives there: reached (the condition's filtered copy
    // is reported) and not stoppable (no entry beneath the copy is certain to exist).
    assert!(
        !marks_walk_descends(&called_rule, false, true),
        "a failed called rule reached through a condition's filtered copy is not entered"
    );
    let type_block = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(Some(String::from("the type block failed")), false, false),
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock#S3/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![under_a_condition(
                RecordType::TypeCondition(Status::FAIL),
                vec![called_rule],
            )],
        }],
    };
    let reports = report_all_failed_clauses_for_rules(&[rule(
        None,
        None,
        CustomSlot::Evaluator,
        &[],
        vec![type_block],
    )]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    let told: Vec<&String> = recorded.iter().filter(|text| text.contains(HELD)).collect();
    assert_eq!(
        (vec![HELD.to_string()], 1),
        (
            told.into_iter().cloned().collect::<Vec<String>>(),
            recorded
                .iter()
                .filter(|text| text.as_str() == "the type block failed")
                .count()
        ),
        "R once, as the called run's own entry, and the type block's sentence alone: {:?}",
        recorded
    );
}

/// The entry a rule writes for the refusals beneath it that no entry of its checks names is attributed to
/// the record that carries one of THOSE refusals: a mark whose refusal an entry already tells is passed over
/// (here a top-level mark for R1, told by the clause's entry), and the rule's own name is never the context.
/// The context is a lookup over the collections the refusals are read from (`context_of_untold`): the mark
/// for R2 under the type block's condition, `NestedMark`. Fails when the entry carries any other context.
#[test]
fn the_rules_untold_refusals_entry_carries_the_context_of_a_record_that_names_them() {
    use crate::rules::CustomSlot;
    use frame_sources::{mark, refused_clause, rule, type_block, HELD, OTHER};
    registered_as_in_a_run!(HELD, OTHER);
    let mut told_mark = mark(HELD);
    told_mark.context = String::from("ToldMark");
    let mut nested_mark = mark(OTHER);
    nested_mark.context = String::from("NestedMark");
    let record = rule(
        Some(String::from("The rule failed")),
        None,
        CustomSlot::Evaluator,
        &[],
        vec![
            told_mark,
            refused_clause(HELD),
            type_block(None, &[], vec![nested_mark]),
        ],
    );
    let reports = report_all_failed_clauses_for_rules(&[record]);
    let entries: Vec<(String, Option<String>)> = match &reports[0] {
        ClauseReport::Rule(main) => main
            .checks
            .iter()
            .filter_map(|entry| match entry {
                ClauseReport::Block(block) => {
                    Some((block.context.clone(), block.messages.error_message.clone()))
                }
                _ => None,
            })
            .collect(),
        other => panic!("a rule report, got {:?}", other),
    };
    let carrying: Vec<&(String, Option<String>)> = entries
        .iter()
        .filter(|(_, text)| text.as_deref() == Some(OTHER))
        .collect();
    assert_eq!(
        vec![String::from("NestedMark")],
        carrying
            .iter()
            .map(|(context, _)| context.clone())
            .collect::<Vec<_>>(),
        "one refusals-alone entry for R2, in the context of the mark that carries it (`NestedMark`, \
         under the type block's condition), not the rule's name and not the told mark's: {:?}",
        entries
    );
}

/// The context of the entry a rule writes for untold refusals is the record that carried the entry's FIRST
/// refusal (`untold[0]`; the entry's text lists the condition's refusals before the clauses'), NOT the first
/// carrier in walk order: among the records that carry that one refusal, the first gate mark in walk order
/// wins, over a deferred `when` or type block above it that the walk visits first. Three rows: a clause mark
/// BEFORE a condition mark in walk order (the first carrier in walk order holds the entry's SECOND refusal;
/// the entry names the condition mark, which carries the first); the same entry with the type block first
/// (the two readings coincide); and a clause mark alone. Fails when the entry names the first carrier in
/// walk order where that is the second refusal's, or the rule.
#[test]
fn the_untold_refusals_entry_takes_the_context_of_the_carrier_of_its_first_refusal() {
    use crate::rules::CustomSlot;
    use frame_sources::{block_check, mark, refused_clause, rule, type_block, HELD, OTHER};
    registered_as_in_a_run!(HELD, OTHER);
    let first_mark = || {
        let mut first = mark(HELD);
        first.context = String::from("FirstMark");
        EventRecord {
            context: String::from("BlockGuardCheck#1"),
            container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
            children: vec![first],
        }
    };
    let second_mark = || {
        let mut second = mark(OTHER);
        second.context = String::from("SecondMark");
        type_block(None, &[], vec![second])
    };
    let contexts_of = |children: Vec<EventRecord<'static>>| -> Vec<String> {
        let record = rule(
            Some(String::from("The rule failed")),
            None,
            CustomSlot::Evaluator,
            &[],
            children,
        );
        let reports = report_all_failed_clauses_for_rules(&[record]);
        match &reports[0] {
            ClauseReport::Rule(main) => main
                .checks
                .iter()
                .filter_map(|entry| match entry {
                    ClauseReport::Block(block)
                        if block
                            .messages
                            .error_message
                            .as_deref()
                            .map_or(false, |text| text.contains(HELD)) =>
                    {
                        Some(block.context.clone())
                    }
                    _ => None,
                })
                .collect(),
            other => panic!("a rule report, got {:?}", other),
        }
    };
    let speaks = || refused_clause("a check that speaks");
    assert_eq!(
        (
            vec![String::from("SecondMark")],
            vec![String::from("SecondMark")],
            vec![String::from("FirstMark")]
        ),
        (
            // The entry's text is `OTHER; HELD` (the condition's refusal, then the clause's mark): its first
            // refusal is OTHER, carried by the mark under the type block's condition, which comes SECOND in
            // walk order here, so the two carriers differ and the entry names OTHER's.
            contexts_of(vec![speaks(), first_mark(), second_mark()]),
            // The same entry with the type block first in walk order: the carriers coincide.
            contexts_of(vec![speaks(), second_mark(), first_mark()]),
            // Only HELD untold: its carrier.
            contexts_of(vec![speaks(), first_mark()]),
        ),
        "the entry's context is the record that carried the entry's first refusal, whatever its place in walk \
         order, a mark before the deferred type block above it"
    );
}

/// The same negation, `rule main { not check << msg >> }`, where the refusal its sentence names is carried
/// beneath it by the refused clause's own entry (`frame_sources::refused_clause` is a clause block with a
/// message, context `GuardAccessClause#blockA`, and no children, so it has no reporting own-value check and
/// writes its entry itself: a Block entry in the report), or by a Disjunctions entry, and not by a called rule's run (there is no
/// "told beneath" filter by entry kind any more: the clause's own entry is always written and what is
/// beneath it is reported as it is). Each shape reports the entry that carries the refusal once, then the
/// negation's own entry with its context and the author's text, once. Fails when the carrying entry is
/// dropped or repeated, or the negation's entry is missing or has lost the author's text.
#[test]
fn a_negation_over_a_clause_or_a_disjunction_reports_the_carrying_entry_and_its_own_once() {
    use crate::rules::CustomSlot;
    use frame_sources::{block_check, refused_clause, rule, HELD};
    registered_as_in_a_run!(HELD);
    let negation_over = |child: EventRecord<'static>| {
        let mut negation_check = block_check(
            Some(format!(
                "`not` failed only on reads it could not decide: {HELD}"
            )),
            true,
            false,
        );
        negation_check.custom_message = Some(String::from("the negation's msg"));
        let negation = EventRecord {
            context: String::from("GuardBlockAccessClause#7"),
            container: Some(RecordType::GuardClauseBlockCheck(negation_check)),
            children: vec![child],
        };
        let record = rule(None, None, CustomSlot::Evaluator, &[], vec![negation]);
        let reports = report_all_failed_clauses_for_rules(&[record]);
        match &reports[0] {
            ClauseReport::Rule(main) => main
                .checks
                .iter()
                .map(|entry| match entry {
                    ClauseReport::Rule(_) => String::from("R"),
                    ClauseReport::Clause(_) => String::from("C"),
                    ClauseReport::Disjunctions(_) => String::from("D"),
                    ClauseReport::Block(block) => {
                        format!("B:{}:{:?}", block.context, block.messages.custom_message)
                    }
                })
                .collect::<Vec<String>>(),
            other => panic!("a rule report, got {:?}", other),
        }
    };
    let disjunction = EventRecord {
        context: String::from("Disjunction#1"),
        container: Some(RecordType::Disjunction(block_check(None, false, false))),
        children: vec![refused_clause(HELD)],
    };
    let own = String::from("B:GuardBlockAccessClause#7:Some(\"the negation's msg\")");
    assert_eq!(
        (
            vec![
                String::from("B:GuardAccessClause#blockA:None"),
                own.clone()
            ],
            vec![String::from("D"), own]
        ),
        (
            negation_over(refused_clause(HELD)),
            negation_over(disjunction)
        ),
        "the refused clause's own block entry (the fixture's refused clause is a clause block with a message, \
         so it is reported as a Block entry), or a Disjunctions entry, then the negation's own entry"
    );
}

/// The comment spans of `source` replaced by spaces, line breaks kept, for the source scan of
/// `every_sentence_the_evaluator_writes_on_a_parent_record_is_read_back_by_the_reader`, by a scan that
/// tracks where it stands character by character: in code, in a string literal (`"` to the next unescaped
/// `"`; a `\` skips the character after it), in a line comment (`//`, `///` or `//!` to the end of the line)
/// or in a block comment (`/*` to `*/`). A `//` or `/*` inside a string is text, not a comment; a `"` inside
/// a comment opens no string; a character literal (`'"'`, `'\''`, `'x'`) is skipped as code, so the quote it
/// holds opens no string, while a lifetime (`'a`) is left to the ordinary scan. Limits, by design: a raw
/// string (`r"..."`, `r#"..."#`) is read as an ordinary string, so a `\"` inside one, or a `"` inside a
/// `r#"..."#`, misplaces the string's end for the rest of that literal; nested block comments are not tracked
/// (the first `*/` closes). The module's sources hold neither shape today, and a misread would show up as a
/// wording count other than one, which the scan's cell asserts.
fn blank_comments(source: &str) -> String {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Where {
        Code,
        Str,
        LineComment,
        BlockComment,
    }
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut state = Where::Code;
    let mut i = 0;
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match state {
            Where::Code => match (c, next) {
                ('/', Some('/')) => {
                    state = Where::LineComment;
                    out.push_str("  ");
                    i += 2;
                }
                ('/', Some('*')) => {
                    state = Where::BlockComment;
                    out.push_str("  ");
                    i += 2;
                }
                ('"', _) => {
                    state = Where::Str;
                    out.push(c);
                    i += 1;
                }
                ('\'', _) => {
                    // A character literal: `'x'`, or `'\..'` up to its closing quote. Anything else after
                    // the quote is a lifetime or a label, scanned on as code.
                    let literal_end = match next {
                        // The escaped character sits at `i + 2` (`'\''` holds a quote there), so the
                        // closing quote is searched from `i + 3`.
                        Some('\\') => chars
                            .get(i + 3..)
                            .and_then(|rest| rest.iter().position(|each| *each == '\''))
                            .map(|rel| i + 3 + rel),
                        Some(_) if chars.get(i + 2) == Some(&'\'') => Some(i + 2),
                        _ => None,
                    };
                    match literal_end {
                        Some(end) => {
                            out.extend(&chars[i..=end]);
                            i = end + 1;
                        }
                        None => {
                            out.push(c);
                            i += 1;
                        }
                    }
                }
                _ => {
                    out.push(c);
                    i += 1;
                }
            },
            Where::Str => {
                out.push(c);
                i += 1;
                match c {
                    '\\' => {
                        if let Some(escaped) = next {
                            out.push(escaped);
                            i += 1;
                        }
                    }
                    '"' => state = Where::Code,
                    _ => {}
                }
            }
            Where::LineComment => {
                out.push(blank(c));
                if c == '\n' {
                    state = Where::Code;
                }
                i += 1;
            }
            Where::BlockComment => {
                if c == '*' && next == Some('/') {
                    out.push_str("  ");
                    state = Where::Code;
                    i += 2;
                } else {
                    out.push(blank(c));
                    i += 1;
                }
            }
        }
    }
    out
}

/// The comment blanker reads a character literal as code, its closing quote included, whatever the literal
/// holds: `'\''`, `'\\'`, `'\n'` and `'"'` each come through as written, the text after each is read as
/// code (a `/* .. */` right after the literal is blanked, a `"..."` right after it is kept), a `//` and a
/// `/*` inside a string stay text, a block comment opened after code and a second block on one line are
/// blanked, and the output keeps the character count and every line break. Fails when a literal's closing
/// quote is read as a lifetime or a string opener, so that what follows is misread.
#[test]
fn the_comment_blanker_reads_character_literals_and_strings_as_code() {
    // Every comment holds a word of its own (`cmt..`) that no code or string of the fixture holds, so a
    // needle found in the output can only be an unblanked comment, never kept code.
    let source = concat!(
        "let q = '\\''; /* cmtA */ let s = \"x // y /* z */\";\n",
        "let b = '\\\\'; /* cmtB */ \"k\" // cmtTail\n",
        "let n = '\\n'; /* cmtC */ let d = '\"'; /* cmtD */ \"m\"\n",
        "code /* cmtOpens\n",
        "cmtStill */ after /* cmtE */ more /* cmtF\n",
        "*/ end\n",
    );
    let blanked = blank_comments(source);
    let kept_literals = ["'\\''", "'\\\\'", "'\\n'", "'\"'"];
    assert_eq!(
        (
            source.chars().count(),
            source.lines().count(),
            kept_literals.iter().all(|literal| blanked.contains(literal)),
            blanked.contains("cmt"),
        ),
        (
            blanked.chars().count(),
            blanked.lines().count(),
            true,
            false
        ),
        "the literals and the strings stay, every comment span is blanked, the shape is kept: {blanked:?}"
    );
    assert!(
        blanked.contains("\"x // y /* z */\"")
            && blanked.contains("\"k\"")
            && blanked.contains("\"m\"")
            && blanked.contains(" after ")
            && blanked.contains(" more ")
            && blanked.contains(" end"),
        "the strings and the code between the comments are read as written: {:?}",
        blanked
    );
}

/// A bailing type block with a sentence and no entries beneath, over a resource's body whose silent block
/// holds a gate mark: the sentence joins the mark behind the body joiner, once. The rule's walk stops at a
/// record with a sentence, so a sentence that left the mark out would leave it told nowhere. Fails when the
/// nested-empty branch of a type block or `when` joins only the failed condition's refusals.
#[test]
fn a_bailing_type_block_with_no_entries_joins_the_marks_of_a_resource_body() {
    use crate::rules::eval_context::BODY_ALSO_MET;
    use crate::rules::TypeBlockCheck;
    use frame_sources::{block_check, mark, HELD};
    registered_as_in_a_run!(HELD);
    const BAILING: &str =
        "Error a plain error that ended the run during type condition evaluation, bailing";
    let silent_block = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![mark(HELD)],
    };
    let type_check = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: block_check(Some(BAILING.to_string()), false, false),
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock#S3/0"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![silent_block],
        }],
    };
    let reports = report_all_failed_clauses_for_rules(&[frame_sources::rule(
        None,
        None,
        crate::rules::CustomSlot::Evaluator,
        &[],
        vec![type_check],
    )]);
    let (recorded, _) = texts_and_reader_messages(&reports[0]);
    let joined: Vec<&String> = recorded
        .iter()
        .filter(|text| text.contains(BAILING) && text.contains(BODY_ALSO_MET))
        .collect();
    assert_eq!(
        (1, 1),
        (
            joined.len(),
            recorded
                .iter()
                .map(|text| text.matches(HELD).count())
                .sum::<usize>()
        ),
        "one sentence joins the mark behind the body joiner and the mark is told once: {:?}",
        recorded
    );
}

/// A block record's `message` is the evaluator's sentence and is written once beside entries that do not
/// carry its error, whatever its wording: under a head the readers do not know it is listed after the
/// entries, once; under a head they know, quoting the error an entry lists, the entry tells it and it is not
/// written again. Fails when an unrecognized sentence is dropped because it quotes nothing the reader knows.
#[test]
fn a_blocks_sentence_is_written_once_by_what_it_is_and_not_by_its_wording() {
    use frame_sources::block_check;
    let reporting = || EventRecord {
        context: String::from("GuardBlockAccessClause#1"),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            Some(String::from("A failed")),
            false,
            false,
        ))),
        children: vec![],
    };
    let parent = |sentence: String| EventRecord {
        context: String::from("BlockGuardClause#1"),
        container: Some(RecordType::BlockGuardCheck(block_check(
            Some(sentence),
            false,
            false,
        ))),
        children: vec![reporting()],
    };
    let messages_of = |record: EventRecord<'static>| -> Vec<Option<String>> {
        report_all_failed_clauses_for_rules(&[record])
            .iter()
            .map(|clause| match clause {
                ClauseReport::Block(block) => block.messages.error_message.clone(),
                other => panic!("a block report, got {:?}", other),
            })
            .collect()
    };
    let unlisted = String::from("An evaluator head no reader lists: boom");
    let known = format!("{}A failed", crate::rules::eval::BLOCK_QUERY_ERROR_HEAD);
    assert_eq!(
        (
            vec![
                Some(String::from("A failed")),
                Some(unlisted.clone())
            ],
            vec![Some(String::from("A failed"))],
        ),
        (messages_of(parent(unlisted)), messages_of(parent(known))),
        "an unlisted head is written once beside the entry; a known head quoting the entry's error is not"
    );
}

/// The body joiner in every arm of a called rule's sentence. A mark of the body (a type block's gate mark,
/// which no condition met) follows `a body clause also met` in the arm that keeps a displaced sentence, in
/// the arm whose slot is the evaluator's, and, beside a refusal the rule's failed condition did meet, after
/// that refusal's own joiner: head, `the condition also met: C`, `a body clause also met: B`. Fails when a
/// body mark is worded as one the condition met in any arm, or when the mixed sentence loses a group.
#[test]
fn a_body_mark_follows_the_body_joiner_in_every_arm_of_a_called_rules_sentence() {
    use crate::rules::eval_context::{
        BODY_ALSO_MET, NESTED_ALSO_MET, RULE_FAILED_ON_AN_ERROR_HEAD,
    };
    use crate::rules::CustomSlot;
    use frame_sources::{mark, rule, under_a_condition, HELD, OTHER};
    const NESTED: &str = "the read of `N` was refused, at path /Resources/N/Tags";
    registered_as_in_a_run!(HELD, OTHER, NESTED);
    const BODY: &str = "the author's body";
    const SENTENCE: &str = "The rule's own sentence";
    let error_of = |record: EventRecord<'static>| -> (Option<String>, Option<String>) {
        match report_all_failed_clauses_for_rules(&[record]).as_slice() {
            [ClauseReport::Rule(rule)] => (
                rule.messages.error_message.clone(),
                rule.messages.custom_message.clone(),
            ),
            other => panic!("one rule report, got {:?}", other),
        }
    };
    // A mark of a clause in the body (a silent failed block holding the gate mark): no condition met it.
    let body_mark = || EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(frame_sources::block_check(
            None, false, false,
        ))),
        children: vec![mark(HELD)],
    };
    // The arm that keeps the sentence the body displaced: the error message.
    let (displaced, _) = error_of(rule(
        Some(BODY.to_string()),
        Some((CustomSlot::Evaluator, SENTENCE.to_string())),
        CustomSlot::Author,
        &[],
        vec![body_mark()],
    ));
    // The arm whose slot is the evaluator's: the sentence is the custom message.
    let (_, evaluator) = error_of(rule(
        Some(SENTENCE.to_string()),
        None,
        CustomSlot::Evaluator,
        &[],
        vec![body_mark()],
    ));
    // Both groups: a failed condition that met OTHER and a body mark HELD.
    let (mixed, _) = error_of(rule(
        Some(BODY.to_string()),
        None,
        CustomSlot::Author,
        &[],
        vec![
            under_a_condition(RecordType::RuleCondition(Status::FAIL), vec![mark(OTHER)]),
            body_mark(),
        ],
    ));
    // All three groups: the rule's own condition met OTHER, a type block nested in its body had a failed
    // condition that met NESTED, and a clause mark HELD.
    let (three, _) = error_of(rule(
        Some(BODY.to_string()),
        None,
        CustomSlot::Author,
        &[],
        vec![
            under_a_condition(RecordType::RuleCondition(Status::FAIL), vec![mark(OTHER)]),
            frame_sources::type_block(None, &[], vec![mark(NESTED)]),
            body_mark(),
        ],
    ));
    assert_eq!(
        (
            Some(format!("{SENTENCE}{BODY_ALSO_MET}{HELD}")),
            Some(format!("{SENTENCE}{BODY_ALSO_MET}{HELD}")),
            Some(format!(
                "{RULE_FAILED_ON_AN_ERROR_HEAD}{ALSO_MET}{OTHER}{BODY_ALSO_MET}{HELD}"
            )),
            Some(format!(
                "{RULE_FAILED_ON_AN_ERROR_HEAD}{ALSO_MET}{OTHER}{NESTED_ALSO_MET}{NESTED}{BODY_ALSO_MET}{HELD}"
            )),
        ),
        (displaced, evaluator, mixed, three),
        "the displaced arm, the evaluator arm, the mixed sentence and the three-group sentence, each mark behind its own joiner"
    );
}

/// Every sentence the evaluator writes on a failed block, `when`, type-block or disjunction record (and the
/// per-value clause record) is built from a head or a tail the reader (`quoted_error`) knows, so the error it
/// quotes is read back whole: a sentence is told by what it quotes and never by wording nobody lists. The
/// shapes are the writers' format strings in `eval.rs`, built here from the same constants: the block's three
/// failure heads and the refused-selection sentence (`fail_block_on_unevaluatable`, `refused_selection`), the
/// block clause's bailing tail and per-value tail, the `when`'s unevaluated head and its condition tail, the
/// type block's two tails and the disjunction's undecided head. A bare refusal sentence (a raised refusal's
/// record) quotes itself. The cell shows that every head and tail in the two lists reads back to the error it
/// quotes, that each listed wording is defined exactly once across the non-test files of this module (never
/// written inline besides its constant), and that every `"Error {` writer names a listed tail within its
/// statement; it does not show that no writer exists outside the lists. Fails when a listed wording is not
/// read back, is written inline, or an `"Error {` writer names no listed tail: its sentence would be
/// written beside entries that already tell the error.
#[test]
fn every_sentence_the_evaluator_writes_on_a_parent_record_is_read_back_by_the_reader() {
    use crate::rules::eval::{PARENT_SENTENCE_HEADS, PARENT_SENTENCE_TAILS};
    const E: &str = "a plain error that ended the run";
    // The two lists are the ones the writers and the reader share (`eval.rs`): every head and tail reads
    // back to the error it quotes, and a bare raised sentence quotes itself.
    let mut shapes: Vec<(String, String)> = PARENT_SENTENCE_HEADS
        .iter()
        .map(|head| (format!("head {head:?}"), format!("{head}{E}")))
        .collect();
    shapes.extend(
        PARENT_SENTENCE_TAILS
            .iter()
            .map(|(_, tail)| (format!("tail {tail:?}"), format!("Error {E}{tail}"))),
    );
    shapes.push((String::from("a bare raised sentence"), E.to_string()));
    let unread: Vec<&String> = shapes
        .iter()
        .filter(|(_, sentence)| quoted_error(sentence) != E)
        .map(|(label, _)| label)
        .collect();
    assert!(
        unread.is_empty(),
        "sentences the reader does not read back to the error they quote: {:?}",
        unread
    );
    // The writers use the lists: scan the non-test source of this module for a wording written inline.
    // Each listed wording is defined exactly once across the files (its constant; a count of zero would
    // mean the scan missed the definition), and every `"Error {` format string names a listed tail within
    // its statement (`statement_of`: its own call, or up to the first `,` or `;` at its nesting level). A
    // new literal writer that is not in the lists fails here, where a
    // cell built only from the lists could not see it.
    //
    // The files are read from the module's directory at test time (every `.rs` under `src/rules`, the
    // test files named `*_tests.rs`, `test_common.rs` and `parser_regression_repros.rs` left out), so a new
    // non-test file is scanned without anyone adding it here; the cell fails when the directory yields no
    // `eval.rs`, the file the lists live in. Every comment span is blanked (`blank_comments`; the line
    // numbers stay), so a wording in a comment is never counted as written.
    fn module_sources(
        dir: &std::path::Path,
        root: &std::path::Path,
        out: &mut Vec<(String, String)>,
    ) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("the module's source directory is readable")
            .map(|entry| entry.expect("a directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                // `libyaml` wraps the C YAML library's events: it writes no sentence of the evaluator's
                // and none of its text is read by the report builder, so it is not scanned.
                if path.file_name().and_then(|name| name.to_str()) != Some("libyaml") {
                    module_sources(&path, root, out);
                }
                continue;
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            let is_test = name.ends_with("_tests.rs")
                || name == "test_common.rs"
                || name == "parser_regression_repros.rs";
            if !name.ends_with(".rs") || is_test {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("a source file is readable");
            // Every comment span is blanked, a trailing comment after code included (a wording there is
            // not written by the code), with the string literals and the code left as they are.
            let code = blank_comments(&source);
            let relative = path.strip_prefix(root).unwrap_or(&path);
            out.push((relative.display().to_string(), code));
        }
    }
    let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/rules");
    // The scan reads the crate's own sources: a run from a packaged crate, or from a build that moved the
    // manifest directory away from its sources, has none to read. A run with no scan proves nothing about the
    // writers, so the cell FAILS there, unless the run opts out by name with
    // `CFN_GUARD_SKIP_SOURCE_SCAN=1` (then it says so and returns; the read-back checks above have run).
    // The value is compared, as the message says: an empty value or `=0` does not skip the scan.
    if !rules_dir.is_dir() {
        if std::env::var("CFN_GUARD_SKIP_SOURCE_SCAN").as_deref() == Ok("1") {
            eprintln!(
                "skipped the source scan of the parent-sentence writers: {} is not a directory",
                rules_dir.display()
            );
            return;
        }
        panic!(
            "the source scan of the parent-sentence writers found no directory at {}; set \
             CFN_GUARD_SKIP_SOURCE_SCAN=1 to run without the scan",
            rules_dir.display()
        );
    }
    let mut files: Vec<(String, String)> = Vec::new();
    module_sources(&rules_dir, &rules_dir, &mut files);
    assert!(
        files.iter().any(|(name, _)| name == "eval.rs"),
        "the scan found no eval.rs under {:?}: {:?}",
        rules_dir,
        files.iter().map(|(name, _)| name).collect::<Vec<_>>()
    );
    let defined_once = |wording: &str| {
        files
            .iter()
            .map(|(_, code)| code.matches(wording.trim()).count())
            .sum::<usize>()
    };
    let not_once: Vec<(&str, usize)> = PARENT_SENTENCE_HEADS
        .iter()
        .copied()
        .chain(PARENT_SENTENCE_TAILS.iter().map(|(_, tail)| *tail))
        .map(|wording| (wording, defined_once(wording)))
        .filter(|(_, count)| *count != 1)
        .collect();
    assert!(
        not_once.is_empty(),
        "a listed wording is not defined exactly once in the module's non-test source (wording, count): {:?}",
        not_once
    );
    // The writer's statement: from the `format!(` that holds the literal (or the literal itself) to the
    // end of that call, or to the first `;`, `,` or closing bracket at the writer's own nesting level,
    // never past the end of the file.
    fn statement_of(code: &str, literal_at: usize) -> &str {
        // The end of the statement that starts at `start`: the first `;` or `,` at its own nesting level
        // or a closing bracket below it. Characters inside a string literal (a `;`, a `,` or a bracket in
        // a message) and inside a char literal (`'"'`, `'\''`) neither end the window nor change the depth;
        // a lifetime's `'` is not a char literal. Raw strings are read as ordinary strings: no scanned
        // file holds a raw string with a quote in it. The window never leaves this file's text.
        fn end_from(code: &str, start: usize) -> usize {
            let bytes = code.as_bytes();
            let (mut depth, mut in_string, mut escaped) = (0i32, false, false);
            let mut at = start;
            while at < bytes.len() {
                let c = bytes[at];
                if in_string {
                    match (escaped, c) {
                        (true, _) => escaped = false,
                        (false, b'\\') => escaped = true,
                        (false, b'"') => in_string = false,
                        _ => {}
                    }
                    at += 1;
                    continue;
                }
                match c {
                    b'"' => in_string = true,
                    b'\'' => {
                        // `'x'` or `'\x'`: skip the whole char literal; otherwise a lifetime.
                        if bytes.get(at + 1) == Some(&b'\\') && bytes.get(at + 3) == Some(&b'\'') {
                            at += 3;
                        } else if bytes.get(at + 2) == Some(&b'\'') {
                            at += 2;
                        }
                    }
                    b'(' | b'[' | b'{' => depth += 1,
                    b')' | b']' | b'}' => {
                        depth -= 1;
                        if depth < 0 {
                            return at;
                        }
                    }
                    b';' | b',' if depth == 0 => return at,
                    _ => {}
                }
                at += 1;
            }
            code.len()
        }
        let before = &code[..literal_at];
        let start = match before.rfind("format!(") {
            Some(at) if literal_at - at < 200 => at,
            _ => literal_at,
        };
        let end = end_from(code, start);
        // The span must cover the literal: a `format!(` in an earlier statement that ended before the
        // literal is not this writer's, so the window is read again from the literal itself.
        match end < literal_at {
            true => &code[literal_at..end_from(code, literal_at)],
            false => &code[start..end],
        }
    }
    let unlisted: Vec<String> = files
        .iter()
        .flat_map(|(name, code)| {
            code.match_indices("\"Error {")
                .filter(|(at, _)| !code[*at..].starts_with("\"Error {e} when handling clause"))
                .filter(|(at, _)| {
                    let statement = statement_of(code, *at);
                    !PARENT_SENTENCE_TAILS
                        .iter()
                        .any(|(tail_name, _)| statement.contains(tail_name))
                })
                .map(|(at, _)| format!("{name}:{}", code[..at].matches('\n').count() + 1))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        unlisted.is_empty(),
        "an `Error {{..}}` sentence written with no listed tail, at {:?}",
        unlisted
    );
}

/// The by-field rule, positively: the author's `<< >>` text sits in `custom_message` and is NOT an entry
/// beside entries that report (the base rule: a parent is listed by that text only when nothing beneath it
/// reports), on a block, an inline `when` and a disjunction alike; the entries alone are listed. The same
/// records carrying an evaluator `message` under a head no reader lists write it once, after the entries.
/// Fails when the author's text is listed as an entry, or the evaluator's sentence is dropped or repeated.
#[test]
fn author_text_beside_reporting_entries_is_not_an_entry_and_an_evaluator_sentence_is_one_once() {
    use frame_sources::block_check;
    const AUTHOR: &str = "the author's text";
    const EVALUATOR: &str = "An evaluator head no reader lists: boom";
    let reporting = || EventRecord {
        context: String::from("GuardBlockAccessClause#1"),
        container: Some(RecordType::GuardClauseBlockCheck(block_check(
            Some(String::from("A failed")),
            false,
            false,
        ))),
        children: vec![],
    };
    let parent = |kind: &str, message: Option<&str>, custom: Option<&str>| {
        let mut check = block_check(message.map(String::from), false, false);
        check.custom_message = custom.map(String::from);
        EventRecord {
            context: String::from("Parent#1"),
            container: Some(match kind {
                "block" => RecordType::BlockGuardCheck(check),
                "when" => RecordType::WhenCheck(check),
                _ => RecordType::Disjunction(check),
            }),
            children: vec![reporting()],
        }
    };
    let listed = |record: EventRecord<'static>| -> Vec<Option<String>> {
        let mut out = Vec::new();
        for clause in report_all_failed_clauses_for_rules(&[record]) {
            match clause {
                ClauseReport::Block(block) => out.push(block.messages.error_message.clone()),
                ClauseReport::Disjunctions(ors) => {
                    for each in &ors.checks {
                        match each {
                            ClauseReport::Block(block) => {
                                out.push(block.messages.error_message.clone())
                            }
                            other => panic!("a block entry, got {:?}", other),
                        }
                    }
                }
                other => panic!("a block or disjunction report, got {:?}", other),
            }
        }
        out
    };
    let a_failed = || Some(String::from("A failed"));
    for kind in ["block", "when", "disjunction"] {
        assert_eq!(
            (
                vec![a_failed()],
                vec![a_failed(), Some(EVALUATOR.to_string())]
            ),
            (
                listed(parent(kind, None, Some(AUTHOR))),
                listed(parent(kind, Some(EVALUATOR), None))
            ),
            "({}) the author's text is no entry beside a reporting entry; an evaluator sentence is written once after it",
            kind
        );
    }
}

/// A sentence is told by an entry that is itself a bailing or head sentence for the same error: a type
/// block's "Error X during type block evaluation, bailing" over a `when`'s "Error X during type condition
/// evaluation, bailing" lists X once, and a different error is not told by it. Fails when the entry side
/// is compared by its clause-error spelling alone, which lists X once per level.
#[test]
fn nested_bailing_sentences_for_one_error_are_told_once() {
    use crate::rules::eval::{TYPE_BLOCK_BAILING_TAIL, TYPE_CONDITION_BAILING_TAIL};
    const X: &str = "a plain error that ended the run";
    const Y: &str = "another plain error";
    let entry = ClauseReport::Block(GuardBlockReport {
        context: String::from("WhenBlock#2"),
        messages: Messages {
            error_message: Some(format!("Error {X}{TYPE_CONDITION_BAILING_TAIL}")),
            custom_message: None,
            location: None,
            refusal: false,
            parts: None,
        },
        unresolved: None,
    });
    let outer = |error: &str| format!("Error {error}{TYPE_BLOCK_BAILING_TAIL}");
    let entries = vec![entry];
    assert_eq!(
        (true, false),
        (
            sentence_told_by(&entries, &outer(X)),
            sentence_told_by(&entries, &outer(Y))
        ),
        "the same error behind another tail is told; a different error is not"
    );
}

/// A refusal whose own text holds a `; ` is named by the sentence a rule's own `when` writes, joined to the
/// error it held: the debug tripwire finds the converted read through the boundary parse, which reads the
/// refusal as a span of its own after the joiner rather than splitting it at its own `; `. Two refused reads,
/// the second joined behind "the condition also met".
#[test]
fn a_converted_read_with_a_semicolon_in_its_text_is_found_in_the_joined_sentence() {
    use crate::rules::eval::RULE_CONDITION_UNEVALUATED_HEAD;
    use crate::rules::CustomSlot;
    use frame_sources::{mark, rule, under_a_condition, HELD};
    const SEMICOLON: &str = "the read of `B` was refused; write it over a key the object holds, at path /Resources/B/Tags";
    registered_as_in_a_run!(HELD, SEMICOLON);
    let record = rule(
        Some(format!(
            "{RULE_CONDITION_UNEVALUATED_HEAD}{HELD}{}{SEMICOLON}",
            crate::rules::eval_context::ALSO_MET
        )),
        None,
        CustomSlot::Refusal,
        &[SEMICOLON],
        vec![under_a_condition(
            RecordType::RuleCondition(Status::FAIL),
            vec![mark(SEMICOLON)],
        )],
    );
    // Nothing panics: the verbatim text is in what the rule wrote.
    let _ = report_all_failed_clauses_for_rules(&[record]);
}

/// A rule called with a `<< >>` body whose body holds a silent block over a refused value (a gate mark): the
/// called rule lists no entry for the silent child, so the refusal is told by the rule's own sentence,
/// once, with the body kept as the custom text.
#[test]
fn a_rule_with_a_body_over_a_silent_block_tells_the_refusal_its_mark_carries() {
    use crate::rules::CustomSlot;
    use frame_sources::{block_check, mark, rule, HELD};
    registered_as_in_a_run!(HELD);
    const BODY: &str = "the author's body";
    let silent_block = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(block_check(None, false, false))),
        children: vec![mark(HELD)],
    };
    let record = rule(
        Some(BODY.to_string()),
        None,
        CustomSlot::Author,
        &[],
        vec![silent_block],
    );
    let reports = report_all_failed_clauses_for_rules(&[record]);
    match &reports[..] {
        [ClauseReport::Rule(rule)] => {
            assert_eq!(
                (true, Some(BODY), 1),
                (
                    rule.checks.is_empty(),
                    rule.messages.custom_message.as_deref(),
                    rule.messages
                        .error_message
                        .as_deref()
                        .map_or(0, |text| text.matches(HELD).count())
                ),
                "the body kept, the refusal told once by the rule's sentence: {:?}",
                rule.messages
            );
            // The mark is a refusal of the body, which the rule's failed condition did not meet: it follows
            // the body joiner and not "the condition also met".
            let error = rule.messages.error_message.as_deref().unwrap_or("");
            let joiner = rule.messages.parts.as_ref().map(|parts| parts.joiner());
            assert_eq!(
                (true, false, Some(crate::rules::eval_context::BODY_ALSO_MET)),
                (
                    error.contains(crate::rules::eval_context::BODY_ALSO_MET),
                    error.contains(ALSO_MET),
                    joiner
                ),
                "the body's mark is joined under the body joiner alone: {}",
                error
            );
            assert!(
                error.starts_with(crate::rules::eval_context::RULE_FAILED_HEAD)
                    && !error.contains(crate::rules::eval_context::RULE_FAILED_ON_AN_ERROR_HEAD),
                "no failed condition met anything, so no error is said to have ended the evaluation: {}",
                error
            );
        }
        other => panic!("one rule report, got {:?}", other),
    }
}

/// The tripwire fires, in a debug build, on a frame whose read no record or sentence names: the loss it
/// exists to catch. One cell per source, each with the read registered as a refusal and nothing in the
/// report that names it (a sentence about another refusal, no records beneath).
///
/// Fails when a source does not panic, so a refusal the conversion swallowed would be reported
/// nowhere.
#[cfg(debug_assertions)]
mod an_untold_frame_read_trips_the_assertion {
    use super::*;
    use crate::rules::eval::{RULE_CONDITION_UNEVALUATED_HEAD, WHEN_UNEVALUATED_HEAD};
    use crate::rules::CustomSlot;
    use frame_sources::*;

    #[test]
    #[should_panic(expected = "converted a refusal that no record or sentence")]
    fn a_rules_own_when() {
        walk_a_converted_frame(rule(
            Some(format!("{RULE_CONDITION_UNEVALUATED_HEAD}{OTHER}")),
            None,
            CustomSlot::Refusal,
            &[HELD],
            vec![],
        ));
    }

    #[test]
    #[should_panic(expected = "converted a refusal that no record or sentence")]
    fn an_inline_when() {
        walk_a_converted_frame(when_block(
            Some(format!("{WHEN_UNEVALUATED_HEAD}{OTHER}")),
            &[HELD],
            vec![],
        ));
    }

    #[test]
    #[should_panic(expected = "converted a refusal that no record or sentence")]
    fn a_type_block() {
        walk_a_converted_frame(type_block(
            Some(format!(
                "Error {OTHER} during type condition evaluation, bailing"
            )),
            &[HELD],
            vec![mark(OTHER)],
        ));
    }

    /// The record's sentence quotes a plain error Z and an entry beneath it carries Z, so the sentence is
    /// not written beside the entries (it is told). The converted read HELD lives in no written text and in
    /// no entry: the sentence is not credited with it, only the entries are. A sentence dropped because an
    /// entry carries ITS error is no account of a read it does not name.
    #[test]
    #[should_panic(expected = "converted a refusal that no record or sentence")]
    fn a_bailing_type_block_whose_sentence_is_not_written_beside_its_entries() {
        const Z: &str = "a plain error that ended the run";
        let carries_z = EventRecord {
            context: String::from("GuardAccessClause#blockZ"),
            container: Some(RecordType::GuardClauseBlockCheck(block_check(
                Some(Z.to_string()),
                false,
                false,
            ))),
            children: vec![],
        };
        walk_a_converted_frame(type_block(
            Some(format!(
                "Error {Z} during type condition evaluation, bailing"
            )),
            &[HELD],
            vec![carries_z],
        ));
    }

    /// A call's body with nothing beneath it that names the read: the author's body is no account of it.
    #[test]
    #[should_panic(expected = "converted a refusal that no record or sentence")]
    fn a_rule_with_a_body_and_nothing_beneath_that_names_the_read() {
        walk_a_converted_frame(rule(
            Some(String::from("the author's body")),
            None,
            CustomSlot::Author,
            &[HELD],
            vec![],
        ));
    }
}

/// `lead; R; cause` yields the refusal R and nothing else: the unregistered `cause` is the sentence's own
/// account of the failure, never a refusal the condition met, so a rule sentence "HEAD: R; cause" gains no
/// "also met: cause". A registered remainder (`lead: R1; R2`) is still a refusal and is kept.
///
/// Fails when `cause` is appended as a refusal part, or when R2 is dropped.
#[test]
fn an_unregistered_remainder_is_never_appended_as_a_refusal() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let _root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    const R1: &str = "the read of `A` was refused, at path /Resources/A/Tags";
    const R2: &str = "the read of `B` was refused, at path /Resources/B/Tags";
    for text in [R1, R2] {
        let _ = register_refusal(text);
    }
    let texts = |sentence: &str| {
        let mut out = Vec::new();
        push_refusal(&mut out, sentence, None);
        out.into_iter().map(|(text, _)| text).collect::<Vec<_>>()
    };
    assert_eq!(
        (
            vec![R1.to_string()],
            vec![R1.to_string()],
            vec![R1.to_string(), R2.to_string()]
        ),
        (
            texts(&format!("lead; {R1}; cause")),
            texts(&format!("{R1}; cause")),
            texts(&format!("lead: {R1}; {R2}"))
        ),
        "the registered refusal alone; a registered remainder kept"
    );
}

/// A call that carries a `<< >>` body over a rule that failed on an error that ended its evaluation, with no
/// sentence of the evaluator's beside the body, reports the refusals its failed condition met in
/// `error_message` under a neutral head (the condition is not claimed to be the deciding error), as two
/// parts: the head and the refusals joined whole. The kind is the deciding error's own, a plain error, so
/// the flag is false; the author's body stays the custom message.
///
/// Fails when the sentence leads with "The rule's condition could not be evaluated", when the
/// flag is true, when the parts are absent, or when the body is displaced.
#[test]
fn a_body_only_call_over_a_run_ending_error_names_the_conditions_refusals_under_a_neutral_head() {
    const FIRST: &str = "the read of `A` was refused";
    const SECOND: &str = "the read of `B` was refused";
    let clause_error = |sentence: &str| EventRecord {
        context: String::from("GuardAccessClause#blockA"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(crate::rules::eval::clause_error_message(
                &crate::rules::errors::Error::undecidable(sentence.to_string()),
            )),
            refusal: true,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let rule = EventRecord {
        context: String::from("gated"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "gated",
            status: Status::FAIL,
            message: Some(String::from("the author's body")),
            slot: crate::rules::CustomSlot::Author,
            displaced: None,
            frame_reads: Vec::new(),
            // The run ended on an error: the head says so (`ended_by_error` is the record's account).
            ended_by_error: true,
        })),
        children: vec![EventRecord {
            context: String::from("Rule#gated/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children: vec![clause_error(FIRST), clause_error(SECOND)],
        }],
    };
    let read = match report_all_failed_clauses_for_rules(&[rule]).as_slice() {
        [ClauseReport::Rule(rule)] => (
            rule.messages.error_message.clone(),
            rule.messages.custom_message.clone(),
            rule.messages.refusal,
            rule.messages.parts.clone(),
        ),
        other => panic!("one rule report, got {:?}", other),
    };
    let head = RULE_FAILED_ON_AN_ERROR_HEAD;
    assert_eq!(
        (
            Some(format!("{head}{ALSO_MET}{FIRST}; {SECOND}")),
            Some(String::from("the author's body")),
            false,
            Some(SentenceParts::refusals_beside(
                head,
                &format!("{FIRST}; {SECOND}"),
                SentenceSlot::Error,
            )),
        ),
        read,
        "a neutral head, the refusals whole as the second part, a plain kind, the body kept"
    );
}

/// A failed condition's records that carry the RAISE survive whatever report kind they become, and a
/// called rule's decided answers are dropped like the condition's own. Under a message-less failed rule's
/// condition (a record order the real tree has: RuleCheck > RuleCondition > the condition's clauses and
/// called rules): a reference that failed on an error (a `DependentRule` with a message) is listed; one
/// that merely did not pass (no message) is not; a per-value check with its refusal flag set is listed; a
/// called rule over [a decided answer, a silent block] is listed with the block's generic sentence alone.
///
/// Fails when the raise-carrying reference or refusal check is dropped (the rule is listed
/// with empty checks), when a decided answer is listed, or when the called rule lists its
/// decided answer.
#[test]
fn a_failed_conditions_raise_survives_in_every_report_kind_and_a_called_rules_decided_answers_do_not(
) {
    const GENERIC: &str =
        "the block clause failed, and none of the checks recorded under it reports why";
    let silent = || EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![EventRecord {
            context: String::from("GuardBlockAccessClause#2"),
            container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: false,
                message: None,
                refusal: false,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            })),
            children: vec![],
        }],
    };
    let reference = |message: Option<&str>| EventRecord {
        context: String::from("gate"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::DependentRule(
            crate::rules::MissingValueCheck {
                rule: "gate",
                message: message.map(String::from),
                custom_message: None,
                status: Status::FAIL,
                // A message is the account of an error the reference failed on, stored once.
                failure: message.map(|text| crate::rules::ReferenceFailure {
                    text: text.to_string(),
                    token: None,
                    refusal: false,
                }),
            },
        ))),
        children: vec![],
    };
    let refused_value = EventRecord {
        context: String::from("Properties.Tags"),
        container: Some(RecordType::ClauseValueCheck(
            ClauseCheck::MissingBlockValue(ValueCheck {
                from: QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(PathAwareValue::try_from("{ A: 1 }").expect("parses")),
                    remaining_query: String::new(),
                    reason: Some(String::from("the read was refused")),
                    kind: UnResolvedKind::Undecidable {
                        refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                        carried: None,
                    },
                }),
                message: Some(String::from("the read was refused")),
                custom_message: None,
                status: Status::FAIL,
                refusal: true,
            }),
        )),
        children: vec![],
    };
    let called_rule = EventRecord {
        context: String::from("helper"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "helper",
            status: Status::FAIL,
            message: None,
            slot: Default::default(),
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![reference(None), silent()],
    };
    let rule = |conditions: Vec<EventRecord<'static>>| EventRecord {
        context: String::from("gated"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "gated",
            status: Status::FAIL,
            message: None,
            slot: Default::default(),
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![EventRecord {
            context: String::from("Rule#gated/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children: conditions,
        }],
    };
    let shape = |conditions: Vec<EventRecord<'static>>| -> Vec<String> {
        match report_all_failed_clauses_for_rules(&[rule(conditions)]).as_slice() {
            [ClauseReport::Rule(rule)] => rule
                .checks
                .iter()
                .map(|check| match check {
                    ClauseReport::Clause(clause) => {
                        let messages = clause.get_message();
                        format!(
                            "clause {:?} refusal={}",
                            messages.error_message.unwrap_or_default(),
                            messages.refusal
                        )
                    }
                    ClauseReport::Block(block) => format!(
                        "block {:?} refusal={}",
                        block.messages.error_message.clone().unwrap_or_default(),
                        block.messages.refusal
                    ),
                    ClauseReport::Rule(called) => format!(
                        "rule {} over {}",
                        called.name,
                        called
                            .checks
                            .iter()
                            .map(|check| match check {
                                ClauseReport::Block(block) => {
                                    block.messages.error_message.clone().unwrap()
                                }
                                ClauseReport::Clause(_) => String::from("clause"),
                                other => panic!("under the called rule, got {:?}", other),
                            })
                            .collect::<Vec<_>>()
                            .join(" | ")
                    ),
                    other => panic!("under the rule, got {:?}", other),
                })
                .collect(),
            other => panic!("one rule report, got {:?}", other),
        }
    };
    assert_eq!(
        (
            vec![String::from(
                "clause \"Check was not compliant as dependent rule [gate] did not PASS. Context [gate]; gate failed due to error\" refusal=false"
            )],
            Vec::<String>::new(),
            vec![String::from(
                "block \"the read was refused\" refusal=true"
            )],
            vec![format!("rule helper over {GENERIC}")],
        ),
        (
            shape(vec![reference(Some("gate failed due to error"))]),
            shape(vec![reference(None)]),
            shape(vec![refused_value]),
            shape(vec![called_rule]),
        ),
        "a reference that failed on an error, a refused value and a called rule's silent block surface; a reference that did not pass does not, and the called rule's decided answer is dropped"
    );
}

/// A reference that failed on a REFUSING error (`fail_reference_on_error` writes its `DependentRule` with the
/// error in the message and the refusal flag from `is_refusal`) is reported with the flag the record
/// carries: the structured reports say `refusal: true` and the console keeps the remedy past the bound a
/// plain message gets. The same record with the flag clear reports no refusal, whatever its words.
///
/// Fails when the flag is dropped (a refusal reported as a plain failure), or when a plain error's
/// reference is flagged.
#[test]
fn a_reference_that_failed_on_a_refusing_error_is_reported_a_refusal() {
    const REFUSAL: &str = "the read of `Tags` was refused, at path /Resources/R/Tags";
    let record = |refusal: bool| EventRecord {
        context: String::from("gate"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::DependentRule(
            crate::rules::MissingValueCheck {
                rule: "gate",
                message: Some(format!("gate failed due to error {REFUSAL}")),
                custom_message: None,
                status: Status::FAIL,
                failure: Some(crate::rules::ReferenceFailure {
                    text: REFUSAL.to_string(),
                    token: None,
                    refusal,
                }),
            },
        ))),
        children: vec![],
    };
    let read = |refusal: bool| -> (bool, bool) {
        let clauses = report_all_failed_clauses_for_rules(&[record(refusal)]);
        match clauses.as_slice() {
            [ClauseReport::Clause(GuardClauseReport::Unary(report))] => (
                report.messages.refusal,
                report
                    .messages
                    .error_message
                    .as_deref()
                    .unwrap_or_default()
                    .contains(REFUSAL),
            ),
            other => panic!(
                "one unary clause report for one record, got {}",
                other.len()
            ),
        }
    };
    assert_eq!(
        ((true, true), (false, true)),
        (read(true), read(false)),
        "a refusing error's reference is flagged and names the refusal; a plain one is not flagged"
    );
}

/// A rule that failed closed on its condition names a refusal a REFERENCE in the condition failed on once, in
/// the rule's sentence: the reference's record stores the error and its token, and the walk of the failed
/// condition reads them there. A refusal the sentence already carries is not repeated.
///
/// Fails when the refusal is absent from the sentence, appears twice, or when the walk reads
/// the words of the reference's message and not the stored error.
#[test]
fn a_refusal_a_reference_failed_on_is_named_once_in_the_rules_sentence() {
    const HEAD: &str = "The rule's condition could not be evaluated, so the rule fails rather than being treated as not applicable";
    const HELD: &str = "the held read of `A` was refused";
    const OTHER: &str = "the read of `B`, which the reference failed on, was refused";
    let reference = |error: &str| EventRecord {
        context: String::from("gate"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::DependentRule(
            crate::rules::MissingValueCheck {
                rule: "gate",
                // Words that differ from the stored error, so a walk that read the message would not
                // find the refusal.
                message: Some(String::from("gate failed for a reason told elsewhere")),
                custom_message: None,
                status: Status::FAIL,
                failure: Some(crate::rules::ReferenceFailure {
                    text: error.to_string(),
                    token: None,
                    refusal: true,
                }),
            },
        ))),
        children: vec![],
    };
    let sentence_for = |held: &str, references: Vec<EventRecord<'static>>| {
        let rule = EventRecord {
            context: String::from("gated"),
            container: Some(RecordType::RuleCheck(NamedStatus {
                name: "gated",
                status: Status::FAIL,
                message: Some(format!("{HEAD}: {held}")),
                slot: crate::rules::CustomSlot::Refusal,
                displaced: None,
                frame_reads: Vec::new(),
                ended_by_error: false,
            })),
            children: vec![EventRecord {
                context: String::from("Rule#gated/When"),
                container: Some(RecordType::RuleCondition(Status::FAIL)),
                children: references,
            }],
        };
        match report_all_failed_clauses_for_rules(&[rule]).as_slice() {
            [ClauseReport::Rule(rule)] => rule.messages.custom_message.clone(),
            other => panic!("one rule report, got {:?}", other),
        }
    };
    assert_eq!(
        (
            Some(format!("{HEAD}: {HELD}; the condition also met: {OTHER}")),
            Some(format!("{HEAD}: {HELD}")),
        ),
        (
            sentence_for(HELD, vec![reference(HELD), reference(OTHER)]),
            sentence_for(HELD, vec![reference(HELD)]),
        ),
        "the second reference's refusal is added once; the one the sentence carries is not repeated"
    );
}

/// The REAL tree of a type block's failed condition: TypeCheck(FAIL, no message) > TypeBlock(FAIL) >
/// TypeCondition(FAIL) > Disjunction > one GuardClauseBlockCheck per disjunct > the disjunct's per-value
/// checks. A disjunction of two decided answers (the first `Resources.X exists`, a decided no, and a
/// reference that did not pass) lists nothing: the condition's own test of whether the type block applies.
/// With a refused value in the second disjunct the refusal is listed alone, with its sentence and its flag,
/// and the decided sibling is not.
///
/// Fails when a decided answer is listed under the condition (the filter stopped at the
/// disjunct's clause record and kept its decided per-value children), or when the refusal is
/// listed without its sentence or flag.
#[test]
fn a_type_blocks_failed_condition_lists_a_refusal_alone_and_never_a_decided_disjunct() {
    let decided = || EventRecord {
        context: String::from("GuardAccessClause#blockX"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        // The shape the evaluator writes for `Properties.A exists` over a map that lacks `A`: the
        // disjunct's block record over a `Unary` clause record whose value check has no message and a
        // clear refusal flag (`record_unary_clause`). A `MissingBlockValue` is written only by the block
        // value loop, with a message and under a block access clause, never here.
        children: vec![EventRecord {
            context: String::from("Properties.A"),
            container: Some(RecordType::ClauseValueCheck(ClauseCheck::Unary(
                UnaryValueCheck {
                    comparison: (CmpOperator::Exists, false),
                    value: ValueCheck {
                        from: QueryResult::UnResolved(UnResolved {
                            traversed_to: Rc::new(
                                PathAwareValue::try_from("{ B: 1 }").expect("parses"),
                            ),
                            remaining_query: String::from("A"),
                            reason: Some(String::from("Could not find key A")),
                            kind: UnResolvedKind::Absent,
                        }),
                        message: None,
                        custom_message: None,
                        status: Status::FAIL,
                        refusal: false,
                    },
                },
            ))),
            children: vec![],
        }],
    };
    // A reference that did not pass: the evaluator closes its `DependentRule` (no message) beside the
    // disjunct's clause records, under the disjunction, not under a clause's own record.
    let decided_reference = || EventRecord {
        context: String::from("gate"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::DependentRule(
            crate::rules::MissingValueCheck {
                rule: "gate",
                message: None,
                custom_message: None,
                status: Status::FAIL,
                failure: None,
            },
        ))),
        children: vec![],
    };
    let refused = || EventRecord {
        context: String::from("GuardAccessClause#blockY"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![EventRecord {
            context: String::from("Properties.Tags"),
            container: Some(RecordType::ClauseValueCheck(
                ClauseCheck::MissingBlockValue(ValueCheck {
                    from: QueryResult::UnResolved(UnResolved {
                        traversed_to: Rc::new(
                            PathAwareValue::try_from("{ A: 1 }").expect("parses"),
                        ),
                        remaining_query: String::new(),
                        reason: Some(String::from("the read was refused")),
                        kind: UnResolvedKind::Undecidable {
                            refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                            carried: None,
                        },
                    }),
                    message: Some(String::from("the read was refused")),
                    custom_message: None,
                    status: Status::FAIL,
                    refusal: true,
                }),
            )),
            children: vec![],
        }],
    };
    let type_check = |disjuncts: Vec<EventRecord<'static>>| EventRecord {
        context: String::from("AWS::X::Y"),
        container: Some(RecordType::TypeCheck(TypeBlockCheck {
            type_name: "AWS::X::Y",
            block: BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: false,
                message: None,
                refusal: false,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            },
        })),
        children: vec![EventRecord {
            context: String::from("TypeBlock"),
            container: Some(RecordType::TypeBlock(Status::FAIL)),
            children: vec![EventRecord {
                context: String::from("TypeBlock/When"),
                container: Some(RecordType::TypeCondition(Status::FAIL)),
                children: vec![EventRecord {
                    context: String::from("Disjunction#1"),
                    container: Some(RecordType::Disjunction(BlockCheck {
                        status: Status::FAIL,
                        at_least_one_matches: false,
                        raised: false,
                        message: None,
                        refusal: false,
                        custom_message: None,
                        gate_mark: false,
                        frame_reads: Vec::new(),
                    })),
                    children: disjuncts,
                }],
            }],
        }],
    };
    let listed = |record: EventRecord<'static>| -> Vec<String> {
        let mut found = Vec::new();
        fn collect(clauses: &[ClauseReport<'_>], found: &mut Vec<String>) {
            for clause in clauses {
                match clause {
                    ClauseReport::Block(block) => found.push(format!(
                        "block {:?} refusal={}",
                        block.messages.error_message.clone().unwrap_or_default(),
                        block.messages.refusal
                    )),
                    ClauseReport::Clause(_) => found.push(String::from("a clause")),
                    ClauseReport::Disjunctions(report) => collect(&report.checks, found),
                    ClauseReport::Rule(rule) => collect(&rule.checks, found),
                }
            }
        }
        collect(&report_all_failed_clauses_for_rules(&[record]), &mut found);
        found
    };
    assert_eq!(
        (
            Vec::<String>::new(),
            vec![String::from("block \"the read was refused\" refusal=true")],
        ),
        (
            listed(type_check(vec![decided(), decided_reference()])),
            listed(type_check(vec![decided(), decided_reference(), refused()])),
        ),
        "a missing property and a reference that did not pass list nothing; a refused disjunct beside them lists the refusal alone"
    );
    // A DECIDED disjunct that keeps an explanatory message (an empty selection explained) is still a
    // decided answer: its record is written with `raised` clear, so the message does not keep it. Red
    // when the walk keeps a block record by the presence of its message.
    let decided_with_message = || {
        let mut record = decided();
        if let Some(RecordType::GuardClauseBlockCheck(check)) = record.container.as_mut() {
            check.message = Some(String::from(
                "the selection was empty, so nothing was checked",
            ));
        }
        record
    };
    // A plain raise (not a refusal): the clause-error record, written on a raise with its refusal flag
    // clear, is the account of the raise and is still kept.
    const PLAIN_RAISE: &str = "a converter could not read the value";
    let plain_raise = || EventRecord {
        context: String::from("GuardAccessClause#blockZ"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(crate::rules::eval::clause_error_message(
                &crate::rules::errors::Error::undecidable(PLAIN_RAISE.to_string()),
            )),
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        // Decided children only: every one is dropped by the walk, so the record is kept by `raised`
        // alone (a childless record would be kept by having no children, whatever its flag).
        children: vec![decided_reference()],
    };
    let kept_plain_raise = listed(type_check(vec![decided(), plain_raise()]));
    // A block record written on a raise that carries no sentence and has no child that carries the raise
    // (the gate-role undecided exit, the run-ending exit): it is kept, and it never prints the retrieval
    // sentence ("did not retrieve any value"), which would be false; it says what is true.
    let raised_silent_block = || EventRecord {
        context: String::from("BlockGuardClause#raised"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    assert_eq!(
        vec![format!("block {:?} refusal=false", SILENT_BLOCK_SENTENCE)],
        listed(type_check(vec![decided(), raised_silent_block()])),
        "a kept raised block record with no sentence and no child lists the silent-block sentence, never the retrieval one"
    );
    assert_eq!(
        (
            Vec::<String>::new(),
            (1, true, true),
        ),
        (
            listed(type_check(vec![decided_with_message(), decided_reference()])),
            (
                kept_plain_raise.len(),
                kept_plain_raise
                    .iter()
                    .all(|entry| entry.contains(PLAIN_RAISE)),
                kept_plain_raise
                    .iter()
                    .all(|entry| entry.ends_with("refusal=false")),
            ),
        ),
        "a decided disjunct that keeps an explanatory message lists nothing; a plain raise's clause-error record is still kept, flagged no refusal"
    );
}

/// The report model keeps every part whole; only the console bounds them. A PLAIN head (a converter's error
/// quoting a long template value) that a refusal is joined to stays whole beside the refusal, as two parts
/// (`SentenceParts`: the sentence, the refusals) whose join is the sentence byte for byte, and a head that
/// is already a refusal's gets the same parts (its kind is the record's flag, which the console reads to
/// bound it); a head that gains nothing is returned as it is, however long. A refusal the head quotes PAST
/// the plain bound (the head is whole, so the carried test reads the text the record emits) is carried, and
/// a bare record of it is not appended.
///
/// Fails when the head is cut in the model, when the parts do not join to the sentence, when an
/// unjoined head changes, or when a refusal quoted past the bound is dropped or appended again.
#[test]
fn a_joined_sentence_keeps_every_part_whole_and_a_refusal_quoted_past_the_bound_is_carried() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let _root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    const REFUSAL: &str = "the read of `Tags` was refused, at path /Resources/M/Tags";
    const QUOTED: &str = "the read of `Late` was refused, at path /Resources/M/Late";
    let _ = crate::rules::eval_context::register_refusal(REFUSAL);
    let _ = crate::rules::eval_context::register_refusal(QUOTED);
    let long_head = format!(
        "failed to convert a string: {} into an integer",
        "x ".repeat(400)
    );
    let record = |sentence: &str| EventRecord {
        context: String::from("GuardAccessClause#blockA"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(crate::rules::eval::clause_error_message(
                &crate::rules::errors::Error::undecidable(sentence.to_string()),
            )),
            refusal: true,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    // The records of a failed condition sit under its `RuleCondition(FAIL)`, as the walk reads them.
    let under = |records: Vec<EventRecord<'static>>| {
        vec![EventRecord {
            context: String::from("Rule#gated/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children: records,
        }]
    };
    let refused = under(vec![record(REFUSAL)]);
    let (plain, plain_parts) =
        sentence_and_whether_refusals_joined(&long_head, &refused, SentenceSlot::Error);
    let (unjoined, unjoined_parts) =
        sentence_and_whether_refusals_joined(&long_head, &[], SentenceSlot::Error);
    // A refusal quoted past the plain bound of a long head: carried, so the bare record adds nothing.
    let quoting = format!("{}: {QUOTED}", "y ".repeat(300));
    let (quoted_text, quoted_parts) = sentence_and_whether_refusals_joined(
        &quoting,
        &under(vec![record(QUOTED)]),
        SentenceSlot::Error,
    );
    let join = format!("{ALSO_MET}{REFUSAL}");
    assert_eq!(
        (
            true,
            true,
            (long_head.clone(), false),
            (quoting.clone(), false),
        ),
        (
            plain == format!("{long_head}{join}"),
            plain_parts.as_ref().is_some_and(|parts| parts.head() == long_head
                && parts.message() == REFUSAL
                && parts.join()
                    == (crate::rules::eval_context::PartsJoin::Refusals {
                        slot: crate::rules::eval_context::SentenceSlot::Error
                    })
                && parts.refusals_text() == plain),
            (unjoined, unjoined_parts.is_some()),
            (quoted_text, quoted_parts.is_some()),
        ),
        "the parts are whole and join to the sentence, whatever kind the head is (the kind is the record's flag, not a reason to carry no parts); an unjoined head is returned as it is; a refusal quoted past the plain bound is carried"
    );
}

/// The one join design of a failed rule's sentence, by row. A plain error's sentence that gains refusals
/// keeps its kind (`refusal` false: the plain error decided the verdict) and carries the join's parts; a
/// called rule under it contributes its children's refusals first and its own sentence, head stripped,
/// only when they add nothing (the refusal is listed once, not as `R; R`); a refused `IN` comparison is
/// read; a sentence that already ends with a refusal as `S: R; cause`, or quotes a numbered raise
/// `(1) R2 (2) R1`, carries those refusals, so a bare record of the same refusal is not appended again
/// (the registry holds R1, and a second registration of it mints another token).
///
/// Fails when the kind is promoted, when a nested rule's refusal is listed twice, when the `IN`
/// refusal is lost, or when a carried refusal is appended.
#[test]
fn a_joined_sentence_keeps_its_kind_and_lists_each_refusal_once() {
    use crate::rules::errors::RefusalToken;
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let _root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    const PLAIN: &str = "failed to convert a string: prod into an integer";
    const R1: &str = "the read of `A` was refused, at path /Resources/A/Tags";
    const R2: &str = "the read of `B` was refused, at path /Resources/B/Tags";
    const R3: &str = "the membership of `C` was refused, at path /Resources/C/Tags";
    for text in [R1, R2, R3] {
        let _ = crate::rules::eval_context::register_refusal(text);
    }
    let clause_error = |sentence: &str| EventRecord {
        context: String::from("GuardAccessClause#blockA"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(crate::rules::eval::clause_error_message(
                &crate::rules::errors::Error::undecidable(sentence.to_string()),
            )),
            refusal: true,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    // The record the evaluator writes for a left-hand value paired with a refused `%name`'s marker under a
    // positive `IN`: a comparison record flagged a refusal, the refusal's text as its message. The
    // membership record (`InComparisonCheck`) is never written flagged.
    let in_refusal = |sentence: &str| EventRecord {
        context: String::from("Properties.C IN"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(
            crate::rules::ComparisonClauseCheck {
                comparison: (CmpOperator::In, false),
                // A value the rules-file value grammar reads (a bare word is no value there: the cell's
                // fixture failed to parse on `x`).
                from: QueryResult::Literal(Rc::new(
                    PathAwareValue::try_from("{ B: 2 }").expect("parses"),
                )),
                to: Some(QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(PathAwareValue::try_from("{ A: 1 }").expect("parses")),
                    remaining_query: String::new(),
                    reason: Some(sentence.to_string()),
                    kind: UnResolvedKind::Undecidable {
                        refusal: Some(RefusalToken::minted(900)),
                        carried: None,
                    },
                })),
                message: Some(sentence.to_string()),
                custom_message: None,
                status: Status::FAIL,
                refusal: true,
            },
        ))),
        children: vec![],
    };
    let nested_rule = |own: &str, children: Vec<EventRecord<'static>>| EventRecord {
        context: String::from("helper"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "helper",
            status: Status::FAIL,
            message: Some(format!(
                "{}{own}",
                crate::rules::eval::RULE_CONDITION_UNEVALUATED_HEAD
            )),
            slot: crate::rules::CustomSlot::Refusal,
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![EventRecord {
            context: String::from("Rule#helper/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children,
        }],
    };
    // (the rule's text, its slot, the records of its failed condition) -> what the report holds
    let read = |sentence: &str, children: Vec<EventRecord<'static>>| {
        let rule = EventRecord {
            context: String::from("gated"),
            container: Some(RecordType::RuleCheck(NamedStatus {
                name: "gated",
                status: Status::FAIL,
                message: Some(sentence.to_string()),
                slot: crate::rules::CustomSlot::Evaluator,
                displaced: None,
                frame_reads: Vec::new(),
                ended_by_error: false,
            })),
            children: vec![EventRecord {
                context: String::from("Rule#gated/When"),
                container: Some(RecordType::RuleCondition(Status::FAIL)),
                children,
            }],
        };
        match report_all_failed_clauses_for_rules(&[rule]).as_slice() {
            [ClauseReport::Rule(rule)] => (
                rule.messages.custom_message.clone().unwrap_or_default(),
                rule.messages.refusal,
                rule.messages.parts.is_some(),
            ),
            other => panic!("one rule report, got {:?}", other),
        }
    };
    let joined = |head: &str, appended: &str| format!("{head}{ALSO_MET}{appended}");
    assert_eq!(
        vec![
            // a plain error's sentence plus a refusal: kind kept, parts carried
            (joined(PLAIN, R1), false, true),
            // a nested rule over a refused child: R1 once, not `R1; R1`
            (joined(PLAIN, R1), false, true),
            // a refused IN comparison is read
            (joined(PLAIN, R3), false, true),
            // `S: R; cause` carries R1: the bare record of R1 adds nothing
            (format!("wrap: {R1}; cause"), false, false),
            // a quoted numbered raise carries R2 and R1; a bare R1 adds nothing
            (format!("wrap: (1) {R2} (2) {R1}"), false, false),
        ],
        vec![
            read(PLAIN, vec![clause_error(R1)]),
            read(PLAIN, vec![nested_rule(R1, vec![clause_error(R1)])]),
            read(PLAIN, vec![in_refusal(R3)]),
            read(&format!("wrap: {R1}; cause"), vec![clause_error(R1)]),
            read(&format!("wrap: (1) {R2} (2) {R1}"), vec![clause_error(R1)]),
        ],
        "a plain sentence keeps its kind and lists each refusal once; a carried refusal is not appended"
    );
}

/// A record that WRAPS an error is skipped by its kind when the failed condition's refusals are read: a
/// `when` block's explanation ("The condition could not be evaluated, so the block it guards is not
/// checked: <e>"), the type-condition wrapper ("Error <e> during type condition evaluation, bailing") and a
/// disjunction's ("Disjunction could not be decided: .. <e>") each quote the refusal the rule's own sentence
/// already carries, so the sentence gains no "also met" part from any of them, while the clause record
/// beneath the wrapper that names a DIFFERENT refusal still adds it, once. One row per wrapper kind.
///
/// Fails when a wrapper's message is read as a refusal of its own (the sentence gains a part that
/// quotes the refusal it already carries), or when the other refusal under it is lost.
#[test]
fn a_wrapper_record_adds_no_part_to_the_sentence_that_quotes_its_refusal() {
    const HELD: &str = "the held refusal at /Resources/A/Tags";
    const OTHER: &str = "the other refusal at /Resources/B/Tags";
    let sentence = format!("The rule's condition could not be evaluated: {HELD}");
    let block = |message: Option<String>, refusal: bool| BlockCheck {
        status: Status::FAIL,
        at_least_one_matches: false,
        raised: message.is_some(), // the fixture's records with a sentence model a raise's record
        message,
        refusal,
        custom_message: None,
        gate_mark: false,
        frame_reads: Vec::new(),
    };
    let record =
        |container: RecordType<'static>, children: Vec<EventRecord<'static>>| EventRecord {
            context: String::from("wrapper"),
            container: Some(container),
            children,
        };
    // The clause record the evaluator writes for a refusal a clause met in the gate role.
    let clause_naming = |refusal: &str| {
        record(
            RecordType::GuardClauseBlockCheck(block(
                Some(format!("Error {refusal} when handling clause, bailing")),
                true,
            )),
            vec![],
        )
    };
    let under = |wrapper: RecordType<'static>, inner: Vec<EventRecord<'static>>| {
        vec![record(
            RecordType::RuleCondition(Status::FAIL),
            vec![record(wrapper, inner)],
        )]
    };
    let extended = |children: Vec<EventRecord<'static>>| {
        sentence_and_whether_refusals_joined(&sentence, &children, SentenceSlot::Error).0
    };
    let when_wrapper = RecordType::WhenCheck(block(
        Some(format!(
            "The condition could not be evaluated, so the block it guards is not checked: {HELD}"
        )),
        true,
    ));
    let type_wrapper = RecordType::WhenCheck(block(
        Some(format!(
            "Error {HELD} during type condition evaluation, bailing"
        )),
        true,
    ));
    let disjunction = RecordType::Disjunction(block(
        Some(format!(
            "Disjunction could not be decided: no disjunct answered, and one could not be evaluated: {HELD}"
        )),
        true,
    ));
    let also = |other: &str| format!("{sentence}; the condition also met: {other}");
    assert_eq!(
        (
            sentence.clone(),
            sentence.clone(),
            sentence.clone(),
            also(OTHER),
            also(OTHER),
            also(OTHER),
        ),
        (
            extended(under(when_wrapper.clone(), vec![clause_naming(HELD)])),
            extended(under(type_wrapper.clone(), vec![clause_naming(HELD)])),
            extended(under(disjunction.clone(), vec![clause_naming(HELD)])),
            extended(under(when_wrapper, vec![clause_naming(OTHER)])),
            extended(under(type_wrapper, vec![clause_naming(OTHER)])),
            extended(under(disjunction, vec![clause_naming(OTHER)])),
        ),
        "a wrapper quoting the held refusal adds nothing; the clause record beneath it naming another refusal adds it once"
    );
}

/// One refusal is one refusal in whichever spelling a record wrote it. A rule's sentence holds the error its
/// condition held as `Error::Unevaluatable`'s display writes it (wrapped: "Clause could not be evaluated
/// against the incoming context `R`"), a clause-error record beneath it holds the same wrapped form, and a
/// settle record holds the bare `R`. The sentence a failed condition's walk builds lists `R` once, as the
/// sentence's own account, whichever of the three records names it again, and still adds the OTHER refusal
/// the condition met, once. Built from `Error::Unevaluatable`, the error that writes the wrapper (the
/// other join cells use `Error::undecidable`, which does not).
///
/// Fails when `R` is listed a second time after the sentence's `; the condition also met:` (the
/// wrapped and the bare spelling counted as two refusals), or when the other refusal is lost.
#[test]
fn a_refusal_in_its_wrapped_and_its_bare_spelling_is_listed_once() {
    use crate::rules::errors::Error;
    // Built over a root scope, as the neighbouring cells are: the registry is what finds the registered
    // refusal inside the wrapped "R; cause", and without the scope the registered tail is not found (the
    // text "R; cause" is then no refusal and is listed beside the sentence's own R).
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let _root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    const HELD: &str = "the read of `A` was refused, at path /Resources/A/Tags";
    const OTHER: &str = "the read of `B` was refused, at path /Resources/B/Tags";
    for text in [HELD, OTHER] {
        let _ = crate::rules::eval_context::register_refusal(text);
    }
    let sentence = format!(
        "{}{}",
        crate::rules::eval::RULE_CONDITION_UNEVALUATED_HEAD,
        Error::Unevaluatable(HELD.to_string())
    );
    let record = |message: String| EventRecord {
        context: String::from("GuardAccessClause#blockA"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(message),
            refusal: true,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    // The wrapped clause-error record the evaluator writes, and the bare settle record.
    let wrapped = |refusal: &str| {
        record(crate::rules::eval::clause_error_message(
            &Error::Unevaluatable(refusal.to_string()),
        ))
    };
    let bare = |refusal: &str| record(refusal.to_string());
    let under = |records: Vec<EventRecord<'static>>| {
        vec![EventRecord {
            context: String::from("Rule#gated/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children: records,
        }]
    };
    let counts = |records: Vec<EventRecord<'static>>| {
        let text =
            sentence_and_whether_refusals_joined(&sentence, &under(records), SentenceSlot::Error).0;
        (text.matches(HELD).count(), text.matches(OTHER).count())
    };
    // The wrapped spelling of a refusal that carries a cause after it ("R; cause"): the wrapper is removed
    // BEFORE the text is split at the refusal's boundary, so the registered `R` is found at position 0 and
    // the cause is not read as a second refusal. Split first, the wrapper's own text leads the candidate and
    // `R` is listed a second time.
    let with_a_cause = format!("{HELD}; a cause");
    assert_eq!(
        vec![(1, 0), (1, 0), (1, 1), (1, 1), (1, 0)],
        vec![
            counts(vec![wrapped(HELD)]),
            counts(vec![bare(HELD)]),
            counts(vec![wrapped(HELD), wrapped(OTHER)]),
            counts(vec![bare(HELD), wrapped(OTHER)]),
            counts(vec![wrapped(&with_a_cause)]),
        ],
        "the held refusal is the sentence's own, once, in either spelling and with a cause after it; the other is added once"
    );
}

/// A type block with an explanation of its own keeps it, and its silent child block gives no generic
/// sentence beside it: the type block's walk of its children runs with the generic fallback off where the
/// block has a message (`generic_fallback && message.is_none()`), so a raised, message-less child is skipped
/// and the explanation is the one entry.
///
/// Fails when the generic "none of the checks recorded under it reports why" sentence is listed
/// beside (or in place of) the explanation.
#[test]
fn a_type_blocks_explanation_is_kept_and_its_silent_child_gives_no_generic_sentence() {
    let silent = EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let type_check = EventRecord {
        context: String::from("TypeBlock#S3"),
        container: Some(RecordType::TypeCheck(crate::rules::TypeBlockCheck {
            type_name: "AWS::S3::Bucket",
            block: BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: true,
                message: Some(String::from("the type block's own explanation")),
                refusal: false,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            },
        })),
        children: vec![silent],
    };
    let listed: Vec<String> = report_failed_clauses(&[type_check], true, false)
        .iter()
        .map(|clause| match clause {
            ClauseReport::Block(block) => block.messages.error_message.clone().unwrap_or_default(),
            other => panic!("a block entry, got {:?}", other),
        })
        .collect();
    assert_eq!(
        vec![String::from("the type block's own explanation")],
        listed,
        "the parent keeps its own explanation and the silent child adds no generic sentence"
    );
}

/// A called rule whose own sentence quotes a HELD refusal that left no flagged record beside a sibling
/// disjunct's flagged one: the outer rule's sentence names both, once each. The children's refusal (the
/// sibling's) is read first, and the called rule's own sentence, head stripped, is read as well, since it is
/// the only account of the held one.
///
/// Fails when the held refusal is dropped (the own sentence was skipped because the children said
/// something), or when either is named twice.
#[test]
fn a_called_rules_held_refusal_and_a_siblings_flagged_one_are_both_listed_once() {
    // Built over a root scope with both sentences registered, as in a run (the neighbouring cells'
    // setup): the dedupe consults the registry, and a cell without it tests a state the evaluator never
    // produces.
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let _root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    const HELD: &str = "the read of `A` was refused, at path /Resources/A/Tags";
    const SIBLING: &str = "the read of `B` was refused, at path /Resources/B/Tags";
    for text in [HELD, SIBLING] {
        let _ = register_refusal(text);
    }
    let sibling = EventRecord {
        context: String::from("GuardAccessClause#blockA"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(crate::rules::eval::clause_error_message(
                &crate::rules::errors::Error::undecidable(SIBLING.to_string()),
            )),
            refusal: true,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let helper = EventRecord {
        context: String::from("helper"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "helper",
            status: Status::FAIL,
            message: Some(format!(
                "{}{HELD}",
                crate::rules::eval::RULE_CONDITION_UNEVALUATED_HEAD
            )),
            slot: crate::rules::CustomSlot::Refusal,
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![EventRecord {
            context: String::from("Rule#helper/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children: vec![sibling],
        }],
    };
    let plain = "The rule's condition could not be evaluated: a plain error";
    let (text, ..) = rule_report_of(rule_over(
        vec![helper],
        plain,
        crate::rules::CustomSlot::Evaluator,
        None,
    ));
    let text = text.unwrap_or_default();
    assert_eq!(
        (1, 1),
        (text.matches(HELD).count(), text.matches(SIBLING).count()),
        "both refusals, once each, in the outer sentence: {text}"
    );
}

/// A record whose text leads with a refusal and carries a cause after it ("R; cause"), beside a rule sentence
/// that already carries R ("lead: R"), adds nothing: R is listed once and the cause is not appended as a
/// refusal (it stays in the sentence that carries it). A record "R1; R2" beside "lead: R1" appends R2, a
/// registered refusal of its own. The first row reads the registry at the position-0 candidate (the whole
/// text starts with the refusal), the second at the boundary after the first.
///
/// Fails when the first row gains "also met: cause" or lists R twice, or when the second row loses
/// R2.
#[test]
fn a_refusal_with_a_cause_after_it_is_listed_once_and_a_second_refusal_is_kept() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let _root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    const R1: &str = "the read of `A` was refused, at path /Resources/A/Tags";
    const R2: &str = "the read of `B` was refused, at path /Resources/B/Tags";
    for text in [R1, R2] {
        let _ = register_refusal(text);
    }
    let record = |message: String| EventRecord {
        context: String::from("GuardAccessClause#blockA"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(message),
            refusal: true,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let under = |records: Vec<EventRecord<'static>>| {
        vec![EventRecord {
            context: String::from("Rule#gated/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children: records,
        }]
    };
    let lead = format!("lead: {R1}");
    let (first, _) = sentence_and_whether_refusals_joined(
        &lead,
        &under(vec![record(format!("{R1}; a cause"))]),
        SentenceSlot::Error,
    );
    let (second, _) = sentence_and_whether_refusals_joined(
        &lead,
        &under(vec![record(format!("{R1}; {R2}"))]),
        SentenceSlot::Error,
    );
    assert_eq!(
        (lead.clone(), format!("{lead}{ALSO_MET}{R2}")),
        (first, second),
        "R once and the cause not appended; R2 kept beside the carried R1"
    );
}

/// A refused per-value record of a failed condition: a unary check flagged a refusal, its marker carrying
/// `token`, with `message` as its sentence.
fn refused_unary(
    message: &str,
    token: Option<crate::rules::errors::RefusalToken>,
) -> EventRecord<'static> {
    EventRecord {
        context: String::from("Properties.Tags"),
        container: Some(RecordType::ClauseValueCheck(ClauseCheck::Unary(
            UnaryValueCheck {
                value: ValueCheck {
                    from: QueryResult::UnResolved(UnResolved {
                        traversed_to: Rc::new(
                            PathAwareValue::try_from("{ A: 1 }").expect("parses"),
                        ),
                        remaining_query: String::new(),
                        reason: Some(message.to_string()),
                        kind: UnResolvedKind::Undecidable {
                            refusal: token,
                            carried: None,
                        },
                    }),
                    message: Some(message.to_string()),
                    custom_message: None,
                    status: Status::FAIL,
                    refusal: true,
                },
                comparison: (CmpOperator::Exists, false),
            },
        ))),
        children: vec![],
    }
}

/// A rule's record over a failed `when` condition holding `conditions`.
fn rule_over(
    conditions: Vec<EventRecord<'static>>,
    message: &str,
    slot: crate::rules::CustomSlot,
    displaced: Option<(crate::rules::CustomSlot, String)>,
) -> EventRecord<'static> {
    EventRecord {
        context: String::from("gated"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "gated",
            status: Status::FAIL,
            message: Some(message.to_string()),
            slot,
            displaced,
            frame_reads: Vec::new(),
            // A rule whose own `when` failed ended on an error (the evaluator closes it so).
            ended_by_error: true,
        })),
        children: vec![EventRecord {
            context: String::from("Rule#gated/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children: conditions,
        }],
    }
}

/// The rule report of a one-rule tree: (custom message, error message, refusal flag, slot).
fn rule_report_of(
    record: EventRecord<'static>,
) -> (
    Option<String>,
    Option<String>,
    bool,
    crate::rules::CustomSlot,
) {
    match report_all_failed_clauses_for_rules(&[record]).as_slice() {
        [ClauseReport::Rule(rule)] => (
            rule.messages.custom_message.clone(),
            rule.messages.error_message.clone(),
            rule.messages.refusal,
            rule.custom_slot,
        ),
        other => panic!("one rule report, got {:?}", other),
    }
}

/// A refusal is one sentence, by identity, in either order of a wrapper that quotes it and the bare record:
/// two records naming one refusal by its token (a wrapper sentence that contains the refusal's text, and the
/// bare text) list it once, wrapper first or bare first, and a rule sentence that already carries it gains
/// nothing from either. A numbered raise `(1) R2 (2) R1` after a collected `R1` lists `R2`: containment never
/// decides. Built over a root scope so the registry holds the sentences, as in a run (the report is built
/// while the scope is alive).
///
/// Fails when the refusal is named twice (a wrapper-first order keeps the wrapper and then the bare
/// text), when a numbered raise is dropped whole because it contains a collected part, or when the
/// sentence that carries the refusal gains it again.
#[test]
fn one_refusal_is_one_sentence_by_identity_in_every_order() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let _root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    let first = "the read of `S` is refused at path /Resources/F/Tags";
    let second = "the read of `T` is refused at path /Resources/G/Tags";
    let first_token = register_refusal(first);
    let _ = register_refusal(second);
    let wrapper = format!("the value to compare from could not be read: {first}");
    let wrapper_token = ensure_registered_wrap(&wrapper, Some(first_token));
    assert_eq!(
        first_token, wrapper_token,
        "premise: the wrap is registered under the refusal's token"
    );
    let plain = "The rule's condition could not be evaluated: a plain error";
    let carrying = format!("The rule's condition could not be evaluated: {first}");
    let occurrences = |text: &Option<String>, needle: &str| {
        text.as_deref().unwrap_or_default().matches(needle).count()
    };
    let evaluator = crate::rules::CustomSlot::Evaluator;
    // Every row is read, so a first failure hides none.
    fn row<T: PartialEq + std::fmt::Debug>(
        failed: &mut Vec<String>,
        label: &str,
        wanted: T,
        got: T,
    ) {
        if wanted != got {
            failed.push(format!("{label}: wanted {wanted:?}, got {got:?}"));
        }
    }
    let mut failed: Vec<String> = Vec::new();
    for (label, order) in [("wrapper first", [0, 1]), ("bare first", [1, 0])] {
        let records = |message: &str| {
            let both = [
                refused_unary(&wrapper, Some(first_token)),
                refused_unary(first, Some(first_token)),
            ];
            let [a, b] = order.map(|index| both[index].clone());
            rule_over(vec![a, b], message, evaluator, None)
        };
        let (named_by_plain, _, _, _) = rule_report_of(records(plain));
        row(
            &mut failed,
            &format!("({label}) a plain sentence gains the refusal once"),
            1,
            occurrences(&named_by_plain, first),
        );
        let (named_by_carrier, _, _, _) = rule_report_of(records(&carrying));
        row(
            &mut failed,
            &format!("({label}) a sentence that carries the refusal gains nothing"),
            Some(carrying.clone()),
            named_by_carrier,
        );
    }
    let numbered = format!("(1) {second} (2) {first}");
    let (text, _, _, _) = rule_report_of(rule_over(
        vec![
            refused_unary(first, Some(first_token)),
            refused_unary(&numbered, None),
        ],
        plain,
        evaluator,
        None,
    ));
    row(
        &mut failed,
        "a numbered raise after a collected part still lists the part beside it",
        (1, 1),
        (occurrences(&text, first), occurrences(&text, second)),
    );
    assert!(failed.is_empty(), "{:#?}", failed);
}

/// A disjunction NESTED under a conjunction keeps its held refusal in the rule's sentence: its per-value
/// records carry no message (the gate role writes none on purpose), so the disjunction's own message is the
/// only account of the refusal and is read, stripped of its head to the quoted error. A disjunction whose
/// children name a refusal is read through them and its message is not read again.
///
/// Fails when the nested refusal is named nowhere, or when the quoted error is named twice.
#[test]
fn a_nested_disjunctions_held_refusal_is_listed_once() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let _root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    let held = "the read of `K` is refused at path /Resources/N/Tags";
    let message = |refusal: bool, text: String| EventRecord {
        context: String::from("Disjunction#1"),
        container: Some(RecordType::Disjunction(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: Some(text),
            refusal,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![EventRecord {
            context: String::from("GuardBlockAccessClause#1"),
            container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: false,
                message: None,
                refusal: true,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            })),
            children: vec![],
        }],
    };
    let wrapped = format!("{}{held}", crate::rules::eval::DISJUNCTION_UNDECIDED_HEAD);
    let plain = "The rule's condition could not be evaluated: a plain error";
    let evaluator = crate::rules::CustomSlot::Evaluator;
    let (text, _, flag, slot) = rule_report_of(rule_over(
        vec![message(true, wrapped.clone())],
        plain,
        evaluator,
        None,
    ));
    let (kept, ..) = rule_report_of(rule_over(
        vec![message(true, wrapped)],
        &format!("{plain}; the condition also met: {held}"),
        evaluator,
        None,
    ));
    assert_eq!(
        (
            Some(format!("{plain}; the condition also met: {held}")),
            false,
            crate::rules::CustomSlot::Evaluator,
            Some(format!("{plain}; the condition also met: {held}")),
        ),
        (text, flag, slot, kept),
        "the nested disjunction's quoted refusal is listed once, and not again where the sentence carries it; the sentence keeps its plain kind"
    );
}

/// A rule whose call carries a `<< >>` body and whose own sentence is absent (the run-ending case: slot
/// Author, nothing displaced) reports the refusals its failed condition met as its error message under the
/// neutral head, joined, with the flag of the deciding error (a plain one: false), and keeps the body
/// untouched. With a sentence the body displaced (slot Author, the displaced sentence a refusal's, so the
/// flag is true), the refusals the condition met beyond the one that sentence carries are appended to the
/// ERROR message and the body is never edited.
///
/// Fails when the body is edited, when the refusals are named nowhere in the report, when the
/// neutral head is missing, or when the alone row is flagged a refusal.
#[test]
fn a_calls_body_keeps_its_text_and_the_refusals_join_the_error_message() {
    let rules_file = RulesFile::try_from("rule r { Resources exists }").expect("parses");
    let _root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from("{ Resources: {} }").expect("parses")),
    );
    let first = "the read of `S` is refused at path /Resources/F/Tags";
    let second = "the read of `T` is refused at path /Resources/G/Tags";
    let author = crate::rules::CustomSlot::Author;
    let body = "the callers own words";
    let two = || vec![refused_unary(first, None), refused_unary(second, None)];
    let alone = rule_report_of(rule_over(two(), body, author, None));
    let sentence = format!("The rule's condition could not be evaluated: {first}");
    let displaced = rule_report_of(rule_over(
        two(),
        body,
        author,
        Some((crate::rules::CustomSlot::Refusal, sentence.clone())),
    ));
    assert_eq!(
        (
            (
                Some(body.to_string()),
                Some(format!(
                    "{RULE_FAILED_ON_AN_ERROR_HEAD}{ALSO_MET}{first}; {second}"
                )),
                false,
                author,
            ),
            (
                Some(body.to_string()),
                Some(format!("{sentence}; the condition also met: {second}")),
                true,
                author,
            ),
        ),
        (alone, displaced),
        "the body stays as written; the refusals join the error message"
    );
}

/// A rule whose own sentence is a PLAIN error's (slot Evaluator, flag clear) that gains a refusal from its
/// failed condition's records KEEPS its kind: the refusal did not decide the verdict, so the report's slot
/// stays Evaluator and the flag false, and the refusal rides as the second of the sentence's two parts,
/// whole with its remedy (the console cuts the plain part at the recorded-message bound and prints the
/// refusal part whole). A sentence that gains nothing keeps its kind and carries no parts.
///
/// Fails when the slot or the flag is promoted to a refusal's, when the refusal part is cut or
/// absent, or when a sentence that gained nothing carries parts.
#[test]
fn a_plain_sentence_that_gains_a_refusal_keeps_its_kind_and_the_refusal_part_is_whole() {
    let refusal_record = || EventRecord {
        context: String::from("Properties.Tags"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(String::from("the settled refusal, remedy included")),
            refusal: true,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let rule = |children: Vec<EventRecord<'static>>, slot: crate::rules::CustomSlot| EventRecord {
        context: String::from("gated"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "gated",
            status: Status::FAIL,
            message: Some(String::from(
                "The rule's condition could not be evaluated: a plain error",
            )),
            slot,
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![EventRecord {
            context: String::from("Rule#gated/When"),
            container: Some(RecordType::RuleCondition(Status::FAIL)),
            children,
        }],
    };
    let read = |record: EventRecord<'static>| match report_all_failed_clauses_for_rules(&[record])
        .as_slice()
    {
        [ClauseReport::Rule(rule)] => (
            rule.custom_slot,
            rule.messages.refusal,
            rule.messages.custom_message.clone().unwrap_or_default(),
            rule.messages.parts.clone(),
        ),
        other => panic!("one rule report, got {:?}", other),
    };
    let (slot, flag, text, parts) = read(rule(
        vec![refusal_record()],
        crate::rules::CustomSlot::Evaluator,
    ));
    assert_eq!(
        (
            crate::rules::CustomSlot::Evaluator,
            false,
            true,
            Some(String::from("the settled refusal, remedy included"))
        ),
        (
            slot,
            flag,
            text.ends_with("the condition also met: the settled refusal, remedy included"),
            parts.map(|parts| parts.message().to_string())
        ),
        "the joined refusal leaves the sentence plain and rides as the whole second part"
    );
    let (slot, flag, text, parts) = read(rule(vec![], crate::rules::CustomSlot::Evaluator));
    assert_eq!(
        (crate::rules::CustomSlot::Evaluator, false, false, false),
        (slot, flag, text.contains("also met"), parts.is_some()),
        "a sentence that gained nothing keeps its kind and carries no parts"
    );
}

/// A call's `<< >>` body over a silent failing block is the failure text in every consumer: the rule's
/// `checks` stay empty (no generic "none of the checks recorded under it reports why" entry fills them), the
/// console's unattributed section names the rule by its message, and the JUnit failure text
/// (`get_message_with_rule_records`) is the body, with the generic sentence nowhere. A rule with NO text
/// keeps the generic entry, so a failing rule is never listed with nothing to say.
///
/// Fails when the body's rule lists the generic sentence in `checks` or in the JUnit text, or when
/// the message-less rule lists nothing.
#[test]
fn a_calls_body_over_a_silent_block_is_the_failure_text_and_the_generic_sentence_is_not() {
    const BODY: &str = "AUTHOR BODY";
    let silent = || EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![EventRecord {
            context: String::from("GuardBlockAccessClause#2"),
            container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: false,
                message: None,
                refusal: false,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            })),
            children: vec![],
        }],
    };
    let call = |message: Option<&str>| EventRecord {
        context: String::from("inner"),
        container: Some(RecordType::RuleCheck(NamedStatus {
            name: "inner",
            status: Status::FAIL,
            message: message.map(String::from),
            slot: match message {
                Some(_) => crate::rules::CustomSlot::Author,
                None => crate::rules::CustomSlot::Evaluator,
            },
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        })),
        children: vec![silent()],
    };
    let read = |record: EventRecord<'static>| match report_all_failed_clauses_for_rules(&[record])
        .as_slice()
    {
        [report @ ClauseReport::Rule(rule)] => (
            rule.checks.len(),
            report
                .get_message_with_rule_records()
                .into_iter()
                .flat_map(|messages| [messages.custom_message, messages.error_message])
                .flatten()
                .collect::<Vec<_>>(),
        ),
        other => panic!("one rule report, got {:?}", other),
    };
    assert_eq!(
        (
            (0, vec![String::from(BODY)]),
            (1, vec![String::from(SILENT_BLOCK_SENTENCE)]),
        ),
        (read(call(Some(BODY))), read(call(None))),
        "the body alone with empty checks; the message-less rule keeps the generic entry"
    );
}

/// A `MissingBlockValue` record flagged a refusal that carries no message of its own (no writer in
/// `eval.rs` builds one, but the record admits it) is reported as the refusal it is, with the marker's
/// reason as its sentence, and not as a missing property with the flag dropped.
///
/// Fails when the report reads "is missing" and refusal false.
#[test]
fn a_refused_missing_value_without_a_message_is_reported_as_the_refusal() {
    let record = EventRecord {
        context: String::from("Properties.Tags"),
        container: Some(RecordType::ClauseValueCheck(
            ClauseCheck::MissingBlockValue(ValueCheck {
                from: QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(PathAwareValue::try_from("{ A: 1 }").expect("parses")),
                    remaining_query: String::new(),
                    reason: Some(String::from("the read was refused")),
                    kind: UnResolvedKind::Undecidable {
                        refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                        carried: None,
                    },
                }),
                message: None,
                custom_message: None,
                status: Status::FAIL,
                refusal: true,
            }),
        )),
        children: vec![],
    };
    match report_all_failed_clauses_for_rules(&[record]).as_slice() {
        [ClauseReport::Block(block)] => assert_eq!(
            (Some("the read was refused"), true),
            (
                block.messages.error_message.as_deref(),
                block.messages.refusal
            ),
            "the marker's reason is the sentence and the flag stays"
        ),
        other => panic!("one block report, got {:?}", other),
    }
}

/// A parent WITH a message of its own drops a silent child block beside a sibling that reports: a block
/// with a message over [one that reports, one silent] is listed by the reporting child alone (a block
/// whose children report is listed by them, as it always was; its own message is for the case none
/// reports), and a disjunction with a message over the same two children lists the reporting disjunct
/// alone.
///
/// Fails when the silent block's generic sentence is listed beside the reporting child.
#[test]
fn a_parent_with_a_message_drops_a_silent_child_beside_a_reporting_sibling() {
    let reporting = || EventRecord {
        context: String::from("GuardBlockAccessClause#1"),
        container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: true,
            message: Some(String::from("A failed")),
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![],
    };
    let silent = || EventRecord {
        context: String::from("BlockGuardClause#2"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![EventRecord {
            context: String::from("GuardBlockAccessClause#2"),
            container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: false,
                message: None,
                refusal: false,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            })),
            children: vec![],
        }],
    };
    let with_message = || BlockCheck {
        status: Status::FAIL,
        at_least_one_matches: false,
        raised: true,
        // The evaluator's sentence quoting the error the reporting child lists (a record's `message` is
        // never the author's text), so that child tells it and the parent writes no entry of its own.
        message: Some(format!(
            "{}A failed",
            crate::rules::eval::WHEN_UNEVALUATED_HEAD
        )),
        refusal: false,
        custom_message: None,
        gate_mark: false,
        frame_reads: Vec::new(),
    };
    let block = EventRecord {
        context: String::from("BlockGuardClause#1"),
        container: Some(RecordType::BlockGuardCheck(with_message())),
        children: vec![reporting(), silent()],
    };
    let disjunction = EventRecord {
        context: String::from("Disjunction#1"),
        container: Some(RecordType::Disjunction(with_message())),
        children: vec![reporting(), silent()],
    };
    let messages_of = |clauses: &[ClauseReport<'_>]| -> Vec<Option<String>> {
        clauses
            .iter()
            .map(|clause| match clause {
                ClauseReport::Block(block) => block.messages.error_message.clone(),
                other => panic!("a block report, got {:?}", other),
            })
            .collect()
    };
    let in_a_block = messages_of(&report_all_failed_clauses_for_rules(&[block]));
    let in_a_disjunction = match report_all_failed_clauses_for_rules(&[disjunction]).as_slice() {
        [ClauseReport::Disjunctions(report)] => messages_of(&report.checks),
        other => panic!("one disjunction report, got {:?}", other),
    };
    assert_eq!(
        (
            vec![Some(String::from("A failed"))],
            vec![Some(String::from("A failed"))],
        ),
        (in_a_block, in_a_disjunction),
        "a parent with a message of its own lists the reporting child alone"
    );
}

/// A failing block whose per-value records report nothing is listed by its own record
/// (`report_all_failed_clauses_for_rules`), with the record's message where it has one and its refusal
/// flag, and otherwise with the generic sentence, which is no refusal's and is flagged `refusal: false`
/// whatever the record's own flag says (copying the block record's flag onto a sentence the record did not
/// carry flagged a generic sentence as a refusal). The child is a gate role's mark: a failing
/// `GuardClauseBlockCheck` with no message and no children.
///
/// Fails when the case with a message reports the generic sentence or loses the flag, when the case
/// without one reports `refusal: true`, or when the block is not listed at all (an empty list of
/// checks).
#[test]
fn a_failing_block_whose_children_report_nothing_is_listed_by_its_own_record() {
    const GENERIC: &str =
        "the block clause failed, and none of the checks recorded under it reports why";
    const SENTENCE: &str = "the read of `Tags` was refused at path /Resources/A/Tags";
    let block = |message: Option<&str>| EventRecord {
        context: String::from("BlockGuardClause#1"),
        container: Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: message.is_some(), // the fixture's records with a sentence model a raise's record
            message: message.map(String::from),
            refusal: true,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![EventRecord {
            context: String::from("GuardBlockAccessClause#1"),
            container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                status: Status::FAIL,
                at_least_one_matches: false,
                raised: false,
                message: None,
                refusal: true,
                custom_message: None,
                gate_mark: false,
                frame_reads: Vec::new(),
            })),
            children: vec![],
        }],
    };
    let listed = |message: Option<&str>| -> Vec<(Option<String>, bool)> {
        report_all_failed_clauses_for_rules(&[block(message)])
            .iter()
            .map(|clause| match clause {
                ClauseReport::Block(report) => (
                    report.messages.error_message.clone(),
                    report.messages.refusal,
                ),
                other => panic!("one block report for one failing block, got {:?}", other),
            })
            .collect()
    };
    assert_eq!(
        (
            vec![(Some(String::from(SENTENCE)), true)],
            vec![(Some(String::from(GENERIC)), false)],
        ),
        (listed(Some(SENTENCE)), listed(None)),
        "a message is listed whole with the record's flag; the generic sentence is flagged no refusal"
    );
    // A CHILDLESS failing block takes the other fallback sentence ("query for block clause did not retrieve
    // any value") when it has no message, and that sentence is no refusal's either, whatever the record's
    // own flag says; with a message the message and the flag are listed as recorded.
    let childless = |message: Option<&str>| -> (Option<String>, bool) {
        let record = EventRecord {
            children: vec![],
            ..block(message)
        };
        match report_all_failed_clauses_for_rules(&[record]).as_slice() {
            [ClauseReport::Block(report)] => (
                report.messages.error_message.clone(),
                report.messages.refusal,
            ),
            other => panic!("one block report for one childless block, got {:?}", other),
        }
    };
    assert_eq!(
        (
            (Some(String::from(SENTENCE)), true),
            (
                Some(String::from(
                    "query for block clause did not retrieve any value"
                )),
                false
            ),
        ),
        (childless(Some(SENTENCE)), childless(None)),
        "a childless block lists its message with its flag; the generic sentence is flagged no refusal"
    );
    // A `when` condition that failed, over a silent child block: the condition's own message is the
    // explanation and the child's generic sentence must not displace it; with no message of its own the
    // condition still lists the silent child (a rule never lists empty checks).
    let condition = |message: Option<&str>| EventRecord {
        context: String::from("WhenCondition#1"),
        container: Some(RecordType::WhenCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: message.is_some(), // the fixture's records with a sentence model a raise's record
            message: message.map(String::from),
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        })),
        children: vec![block(None)],
    };
    let under_a_condition = |message: Option<&str>| -> Vec<Option<String>> {
        report_all_failed_clauses_for_rules(&[condition(message)])
            .iter()
            .map(|clause| match clause {
                ClauseReport::Block(report) => report.messages.error_message.clone(),
                other => panic!(
                    "one block report for one failing condition, got {:?}",
                    other
                ),
            })
            .collect()
    };
    assert_eq!(
        (
            vec![Some(String::from("the condition could not be evaluated"))],
            vec![Some(String::from(GENERIC))],
        ),
        (
            under_a_condition(Some("the condition could not be evaluated")),
            under_a_condition(None),
        ),
        "a condition with a message of its own is listed by it, and one without lists its silent child"
    );
}
