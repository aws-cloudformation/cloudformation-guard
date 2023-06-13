use super::*;

#[test]
fn append_cdk_metadata_test() -> Result<()> {
    let resources = r#"{
         "Resources": {
            "table1F1EAFA30": {
              "Type": "AWS::DynamoDB::Table",
              "Properties": {
                "KeySchema": [
                  {
                    "AttributeName": "table1",
                    "KeyType": "HASH"
                  }
                ],
                "AttributeDefinitions": [
                  {
                    "AttributeName": "table1",
                    "AttributeType": "S"
                  }
                ],
                "ProvisionedThroughput": {
                  "ReadCapacityUnits": 5,
                  "WriteCapacityUnits": 5
                }
              },
              "UpdateReplacePolicy": "Retain",
              "DeletionPolicy": "Retain",
              "Metadata": {
                "aws:cdk:path": "FtCdkDynamoDBStack/table1/Resource"
              }
            }
        }
    }"#;
    let root = PathAwareValue::try_from(resources)?;
    let query = AccessQuery::try_from(
        "Resources['table1F1EAFA30'].Properties.ProvisionedThroughput.ReadCapacityUnits",
    )?;
    struct Capture {}
    impl EvaluationContext for Capture {
        fn resolve_variable(&self, _: &str) -> Result<Vec<&PathAwareValue>> {
            unimplemented!()
        }

        fn rule_status(&self, _: &str) -> Result<Status> {
            unimplemented!()
        }

        fn end_evaluation(
            &self,
            _: EvaluationType,
            _: &str,
            msg: String,
            _: Option<PathAwareValue>,
            _: Option<PathAwareValue>,
            _: Option<Status>,
            _cmp: Option<(CmpOperator, bool)>,
        ) {
            assert_ne!(msg.as_str(), "");
            assert!(msg.starts_with("FIRST PART"));
            assert!(msg.len() > "FIRST PART".len());
            println!("{}", msg);
        }

        fn start_evaluation(&self, _: EvaluationType, _: &str) {
            unimplemented!()
        }
    }
    let capture = Capture {};
    let appender = MetadataAppender {
        root_context: &root,
        delegate: &capture,
    };
    let value = root.select(true, &query.query, &appender)?[0];
    println!("{:?}", value);
    appender.end_evaluation(
        EvaluationType::Clause,
        "Clause",
        "FIRST PART".to_string(),
        Some(value.clone()),
        None,
        Some(Status::FAIL),
        None,
    );
    Ok(())
}
