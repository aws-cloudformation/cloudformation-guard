use super::*;
use super::super::common_test_helpers::DummyEval;

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
        "Resources['table1F1EAFA30'].Properties.ProvisionedThroughput.ReadCapacityUnits"
    )?;
    struct Capture {};
    impl EvaluationContext for Capture {
        fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>> {
            unimplemented!()
        }

        fn rule_status(&self, rule_name: &str) -> Result<Status> {
            unimplemented!()
        }

        fn end_evaluation(&self, eval_type: EvaluationType, context: &str, msg: String, from: Option<PathAwareValue>, to: Option<PathAwareValue>, status: Option<Status>) {
            assert_ne!(msg.as_str(), "");
            assert_eq!(msg.starts_with("FIRST PART"), true);
            assert_eq!(msg.len() > "FIRST PART".len(), true);
            println!("{}", msg);
        }

        fn start_evaluation(&self, eval_type: EvaluationType, context: &str) {
            unimplemented!()
        }
    }
    let capture = Capture{};
    let appender = MetadataAppender{root_context: &root, delegate: &capture};
    let value = root.select(true, &query.query, &appender)?[0];
    println!("{:?}", value);
    appender.end_evaluation(EvaluationType::Clause, "Clause",
                            "FIRST PART".to_string(),
                            Some(value.clone()), None, Some(Status::FAIL));
    Ok(())
}