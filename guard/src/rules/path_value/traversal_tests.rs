use super::*;
use std::convert::TryFrom;

#[test]
fn test_absolute_pointer_traversal() -> crate::rules::Result<()> {
    let value = PathAwareValue::try_from(crate::rules::values::read_from(
        r#"
        Resources:
          Helper:
            Type: AWS::S3::Bucket
          s3:
            Type: AWS::S3::Bucket
            Properties:
              Name: MyBucket
              AnalyticsConfiguration:
                - Prefix: MyBucket/2021/10
                  StorageClassAnalysis:
                    DataExport:
                      Destination:
                        BucketAccountId: 123456789012
                        BucketArn: arn:aws:s3:us-west-2:123456789112:ThatBucket/2021
                        Format: Parquet
                  TagFilters:
                    - Key: ProdApp
                      Value: MyAppStuff
              InventoryConfigurations:
                - Id: InventoryConfigurationId
                  Destination:
                    BucketArn:
                      Fn::GetAtt:
                        - Helper
                        - Arn
                    Format: CSV
                    Prefix: InventoryDestinationPrefix
                  Enabled: true
                  IncludedObjectVersions: Current
                  Prefix: InventoryConfigurationPrefix
                  ScheduleFrequency: Weekly
        "#,
    )?)?;

    let traversal = Traversal::from(&value);
    let root = traversal.root().unwrap();
    let result = traversal.at("/", root)?;
    assert_eq!(matches!(result, TraversalResult::Value(_)), true);
    if let TraversalResult::Value(curr) = result {
        assert_eq!(std::ptr::eq(&value, curr.value), true);
    }
    let result = match result {
        TraversalResult::Value(val) => val,
        _ => unreachable!(),
    };

    let result = traversal.at("/Resources/s3/Properties/AnalyticsConfiguration", result)?;
    assert_eq!(matches!(result, TraversalResult::Value(_)), true);
    let result = match result {
        TraversalResult::Value(val) => val,
        _ => unreachable!(),
    };
    assert_eq!(matches!(result.value, PathAwareValue::List(_)), true);

    //
    // Testing relative
    //
    let upward = traversal.at("1/Name", result)?;
    assert_eq!(matches!(upward, TraversalResult::Value(_)), true);
    let upward = match upward {
        TraversalResult::Value(up) => up,
        _ => unreachable!(),
    };
    match upward.value {
        PathAwareValue::String((path, value)) => {
            assert_eq!(path.0, "/Resources/s3/Properties/Name");
            assert_eq!(value, "MyBucket");
        }
        _ => unreachable!(),
    }

    Ok(())
}
