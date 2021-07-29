# Troubleshooting AWS CloudFormation Guard<a name="troubleshooting"></a>

If you encounter issues while working with AWS CloudFormation Guard, consult the topics in this section\.

**Topics**
+ [Clause fails when no resources of the selected type are present](#troubleshooting-when-conditions-filters)
+ [Guard does not evaluate CloudFormation template with long\-form Fn::GetAtt references](#troubleshooting-cfn-intrinsic-functions)
+ [General troubleshooting topics](#troubleshooting-general)

## Clause fails when no resources of the selected type are present<a name="troubleshooting-when-conditions-filters"></a>

When a query uses a filter like `Resources.*[ Type == 'AWS::ApiGateway::RestApi' ]`, if there are no `AWS::ApiGateway::RestApi` resources in the input, the clause evaluates to `FAIL`\.

```
%api_gws.Properties.EndpointConfiguration.Types[*] == "PRIVATE"
```

To avoid this outcome, assign filters to variables and use the `when` condition check\.

```
let api_gws = Resources.*[ Type == 'AWS::ApiGateway::RestApi' ]
    when %api_gws !empty { ...}
```

## Guard does not evaluate CloudFormation template with long\-form Fn::GetAtt references<a name="troubleshooting-cfn-intrinsic-functions"></a>

Guard doesn't support the short forms of intrinsic functions\. For example, using `!Join`, `!Sub` in a YAML\-formatted AWS CloudFormation template isn't supported\. Instead, use the expanded forms of CloudFormation intrinsic functions\. For example, use `Fn::Join`, `Fn::Sub` in YAML\-formatted CloudFormation templates when evaluating them against Guard rules\.

For more information about intrinsic functions, see the [intrinsic function reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference.html) in the *AWS CloudFormation User Guide*\.

## General troubleshooting topics<a name="troubleshooting-general"></a>
+ Verify that `string` literals don't contain embedded escaped strings\. Currently, Guard doesn't support embedded escape strings in `string` literals\.
+ Verify that your `!=` comparisons compare compatible data types\. For example, a `string` and an `int` are not compatible data types for comparison\. When performing `!=` comparison, if the values are incompatible, an error occurs internally\. Currently, the error is suppressed and converted to `false` to satisfy the [PartialEq](https://doc.rust-lang.org/std/cmp/trait.PartialEq.html) trait in Rust\.