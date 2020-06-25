// © Amazon Web Services, Inc. or its affiliates. All Rights Reserved. This AWS Content is provided subject to the terms of the AWS Customer Agreement available at http://aws.amazon.com/agreement or other written agreement between Customer and either Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.

// Tests
// use cfn_guard_rulegen;

mod tests {

    #[test]
    fn test_simple_mixed_template() {
        let template_contents = String::from(r#"
Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument: |
        {
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "Service": [
                  "notlambda.amazonaws.com"
                ]
              }
            }
          ]
        }
"#);
        assert_eq!(
            cfn_guard_rulegen::run_gen(&template_contents ),
            vec![String::from(r#"AWS::IAM::Role AssumeRolePolicyDocument == {  "Statement": [    {      "Effect": "Allow",      "Principal": {        "Service": [          "notlambda.amazonaws.com"        ]      }    }  ]}"#)]
        );
    }

#[test]
fn test_no_properties_template() {
    let template_contents = String::from(r#"
Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
"#);
    let empty_vec: Vec<String> = vec![];
        assert_eq!(
            cfn_guard_rulegen::run_gen(&template_contents ),
            empty_vec
        );
    }
}
