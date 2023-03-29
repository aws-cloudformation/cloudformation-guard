#[cfg(test)]
mod tests {
    use cfn_guard_lambda;
    use cfn_guard_lambda::main::{call_cfn_guard, CustomEvent, CustomOutput};
    use lambda_runtime::Context;

    const NON_COMPLIANT_DATA: &str = "{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":true,\"AvailabilityZone\":\"us-west-2c\"}}}}";
    const RULE: &str = "let ec2_volumes = Resources.*[ Type == /EC2::Volume/ ]\nrule EC2_ENCRYPTION_BY_DEFAULT when %ec2_volumes !empty {\n    %ec2_volumes.Properties.Encrypted == true \n      <<\n            Violation: All EBS Volumes should be encryped \n            Fix: Set Encrypted property to true\n       >>\n}";
    const FAILURE_MESSAGE: &str = "Failed to handle event";

    #[tokio::test]
    async fn test_guard_lambda_handler_non_verbose() {
        let context = Context::default();

        let request = CustomEvent {
            data: NON_COMPLIANT_DATA.parse().unwrap(),
            rules: vec![RULE.parse().unwrap()],
            verbose: false,
        };
        println!("Request:\n{}", request);

        let response: CustomOutput = call_cfn_guard(request, context)
            .await
            .expect(FAILURE_MESSAGE);
        println!("Response:\n{}", response);
    }

    #[tokio::test]
    async fn test_guard_lambda_handler_verbose() {
        let context = Context::default();

        let request = CustomEvent {
            data: NON_COMPLIANT_DATA.parse().unwrap(),
            rules: vec![RULE.parse().unwrap()],
            verbose: true,
        };
        println!("Request:\n{}", request);

        let response: CustomOutput = call_cfn_guard(request, context)
            .await
            .expect(FAILURE_MESSAGE);
        println!("Response:\n{}", response);
    }
}
