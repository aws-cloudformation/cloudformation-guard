# Welcome to your CDK TypeScript project for cfn-guard-rulegen-lambda

This project uses TypeScript development with CDK, to leverage cloud infrastructure in code and support the provisioning of cfn-guard-rulegen-lambda through AWS CloudFormation

To emit the synthesized AWS CloudFormation template
1. Ensure you're in the `cfn-guard-rulegen-lambda` directory
1. Run `make build`
1. Run `cd cdk; npm install; npm run build; cdk synth`