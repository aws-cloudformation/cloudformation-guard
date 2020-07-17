import * as cdk from '@aws-cdk/core';
import * as lambda from '@aws-cdk/aws-lambda';
import * as path from 'path';

export class CfnGuardRulegenStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const fn = new lambda.Function(this, 'CfnGuardRulegen', {
      runtime: lambda.Runtime.PROVIDED,
      handler: 'CfnGuard.my_handler',
      functionName: this.node.tryGetContext('function-name'),
      code: lambda.Code.fromAsset(path.join(__dirname, '/../../lambda.zip'))
    });
  }
}
