import { expect as expectCDK, matchTemplate, MatchStyle } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import * as Cdk from '../lib/cdk-stack';

test('CfnGuard Stack', () => {
    const app = new cdk.App();
    // WHEN
    const stack = new Cdk.CfnGuardStack(app, 'CfnGuardStack');
    // THEN
    expectCDK(stack).to(matchTemplate({
      "Resources": {}
    }, MatchStyle.EXACT))
});
