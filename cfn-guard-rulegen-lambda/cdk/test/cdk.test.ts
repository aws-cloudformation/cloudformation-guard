import { expect as expectCDK, matchTemplate, MatchStyle } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import * as Cdk from '../lib/cdk-stack';

test('CfnGuardRulegen Stack', () => {
    const app = new cdk.App();
    // WHEN
    const stack = new Cdk.CfnGuardRulegenStack(app, 'CfnGuardRulegenStack');
    // THEN
    expectCDK(stack).to(matchTemplate({
      "Resources": {}
    }, MatchStyle.EXACT))
});
