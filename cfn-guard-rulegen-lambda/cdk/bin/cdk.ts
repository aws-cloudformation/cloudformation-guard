#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import { CfnGuardRulegenStack } from '../lib/cdk-stack';

const app = new cdk.App();
new CfnGuardRulegenStack(app, 'CfnGuardRulegenStack');
