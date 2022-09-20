#!/usr/bin/env python3
import os

import aws_cdk as cdk

from pipeline.pipeline_stack import PipelineStack

app = cdk.App()
PipelineStack(app, "CfnGuardPipelineStack",
              env=cdk.Environment(account='711319330327', region='us-east-1')
              )

app.synth()
