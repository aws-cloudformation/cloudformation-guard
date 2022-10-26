import aws_cdk as core
import aws_cdk.assertions as assertions

from pipeline.pipeline_stack import PipelineStack

# example tests. To run these tests, uncomment this file along with the example
# resource in pipeline/pipeline_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = PipelineStack(app, "pipeline")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
