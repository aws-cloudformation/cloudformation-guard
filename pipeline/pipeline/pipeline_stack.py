from aws_cdk.pipelines import CodePipeline, CodePipelineSource, ShellStep
from constructs import Construct
from aws_cdk import Stack, SecretValue

class PipelineStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        pipeline = CodePipeline(self, "Pipeline",
                                pipeline_name="CfnGuardPipeline",
                                synth=ShellStep("Synth",
                                                input=CodePipelineSource.git_hub("akshayrane/cloudformation-guard?", "docker",
                                                                                 authentication=SecretValue.secrets_manager(
                                                                                     secret_id='github-token',
                                                                                     json_field='gh_api_token'
                                                                                 ),
                                                                                 ),
                                                commands=["npm install -g aws-cdk",
                                                          "python -m pip install -r requirements.txt",
                                                          "cdk synth"]
                                                )
                                )
