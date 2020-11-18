#
# Translated from https://code.amazon.com/packages/AwsFalconPythonManagedRules/blobs/mainline/--/src/ECS_REPOSITORY_CHECK.py
#
rule ecs_task_definitions_are_valid_repository_urls {
    AWS::ECS::TaskDefinition {
        #
        # Check that incoming parameter comply with ECR or Docker based repository specification
        #
        when PARAMETERS.RepositoryImageUriList != null {

            PARAMETERS.RepositoryImageUriList IN %DEFAULTS
            #
            # Check that all any image that is specified for a container definition is in
            # only from the allowed set of images
            #
            configuration.containerDefinitions.*.image IN PARAMETERS.RepositoryImageUriList
        }

        when PARAMETERS.RepositoryImageUriList == null {
            configuration.containerDefinitions.*.image IN %DEFAULTS
        }

    }
}

let DEFAULTS := [ /^.*.dkr.ecr..*.amazonaws[.*]*.com\/.*[:@]+(.*){2,255}$/, # ECR Repo
                  /^[a-z0-9-_:\.]{2,255}$/ ]

rule ecs_task_definitions_with_defaults {
    AWS::ECS::TaskDefinition {
        #
        # Check that all any image that is specified for a container definition is in
        # only from the allowed set of images
        #
        configuration.containerDefinitions.*.image IN %DEFAULTS
    }
}

rule real_check {
    ecs_task_definitions_are_valid_repository_urls or
    ecs_task_definitions_with_defaults
}

#
# Translated from https://code.amazon.com/packages/AwsFalconPythonManagedRules/blobs/mainline/--/src/ECS_TASKDEFINITION_LOGCONFIGURATION.py
#
rule ecs_task_definition_log_configuration_exists {
    #
    # check that logConfiguration is set for all container definitions
    #
    AWS::ECS::TaskDefinition {
        configuration.containerDefinitions.*.logConfiguration != null
    }
}

#
# Translated from https://code.amazon.com/packages/AwsFalconPythonManagedRules/blobs/mainline/--/src/ECS_PORT_MAPPING_ALLOWED.py
#
rule ecs_task_definition_port_mappings {
    AWS::ECS::TaskDefinition {
        #
        # Parameter validation ensure the list is provided
        #
        PARAMETERS.allowedHostPortList != null

        #
        # check that network mode is not none
        #
        configuration.networkMode != "none"

        #
        # for each container definition
        #   for each portMapping definition 
        #     take the containerPort
        #
        # compare the containerPort is within range as specified by incoming PARAMETERS
        let container_ports := configuration.containerDefinitions.*.portMappings.*.containerPort
        %container_ports >= PARAMETERS.allowedHostPortList.*.begin
        %container_ports <= PARAMETERS.allowedHostPortList.*.end
    }
}
