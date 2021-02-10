# https://code.amazon.com/packages/AwsFalconPythonManagedRules/blobs/mainline/--/src/AURORA_MYSQL_BACKTRACKING_ENABLED.py

rule is_resource_type {
    configuration.resourceType == "AWS::RDS::DBCluster"
}

rule validate_parameters when is_resource_type {
    PRAMETERS.BacktrackWindowInSeconds != null
    PRAMETERS.BacktrackWindowInSeconds >= 0
    PRAMETERS.BacktrackWindowInSeconds <= 259200
}

rule not_applicable when validate_parameters {
    let allowedEngines = ['aurora','aurora-mysql']
    AWS::RDS::DBCluster {
        configuration.engine NOT IN %allowedEngines
    }
}

rule compliant when not not_applicable {
    AWS::RDS::DBCluster {
        let backtrackWindow = configuration.backtrackWindow
        %backtrackWindow == null or 
        %backtrackWindow >= PRAMETERS.BacktrackWindowInSeconds
    }

} 

