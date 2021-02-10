#
#  PARAMETERS : {
#     "additionalLogs": {
#          "aurora": ["", ""],
#          "mysql": ["", ""]
#     }
#  }
#

let ENGINE_LOGS = {
    'postgres':      ["postgresql", "upgrade"],
    'mariadb':       ["audit", "error", "general", "slowquery"],
    'mysql':         ["audit", "error", "general", "slowquery"],
    'oracle-ee':     ["trace", "audit", "alert", "listener"],
    'oracle-se':     ["trace", "audit", "alert", "listener"],
    'oracle-se1':    ["trace", "audit", "alert", "listener"],
    'oracle-se2':    ["trace", "audit", "alert", "listener"],
    'sqlserver-ee':  ["error", "agent"],
    'sqlserver-ex':  ["error"],
    'sqlserver-se':  ["error", "agent"],
    'sqlserver-web': ["error", "agent"],
    'aurora':        ["audit", "error", "general", "slowquery"],
    'aurora-mysql':  ["audit", "error", "general", "slowquery"],
    'aurora-postgresql': ["postgresql", "upgrade"]
}

rule rds_YYYY {

    AWS::RDS::DBInstance {
        PARAMETERS.additionalLogs == /^[a-z: ;,-]+$/

        let engine := configuration.engine

        when configuration.dBInstanceStatus == "available"
             %ENGINE_LOGS CONTAINS_KEY %engine {
            configuration.enabledCloudwatchLogsExports == %ENGINE_LOGS.%engine

            #
            # Tags: [ { "Key": "..", "Value": "" } ]
            #
            # Object: {
            #    "a": ...,
            #    "b": ....
            # }
            #
            configuration.Tags.*.Key == /,,,,/
            configuration.Tags.*.Value == /.../

            configuration.Object.* == /,,,,/

            configuration.Tags /.+/

            configuration.Tags != null

            #
            # Tags: [ { ",,": "..." }, ... ]
            #
            configuration.Tags KEYS
            configuration.Tags.*.*
        }
    }



}
