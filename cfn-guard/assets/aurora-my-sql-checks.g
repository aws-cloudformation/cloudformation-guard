rule aurora_mysql_backtrack_enabled {
    # rule parameter validation
    PARAMETERS.BacktrackWindowInSeconds > 0.0
    PARAMETERS.BacktrackWindowInSeconds <= 259200.0 # 72 hours

    AWS::RDS::DBCluster {
        configuration.engine IN ["aurora", "aurora-mysql"]
        configuration.backtrackWindow >= PARAMETERS.BacktrackWindowInSeconds
    }
}