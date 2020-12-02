## CloudFormation Use Cases

This document demonstrates how cfn-guard provides a general tool for evaluating CloudFormation templates for inspection 
and assertions on what can be configured and not configured for various resources. It can performs checks against both 
JSON and YAML form. Here are some of use cases that we can support. 

### Check that all stateful resources have DeletionPolicy as Retain

```
rule cfn_contains_stateful_resources {
    resources.*[type IN [/AWS::RDS/, /AWS::DynamoDB/, /AWS::SQS/]]
}

rule deletion_policy_is_set when cfn_contains_stateful_resources {
    let resources = resources.*[type IN [/AWS::RDS/, /AWS::DynamoDB/, /AWS::SQS/]]

    %resources.DeletionPolicy EXISTS 
    %resources.DeletionPolicy IN ["Retain", "Snapshot"] # the later is not RDS
}
```

### Check that all resources have tags present

```
rule cfn_all_resources_have_tags {
    let tags = resources.*.properties.tags

    %tags EXITS 
    %tags NOT EMPTY
}
``` 

### Check that all RDS Aurora instances have backup retention, CWL and Storage encryption on 

```
#
# Regional Aurora DBs
# 
rule cfn_contains_rds_aurora_resources {
    resources.*[type == /AWS::RDS::DBCluster/] NOT EMPTY
}

rule rds_aurora_clusters_checks when cfn_contains_rds_aurora_resources {
    let aurora_dbs = resources.*[type == /AWS::RDS::DBCluster/]
    
    %aurora_dbs.BackupRetentionPeriod EXISTS
    %aurora_dbs.BackupRetentionPeriod >= 7
    %aurora_dbs.DeletionProtection == true
    %aurora_dbs.EnableCloudwatchLogsExports IN 
        ["audit", error, general, "slowquery", "postgresql", "upgrade"]
    %aurora_dbs.StorageEncrypted == true
}

#
# Global cross regional Aurora clusters
#
rule cfn_contains_rds_aurora_global_resources {
    resources.*[type == /AWS::RDS::GlobalCluster/] NOT EMPTY
}

#
# Check global cluster setup is done right
#
rule rds_aurora_global_checks when cfn_contains_rds_aurora_global_resources {
    let global_dbs = resources.*[type==/AWS::RDS::GlobalCluster/]

    %global_dbs.DeletionProtection == true
    %global_dbs.StorageEncrypted == true
    
}

```
 