# Language Syntax 

## Rule Block Statement

Language compromises of a set of discrete rules defined within a file. Each rule block has the following syntax 

<pre>
<b>rule</b> <em>rule_name</em> [<b>when</b> <em>conditions</em>] {
    <em>clauses</em>
    <em>assignments</em>
}
</pre>

Here, _rule_ keyword disgnates the start of a rule block. The keyword is followed by the *rule_name* that is a human 
readable name. When evaluating the rules file, the *rule_name* is displayed along with with status for the 
evaluation <b>PASS. FAIL or SKIP</b>. The rule name can be followed by optional conditions (_When_ guards) that act as 
a guard to determine if the rule is application for evaluation or must be skipped, a.k.a conditionally evaluated. 
We will go in depth about conditions later. 

The block contains a set of clauses in Conjunctive Normal Form. To simplify authoring clauses and provide a 
consistent interpretation model, the following rules apply 
1. each clause present on its own newline provides an implicit AND in CNF notation. 
2. Any clause joined with an "or" keyword represents a disjunction or OR clause with the next one. 

As an example

<pre>
<b>rule</b> <em>example</em> {

    <em>clause1</em>
    <em>clause2</em>
    
    <em>clause3</em> OR
    <em>clause4</em>
    
    <em>clause5</em> OR <em>clause6</em>
}
</pre>

represents ```clause1 AND clause2 AND (clause3 or clause4) AND (clause5 OR clause6)```

## Assignment Statement

A assignment allows for either literal values or queries to be referenced using a named variable. Assignments are scoped
at the guard file level or inside any block level statement like rule block, type block, when block etc. We will define
these later in this document. All assignment statements start with a <code><b>let</b></code> keyword.

Examples of assignments are shown below 

<pre><code>
# file scoped variables that can be referenced inside any blocks
# like rules, types, conditional block (when). This assigns 
# a map type to ENGINE_LOGS
<b>let ENGINE_LOGS</b> = {  
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

# This rule only applies when the configuration contains RDS
# based resource types.
rule check_rds_instance when resourceType == /AWS::RDS/ {

    # these are variable assignments that can take values from 
    # a query from incoming context. We have a local variable 
    # called engine within the check_rds_instance rule block 
    # scope
    <b>let engine = configuration.engine</b>
    
    # first checks if PARAMETERS section inside the incoming context
    # complies with expected names
    PARAMETERS.additionalLogs == /^[a-z: ;,-]+$/
    
    # conditionally evaluate checks for the RDS instance only if 
    # the instance's status was "available" and the engine 
    # type exists inside the ENGINE_LOGS set of engines we are 
    # interested in
    when configuration.dBInstanceStatus == "available"
         <b>%ENGINE_LOGS.%engine</b> EXISTS   # check if there is an entry for the engine
    {
        # ensure that the sinks for CW Logs based on the engine match 
        # the expected set of logs based on the engine type
        configuration.enabledCloudwatchLogsExports == <b>%ENGINE_LOGS.%engine</b> or 
        configuration.enabledCloudwatchLogsExports == PARAMETERS.additionalLogs
    }

}
</code></pre>
Variables can be referenced using ```%``` followed by their name, e.g. ```%engine``` or ```%ENGINE_LOGS```. Variables 
references are resolved from the inner most block scope upto to file scope for resolution. Variable assignments can 
shadow a reference from an out scope. 

<pre>
<code>
# This is file scope variable <b>engine</b> assigned a value of "aurora"
let engine = "aurora"

rule check_rds_instance when resourceType == /AWS::RDS/ {
    # This variable <b>engine</b> shadows the file scoped variable and is assigned from incoming 
    # context. During resolution this value is used in subsequent references within this scope. 
    # Within a given scope a variable can be assigned only once.
    let engine = configuration.engine
    
}

</code>
</pre>

## Clause Statements

Clauses are boolean expressions that evaluate to true or false expressed in CFN form. For detailed description of clause
statements read [Clauses](clause-RFC.md) document.

**Example Uses**

This example is a set of rules that are evaluated against an incoming JSON/YAML payload for CFN template. Here is template
against which the examples are written 

```yaml
Resources:
  RDSCluster:
    Type: 'AWS::RDS::DBCluster'
    Properties:
      MasterUsername: !Ref DBUsername
      MasterUserPassword: !Ref DBPassword
      DBClusterIdentifier: aurora-postgresql-cluster
      Engine: aurora-postgresql
      EngineVersion: '10.7'
      DeletionProtection: true
      BackupRetentionPeriod: 14
      DBClusterParameterGroupName: default.aurora-postgresql10
      EnableCloudwatchLogsExports:
        - postgresql
  RDSDBInstance1:
    Type: 'AWS::RDS::DBInstance'
    Properties:
      DBInstanceIdentifier: aurora-postgresql-instance1
      Engine: aurora-postgresql
      DBClusterIdentifier: !Ref RDSCluster
      PubliclyAccessible: 'true'
      DBInstanceClass: db.r4.large
  RDSDBInstance2:
    Type: 'AWS::RDS::DBInstance'
    Properties:
      DBInstanceIdentifier: aurora-postgresql-instance2
      Engine: aurora-postgresql
      DBClusterIdentifier: !Ref RDSCluster
      PubliclyAccessible: 'true'
      DBInstanceClass: db.r4.large
```

<pre><code>
#
# Check on Regional Aurora DBs
# 

#
# This first checks in the template contains Aurora DB cluster and instances. All the 
# other checks are contingent on this. If this FAILS to evaluate, then all
# other dependent checks are SKIPPED.
#
rule cfn_contains_rds_aurora_resources {
    
    #
    # We are using a predicate clause to check if there are indeed resources present 
    # inside the CFN template. See Query document for details
    #
    <b><em>resources.*[type == /AWS::RDS::DBCluster/] NOT EMPTY</em></b>
}

#
# check on DB cluster settings for aurora DB is compliant with always having backup 
# setup with a min of 7 days and CW logs are indeed enabled. We also need storage 
# encryption on by default
#
rule rds_aurora_clusters_checks when cfn_contains_rds_aurora_resources {    
    #
    # select all Aurora DB clusters in the template.
    #
    let aurora_dbs = resources.*[type == /AWS::RDS::DBCluster/]
    
    #
    # For each cluster selected checks for the all of these being set (with ANDs)
    # - Backup is >= 7 days
    # - deletion protection is enabled
    # - logs are enabled and is one of the provided
    # - storage encryption is on
    #
    <b><em>%aurora_dbs.BackupRetentionPeriod EXISTS
    %aurora_dbs.BackupRetentionPeriod >= 7
    %aurora_dbs.deletion_protection == true  # the tool must support casing differences for match. 
    %aurora_dbs.enable_cloudwatch_logs_exports IN 
        ["audit", error, general, "slowquery", "postgresql", "upgrade"]
    %aurora_dbs.StorageEncrypted == true</em></b>
}

#
# Check to see if there are DB instances configured that are 
#
rule check_aurora_db_instances_are_present {
    resources.*[ type == /RDS::DBInstance/ 
                 engine == /^aurora/        ] NOT EMPTY
}

#
# If Aurora DB instances do exist, then check that each instance is not 
# - publicly accessible 
# - must be either in one of these classes db.r4*, db.m*
#
rule check_aurora_db_instances when check_aurora_db_instances_are_present {
    let dbs = resources.*[ type == /RDS::DBInstance/ 
                            engine == /^aurora/        ]
    
    %dbs.PubliclyAccessible == false
    %db.DBInstanceClass IN [/^db\.r4/, /^db\.m/]
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

</code></pre>

