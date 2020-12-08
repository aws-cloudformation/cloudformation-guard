# Query 

A query represents an access to extract views of data from a structured data (like JSON). The query allows for 
traversal of the hierarchy using a simple dotted notation with support for predicate clauses for filtering down selections. 
The query permits selecting all elements in a collection or selecting a particular indexed element.

Here are example queries  
<pre>
   BucketName
   configuration.containerDefinitions.*.image
   block_device_mappings[*].device_name
   resources.*[type == "AWS::RDS::DBCluster"].properties
   %aurora_dbs.BackupRetentionPeriod
</pre>

## Understanding the syntax

All queries provide a path dotted notation for traversal. Each part is matched with the corresponding "key" in the 
structured data. We will illustrate this with an example below. The JSON below is a configuration sample for 
AWS::S3::Bucket type.

```json
  {
    "BucketName": "This-Is-Encrypted",
    "BucketEncryption": {
      "ServerSideEncryptionConfiguration": [
        {
          "ServerSideEncryptionByDefault": {
            "SSEAlgorithm": "aws:kms",
            "KMSMasterKeyID": "kms-xxx-1234"
          }
        },
        {
          "ServerSideEncryptionByDefault": {
            "SSEAlgorithm": "aws:kms",
            "KMSMasterKeyID": "kms-yyy-1234"
          }
        },
        {
          "ServerSideEncryptionByDefault": {
            "SSEAlgorithm": "AES256"
          }
        }
      ]
    }
  }
```

Here are some sample queries with extracted values that match against that query.

<ol>
<li> <code>BucketName</code> query will provide match against <code>"BucketName"</code> key and retrieves the value <code>"This-Is-Encrypted"</code></li>
<li> <code>BucketEncryption.ServerSideEncryptionConfiguration[*].ServerSideEncryptionByDefault</code> query matches against the path 
show in <b><em>italic bold</em></b> <p></p>
<pre><code> {
    "BucketName": "This-Is-Encrypted",
    <b><em>"BucketEncryption"</em></b>: {
      <b><em>"ServerSideEncryptionConfiguration"</em></b>: [ 
        <b><em>* matches for all indices in this collection</em></b> 
        {
          <b><em>"ServerSideEncryptionByDefault"</em></b>: {
            "SSEAlgorithm": "aws:kms",
            "KMSMasterKeyID": "kms-xxx-1234"
          }
        },
        {
          <b><em>"ServerSideEncryptionByDefault"</em></b>: {
            "SSEAlgorithm": "aws:kms",
            "KMSMasterKeyID": "kms-yyy-1234"
          }
        },
        {
          <b><em>"ServerSideEncryptionByDefault"</em></b>: {
            "SSEAlgorithm": "AES256"
          }
        }
      ]
    }
  }
</code></pre>
yields the following values <p></p>
<pre><code>[
    {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "kms-xxx-1234"
    },
    {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "kms-yyy-1234"
    },
    {
      "SSEAlgorithm": "AES256"
    }
]
</code></pre>
</li>
</ol>

## Predicate Filters

The query support predicate filters that also use the same CNF form to select specific instances within a collection. 
Extending the AWS::S3::Bucket use case one can select only bucket encryption that match <code>SSEAlgorithm</code> for 
```aws:kms```. The query is written as follows <code>BucketEncryption.ServerSideEncryptionConfiguration[*].ServerSideEncryptionByDefault[ SSEAlgorithm == "aws:kms" ]</code>. They query will then yields 
<pre><code>[
    {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "kms-xxx-1234"
    },
    {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "kms-yyy-1234"
    }
]
</code></pre>

If a predicate filter is used on a non-collection then it will be an error at runtime.

### Can filters be combined?

Yes. Predicate filter supports the same CNF format to perform filtering with some restrictions. Predicate filters can only
access "keys" inside the structure for LHS of the comparison. They do not support assignments statements. Otherwise 
everything in expressing the clause applies here. Here is an example query on the CloudFormation template 

```yaml
Resources:
  DBCluster:
    Type: "AWS::DocDB::DBCluster"
    DeletionPolicy: Delete
    Properties:
      DBClusterIdentifier: !Ref DBClusterName
      MasterUsername: !Ref MasterUser
      MasterUserPassword: !Ref MasterPassword
      EngineVersion: 4.0.0

  DBCluster2:
    Type: "AWS::DocDB::DBCluster"
    DeletionPolicy: Delete
    Properties:
      DBClusterIdentifier: !Ref DBClusterName
      MasterUsername: !Ref MasterUser
      MasterUserPassword: !Ref MasterPassword
      EngineVersion: 3.8.0


  DBInstance:
    Type: "AWS::DocDB::DBInstance"
    Properties:
      DBClusterIdentifier: !Ref DBCluster
      DBInstanceIdentifier: !Ref DBInstanceName
      DBInstanceClass: !Ref DBInstanceClass
    DependsOn: DBCluster
```
<ol>
<li><b>Select all resources of type DBCluster</b><code>resources.*[type == /DocDB::DBCluster/]</code>. This query yields 
<pre><code>
-   Type: "AWS::DocDB::DBCluster"
    DeletionPolicy: Delete
    Properties:
      DBClusterIdentifier: !Ref DBClusterName
      MasterUsername: !Ref MasterUser
      MasterUserPassword: !Ref MasterPassword
      EngineVersion: 4.0.0
-   Type: "AWS::DocDB::DBCluster"
    DeletionPolicy: Delete
    Properties:
      DBClusterIdentifier: !Ref DBClusterName
      MasterUsername: !Ref MasterUser
      MasterUserPassword: !Ref MasterPassword
      EngineVersion: 3.8.0
</code></pre> 
</li>
<li><b>Select all resources of type DocDB cluster with engine version > 4.0</b>
<pre><code>
resources.*[ type == /DocDB::DBCluster/ 
             properties.engine_version > "4.0" ]</code></pre>
this yields the result <p></p>
<pre><code>
-   Type: "AWS::DocDB::DBCluster"
    DeletionPolicy: Delete
    Properties:
      DBClusterIdentifier: !Ref DBClusterName
      MasterUsername: !Ref MasterUser
      MasterUserPassword: !Ref MasterPassword
      EngineVersion: 4.0.0
</code></pre>
</li>
<li><b>Select all resources of type DocDB or Aurora cluster</b>
<pre><code>
resources.*[ type == /RDS::DBCluster/ OR
             type == /DocDB::DBCluster/ ]
</code></pre>
yields the result as there are no aurora clusters in the template <p></p>
<pre><code>
-   Type: "AWS::DocDB::DBCluster"
    DeletionPolicy: Delete
    Properties:
      DBClusterIdentifier: !Ref DBClusterName
      MasterUsername: !Ref MasterUser
      MasterUserPassword: !Ref MasterPassword
      EngineVersion: 4.0.0
</code></pre>
</li>
</ol>

