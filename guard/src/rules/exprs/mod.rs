///
/// Guard Language Syntax
///
/// ```
/// # Rule blocks
/// rule s3_secure {
///     AWS::S3::Bucket {
///         BucketName == /Encrypted/
///         BucketEncryption EXISTS
///     }
/// }
///
/// rule s3_secure_sse {
///     s3_secure
///     AWS::S3::Bucket {
///         let algo =
///             BucketEncryption.ServerSideEncryptionConfiguration.*.ServerSideEncryptionByDefault
///
///         %algo.Algorithm == "aws"
///     }
/// }
///
/// rule s3_secure_kms {
///     s3_secure
///     AWS::S3::Bucket {
///         let algo =
///             BucketEncryption.ServerSideEncryptionConfiguration.*.ServerSideEncryptionByDefault
///
///         %algo.Algorithm == "aws:kms",
///         %algo.KmsKeyArn IN [/kms-XXX/, 'kms-YYY/]
///     }
/// }
///
/// rule s3_is_secured {
///     s3_secure
///     s3_secure_kms or s3_secure_sse
/// }
///
/// # When guards
/// rule contains_production_tags {
///     let tags = resources.*.properties.Tags
///     %tags.key == /PROD/
///     %tags.value == /prod/
/// }
///
/// rule DDB_in_production when contains_production_tags {
///     # select all DDB tables
///     let ddb_tables = resources[type=/AWS::Dynamo/]
///     %ddb_tables.SSE_Specification.SSEEnabled == true or
///     %ddb_tables.KMSMasterKeyId EXISTS
/// }
/// ```
///
///

mod types;
mod scope;
mod evaluate;
mod helper;
mod query;

pub(crate) use types::*;
pub(crate) use scope::*;
pub(crate) use evaluate::*;

