rule s3_encrypted_buckets {
    AWS::S3::Bucket {
        BucketName == /Encrypted/
        BucketEncryption != null
    }
}

rule s3_with_kms {
    s3_encrypted_buckets
    AWS::S3::Bucket {
        let algo := BucketEncryption.ServerSideEncryptionConfiguration.*.ServerSideEncryptionByDefault
        %algo.SSEAlgorithm == "aws:kms"
        %algo.KMSMasterKeyID in [/kms-xxx/, /kms-yyy/]
        # algo := BucketEncryption.ServerSideEncryptionConfiguration
        # %algo.*.*.SSEAlgorithm == "aws:kms"
        # %algo.*.*.KMSMasterKeyID in [/kms-xxx/, /kms-yyy/]
    }
}

