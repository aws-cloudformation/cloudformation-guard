AWS::ACM::Certificate {
    # assign to local variable 
    # rules translated from config's managed rules 
    # 
    let config := configuration
    
    # check if version for version match
    # TODO support auto conversion to perform version >= 1.3
    version == "1.3"


    # https://code.amazon.com/packages/AwsFalconPythonManagedRules/blobs/mainline/--/src/ACM_CERTIFICATE_AUTHORITY_CHECK.py 
    # use of snake case still evaluates correctly from incoming context
    %config.certificate_arn == /arn:[\w+=\/,.@-]+:[\w+=\/,.@-]+:[\w+=\/,.@-]*:[0-9]*:[\w+=,.@-]+(\/[\w+=,.@-]+)*/
    %config.certificate_arn IN %RULE_PARAMETERS.CertificateAuthorityArns

    # https://code.amazon.com/packages/AwsFalconPythonManagedRules/blobs/mainline/--/src/ACM_TRUSTED_CERTIFICATE_ISSUER.py 
    %config.issuer == /\b\w{1,64}$/
    %config.issuer IN %RULE_PARAMETERS.TrustedIssuers
}
