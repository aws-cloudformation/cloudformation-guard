AWS::EC2::Instance {
    let ALLOWED_GROUPS = [/sg-1245/, /sg-23/]
    securityGroups IN %ALLOWED_GROUPS
    keyName == "KeyName" or keyName == "Key2"
    availabilityZone in %ALLOWED_ZONES
    instanceType == %INS_TYPE
}
