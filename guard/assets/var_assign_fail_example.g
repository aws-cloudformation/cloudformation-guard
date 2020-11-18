# assign from incoming context to variable, this is the
# support that Config needed
let latest := latest
let zones  := allowedZones

AWS::EC2::Instance imageId == %latest
AWS::EC2::Instance availabilityZone in %zones

