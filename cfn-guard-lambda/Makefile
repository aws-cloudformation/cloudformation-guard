UNAME_S := $(shell uname -s)
SYSTEM_RELEASE := $(shell cat /etc/system-release 2>/dev/null || echo 'Unknown')
AWS_CLI_VERSION := $(shell aws --version 2>&1 | sed 's/aws-cli\/\(.\).*/\1/')
project_name = cfn-guard-lambda
role_arn := ${CFN_GUARD_LAMBDA_ROLE_ARN}
request_payload_fail = '{ "template": "{\n    \"Resources\": {\n        \"NewVolume\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 100,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        },\n        \"NewVolume2\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 99,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        } }\n}",\
                     "ruleSet": "let require_encryption = true\nlet disallowed_azs = [us-east-1a,us-east-1b,us-east-1c]\n\nAWS::EC2::Volume AvailabilityZone NOT_IN %disallowed_azs\nAWS::EC2::Volume Encrypted != %require_encryption\nAWS::EC2::Volume Size == 101 |OR| AWS::EC2::Volume Size == 99\nAWS::IAM::Role AssumeRolePolicyDocument.Version == 2012-10-18\nAWS::EC2::Volume Lorem == true\nAWS::EC2::Volume Encrypted == %ipsum\nAWS::EC2::Volume AvailabilityZone != /us-east-.*/",\
                      "strictChecks": true}'

#======================================================================
# Request Payload Fail:
#======================================================================
# Template
#{"Resources": {
#  "NewVolume" : {
#    "Type" : "AWS::EC2::Volume",
#    "Properties" : {
#      "Size" : 100,
#      "Encrypted": true,
#      "AvailabilityZone" : "us-east-1b"
#    }
#  },
#  "NewVolume2" : {
#    "Type" : "AWS::EC2::Volume",
#    "Properties" : {
#    "Size" : 99,
#    "Encrypted": true,
#    "AvailabilityZone" : "us-east-1b"
#    }
#  }
#}

# Rule Set
# let require_encryption = true
# let disallowed_azs = [us-east-1a,us-east-1b,us-east-1c]

# AWS::EC2::Volume AvailabilityZone NOT_IN %disallowed_azs
# AWS::EC2::Volume Encrypted != %require_encryption
# AWS::EC2::Volume Size == 101 |OR| AWS::EC2::Volume Size == 99
# AWS::IAM::Role AssumeRolePolicyDocument.Version == 2012-10-18
# AWS::EC2::Volume Lorem == true
# AWS::EC2::Volume Encrypted == %ipsum
# AWS::EC2::Volume AvailabilityZone != /us-east-.*/

# Strict Checks
# true
#======================================================================


request_payload_pass = '{ "template": "{\n    \"Resources\": {\n        \"NewVolume\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 100,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        },\n        \"NewVolume2\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 99,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        } }\n}",\
                     "ruleSet": "let require_encryption = true",\
                      "strictChecks": true}'

#======================================================================
# Request Payload Pass
#======================================================================
# Template
# {"Resources": {
#  "NewVolume" : {
#    "Type" : "AWS::EC2::Volume",
#    "Properties" : {
#    "Size" : 100,
#    "Encrypted": true,
#    "AvailabilityZone" : "us-east-1b"
#    }
#  },
#  "NewVolume2" : {
#    "Type" : "AWS::EC2::Volume",
#    "Properties" : {
#      "Size" : 99,
#      "Encrypted": true,
#      "AvailabilityZone" : "us-east-1b"
#    }
#  }
#}

# Rule Set
# let require_encryption = true

# Strict Checks
# true
#======================================================================

request_payload_err = '{ "template": "{\n    \"Resources\": \n        \"NewVolume\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 100,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        },\n        \"NewVolume2\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 99,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        } }\n}",\
                     "ruleSet": "let require_encryption = true",\
                      "strictChecks": true}'

#======================================================================
# Request Payload Fail
#======================================================================
# Template
# {"Resources":   <== Missing '{'
#   "NewVolume" : {
#     "Type" : "AWS::EC2::Volume",
#     "Properties" : {
#       "Size" : 100,
#       "Encrypted": true,
#       "AvailabilityZone" : "us-east-1b"
#     }
#   },
#   "NewVolume2" : {
#     "Type" : "AWS::EC2::Volume",
#     "Properties" : {
#       "Size" : 99,
#       "Encrypted": true,
#       "AvailabilityZone" : "us-east-1b"
#     }
#   }
# }

# Rule Set
# let require_encryption = true

# Strict Checks
# true
#======================================================================

ifeq (${CFN_GUARD_LAMBDA_ROLE_ARN},)
    $(error You need to set the CFN_GUARD_LAMBDA_ROLE_ARN environment variable)
endif

ifeq ($(AWS_CLI_VERSION),)
    $(error You need to install and configure AWS CLI)
else ifneq ($(AWS_CLI_VERSION),1)
	aws_cli_parameters = --cli-binary-format raw-in-base64-out
endif

test: build
	aws lambda update-function-code --function-name $(project_name) --zip-file fileb://./lambda.zip
	$(MAKE) fail
	$(MAKE) pass
	$(MAKE) err

clean:
	@sh -c "if test -f bootstrap; then rm bootstrap; fi"
	@sh -c "if test -f lambda.zip; then rm lambda.zip; fi"

pre-reqs:
	rustup target add x86_64-unknown-linux-musl
    ifeq ($(UNAME_S),Linux)
		@echo This is a $(UNAME_S) machine...
        ifeq "$(shell echo '$(SYSTEM_RELEASE)' | grep -v 'Amazon Linux')" ""
			@echo Distro is Amazon Linux.
			sudo yum install -y jq gcc zip
        else ifeq "$(shell echo '$(SYSTEM_RELEASE)' | grep -v 'CentOS Linux')" ""
			@echo Distro is CentOS.
			sudo yum install -y jq gcc zip musl-devel
        else ifeq "$(shell echo '$(SYSTEM_RELEASE)' | grep -v 'Red Hat Enterprise Linux')" ""
			@echo Distro is RHEL.
			sudo yum install -y jq gcc zip musl-devel
        else ifeq "$(shell lsb_release -si)" "Ubuntu"
			@echo Distro is Ubuntu
			sudo apt install jq musl-dev musl-tools zip awscli build-essential
			sudo ln -s /usr/bin/musl-gcc /usr/local/bin/x86_64-linux-musl-gcc
        endif
    endif
    ifeq ($(UNAME_S),Darwin)
		brew install filosottile/musl-cross/musl-cross
		ln -s /usr/local/bin/x86_64-linux-musl-gcc /usr/local/bin/musl-gcc
		brew install jq
    endif


build: clean
	@echo This is a $(UNAME_S) machine...
	env PKG_CONFIG_ALLOW_CROSS=1 cargo build --release --target x86_64-unknown-linux-musl
	cp ../target/x86_64-unknown-linux-musl/release/$(project_name) ./bootstrap
	chmod +x bootstrap
	zip lambda.zip bootstrap

fail:
	aws lambda invoke --function-name $(project_name) --payload $(request_payload_fail) $(aws_cli_parameters) output.json
	cat output.json | jq '.'

pass:
	aws lambda invoke --function-name $(project_name) --payload $(request_payload_pass) $(aws_cli_parameters) output.json
	cat output.json | jq '.'

err:
	aws lambda invoke --function-name $(project_name) --payload $(request_payload_err) $(aws_cli_parameters) output.json
	cat output.json | jq '.'

install: build
	aws lambda create-function --function-name $(project_name) --handler doesnt.matter --zip-file fileb://./lambda.zip --runtime provided --role $(role_arn)  --environment Variables={RUST_BACKTRACE=1}
	$(MAKE) fail
	$(MAKE) pass
	$(MAKE) err

invoke: fail pass err

uninstall:
	aws lambda delete-function --function-name $(project_name)
