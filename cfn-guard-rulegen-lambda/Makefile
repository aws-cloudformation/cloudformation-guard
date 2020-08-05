UNAME_S := $(shell uname -s)
AWS_CLI_VERSION := $(shell aws --version 2>/dev/null | sed 's/aws-cli\/\(.\).*/\1/')
project_name = cfn-guard-rulegen-lambda
role_arn := ${CFN_GUARD_LAMBDA_ROLE_ARN}


request_payload = '{ "template": "{\n    \"Resources\": {\n        \"NewVolume\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 100,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        },\n        \"NewVolume2\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 99,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        } }\n}"}'

#======================================================================
# Request Payload
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
#======================================================================

request_payload_err = '{ "template": "{\n    \"Resources\": \n        \"NewVolume\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 100,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        },\n        \"NewVolume2\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 99,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        } }\n}"}'

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
	$(MAKE) run
	$(MAKE) err

clean:
	@sh -c "if test -f bootstrap; then rm bootstrap; fi"
	@sh -c "if test -f lambda.zip; then rm lambda.zip; fi"

pre-reqs:
	rustup target add x86_64-unknown-linux-musl
    ifeq ($(UNAME_S),Linux)
		@echo This is a $(UNAME_S) machine...
        ifeq "$(shell lsb_release -si)" "Ubuntu"
			@echo Distro is Ubuntu
			sudo apt install jq musl-dev musl-tools zip awscli build-essential
			sudo ln -s /usr/bin/musl-gcc /usr/local/bin/x86_64-linux-musl-gcc
        else
			@echo Distro is CentOS. Support coming soon.
			# sudo yum install jq
			# sudo yum install equivalent of musl-dev musl-tools
			# sudo ln -s /usr/bin/musl-gcc /usr/local/bin/x86_64-linux-musl-gcc
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
	cp target/x86_64-unknown-linux-musl/release/$(project_name) ./bootstrap
	chmod +x bootstrap
	zip lambda.zip bootstrap

run:
	aws lambda invoke --function-name $(project_name) --payload $(request_payload) $(aws_cli_parameters) output.json
	cat output.json | jq '.'

err:
	aws lambda invoke --function-name $(project_name) --payload $(request_payload_err) $(aws_cli_parameters) output.json
	cat output.json | jq '.'

install: build
	aws lambda create-function --function-name $(project_name) --handler doesnt.matter --zip-file fileb://./lambda.zip --runtime provided --role $(role_arn)  --environment Variables={RUST_BACKTRACE=1}
	$(MAKE) run
	$(MAKE) err

invoke: run err

uninstall:
	aws lambda delete-function --function-name $(project_name)
