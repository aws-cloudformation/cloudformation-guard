UNAME_S := $(shell uname -s)
project_name = cfn-guard-rulegen-lambda
role_arn := ${CFN_GUARD_LAMBDA_ROLE_ARN}
template='{"template": "{\n \"Resources\": {\n \"NewVolume\" : {\n \"Type\" : \"AWS::EC2::Volume\",\n \"Properties\" : {\n \"Size\" : 100,\n \"Encrypted\": true,\n \"AvailabilityZone\" : \"us-east-1b\"\n }\n },\n \"NewVolume2\" : {\n \"Type\" : \"AWS::EC2::Volume\",\n \"Properties\" : {\n \"Size\" : 99,\n \"Encrypted\": true,\n \"AvailabilityZone\" : \"us-east-1b\"\n }\n } }\n}"}'

ifeq (${CFN_GUARD_LAMBDA_ROLE_ARN},)
    $(error You need to set the CFN_GUARD_LAMBDA_ROLE_ARN environment variable)
endif

test: build
	aws lambda update-function-code --function-name $(project_name) --zip-file fileb://./lambda.zip
	aws lambda invoke --function-name $(project_name) --payload $(template) output.json
	cat output.json | jq '.'

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
			@echo Distro is CentOS
			sudo yum install jq
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

install: build
	aws lambda create-function --function-name $(project_name) --handler doesnt.matter --zip-file fileb://./lambda.zip --runtime provided --role $(role_arn)  --environment Variables={RUST_BACKTRACE=1}
	aws lambda invoke --function-name $(project_name) --payload $(template) output.json
	cat output.json | jq '.'

invoke:
	aws lambda invoke --function-name $(project_name) --payload $(template) output.json
	cat output.json | jq '.'

uninstall:
	aws lambda delete-function --function-name $(project_name)
