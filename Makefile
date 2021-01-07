.PHONY: cfn-guard cfn-guard-rulegen

cfn-guard:
	cargo build --release; cp target/release/cfn-guard ./bin

cfn-guard-rulegen:
	cargo build --release; cp target/release/cfn-guard-rulegen ./bin

cfn-guard-lambda_install:
	cd cfn-guard-lambda; make install

cfn-guard-lambda_update:
	cd cfn-guard-lambda; make test

clean:
	if test -f cloudformation-guard.tar.gz; then rm cloudformation-guard.tar.gz; fi

test:
	cargo test

release_with_binaries: clean cfn-guard cfn-guard-rulegen
	tar czvf cloudformation-guard.tar.gz -X Exclude.txt .

release: clean
	tar czvf cloudformation-guard.tar.gz -X Exclude.txt .

build-CfnGuardFunction:
	cd cfn-guard-lambda; CFN_GUARD_LAMBDA_ROLE_ARN='not-used' make build
	cp cfn-guard-lambda/bootstrap $(ARTIFACTS_DIR)

build-CfnGuardRulegenFunction:
	cd cfn-guard-rulegen-lambda; CFN_GUARD_LAMBDA_ROLE_ARN='not-used' make build
	cp cfn-guard-rulegen-lambda/bootstrap $(ARTIFACTS_DIR)
