.PHONY: cfn-guard cfn-guard-rulegen

default:
	cargo build --verbose --release; cp target/release/cfn-guard ./bin

cfn-guard:
	cd cfn-guard; make

cfn-guard-rulegen:
	cd cfn-guard-rulegen; make

cfn-guard-lambda_install:
	cd cfn-guard-lambda; make install

cfn-guard-lambda_update:
	cd cfn-guard-lambda; make test

clean:
	if test -f cloudformation-guard.tar.gz; then rm cloudformation-guard.tar.gz; fi

test:
	cargo test --verbose

release_with_binaries: clean cfn-guard cfn-guard-rulegen
	tar czvf cloudformation-guard.tar.gz -X Exclude.txt .

release: clean
	tar czvf cloudformation-guard.tar.gz -X Exclude.txt .
