build-CloudFormationGuardLambda:
# installing rust every time you build is not great, but it's better than having
# to install a toolchain yourself. In most cases builds will be infrequent.
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
	source ${HOME}/.cargo/env && rustup target add x86_64-unknown-linux-musl
	source ${HOME}/.cargo/env && cd guard-lambda && cargo build --release --target x86_64-unknown-linux-musl
	cp -r /tmp/samcli/scratch/target/x86_64-unknown-linux-musl/release/cfn-guard-lambda $(ARTIFACTS_DIR)/bootstrap
