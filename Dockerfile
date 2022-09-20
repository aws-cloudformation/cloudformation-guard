####################################################################################################
## Build Container
####################################################################################################
FROM rust:latest AS builder

RUN rustup target add x86_64-unknown-linux-musl
RUN apt update && apt install -y musl-tools musl-dev

WORKDIR /usr/src/cloudformation-guard

COPY . .

RUN cargo build --target x86_64-unknown-linux-musl --release

####################################################################################################
## Execution container
####################################################################################################
FROM alpine

WORKDIR /usr/src/cloudformation-guard

# Copy our build
COPY --from=builder /usr/src/cloudformation-guard/target/x86_64-unknown-linux-musl/release/cfn-guard .

# Copy any additional files
COPY --from=builder /usr/src/cloudformation-guard/test-files/data-dir ./data-dir
COPY --from=builder /usr/src/cloudformation-guard/test-files/rules-dir ./rules-dir

CMD [ "./cfn-guard", "--help" ]