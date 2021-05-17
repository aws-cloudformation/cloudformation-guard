#!/bin/bash

# Enable the required Rust flags to generate the coverage files
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off"

# grcov requires rust nightly at this time
cargo +nightly test

# generate the html report
grcov ./target/debug/ -s . -t html --llvm --branch --ignore-not-existing -o ./target/debug/coverage/

