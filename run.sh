#!/bin/bash


PLATFORM="linux/amd64" # linux/arm64
TARGET="x86_64-unknown-linux-musl" # aarch64-unknown-linux-gnu

docker run -it -d \
  --platform "${PLATFORM}" \
  --rm --user "$(id -u)":"$(id -g)" \
  -v "${PWD}":/usr/src/myapp -w /usr/src/myapp/guard-lambda rust:latest
  #ls -lsa && cargo build --release --target "${TARGET}"