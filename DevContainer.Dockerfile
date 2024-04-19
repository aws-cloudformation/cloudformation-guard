FROM rust:latest

RUN echo "alias gval='cargo run --bin cfn-guard validate'" >> ~/.bashrc
RUN echo "alias gtest='cargo run --bin cfn-guard test'" >> ~/.bashrc
RUN echo "alias gparse='cargo run --bin cfn-guard parse-tree'" >> ~/.bashrc
RUN echo "alias cb='cargo build'" >> ~/.bashrc
RUN echo "alias ct='cargo nextest run'" >> ~/.bashrc
RUN echo "alias cn='cargo +nightly'" >> ~/.bashrc

CMD [ "source", "~/.bashrc" ]

RUN rustc --version

RUN cargo install cargo-nextest