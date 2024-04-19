FROM rust:latest

RUN apt-get update && \
  apt-get install -y sudo \
  zsh

ENV SHELL /bin/zsh
RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true
COPY .zshrc /root/.zshrc
CMD [ "source", "~/.zshrc" ]

RUN rustc --version

RUN cargo install cargo-nextest
