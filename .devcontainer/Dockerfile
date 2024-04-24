FROM rust:latest

RUN apt-get update
RUN apt-get install zsh -y
RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true

COPY .bashrc /root/.bashrc
RUN bash -c "source ~/.bashrc"

COPY .zshrc /root/.zshrc
RUN zsh -c "source ~/.zshrc"

RUN rustc --version
RUN cargo install cargo-nextest
