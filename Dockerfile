FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    gdb \
    libpcap-dev \
    pkg-config \
    git \
    vim \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# switch to root to install dependencies if needed
USER root
WORKDIR /home/developer

COPY --chown=developer:developer . /home/developer/ft_nmap

WORKDIR /home/developer/ft_nmap

# RUN make

ENTRYPOINT ["/bin/bash"]