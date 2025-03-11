FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm

RUN apt-get update \
    && apt-get install -y openssh-server git \
    && apt-get clean \
    && mkdir /var/run/sshd \
    && echo root:password | chpasswd \
    && sed -i 's/#\?PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

WORKDIR /root
COPY --from=builder /build/target/release/tiny-git .

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
