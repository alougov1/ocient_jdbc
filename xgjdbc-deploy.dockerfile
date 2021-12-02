FROM ubuntu:20.04 AS xgjdbc-deploy

RUN apt update && DEBIAN_FRONTEND="noninteractive" apt install -y autoconf automake libtool curl wget make g++ unzip openjdk-13-jdk maven python3 gpg openssh-client sshpass zlib1g-dev

RUN wget https://github.com/bazelbuild/bazel/releases/download/4.2.1/bazel_4.2.1-linux-x86_64.deb

RUN dpkg -i bazel_4.2.1-linux-x86_64.deb

ENV JAVA_HOME=/usr/lib/jvm/java-13-openjdk-amd64
ENV GPG_TTY=$(tty)
ENV IN_XGJDBC_DOCKER_CONTAINER=True