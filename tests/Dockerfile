FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    coreutils \
    sed \
    grep \
    mawk \
    gzip \
    util-linux \
    procps \
    iproute2 \
    hostname \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install bats and helpers from tarballs
RUN mkdir -p /opt/bats && \
    wget -qO- https://github.com/bats-core/bats-core/archive/refs/tags/v1.11.0.tar.gz | \
      tar xz -C /opt/bats --strip-components=1 && \
    /opt/bats/install.sh /usr/local && \
    mkdir -p /usr/local/lib/bats/bats-support && \
    wget -qO- https://github.com/bats-core/bats-support/archive/refs/tags/v0.3.0.tar.gz | \
      tar xz -C /usr/local/lib/bats/bats-support --strip-components=1 && \
    mkdir -p /usr/local/lib/bats/bats-assert && \
    wget -qO- https://github.com/bats-core/bats-assert/archive/refs/tags/v2.1.0.tar.gz | \
      tar xz -C /usr/local/lib/bats/bats-assert --strip-components=1

# Copy BFD source and tests
COPY files/ /opt/bfd/files/
COPY importconf /opt/bfd/importconf
COPY bfd-watch.init /opt/bfd/bfd-watch.init
COPY bfd-watch.service /opt/bfd/bfd-watch.service
COPY bfd.service /opt/bfd/bfd.service
COPY cron /opt/bfd/cron
COPY cron.daily /opt/bfd/cron.daily
COPY install.sh /opt/bfd/install.sh
COPY uninstall.sh /opt/bfd/uninstall.sh
COPY bfd.1 /opt/bfd/bfd.1
COPY tests/ /opt/bfd/tests/

WORKDIR /opt/bfd/tests

# Default: run all tests with tap formatter
CMD ["bats", "--formatter", "tap", "/opt/bfd/tests/"]
