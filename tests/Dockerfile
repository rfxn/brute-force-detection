ARG BASE_IMAGE=bfd-base-debian12
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Copy BFD source and tests — files/ at /opt/files/ so PROJECT_ROOT=/opt
COPY files/ /opt/files/
COPY importconf /opt/importconf
COPY bfd-watch.init /opt/bfd-watch.init
COPY bfd-watch.service /opt/bfd-watch.service
COPY bfd.service /opt/bfd.service
COPY cron /opt/cron
COPY cron.daily /opt/cron.daily
COPY install.sh /opt/install.sh
COPY uninstall.sh /opt/uninstall.sh
COPY README /opt/README
COPY CHANGELOG /opt/CHANGELOG
COPY COPYING.GPL /opt/COPYING.GPL
COPY logrotate.d.bfd /opt/logrotate.d.bfd
COPY bfd.timer /opt/bfd.timer
COPY bfd.1 /opt/bfd.1
COPY bfd.bash-completion /opt/bfd.bash-completion
COPY tests/ /opt/tests/

WORKDIR /opt/tests
CMD ["bats", "--formatter", "tap", "/opt/tests/"]
