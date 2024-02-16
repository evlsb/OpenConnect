FROM ubuntu:jammy

COPY scripts/ /opt/src/scripts/
COPY src/ocserv_init /etc/init.d/ocserv
COPY src/ocserv/* /etc/ocserv/

RUN /bin/bash /opt/src/scripts/build.sh
