FROM quay.io/centos/centos:stream8

MAINTAINER Colin Stubbs <cstubbs@find-me-on-the-inter.nets>

ENV FORCEPOINT_HOST=$FORCEPOINT_HOST
ENV FORCEPOINT_USERNAME=$FORCEPOINT_USERNAME
ENV FORCEPOINT_PASSWORD=$FORCEPOINT_PASSWORD

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint
COPY forcepoint/ /home/forcepoint

RUN adduser -u 1000 -m forcepoint && \
  chown -Rv forcepoint:forcepoint /home/forcepoint && \
  chmod 0644 /home/forcepoint/*.* && \
  chmod 0755 /usr/local/bin/docker-entrypoint && \
  dnf -y install epel-release && \
  dnf -y install glibc-langpack-en perl perl-PAR perl-XML-Parser perl-XML-XPath perl-Text-CSV_XS && \
  dnf clean all && \
  rm -rfv /var/cache/dnf/*

USER forcepoint
ENTRYPOINT /usr/local/bin/docker-entrypoint
