# syntax=docker/dockerfile-upstream:1.9.0

# dovecot image
FROM base AS system

ARG VERSION
LABEL version=$VERSION

RUN set -euxo pipefail \
  ; apk add --no-cache 'dovecot<2.4' dovecot-lmtpd dovecot-pigeonhole-plugin dovecot-pop3d dovecot-submissiond rspamd-client dovecot-fts-flatcurve \
  ; mkdir /var/lib/dovecot

FROM system AS build

ARG xaps_plugin_repo=https://github.com/qtmlabs/dovecot-xaps-plugin.git
ARG xaps_plugin_revision=29a2538b6ae407498e47ac75ffee9198572e8471

RUN apk add --no-cache build-base ninja cmake dovecot-dev

ADD ${xaps_plugin_repo}#${xaps_plugin_revision} /build

WORKDIR /build

RUN set -euxo pipefail \
  ; cmake -G Ninja -B build -D CMAKE_BUILD_TYPE=Release \
  ; cmake --build build \
  ; DESTDIR=/install cmake --install build

FROM system

COPY --from=build /install/ /

COPY conf/ /conf/
COPY start.py /

RUN echo $VERSION >/version

# EXPOSE 110/tcp 143/tcp 993/tcp 4190/tcp 2525/tcp
HEALTHCHECK CMD kill -0 `cat /run/dovecot/master.pid`

VOLUME ["/mail"]

CMD /start.py
