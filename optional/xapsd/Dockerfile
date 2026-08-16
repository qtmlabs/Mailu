# syntax=docker/dockerfile-upstream:1.9.0

# apple push gateway image
FROM docker.io/library/golang:1.19.7-alpine AS build

ARG xapsd_repo=https://github.com/qtmlabs/dovecot-xaps-daemon.git
ARG xapsd_revision=8d0358a83cccd3a43232a334dee682b54f1234f4

ADD ${xapsd_repo}#${xapsd_revision} /build

WORKDIR /build

RUN go build -o ./ ./cmd/xapsd/

FROM base

ARG VERSION=local
LABEL version=$VERSION

COPY --from=build /build/xapsd /usr/sbin/

COPY /xapsd.yaml /
COPY /start.py /

RUN install -o mailu -g mailu -m 0700 -d /etc/xapsd

RUN echo $VERSION >/version

CMD /start.py
