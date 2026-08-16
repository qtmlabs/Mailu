# syntax=docker/dockerfile-upstream:1.4.3

# apple push gateway image
FROM docker.io/library/golang:1.19.7-alpine AS build

RUN apk add --no-cache git

RUN git clone https://github.com/freswa/dovecot-xaps-daemon.git /build

WORKDIR /build

RUN git checkout abce2f14cf1b5afa56329ebb4d923c9c2aebdfe3

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
