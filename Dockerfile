# copied from https://github.com/tmknight/docker-privoxy/blob/main/docker/alpine/privoxy.dockerfile
ARG ALPINE_VER
FROM alpine:${ALPINE_VER}
ARG ALPINE_VER
EXPOSE 8080
## Ensure alpine updated & add required packages for privoxy
RUN apk update \
  && apk upgrade --no-cache --no-progress --purge \
  && apk add --update --upgrade --no-cache --no-progress --purge --quiet \
  alpine-sdk \
  curl \
  jq \
  openssl \
  openssl-dev \
  bash \
  go \
  util-linux-misc
CMD /usr/local/bin/kidsproxy
COPY ./*.go /build/
COPY ./go.sum /build/
COPY ./go.mod /build/
WORKDIR /build
RUN go build . && cp kidsproxy /usr/local/bin/ && rm -rf /build
