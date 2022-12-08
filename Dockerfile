# syntax = docker/dockerfile:1.3
FROM --platform=linux/amd64 golang:1.19 AS build

WORKDIR /go/src/github.com/mccutchen/go-httpbin

COPY . .

RUN --mount=type=cache,id=gobuild,target=/root/.cache/go-build \
    make build buildtests

FROM --platform=linux/amd64 ubuntu:20.04 

COPY --from=build /go/src/github.com/mccutchen/go-httpbin/dist/go-httpbin* /bin/

EXPOSE 8080
ENV OTEL_SERVICE_NAME=go-httpbin
CMD ["/bin/go-httpbin"]
