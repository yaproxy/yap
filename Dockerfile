FROM golang:1.18-alpine as builder

RUN apk add --no-cache --update ca-certificates git
ADD . /go/src/github.com/yaproxy/yap/

ENV CGO_ENABLED=0
RUN cd /go/src/github.com/yaproxy/yap/ && \
    go mod download && \
    go build -o yap cmd/main.go

FROM alpine:3.16

RUN apk add --no-cache --update ca-certificates && \
    mkdir /yap

COPY --from=builder /go/src/github.com/yaproxy/yap/yap /usr/local/bin/
WORKDIR /yap

CMD ["/usr/local/bin/yap"]
