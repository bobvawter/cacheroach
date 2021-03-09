FROM golang:1.16 AS builder
# We'll add protoc to the builder as a cacheable stage, since it
# won't change all that often.
ARG PROTOVER=3.14.0
ARG PROTOARCH=linux-x86_64
RUN apt-get update && \
    apt-get -y install curl graphviz unzip && \
    curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOVER/protoc-$PROTOVER-$PROTOARCH.zip && \
    unzip protoc-$PROTOVER-$PROTOARCH.zip -d /usr/
WORKDIR /tmp/compile
COPY . .
RUN go mod download && \
    go get google.golang.org/protobuf/cmd/protoc-gen-go \
           google.golang.org/grpc/cmd/protoc-gen-go-grpc && \
    go generate -v tools.go && \
    CGO_ENABLED=0 go build -v -ldflags="-s -w" -o /usr/bin/cacheroach .

FROM scratch
WORKDIR /data/
ENTRYPOINT ["/usr/bin/cacheroach"]
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/bin/cacheroach /usr/bin/
