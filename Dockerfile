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
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go \
               google.golang.org/grpc/cmd/protoc-gen-go-grpc && \
    go generate -v tools.go && \
    CGO_ENABLED=0 go build -v -ldflags="-s -w" -o /usr/bin/cacheroach .

# Create a single-binary docker image, including a set of core CA
# certificates so that we can call out to any external APIs.
FROM scratch AS cacheroach
WORKDIR /data/
ENTRYPOINT ["/usr/bin/cacheroach"]
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/bin/cacheroach /usr/bin/

# This is a default configuration for Google Cloud Run. It assumes that
# you have the secret manager API installed. A named secret should
# contain a tar.gz file that has files with the @filename values below.
#
# The OIDC integration is optional, but if you're already deploying
# into GCR, you need only to create credentials for an OAuth2 webapp.
FROM cacheroach AS cloudrun
# Expect $PORT from Cloud Run environment.
ENV CACHE_MEMORY="128" \
    CONNECT="@connect" \
    GCLOUD_SECRET_NAME="" \
    HMAC="@hmac" \
    OIDC_CLIENT_ID="@oidc_client_id" \
    OIDC_CLIENT_SECRET="@oidc_client_secret" \
    OIDC_DOMAINS="cockroachlabs.com" \
    OIDC_ISSUER="https://accounts.google.com"
ENTRYPOINT [ \
  "/usr/bin/cacheroach", \
  "start", \
  "--assumeSecure", \
  "--bindAddr", ":$PORT", \
  "--cacheMemory", "$CACHE_MEMORY", \
  "--connect", "$CONNECT", \
  "--oidcClientID", "$OIDC_CLIENT_ID", \
  "--oidcClientSecret", "$OIDC_CLIENT_SECRET", \
  "--oidcDomains", "$OIDC_DOMAINS", \
  "--oidcIssuer", "$OIDC_ISSUER", \
  "--signingKey", "$HMAC" \
]

# Set a default target for e.g. DockerHub builds.
FROM cacheroach