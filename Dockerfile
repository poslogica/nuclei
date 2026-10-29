ARG ALPINE_BASE=alpine:latest
ARG GO_BASE=golang:1.27-alpine

# Build
FROM ${GO_BASE} AS builder

RUN apk add build-base
WORKDIR /app
COPY . /app
RUN make verify
RUN make build

# Release
FROM ${ALPINE_BASE}

RUN apk add --no-cache bind-tools chromium ca-certificates
COPY --from=builder /app/bin/nuclei /usr/local/bin/

ENTRYPOINT ["nuclei"]
