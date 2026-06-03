FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /agent ./cmd/agent

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /agent /usr/local/bin/agent
COPY config.yaml /etc/kirov/agent/config.yaml
RUN adduser -D -H -u 1000 kirov
USER kirov
ENTRYPOINT ["/usr/local/bin/agent"]
CMD ["--config", "/etc/kirov/agent/config.yaml"]
