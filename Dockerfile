# -----------------------------------------------------------------------------
# Stage 1: Build Binary
# -----------------------------------------------------------------------------
FROM golang:1.23-alpine AS builder

WORKDIR /build

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/krypton-mcp/krypton/internal/version.Version=v1.0.0" \
    -o /build/krypton ./cmd/krypton

# -----------------------------------------------------------------------------
# Stage 2: Minimal Distroless / Alpine Runtime
# -----------------------------------------------------------------------------
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -g 10001 -S krypton && \
    adduser -u 10001 -S krypton -G krypton

COPY --from=builder /build/krypton /usr/local/bin/krypton

USER krypton:krypton
WORKDIR /home/krypton

ENTRYPOINT ["/usr/local/bin/krypton"]
CMD ["start"]
