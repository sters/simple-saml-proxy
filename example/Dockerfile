FROM golang:1.24 AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o simple-saml-proxy ./cmd/simple-saml-proxy

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/simple-saml-proxy .

# Create directory for certificates
RUN mkdir -p /certs

EXPOSE 8080

ENTRYPOINT ["./simple-saml-proxy"]

