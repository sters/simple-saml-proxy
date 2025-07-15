FROM golang:1.24 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o simple-saml-proxy ./cmd/simple-saml-proxy

FROM debian:stable-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
WORKDIR /root/

COPY --from=builder /app/simple-saml-proxy .

# Add health check endpoint
EXPOSE 8080
CMD ["./simple-saml-proxy"]