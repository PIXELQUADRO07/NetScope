# Build stage
FROM golang:1.26-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /netscope .

# Final stage
FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=builder /netscope /netscope
COPY --from=builder /app/web /web
WORKDIR /
ENTRYPOINT ["/netscope"]
