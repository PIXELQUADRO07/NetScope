# Build stage
FROM golang:1.26-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /netscope .

# Final stage
FROM scratch
COPY --from=builder /netscope /netscope
ENTRYPOINT ["/netscope"]
