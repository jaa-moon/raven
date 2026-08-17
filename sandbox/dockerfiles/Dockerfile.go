FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o raven_target . || true
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/raven_target .
EXPOSE 8080
CMD ["./raven_target"]
