FROM golang:1.24 AS builder

# Install dependencies
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod tidy
RUN go install github.com/swaggo/swag/cmd/swag@latest

# Copy whole sources
COPY . .

# Build application
RUN swag init -g cmd/api/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o supmap-users cmd/api/main.go

# Build final image
FROM golang:1.24-alpine
RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /app/supmap-users .
COPY --from=builder /app/docs ./docs

ENV PORT=80
EXPOSE 80

ENTRYPOINT ["./supmap-users"]
