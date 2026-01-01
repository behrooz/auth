# Build stage
<<<<<<< HEAD
FROM golang:1.22-alpine AS builder

# Set working directory
WORKDIR /app

# Install git (needed for some Go dependencies)
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o authservice .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/
=======
FROM golang:1.22 AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o authservice main.go

# Final stage
FROM alpine:3.19

WORKDIR /app
>>>>>>> 72991b1e5511707844f76cd4996eb74a49a1dc2b

# Copy the binary from builder
COPY --from=builder /app/authservice .

# Expose port
EXPOSE 8083

<<<<<<< HEAD
# Run the application
CMD ["./authservice"]

=======
# Command to run
CMD ["./authservice"]
>>>>>>> 72991b1e5511707844f76cd4996eb74a49a1dc2b
