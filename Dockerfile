FROM golang:1.21.4-bullseye
USER root

RUN apt update && yes | apt install iptables && yes | apt install libpcap-dev


# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./


RUN go mod download


# Copy the source code.
COPY . .

# Build
RUN CGO_ENABLED=1 GOOS=linux go build -o /firewall


EXPOSE 8080

# Run
CMD ["/firewall"]