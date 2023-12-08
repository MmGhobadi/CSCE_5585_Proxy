Linux:
need a root user to runt this app.
1. "sudo go run ."
2. go to the localhost:8080 by your browser

Or you can run it with Docker:

1. "docker build -t firewall ."
2. "docker run --publish 8080:8080 --cap-add=NET_ADMIN firewall"
3. go to the localhost:8080 by your browser



./bin/golangci-lint run

sudo go test -v -coverpkg=./...