# Proxy Application with Go

This project implements a simple Proxy Application in Go, providing features such as basic firewall functionality, rate limiting, geo-blocking, logging, and a web-based user interface.


The Proxy Application includes the following features:

1. **Basic Firewall Features:**
    - Source/Destination IP blocking.
    - Source/Destination port blocking.
    - Protocol-based blocking (e.g., block all HTTPS traffic).

2. **Rate Limiting:**
    - Limit the number of requests from a particular source IP within a specific time frame (e.g., max 100 requests per minute).
    - Limit the total bandwidth used by a particular IP or service.

3. **Geo-blocking:**
    - Block or allow traffic based on the geographic location of the source or destination IP using a GeoIP database.

4. **Logging:**
    - Log all blocked traffic with timestamps, source/destination IPs, and the reason for blocking.
    - Implement a mechanism to regularly rotate and archive logs.

5. **Information:**
    - Develop a web-based UI that allows an admin to set rules, view logs, and monitor the system.
    - Display statistics such as bandwidth usage over time.

6. **Test Coverage:**
    - Implement unit tests for both the firewall logic and the UI.
    - Aim for at least 80% code coverage.

7. **Static Analysis (Linting):**
    - Code adheres to best practices and standards.
    - Utilize `golangci-lint`.


## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Installation (Root permission needed)

1. Clone the repository:

    ```bash
    git clone https://github.com/your-username/your-repo.git
    ```

2. Change to the project directory:

    ```bash
    cd your-repo
    ```

3. Install the dependencies:

    ```bash
    go mod download
    ```
Or you can run it with Docker:

1. 
    ```bash
    docker build -t firewall .
    ```

2. 
    ```bash
    docker run --publish 8000:8000 --cap-add=NET_ADMIN firewall
    ```
3. Open localhost:8000 by your browser


## Usage (Root permission needed)

1. Start the application:

    ```bash
    sudo go run .
    ```

2. Open your browser and navigate to `http://localhost:8000`.

## Testing (Root permission needed)

1. Run the tests:

    ```bash
    sudo go test ./... -cover -coverprofile=coverage.out
    ```

2. View the test coverage report:

    ```bash
    sudo go tool cover -func=coverage.out -o=coverage.out
    ```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch: `git checkout -b my-feature-branch`.
3. Make your changes and commit them: `git commit -am 'Add new feature'`.
4. Push to the branch: `git push origin my-feature-branch`.
5. Submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).
