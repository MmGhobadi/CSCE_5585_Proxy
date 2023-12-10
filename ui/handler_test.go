package ui

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	myFirewall "proxy/firewall"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func getFirewall() *myFirewall.Firewall {
	firewall, _ := myFirewall.NewFirewall("wlp0s20f3")
	go firewall.Start()
	return firewall
}

func TestBlockIPHandler(t *testing.T) {
	firewall := getFirewall()
	app := fiber.New()
	app.Post("/block-ip", func(c *fiber.Ctx) error {
		return blockIPHandler(c, firewall)
	})

	request := httptest.NewRequest(http.MethodPost, "/block-ip", strings.NewReader("ip=192.168.0.1"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)

	body, err := io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Blocked traffic from IP 192.168.0.1", string(body))

	request = httptest.NewRequest(http.MethodPost, "/block-ip", strings.NewReader("ip="))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)

	body, err = io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Invalid IP address format", string(body))
}

func TestUnblockIPHandler(t *testing.T) {
	firewall := getFirewall()
	app := fiber.New()
	app.Post("/unblock-ip", func(c *fiber.Ctx) error {
		return unblockIPHandler(c, firewall)
	})

	ip := net.ParseIP("192.168.0.1")
	_, err := firewall.BlockIP(ip, "Blocked via web UI")
	if err != nil {
		log.Println(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/unblock-ip", strings.NewReader("ip=192.168.0.1"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "unBlocked traffic from IP 192.168.0.1", string(body))

	request = httptest.NewRequest(http.MethodPost, "/unblock-ip", strings.NewReader("ip="))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	body, err = io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Invalid IP address format", string(body))

}

func TestBlockPortHandler(t *testing.T) {
	firewall := getFirewall()
	app := fiber.New()
	app.Post("/block-port", func(c *fiber.Ctx) error {
		return blockPortHandler(c, firewall)
	})

	request := httptest.NewRequest(http.MethodPost, "/block-port", strings.NewReader("port=80"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Blocked traffic on port 80", string(body))

	request = httptest.NewRequest(http.MethodPost, "/block-port", strings.NewReader("port="))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	body, err = io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Invalid port format", string(body))

}

func TestUnblockPortHandler(t *testing.T) {
	firewall := getFirewall()
	app := fiber.New()
	app.Post("/unblock-port", func(c *fiber.Ctx) error {
		return unblockPortHandler(c, firewall)
	})

	port := 80
	_, err := firewall.BlockPort(port, "Blocked via web UI")
	if err != nil {
		log.Println(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/unblock-port", strings.NewReader("port=80"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Unblocked traffic on port 80", string(body))

	request = httptest.NewRequest(http.MethodPost, "/unblock-port", strings.NewReader("port="))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	body, err = io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Invalid port format", string(body))

}

func TestBlockProtocolHandler(t *testing.T) {
	firewall := getFirewall()
	app := fiber.New()
	app.Post("/block-protocol", func(c *fiber.Ctx) error {
		return blockProtocolHandler(c, firewall)
	})

	request := httptest.NewRequest(http.MethodPost, "/block-protocol", strings.NewReader("protocol=ICMP"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Blocked traffic of protocol ICMP", string(body))

	request = httptest.NewRequest(http.MethodPost, "/block-protocol", strings.NewReader("protocol="))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	body, err = io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Invalid protocol format", string(body))

}

func TestUnblockProtocolHandler(t *testing.T) {
	firewall := getFirewall()
	app := fiber.New()
	app.Post("/unblock-protocol", func(c *fiber.Ctx) error {
		return unblockProtocolHandler(c, firewall)
	})

	protocol := "ICMP"
	_, err := firewall.BlockProtocol(protocol, "Blocked via web UI")
	if err != nil {
		log.Println(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/unblock-protocol", strings.NewReader("protocol=ICMP"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Unblocked traffic of protocol ICMP", string(body))

	request = httptest.NewRequest(http.MethodPost, "/unblock-protocol", strings.NewReader("protocol="))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	body, err = io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Invalid protocol format", string(body))

}

func TestDisplayBandwidthUsageHandler(t *testing.T) {

	firewall := getFirewall()
	app := fiber.New()
	app.Get("/bandwidth-usage", func(c *fiber.Ctx) error {
		return displayBandwidthUsageHandler(c, firewall)
	})

	request := httptest.NewRequest(http.MethodGet, "/bandwidth-usage", nil)
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)

	// Check the response body
	body, err := io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.NotEmpty(t, body)

}

func TestRateLimitIPHandler(t *testing.T) {
	firewall := getFirewall()
	app := fiber.New()
	app.Post("/rate-limit-ip", func(c *fiber.Ctx) error {
		return rateLimitIPHandler(c, firewall)
	})

	requestBody := "ip=127.0.0.1&limit=100&duration=1m"
	request := httptest.NewRequest(http.MethodPost, "/rate-limit-ip", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)

	// Check the response body
	body, err := io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Rate limited traffic from IP 127.0.0.1", string(body))

	requestBody = "ip=&limit=100&duration=1m"
	request = httptest.NewRequest(http.MethodPost, "/rate-limit-ip", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)

	// Check the response body
	body, err = io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Invalid IP address format", string(body))

}

func TestGeoBlockHandler(t *testing.T) {
	firewall := getFirewall()
	app := fiber.New()
	app.Post("/geo-block", func(c *fiber.Ctx) error {
		return geoBlockHandler(c, firewall)
	})

	request := httptest.NewRequest(http.MethodPost, "/geo-block", strings.NewReader("countryName=Iraq"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Blocked traffic from Iraq geo-location", string(body))

	request = httptest.NewRequest(http.MethodPost, "/geo-block", strings.NewReader("countryName="))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	body, err = io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Invalid Country Name format", string(body))

}

func TestHomeHandler(t *testing.T) {
	app := fiber.New()
	app.Get("/", homeHandler)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusInternalServerError, response.StatusCode)

}

func TestLogsHandler(t *testing.T) {
	firewall := getFirewall()
	app := fiber.New()
	app.Get("/logs", func(c *fiber.Ctx) error {
		return logsHandler(c, firewall)
	})

	request := httptest.NewRequest(http.MethodGet, "/logs", nil)
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)

}

func TestRulesHandler(t *testing.T) {
	app := fiber.New()
	app.Get("/rules", rulesHandler)

	request := httptest.NewRequest(http.MethodGet, "/rules", nil)
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)

}

func TestNotFound(t *testing.T) {
	app := fiber.New()
	app.Use(NotFound)

	request := httptest.NewRequest(http.MethodGet, "/not-found", nil)
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusInternalServerError, response.StatusCode)

}
func TestGeoUnBlockHandler(t *testing.T) {
	firewall := getFirewall()
	app := fiber.New()
	app.Post("/geo-unblock", func(c *fiber.Ctx) error {
		return geoUnBlockHandler(c, firewall)
	})

	request := httptest.NewRequest(http.MethodPost, "/geo-unblock", strings.NewReader("countryName=Iraq"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Unblocked traffic from Iraq geo-location", string(body))

	request = httptest.NewRequest(http.MethodPost, "/geo-unblock", strings.NewReader("countryName="))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	body, err = io.ReadAll(response.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Invalid Country Name format", string(body))
}
func TestGeoCountryListHandler(t *testing.T) {
	firewall := getFirewall()
	app := fiber.New()
	app.Get("/geo-country-list", func(c *fiber.Ctx) error {
		return geoCountryListHandler(c, firewall)
	})

	request := httptest.NewRequest(http.MethodGet, "/geo-country-list", nil)
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)

	// Check the response body
	body, err := io.ReadAll(response.Body)
	assert.Nil(t, err)

	// Parse the response body
	var result fiber.Map
	err = json.Unmarshal(body, &result)
	assert.Nil(t, err)

	assert.NotNil(t, result["countryList"])
	assert.NotEmpty(t, result["countryList"])
}
