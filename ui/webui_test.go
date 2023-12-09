package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestStartWebUI(t *testing.T) {
	firewall := getFirewall()
	app := fiber.New()

	// Start the web UI
	go StartWebUI(firewall)

	// Test the home page
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response, err := app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)

	// Test the logs page
	request = httptest.NewRequest(http.MethodGet, "/logs", nil)
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)

	// Test the rules page
	request = httptest.NewRequest(http.MethodGet, "/rules", nil)
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)

	// Test blocking an IP
	request = httptest.NewRequest(http.MethodPost, "/block-ip", nil)
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)

	// Test unblocking an IP
	request = httptest.NewRequest(http.MethodPost, "/unblock-ip", nil)
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)

	// Test blocking a port
	request = httptest.NewRequest(http.MethodPost, "/block-port", nil)
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)

	// Test unblocking a port
	request = httptest.NewRequest(http.MethodPost, "/unblock-port", nil)
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)

	// Test blocking a protocol
	request = httptest.NewRequest(http.MethodPost, "/block-protocol", nil)
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)

	// Test unblocking a protocol
	request = httptest.NewRequest(http.MethodPost, "/unblock-protocol", nil)
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)

	// Test rate limiting an IP
	request = httptest.NewRequest(http.MethodPost, "/rate-limit-ip", nil)
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)

	// Test geo-blocking an IP
	request = httptest.NewRequest(http.MethodPost, "/geo-block", nil)
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)

	// Test bandwidth usage
	request = httptest.NewRequest(http.MethodGet, "/bandwidth-usage", nil)
	response, err = app.Test(request)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)
}
