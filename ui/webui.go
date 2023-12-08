package ui

import (
	"log"
	myFirewall "proxy/firewall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

func StartWebUI(firewall *myFirewall.Firewall) {

	engine := html.New("./views", ".html")
	app := fiber.New(fiber.Config{
		Views:       engine,
		ViewsLayout: "layouts/layout",
	})

	// Define routes
	app.Get("/", homeHandler)
	app.Get("/logs", func(c *fiber.Ctx) error {
		return logsHandler(c, firewall)
	})
	app.Get("/rules", rulesHandler)

	// A route for blocking IP
	app.Post("/block-ip", func(c *fiber.Ctx) error {
		return blockIPHandler(c, firewall)
	})
	// A route for unblocking IP
	app.Post("/unblock-ip", func(c *fiber.Ctx) error {
		println("Hiiii")
		return unblockIPHandler(c, firewall)
	})
	// A route for blocking a port
	app.Post("/block-port", func(c *fiber.Ctx) error {
		return blockPortHandler(c, firewall)
	})

	// A route for unblocking a port
	app.Post("/unblock-port", func(c *fiber.Ctx) error {
		return unblockPortHandler(c, firewall)
	})

	// A route for blocking a protocol
	app.Post("/block-protocol", func(c *fiber.Ctx) error {
		return blockProtocolHandler(c, firewall)
	})

	// A route for unblocking a protocol
	app.Post("/unblock-protocol", func(c *fiber.Ctx) error {
		return unblockProtocolHandler(c, firewall)
	})

	// A new route for rate limiting an IP
	app.Post("/rate-limit-ip", func(c *fiber.Ctx) error {
		return rateLimitIPHandler(c, firewall)
	})

	// A new route for geo-blocking an IP
	app.Post("/geo-block", func(c *fiber.Ctx) error {
		return geoBlockHandler(c, firewall)
	})

	// A new route for bandwidth-usage
	app.Get("/bandwidth-usage", func(c *fiber.Ctx) error {
		return displayBandwidthUsageHandler(c, firewall)
	})

	// Handle not founds
	app.Use(NotFound)

	// Start the Echo server
	log.Fatal(app.Listen(":8000"))
}
