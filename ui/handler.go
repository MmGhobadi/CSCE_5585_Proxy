package ui

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"time"

	myFirewall "proxy/firewall"

	"github.com/gofiber/fiber/v2"
)

func blockIPHandler(c *fiber.Ctx, firewall *myFirewall.Firewall) error {
	// Parse the user-provided IP from the request body
	ipStr := c.FormValue("ip")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid IP address format")
	}

	// Block the specified IP using the Firewall
	_, err := firewall.BlockIP(ip, "Blocked via web UI")
	if err != nil {
		log.Println(err)
	}

	return c.SendString(fmt.Sprintf("Blocked traffic from IP %s", ip))
}

func unblockIPHandler(c *fiber.Ctx, firewall *myFirewall.Firewall) error {
	// Parse the user-provided IP from the request body
	ipStr := c.FormValue("ip")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid IP address format")
	}

	// unBlock the specified IP using the Firewall
	_, err := firewall.UnblockIP(ip, "unBlocked via web UI")
	if err != nil {
		log.Println(err)
	}

	return c.SendString(fmt.Sprintf("unBlocked traffic from IP %s", ip))
}

func blockPortHandler(c *fiber.Ctx, firewall *myFirewall.Firewall) error {
	// Parse the user-provided port from the request body
	portStr := c.FormValue("port")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid port format")
	}

	// Block the specified port using the Firewall
	_, err = firewall.BlockPort(port, "Blocked via web UI")
	if err != nil {
		log.Println(err)
	}

	return c.SendString(fmt.Sprintf("Blocked traffic on port %d", port))
}

func unblockPortHandler(c *fiber.Ctx, firewall *myFirewall.Firewall) error {
	// Parse the user-provided port from the request body
	portStr := c.FormValue("port")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid port format")
	}

	// Unblock the specified port using the Firewall
	_, err = firewall.UnblockPort(port)
	if err != nil {
		log.Println(err)
	}

	return c.SendString(fmt.Sprintf("Unblocked traffic on port %d", port))
}

func blockProtocolHandler(c *fiber.Ctx, firewall *myFirewall.Firewall) error {
	// Parse the user-provided protocol from the request body
	protocol := c.FormValue("protocol")

	// Block the specified protocol using the Firewall
	_, err := firewall.BlockProtocol(protocol, "Blocked via web UI")

	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid protocol format")
	}

	return c.SendString(fmt.Sprintf("Blocked traffic of protocol %s", protocol))
}

func unblockProtocolHandler(c *fiber.Ctx, firewall *myFirewall.Firewall) error {
	// Parse the user-provided protocol from the request body
	protocol := c.FormValue("protocol")

	// Unblock the specified protocol using the Firewall
	_, err := firewall.UnblockProtocol(protocol)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid protocol format")
	}

	return c.SendString(fmt.Sprintf("Unblocked traffic of protocol %s", protocol))
}

func displayBandwidthUsageHandler(c *fiber.Ctx, firewall *myFirewall.Firewall) error {

	usage := firewall.DisplayBandwidthUsage()
	// Extract keys from map
	keys := make([]string, 0, len(usage))
	for k := range usage {
		keys = append(keys, k)
	}

	// Sort keys
	sort.Strings(keys)

	usageSize := make([]float64, 0, len(usage))

	// Print sorted map
	for _, k := range keys {
		size := float64(usage[k])
		usageSize = append(usageSize, size)
	}

	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.JSON(fiber.Map{
		"label": keys,
		"usage": usageSize,
	})
}

func rateLimitIPHandler(c *fiber.Ctx, firewall *myFirewall.Firewall) error {
	// Parse the user-provided IP, limit, and duration from the request body
	ipStr := c.FormValue("ip")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid IP address format")
	}

	limitStr := c.FormValue("limit")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid limit format")
	}

	durationStr := c.FormValue("duration")
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid duration format")
	}

	// Rate limit the specified IP using the Firewall
	_ = firewall.RateLimitIP(ip, limit, duration)

	return c.SendString(fmt.Sprintf("Rate limited traffic from IP %s", ip))
}

func geoBlockHandler(c *fiber.Ctx, firewall *myFirewall.Firewall) error {
	// Parse the user-provided IP from the request body
	ipStr := c.FormValue("ip")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid IP address format")
	}

	// // Geo-block the specified IP using the Firewall
	// firewall.GeoBlock(ip, "Blocked via web UI")

	return c.SendString(fmt.Sprintf("Blocked traffic from IP %s based on geo-location", ip))
}

func homeHandler(c *fiber.Ctx) error {
	// Render the main page template
	return c.Render("homePage", fiber.Map{
		"Title": "Hello, World!",
	})
}

func logsHandler(c *fiber.Ctx, firewall *myFirewall.Firewall) error {

	in_out_list := firewall.Get_in_out_log()
	var result string
	for i := 0; i < len(in_out_list); i++ {
		result = result + fmt.Sprintf(in_out_list[i]) + "\n"
	}
	// Add logic to display logs
	return c.SendString(result)
}

func rulesHandler(c *fiber.Ctx) error {
	// Add logic to display and manage rules
	return c.SendString("Displaying and managing rules...")
}

// NoutFound renders the 404 view
func NotFound(c *fiber.Ctx) error {
	return c.Status(404).Render("404", nil)
}
