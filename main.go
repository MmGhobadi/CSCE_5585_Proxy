package main

import (
	"log"
	myFirewall "proxy/firewall"
	myUI "proxy/ui"
)

func main() {

	// Create a new instance of the firewall
	firewall, err := myFirewall.NewFirewall("wlp0s20f3") // eth0 or wlp0s20f3
	if err != nil {
		log.Fatalf("Error creating firewall: %s", err)
	}

	// Start the firewall logic
	go firewall.Start()

	// Start the web-based UI
	go myUI.StartWebUI(firewall)

	// Block the main goroutine to keep the program running
	select {}
}
