package firewall

import (
	"testing"

	"github.com/google/gopacket"
)

func TestNewPacketCapture(t *testing.T) {
	interfaceName := "wlp0s20f3"
	packetCapture, err := NewPacketCapture(interfaceName)
	if err != nil {
		t.Errorf("Failed to create PacketCapture: %v", err)
	}
	defer packetCapture.Close()

	// Assert that the handle is not nil
	if packetCapture.handle == nil {
		t.Error("PacketCapture handle is nil")
	}
}

func TestPacketCapture_Start(t *testing.T) {
	interfaceName := "wlp0s20f3"
	packetCapture, err := NewPacketCapture(interfaceName)
	if err != nil {
		t.Errorf("Failed to create PacketCapture: %v", err)
	}
	defer packetCapture.Close()

	// Define a packet handler function for testing
	packetHandler := func(packet gopacket.Packet) {
		// Do nothing for testing purposes
	}

	// Start capturing packets
	go packetCapture.Start(packetHandler)
}

func TestGetOutboundIP(t *testing.T) {
	ip := GetOutboundIP()

	// Assert that the IP is not nil
	if ip == nil {
		t.Error("Outbound IP is nil")
	}

	// Assert that the IP is a valid IPv4 or IPv6 address
	if ip.To4() == nil && ip.To16() == nil {
		t.Errorf("Invalid outbound IP address: %s", ip.String())
	}
}
