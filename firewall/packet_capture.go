package firewall

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PacketCapture struct to manage packet capture
type PacketCapture struct {
	handle *pcap.Handle
}

// NewPacketCapture creates a new PacketCapture instance
func NewPacketCapture(interfaceName string) (*PacketCapture, error) {
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return &PacketCapture{handle: handle}, nil
}

// Start capturing packets
func (pc *PacketCapture) Start(packetHandler func(gopacket.Packet)) {
	packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())
	for packet := range packetSource.Packets() {
		packetHandler(packet)
	}
}

// Close the packet capture handle
func (pc *PacketCapture) Close() {
	pc.handle.Close()
}

// Get preferred outbound ip of this machine
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}
