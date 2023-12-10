package firewall

import (
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func TestNewFirewall(t *testing.T) {

	logs_path := RootDir() + "/logs/"

	logFileName := logs_path + "current_log.txt"
	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)

	assert.Nil(t, err)
	assert.NotNil(t, firewall)
	assert.NotNil(t, firewall.iptables)
	assert.NotNil(t, firewall.rateLimiter)
	assert.NotNil(t, firewall.geoDB)
	assert.NotNil(t, firewall.logFile)
	assert.NotNil(t, firewall.logRotateChan)
	assert.NotNil(t, firewall.packetCapture)
	assert.Equal(t, interfaceName, firewall.interfaceName)
	assert.NotEmpty(t, firewall.interfaceIPs)
	assert.NotNil(t, firewall.protocolCounters)
	assert.NotNil(t, firewall.sourceIPCounters)
	assert.NotNil(t, firewall.destIPCounters)
	assert.NotNil(t, firewall.geoCounters)
	assert.NotNil(t, firewall.ruleBlockCounters)
	assert.NotNil(t, firewall.bandwidthUsage)
	assert.NotZero(t, firewall.lastBandwidthTime)
	assert.Equal(t, 1*time.Second, firewall.bandwidthUpdateInterval)

	// Clean up
	os.Remove(logFileName)
}

func TestFirewall_Start(t *testing.T) {

	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	// Start the firewall
	go firewall.Start()

	// Wait for a few seconds to allow the firewall to start
	time.Sleep(5 * time.Second)

	// Stop the firewall
	// Note: This is just an example, you may need to implement a way to gracefully stop the firewall in your code
}

func TestFirewall_HandlePacket(t *testing.T) {

	logs_path := RootDir() + "/logs/"

	logFileName := logs_path + "current_log.txt"
	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	// Create a sample packet for testing
	packet := createSamplePacket()

	// Call the handlePacket function
	firewall.handlePacket(packet)

	// Add assertions to verify the expected behavior of the handlePacket function

	// ...

	// Clean up
	os.Remove(logFileName)
}

func createSamplePacket() gopacket.Packet {
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{192, 168, 0, 1},
		DstIP:    net.IP{192, 168, 0, 2},
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(1234),
		DstPort: layers.TCPPort(5678),
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		ethernetLayer,
		ipLayer,
		tcpLayer,
	)
	if err != nil {
		log.Println(err)
	}

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}
func TestFirewall_BlockIP(t *testing.T) {

	logs_path := RootDir() + "/logs/"

	logFileName := logs_path + "current_log.txt"
	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	ip := net.ParseIP("192.168.0.1")
	reason := "Blocked for testing"

	// Block the IP
	result, err := firewall.BlockIP(ip, reason)
	assert.Nil(t, err)
	assert.Equal(t, fmt.Sprintf("Blocked traffic from IP %s", ip), result)

	result, err = firewall.BlockIP(nil, reason)
	assert.NotEmpty(t, err)
	assert.Equal(t, "", result)

	// Verify that the IP is blocked
	blockedIPs, err := firewall.GetBlockedIPs()
	assert.Nil(t, err)
	assert.Contains(t, blockedIPs, "192.168.0.1")

	// Clean up
	os.Remove(logFileName)
}
func TestFirewall_UnblockIP(t *testing.T) {

	logs_path := RootDir() + "/logs/"

	logFileName := logs_path + "current_log.txt"
	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	ip := net.ParseIP("192.168.0.1")
	reason := "Unblocked for testing"

	// Block the IP first
	_, err = firewall.BlockIP(ip, reason)
	assert.Nil(t, err)

	// Unblock the IP
	result, err := firewall.UnblockIP(ip, reason)
	assert.Nil(t, err)
	assert.Equal(t, fmt.Sprintf("Unblocked traffic from IP %s", ip), result)

	result, err = firewall.UnblockIP(nil, reason)
	assert.NotEmpty(t, err)
	assert.Equal(t, "", result)

	os.Remove(logFileName)
}

func TestFirewall_BlockPort(t *testing.T) {

	logs_path := RootDir() + "/logs/"

	logFileName := logs_path + "current_log.txt"
	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	port := 80
	reason := "Blocked for testing"

	// Block the port
	result, err := firewall.BlockPort(port, reason)
	assert.Nil(t, err)
	assert.Equal(t, fmt.Sprintf("Blocked traffic on port %d", port), result)

	result, err = firewall.BlockPort(-1, reason)
	assert.NotEmpty(t, err)
	assert.Equal(t, "", result)

	// Clean up
	os.Remove(logFileName)
}
func TestFirewall_UnblockPort(t *testing.T) {

	logs_path := RootDir() + "/logs/"

	logFileName := logs_path + "current_log.txt"
	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	port := 80

	// Unblock the port
	result, err := firewall.UnblockPort(port)
	assert.Nil(t, err)
	assert.Equal(t, fmt.Sprintf("Unblocked traffic on port %d", port), result)

	result, err = firewall.UnblockPort(-1)
	assert.NotEmpty(t, err)
	assert.Equal(t, "", result)

	// Clean up
	os.Remove(logFileName)
}
func TestFirewall_BlockProtocol(t *testing.T) {

	logs_path := RootDir() + "/logs/"

	logFileName := logs_path + "current_log.txt"
	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	protocol := "ICMP"
	reason := "Blocked for testing"

	assert.Nil(t, err)

	// Block the protocol
	result, err := firewall.BlockProtocol(protocol, reason)
	assert.Nil(t, err)
	assert.Equal(t, fmt.Sprintf("Blocked traffic of protocol %s", protocol), result)

	result, err = firewall.BlockProtocol("-1", reason)
	assert.NotEmpty(t, err)
	assert.Equal(t, "", result)

	// Clean up
	os.Remove(logFileName)
}
func TestFirewall_UnblockProtocol(t *testing.T) {

	logs_path := RootDir() + "/logs/"

	logFileName := logs_path + "current_log.txt"
	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	protocol := "ICMP"
	reason := "Unblocked for testing"

	assert.Nil(t, err)

	// Block the protocol first
	_, err = firewall.BlockProtocol(protocol, reason)
	assert.Nil(t, err)

	// Unblock the protocol
	result, err := firewall.UnblockProtocol(protocol)
	assert.Nil(t, err)
	assert.Equal(t, fmt.Sprintf("Unblocked traffic of protocol %s", protocol), result)

	result, err = firewall.UnblockProtocol("-1")
	assert.NotEmpty(t, err)
	assert.Equal(t, "", result)

	// Clean up
	os.Remove(logFileName)
}
func TestFirewall_LogBlockedTraffic(t *testing.T) {

	logs_path := RootDir() + "/logs/"

	logFileName := logs_path + "current_log.txt"
	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	sourceIP := net.ParseIP("192.168.0.1")
	destinationIP := net.ParseIP("192.168.0.2")
	reason := "Blocked for testing"

	// Call the logBlockedTraffic method
	err = firewall.logBlockedTraffic(sourceIP, destinationIP, reason)
	assert.Nil(t, err)

	// Verify that the log entry is added to the logEntries slice
	assert.Len(t, firewall.logEntries, 1)
	assert.Equal(t, sourceIP, firewall.logEntries[0].SourceIP)
	assert.Equal(t, destinationIP, firewall.logEntries[0].DestinationIP)
	assert.Equal(t, reason, firewall.logEntries[0].Reason)

	// Verify that the log entry is written to the log file
	logFileContent, err := os.ReadFile(logFileName)
	assert.Nil(t, err)
	assert.Contains(t, string(logFileContent), fmt.Sprintf("[%s] Blocked traffic from %s to %s: %s\n", firewall.logEntries[0].Timestamp, sourceIP, destinationIP, reason))

	// Clean up
	os.Remove(logFileName)
}
func TestFirewall_RotateLogs(t *testing.T) {
	logs_path := RootDir() + "/logs/"

	logFileName := logs_path + "current_log.txt"
	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	// Create a sample log file
	logFile, err := os.Create(logFileName)
	assert.Nil(t, err)
	firewall.logFile = logFile

	// Call the rotateLogs method
	err = firewall.rotateLogs()
	assert.Nil(t, err)

	// Verify that the log file is renamed with a timestamp
	newLogFileName := fmt.Sprintf("firewall_log_%s.txt", time.Now().Format("2006-01-02"))
	_, err = os.Stat(logs_path + newLogFileName)
	assert.Nil(t, err)

	// Verify that a new log file is created
	newLogFile, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	assert.Nil(t, err)
	assert.NotNil(t, newLogFile)
	firewall.logFile = newLogFile

	// Clean up
	os.Remove(logFileName)
	os.Remove(logs_path + newLogFileName)
}

func TestFirewall_RateLimitIP(t *testing.T) {
	interfaceName := "wlp0s20f3"
	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	ip := net.ParseIP("192.168.0.10")
	limit := 1
	duration := 1 * time.Minute

	// Test rate limiting after the limit is exceeded
	result := firewall.RateLimitIP(ip, limit, duration)
	assert.False(t, result)

	// Test rate limiting before the limit is exceeded
	for i := 0; i < limit-1; i++ {
		result = firewall.RateLimitIP(ip, limit, duration)
		assert.False(t, result)
	}

	// Test rate limiting after the limit is exceeded
	result = firewall.RateLimitIP(ip, limit, duration)
	assert.True(t, result)

	// Test rate limiting for a different IP
	anotherIP := net.ParseIP("192.168.0.2")
	result = firewall.RateLimitIP(anotherIP, limit, duration)
	assert.False(t, result)
}
func TestFirewall_IsBlockedCountry(t *testing.T) {

	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	// Test with a blocked country
	// countryCode := "CN"
	result, err := firewall.isBlockedCountry("192.168.0.1")
	assert.Nil(t, err)
	assert.False(t, result)

	// Test with a non-blocked country
	// countryCode = "US"
	result, err = firewall.isBlockedCountry("192.168.0.2")
	assert.Nil(t, err)
	assert.False(t, result)

	result, err = firewall.isBlockedCountry("-1")
	assert.NotEmpty(t, err)
	assert.True(t, result)

	firewall.db_path = "/wrong/"
	result, err = firewall.isBlockedCountry("192.168.0.2")
	assert.NotEmpty(t, err)
	assert.True(t, result)
}

func TestFirewall_updateTrafficCounters(t *testing.T) {

	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	srcIP := net.ParseIP("192.168.0.1")
	dstIP := net.ParseIP("192.168.0.2")
	protocol := "TCP"

	// Call the updateTrafficCounters method
	err = firewall.updateTrafficCounters(srcIP.String(), dstIP.String(), protocol)
	if err != nil {
		log.Println(err)
	}

	// Verify that the protocol counter is incremented
	assert.Equal(t, 1, firewall.protocolCounters[protocol])

	// Verify that the source IP counter is incremented
	assert.Equal(t, 1, firewall.sourceIPCounters[srcIP.String()])

	// Verify that the destination IP counter is incremented
	assert.Equal(t, 1, firewall.destIPCounters[dstIP.String()])
}

func TestFirewall_updateBandwidthUsage(t *testing.T) {

	interfaceName := "wlp0s20f3"

	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	// Create a sample packet for testing
	packet := createSamplePacketV2()

	// Call the updateBandwidthUsage method
	firewall.updateBandwidthUsage(packet)

	// Verify that the bandwidth usage is updated
	expectedUsage := firewall.getTotalLength(packet)
	assert.Equal(t, expectedUsage, firewall.bandwidthUsage[packet.NetworkLayer().NetworkFlow().Src().String()])

	// Wait for a second to allow the bandwidth usage to be updated again
	time.Sleep(1 * time.Second)

	// Call the updateBandwidthUsage method again
	firewall.updateBandwidthUsage(packet)

	// Verify that the bandwidth usage is incremented
	expectedUsage += firewall.getTotalLength(packet)
	assert.Equal(t, expectedUsage, firewall.bandwidthUsage[packet.NetworkLayer().NetworkFlow().Src().String()])
}

func createSamplePacketV2() gopacket.Packet {
	// Create a sample packet with data
	data := []byte("Sample packet data")

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{192, 168, 0, 1},
		DstIP:    net.IP{192, 168, 0, 2},
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(1234),
		DstPort: layers.TCPPort(5678),
	}

	// Create a buffer and serialize the layers
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(data),
	)
	if err != nil {
		log.Println(err)
	}

	// Create a new packet from the serialized buffer
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}
func TestFirewall_DisplayBandwidthUsage(t *testing.T) {
	interfaceName := "wlp0s20f3"
	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	// Add some sample bandwidth usage data
	firewall.bandwidthUsage["192.168.0.1"] = 100
	firewall.bandwidthUsage["192.168.0.2"] = 200
	firewall.bandwidthUsage["192.168.0.3"] = 300

	// Call the DisplayBandwidthUsage method
	result := firewall.DisplayBandwidthUsage()

	// Verify the returned bandwidth usage data
	assert.Equal(t, float64(100), result["192.168.0.1"])
	assert.Equal(t, float64(200), result["192.168.0.2"])
	assert.Equal(t, float64(300), result["192.168.0.3"])
}
func TestFirewall_Get_in_out_log(t *testing.T) {
	interfaceName := "wlp0s20f3"
	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	expected := []string{"log3", "log2", "log1"}
	result := firewall.Get_in_out_log()

	assert.Equal(t, reflect.TypeOf(expected), reflect.TypeOf(result))
}
func TestSaveLog(t *testing.T) {
	// Initialize the in_out_log slice
	in_out_log = make([]string, 0)

	// Call the saveLog function
	packageLog := "Sample log"
	saveLog(packageLog)

	// Verify that the packageLog is added to the in_out_log slice
	assert.Equal(t, []string{packageLog}, in_out_log)

	// Add more logs to exceed the limit
	for i := 0; i < 10000; i++ {
		saveLog(fmt.Sprintf("Log %d", i))
	}

	// Call the saveLog function again
	saveLog(packageLog)

	// Verify that the in_out_log slice is reset and only contains the latest log
	assert.Equal(t, []string{packageLog}, in_out_log)
}
func TestFirewall_GetBlockedCountries(t *testing.T) {

	interfaceName := "wlp0s20f3"
	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	// Call the GetBlockedCountries method
	countryList, err := firewall.GetBlockedCountries()
	// Verify the results
	assert.Nil(t, err)
	assert.IsType(t, []string{}, countryList)

	err = firewall.GeoBlock("United States")
	assert.Nil(t, err)
	countryList, err = firewall.GetBlockedCountries()
	assert.Nil(t, err)
	assert.NotEqual(t, []string{}, countryList)

	err = firewall.GeoUnBlock("United States")
	assert.Nil(t, err)

}
func TestFirewall_GetGeoCountryList(t *testing.T) {
	interfaceName := "wlp0s20f3"
	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	// Test case 1: Valid database path
	expectedCountryList, err := firewall.GetGeoCountryList()
	assert.Nil(t, err)
	assert.NotEmpty(t, expectedCountryList)

	// Test case 2: Invalid database path
	firewall.db_path = "/wrong/"
	expectedCountryList, err = firewall.GetGeoCountryList()
	assert.NotEmpty(t, err)
	assert.Nil(t, expectedCountryList)

	// Test case 3: Empty database path
	firewall.db_path = ""
	expectedCountryList, err = firewall.GetGeoCountryList()
	assert.NotEmpty(t, err)
	assert.Nil(t, expectedCountryList)

	// Test case 4: Non-existent database file
	firewall.db_path = "/path/to/nonexistent/file"
	expectedCountryList, err = firewall.GetGeoCountryList()
	assert.NotEmpty(t, err)
	assert.Nil(t, expectedCountryList)
}
func TestFirewall_GeoUnBlock(t *testing.T) {
	interfaceName := "wlp0s20f3"
	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	countryName := "United States"

	err = firewall.GeoUnBlock(countryName)
	assert.Nil(t, err)

	// Verify that the file has been updated correctly
	readFile, err := os.Open(firewall.db_path + "GeoLite2-Country-Locations-en.csv")
	assert.Nil(t, err)
	defer readFile.Close()

	reader := csv.NewReader(readFile)
	records, err := reader.ReadAll()
	assert.Nil(t, err)

	for _, record := range records {
		if record[5] == countryName {
			assert.Equal(t, "FALSE", record[6])
		}
	}
	firewall.db_path = "/wrong/"
	err = firewall.GeoUnBlock(countryName)
	assert.NotEmpty(t, err)
}
func TestFirewall_GeoBlock(t *testing.T) {
	interfaceName := "wlp0s20f3"
	firewall, err := NewFirewall(interfaceName)
	assert.Nil(t, err)

	countryName := "United States"

	err = firewall.GeoBlock(countryName)
	assert.Nil(t, err)

	// Verify that the file was written correctly
	filePath := firewall.db_path + "GeoLite2-Country-Locations-en.csv"
	file, err := os.Open(filePath)
	assert.Nil(t, err)
	assert.NotEmpty(t, file)
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	assert.Nil(t, err)

	for _, record := range records {
		if record[5] == countryName {
			assert.Equal(t, "TRUE", record[6])
		}
	}
	err = firewall.GeoUnBlock(countryName)
	assert.Nil(t, err)

	firewall.db_path = "/wrong/"
	err = firewall.GeoBlock(countryName)
	assert.NotEmpty(t, err)

}
