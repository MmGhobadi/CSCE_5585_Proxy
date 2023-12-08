package firewall

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/oschwald/geoip2-golang"
	"golang.org/x/time/rate"
)

type LogEntry struct {
	Timestamp     time.Time
	SourceIP      net.IP
	DestinationIP net.IP
	Reason        string
}

// Firewall struct to manage firewall functionality
type Firewall struct {
	iptables      *iptables.IPTables
	rateLimiter   map[string]*rate.Limiter // Map to store rate limiters for each IP
	geoDB         *geoip2.Reader
	logFile       *os.File
	logEntries    []LogEntry
	logMutex      sync.Mutex
	logRotateChan chan bool
	packetCapture *PacketCapture
	interfaceName string
	interfaceIPs  []string
	logs_path     string
	db_path       string

	// Counters for traffic breakdown
	protocolCounters map[string]int
	sourceIPCounters map[string]int
	destIPCounters   map[string]int
	geoCounters      map[string]int

	// Counter for requests blocked by each rule
	ruleBlockCounters map[string]int

	// Bandwidth usage tracking
	bandwidthUsage          map[string]uint16
	lastBandwidthTime       time.Time
	bandwidthUpdateInterval time.Duration
}

func RootDir() string {
	_, b, _, _ := runtime.Caller(0)
	d := path.Join(path.Dir(b))
	return filepath.Dir(d)
}

// NewFirewall creates a new Firewall instance
func NewFirewall(interfaceName string) (*Firewall, error) {
	println(RootDir())

	db_path := RootDir() + "/db/"

	logs_path := RootDir() + "/logs/"

	logFileName := logs_path + "current_log.txt"
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}

	rateLimiter := make(map[string]*rate.Limiter)

	geoDB, err := geoip2.Open(db_path + "GeoIP2-Country.mmdb")
	if err != nil {
		return nil, err
	}

	logFile, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	logRotateChan := make(chan bool)
	go func() {
		for range time.Tick(1 * time.Minute) {
			logRotateChan <- true
		}
	}()

	packetCapture, err := NewPacketCapture(interfaceName)
	if err != nil {
		return nil, err
	}

	// Get the network interface by name
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		fmt.Println("Error getting interface by name:", err)
		os.Exit(1)
	}

	// Get the addresses associated with the interface
	addrs, err := iface.Addrs()
	if err != nil {
		fmt.Println("Error getting addresses for interface", iface.Name, ":", err)
		os.Exit(1)
	}

	ipList := []string{}
	// Iterate through each address
	for _, addr := range addrs {
		ipnet, _ := addr.(*net.IPNet)
		ipList = append(ipList, ipnet.IP.String())
	}

	return &Firewall{
		iptables:                ipt,
		rateLimiter:             rateLimiter,
		geoDB:                   geoDB,
		logFile:                 logFile,
		logRotateChan:           logRotateChan,
		packetCapture:           packetCapture,
		interfaceName:           interfaceName,
		interfaceIPs:            ipList,
		logs_path:               logs_path,
		db_path:                 db_path,
		protocolCounters:        make(map[string]int),
		sourceIPCounters:        make(map[string]int),
		destIPCounters:          make(map[string]int),
		geoCounters:             make(map[string]int),
		ruleBlockCounters:       make(map[string]int),
		bandwidthUsage:          make(map[string]uint16),
		lastBandwidthTime:       time.Now(),
		bandwidthUpdateInterval: 1 * time.Second,
	}, nil
}

// Start the firewall and log rotation logic
func (f *Firewall) Start() {
	go f.packetCapture.Start(f.handlePacket)
	for range f.logRotateChan {
		err := f.rotateLogs()
		if err != nil {
			panic(err)
		}
	}
}

// handlePacket is a callback function for processing each captured packet
func (f *Firewall) handlePacket(packet gopacket.Packet) {
	// Extract packet information and log it
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	if networkLayer == nil || transportLayer == nil {
		return
	}

	srcIP := networkLayer.NetworkFlow().Src().String()
	dstIP := networkLayer.NetworkFlow().Dst().String()
	protocol := transportLayer.LayerType().String()
	srcPort := transportLayer.TransportFlow().Src().String()
	dstPort := transportLayer.TransportFlow().Dst().String()
	direction := "incoming"

	_sourceIP := packet.NetworkLayer().NetworkFlow().Src().String()

	if slices.Contains(f.interfaceIPs, _sourceIP) {
		direction = "outgoing"
	}
	saveLog(fmt.Sprintf("[%s] %s:%s -> %s:%s (%s) - %s\n", direction, srcIP, srcPort, dstIP, dstPort, protocol, time.Now().Format("2006-01-02 15:04:0")))

	// log.Printf("[%s] %s:%s -> %s:%s (%s) - %s\n", direction, srcIP, srcPort, dstIP, dstPort, protocol, time.Now().Format(time.RFC3339))

	// Example: Block packets from a specific country (e.g., China)
	if f.isBlockedCountry(srcIP, "CN") {
		log.Printf("Dropping packet from blocked country: %s\n", srcIP)
		f.ruleBlockCounters["CountryBlock"]++
		return
	}

	// Update counters for traffic breakdown
	err := f.updateTrafficCounters(srcIP, dstIP, protocol)
	if err != nil {
		log.Printf("Error updating traffic counters: %s\n", err)
	}

	// Update bandwidth usage
	f.updateBandwidthUsage(packet)
}

var in_out_log []string

func saveLog(package_log string) {

	if len(in_out_log) > 10000 {
		in_out_log = nil
	}

	in_out_log = append(in_out_log, package_log)

}

func (f *Firewall) Get_in_out_log() []string {
	slices.Reverse(in_out_log)
	return in_out_log
}

// Rotate logs by creating a new log file and updating the log file reference
func (f *Firewall) rotateLogs() error {
	f.logMutex.Lock()
	defer f.logMutex.Unlock()

	// Close the current log file
	if f.logFile != nil {
		f.logFile.Close()
	}

	// Rename the current log file to include a timestamp (e.g., firewall_log_2023-12-01.txt)
	newLogFileName := fmt.Sprintf("firewall_log_%s.txt", time.Now().Format("2006-01-02"))
	err := os.Rename(f.logs_path+"current_log.txt", f.logs_path+newLogFileName)
	if err != nil {
		log.Printf("Error rotating logs: %s\n", err)
	}

	// Open a new log file for writing
	logFile, err := os.OpenFile(f.logs_path+"current_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening new log file: %s\n", err)
		return err
	}

	// Update the log file reference
	f.logFile = logFile
	return nil
}

// Log blocked traffic
func (f *Firewall) logBlockedTraffic(sourceIP, destinationIP net.IP, reason string) error {
	f.logMutex.Lock()
	defer f.logMutex.Unlock()

	// Create a new log entry
	logEntry := LogEntry{
		Timestamp:     time.Now(),
		SourceIP:      sourceIP,
		DestinationIP: destinationIP,
		Reason:        reason,
	}

	// Append the log entry to the log entries slice
	f.logEntries = append(f.logEntries, logEntry)

	// Log the entry to the current log file
	logLine := fmt.Sprintf("[%s] Blocked traffic from %s to %s: %s\n", logEntry.Timestamp, sourceIP, destinationIP, reason)
	if _, err := f.logFile.WriteString(logLine); err != nil {
		log.Printf("Error writing to log file: %s\n", err)
		return err
	}
	return nil

}

// BlockIP blocks traffic from a specific IP
func (f *Firewall) BlockIP(ip net.IP, reason string) (string, error) {
	// Block traffic from a specific IP
	err := f.iptables.Insert("filter", "INPUT", 1, "-s", ip.String(), "-j", "DROP")
	if err != nil {
		log.Printf("Error blocking IP %s: %s\n", ip, err)
		return "", err
	}

	// Log the blocked traffic
	err = f.logBlockedTraffic(ip, nil, reason)
	if err != nil {
		log.Println(err)
	}
	return fmt.Sprintf("Blocked traffic from IP %s", ip), nil
}

func (f *Firewall) UnblockIP(ip net.IP, reason string) (string, error) {
	// Remove the rule blocking traffic from a specific IP
	err := f.iptables.Delete("filter", "INPUT", "-s", ip.String(), "-j", "DROP")
	if err != nil {
		log.Printf("Error unblocking IP %s: %s\n", ip, err)
		return "", err
	}

	// Log the unblocked traffic
	err = f.logBlockedTraffic(ip, nil, reason)
	if err != nil {
		log.Println(err)
	}

	return fmt.Sprintf("Unblocked traffic from IP %s", ip), nil
}

func (f *Firewall) GetBlockedIPs() (string, error) {
	cmd := exec.Command("/usr/sbin/iptables", "-L", "INPUT", "-v", "-n", "--line-numbers")
	println(cmd)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return "", fmt.Errorf("error running iptables command: %v", err)
	}

	return string(output), nil
}

func (f *Firewall) BlockPort(port int, reason string) (string, error) {
	// Block traffic on a specific port
	err := f.iptables.Insert("filter", "INPUT", 1, "-p", fmt.Sprintf("%d", port), "-j", "DROP")
	if err != nil {
		log.Printf("Error blocking port %d: %s\n", port, err)
		return "", err
	}

	// Log the blocked traffic
	err = f.logBlockedTraffic(nil, nil, fmt.Sprintf("Blocked traffic on port %d: %s", port, reason))
	if err != nil {
		log.Println(err)
	}
	return fmt.Sprintf("Blocked traffic on port %d", port), nil
}

func (f *Firewall) UnblockPort(port int) (string, error) {
	// Remove the rule blocking traffic on a specific port
	err := f.iptables.Delete("filter", "INPUT", "-p", fmt.Sprintf("%d", port), "-j", "DROP")
	if err != nil {
		log.Printf("Error unblocking port %d: %s\n", port, err)
		return "", err
	}

	// Log the unblocked traffic
	err = f.logBlockedTraffic(nil, nil, fmt.Sprintf("Unblocked traffic on port %d", port))
	if err != nil {
		log.Println(err)
	}
	return fmt.Sprintf("Unblocked traffic on port %d", port), nil

}

// Blocks traffic of a specific protocol
func (f *Firewall) BlockProtocol(protocol string, reason string) (string, error) {
	// Block traffic of a specific protocol
	err := f.iptables.Insert("filter", "INPUT", 1, "-p", protocol, "-j", "DROP")
	if err != nil {
		log.Printf("Error blocking protocol %s: %s\n", protocol, err)
		return "", err
	}

	// Log the blocked traffic
	err = f.logBlockedTraffic(nil, nil, fmt.Sprintf("Blocked traffic of protocol %s: %s", protocol, reason))
	if err != nil {
		log.Println(err)
	}
	return fmt.Sprintf("Blocked traffic of protocol %s", protocol), nil
}

// Unblocks traffic of a specific protocol
func (f *Firewall) UnblockProtocol(protocol string) (string, error) {
	// Unblock traffic of a specific protocol
	err := f.iptables.Delete("filter", "INPUT", "-p", protocol, "-j", "DROP")
	if err != nil {
		log.Printf("Error unblocking protocol %s: %s\n", protocol, err)
		return "", err
	}

	// Log the unblocked traffic
	err = f.logBlockedTraffic(nil, nil, fmt.Sprintf("Unblocked traffic of protocol %s", protocol))
	if err != nil {
		log.Println(err)
	}
	return fmt.Sprintf("Unblocked traffic of protocol %s", protocol), nil
}

// Allows dynamic rate limiting for each IP
func (f *Firewall) RateLimitIP(ip net.IP, limit int, duration time.Duration) bool {
	// Check if a rate limiter already exists for the given IP
	limiter, exists := f.rateLimiter[ip.String()]
	if !exists {
		// If not, create a new rate limiter with the specified limit and add it to the map
		limiter = rate.NewLimiter(rate.Limit(limit), 1)
		f.rateLimiter[ip.String()] = limiter
	}

	// Check if the rate limit is exceeded for the given IP
	if !limiter.Allow() {
		// Log the reason for blocking
		fmt.Printf("Blocked traffic from IP %s: Rate limit exceeded\n", ip)
		// Log the rate limit action
		err := f.logBlockedTraffic(ip, nil, fmt.Sprintf("Rate limited traffic from IP %s: %d requests per %s", ip, limit, duration))
		if err != nil {
			log.Println(err)
		}
		return true
	}

	return false
}

func (f *Firewall) GeoBlock(ip net.IP, reason string) bool {
	// Perform GeoIP lookup
	record, err := f.geoDB.Country(ip)
	if err != nil {
		log.Printf("Error performing GeoIP lookup: %s\n", err)
		return false
	}

	// If the country code is in the blocklist (e.g., "US")
	blocklist := []string{"US"} // ****Need to make it dynamic****
	for _, blockedCode := range blocklist {
		if record.Country.IsoCode == blockedCode {
			// Log the reason for blocking
			fmt.Printf("Blocked traffic from IP %s: Geo-blocked\n", ip)
			// Log the blocked traffic
			err := f.logBlockedTraffic(ip, nil, fmt.Sprintf("Blocked traffic from IP %s based on geo-location: %s", ip, reason))
			if err != nil {
				log.Println(err)
			}
			return true
		}
	}

	return false
}

// Checks if the source IP belongs to a blocked country
func (f *Firewall) isBlockedCountry(ip string, countryCode string) bool {
	record, err := f.geoDB.Country(net.ParseIP(ip))
	if err != nil {
		log.Printf("There is an err %s", err.Error())
		return false
	}

	return record.Country.IsoCode == countryCode
}

// Updates counters for traffic breakdown
func (f *Firewall) updateTrafficCounters(srcIP, dstIP, protocol string) error {
	f.protocolCounters[protocol]++
	f.sourceIPCounters[srcIP]++
	f.destIPCounters[dstIP]++

	// Use GeoIP to determine geography and update counters
	geoInfo, err := f.geoDB.Country(net.ParseIP(srcIP))
	if err == nil {
		countryCode := geoInfo.Country.IsoCode
		f.geoCounters[countryCode]++
		return nil
	}
	return err
}

// Updates bandwidth usage based on packet size
func (f *Firewall) updateBandwidthUsage(packet gopacket.Packet) {
	if len(f.bandwidthUsage) > 10 {
		f.bandwidthUsage = make(map[string]uint16)
	}
	// packetSize := packet.Metadata().CaptureInfo.Length
	packetSize := f.getTotalLength(packet)
	currentTime := time.Now()

	// Check if it's time to update bandwidth usage
	if currentTime.Sub(f.lastBandwidthTime) >= f.bandwidthUpdateInterval {

		index := strconv.Itoa(currentTime.Hour()) + ":" + strconv.Itoa(currentTime.Minute())
		f.bandwidthUsage[index] += packetSize

		f.lastBandwidthTime = currentTime
	}

}

func (f *Firewall) getTotalLength(packet gopacket.Packet) uint16 {
	var (
		eth  layers.Ethernet
		ipv4 layers.IPv4
		ipv6 layers.IPv6
		tcp  layers.TCP
		err  error
	)
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth,
		&ipv4,
		&ipv6,
		&tcp)

	var layersInPacket []gopacket.LayerType

	err = parser.DecodeLayers(packet.Data(), &layersInPacket)
	var total_len uint16
	total_len = 0
	if err == nil {
		total_len = ipv4.Length - uint16(ipv4.IHL*4)
	}
	return total_len
}

// // Display traffic breakdown counters
// func (f *Firewall) displayTrafficCounters() {
// 	fmt.Println("Protocol Counters:")
// 	fmt.Println(f.protocolCounters)

// 	fmt.Println("Source IP Counters:")
// 	fmt.Println(f.sourceIPCounters)

// 	fmt.Println("Destination IP Counters:")
// 	fmt.Println(f.destIPCounters)

// 	fmt.Println("Geography Counters:")
// 	fmt.Println(f.geoCounters)
// }

// // Display rule block counters
// func (f *Firewall) displayRuleBlockCounters() {
// 	fmt.Println("Rule Block Counters:")
// 	fmt.Println(f.ruleBlockCounters)
// }

func (f *Firewall) DisplayBandwidthUsage() map[string]uint16 {
	return f.bandwidthUsage
}
