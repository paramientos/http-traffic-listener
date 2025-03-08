package logger

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/aras/http_traffic_listener/pkg/config"
	"github.com/aras/http_traffic_listener/pkg/parser"
)

// TrafficStats holds statistics about captured traffic
type TrafficStats struct {
	HTTPPackets    int
	HTTPSPackets   int
	TotalBytes     int
	UniqueIPs      map[string]bool
	UniqueDomains  map[string]bool
	UniqueURLs     map[string]bool // Added for URL tracking
	mutex          sync.Mutex
}

// HTTPTrafficLogger represents the traffic monitoring state
type HTTPTrafficLogger struct {
	logFile    *os.File
	deviceName string
	logger     *log.Logger
	stats      TrafficStats
	lumberjack *lumberjack.Logger // For log rotation
}

// NewHTTPTrafficLogger creates a new traffic logger instance
func NewHTTPTrafficLogger(logFilePath, deviceName string) (*HTTPTrafficLogger, error) {
	// Create lumberjack logger for log rotation
	ljLogger := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    config.DefaultLogRotationConfig.MaxSize,
		MaxBackups: config.DefaultLogRotationConfig.MaxBackups,
		MaxAge:     config.DefaultLogRotationConfig.MaxAge,
		Compress:   config.DefaultLogRotationConfig.Compress,
	}

	// Add header
	header := "Timestamp | Interface | Protocol | Source -> Destination | Real IP | Flags | Size | URL\n"
	header += "---------------------------------------------------------------------------------------------\n"
	if _, err := ljLogger.Write([]byte(header)); err != nil {
		return nil, fmt.Errorf("could not write header: %v", err)
	}

	// Log program start
	startLog := fmt.Sprintf("--- HTTP/HTTPS Traffic Monitoring Started: %s (Device: %s) ---\n",
		time.Now().Format("2006-01-02 15:04:05"), deviceName)
	if _, err := ljLogger.Write([]byte(startLog)); err != nil {
		return nil, fmt.Errorf("could not write start log: %v", err)
	}

	return &HTTPTrafficLogger{
		logFile:    nil, // We don't use file directly anymore
		deviceName: deviceName,
		logger:     log.New(ljLogger, "", 0),
		lumberjack: ljLogger,
		stats: TrafficStats{
			UniqueIPs:      make(map[string]bool),
			UniqueDomains:  make(map[string]bool),
			UniqueURLs:     make(map[string]bool),
		},
	}, nil
}

// Close cleans up resources
func (l *HTTPTrafficLogger) Close() {
	// Log statistics
	l.logStatistics()
	// lumberjack will be closed automatically
}

// logStatistics logs the traffic statistics
func (l *HTTPTrafficLogger) logStatistics() {
	stats := fmt.Sprintf("\n--- Monitoring Statistics ---\n")
	stats += fmt.Sprintf("Total HTTP Packets: %d\n", l.stats.HTTPPackets)
	stats += fmt.Sprintf("Total HTTPS Packets: %d\n", l.stats.HTTPSPackets)
	stats += fmt.Sprintf("Total Transfer Size: %d bytes\n", l.stats.TotalBytes)
	stats += fmt.Sprintf("Unique IP Addresses: %d\n", len(l.stats.UniqueIPs))
	stats += fmt.Sprintf("Unique Domains: %d\n", len(l.stats.UniqueDomains))
	stats += fmt.Sprintf("Unique URLs: %d\n", len(l.stats.UniqueURLs))
	stats += "------------------------\n"

	l.lumberjack.Write([]byte(stats))
	fmt.Println(stats)
}

// StartCapturing starts capturing traffic on a single interface
func (l *HTTPTrafficLogger) StartCapturing() error {
	// Settings for live capture
	handle, err := pcap.OpenLive(l.deviceName, 1600, false, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not open device %s: %v", l.deviceName, err)
	}
	defer handle.Close()

	// Filter only TCP packets to HTTP and HTTPS ports
	if err := handle.SetBPFFilter("tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 443 or tcp port 8443"); err != nil {
		return fmt.Errorf("could not set BPF filter: %v", err)
	}

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Capture interrupt signal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Start processing packets
	fmt.Printf("HTTP/HTTPS Traffic Monitor (with Real IP Support)\n")
	fmt.Printf("----------------------------------------\n")
	fmt.Printf("Device: %s\n", l.deviceName)
	fmt.Printf("Monitoring HTTP ports: 80, 8080, 8000\n")
	fmt.Printf("Monitoring HTTPS ports: 443, 8443\n")
	fmt.Printf("Press Ctrl+C to stop...\n\n")

	for {
		select {
		case packet := <-packetSource.Packets():
			// Get IP and TCP layers
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)

			if ipLayer != nil && tcpLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				tcp, _ := tcpLayer.(*layers.TCP)

				// Check if it's HTTP or HTTPS traffic
				isHTTP, protocol := parser.IsHTTPorHTTPS(tcp)
				if isHTTP {
					timestamp := time.Now().Format("2006-01-02 15:04:05.000")
					srcIP := ip.SrcIP.String()
					dstIP := ip.DstIP.String()
					srcPort := uint16(tcp.SrcPort)
					dstPort := uint16(tcp.DstPort)
					flags := parser.GetTCPFlags(tcp)
					size := packet.Metadata().Length

					// Default value for real IP
					realIP := "-"

					// Default log entry
					logEntry := fmt.Sprintf("%s | %s | %s | %s:%d -> %s:%d",
						timestamp, l.deviceName, protocol, srcIP, srcPort, dstIP, dstPort)

					// Try to extract SNI information from HTTPS (TLS Client Hello)
					url := ""
					if protocol == "HTTPS" && tcp.SYN == false && tcp.PSH == true && tcp.ACK == true {
						// Get application data
						appLayer := packet.ApplicationLayer()
						if appLayer != nil {
							payload := appLayer.Payload()
							sni := parser.ExtractSNI(payload)
							if sni != "" {
								// Create full HTTPS URL with SNI
								url = fmt.Sprintf("https://%s", sni)
							}
						}
					}

					// For HTTP, try to extract both host header and real IP address
					if protocol == "HTTP" && tcp.PSH == true && tcp.ACK == true {
						appLayer := packet.ApplicationLayer()
						if appLayer != nil {
							payload := appLayer.Payload()

							// Extract full URL from HTTP request
							fullURL := parser.ExtractURLFromHTTP(payload)
							if fullURL != "" {
								url = fullURL
							}

							// Extract real IP address and port from HTTP headers
							extractedIP, extractedPort := parser.ExtractRealIPFromHTTPHeaders(payload)
							if extractedIP != "" {
								realIP = extractedIP
								if extractedPort > 0 {
									realIP = fmt.Sprintf("%s:%d", extractedIP, extractedPort)
								}
							}
						}
					}

					// Filter local IPs - only show public IPs
					isLocalIP := parser.IsLocalIPAddress(srcIP)
					if isLocalIP && realIP == "-" {
						// If source IP is local and there's no real IP, we can skip this packet
						continue
					}

					// Complete the log entry
					logEntry += fmt.Sprintf(" | %s | Flags: %s | Size: %d bytes", realIP, flags, size)

					if url != "" {
						logEntry += fmt.Sprintf(" | URL: %s", url)

						// Update statistics
						l.stats.mutex.Lock()
						if protocol == "HTTP" {
							l.stats.HTTPPackets++
						} else if protocol == "HTTPS" {
							l.stats.HTTPSPackets++
						}
						l.stats.TotalBytes += size

						// Save real IP address (if available)
						if realIP != "-" {
							l.stats.UniqueIPs[realIP] = true
						} else if !isLocalIP {
							// Otherwise use source IP if not local
							l.stats.UniqueIPs[srcIP] = true
						}

						// Extract domain from URL
						domain := parser.ExtractDomainFromURL(url)
						
						// Save domain and URL information
						if domain != "" {
							l.stats.UniqueDomains[domain] = true
						}
						l.stats.UniqueURLs[url] = true
						l.stats.mutex.Unlock()

						// Write to log file
						l.logger.Println(logEntry)

						// Print to console
						//fmt.Println(logEntry)
					}
				}
			}

		case <-signalChan:
			fmt.Println("\nStopping packet capture...")

			// Log stop message
			stopMsg := fmt.Sprintf("--- HTTP/HTTPS Traffic Monitoring Stopped: %s ---\n",
				time.Now().Format("2006-01-02 15:04:05"))
			l.lumberjack.Write([]byte(stopMsg))

			return nil
		}
	}
}
