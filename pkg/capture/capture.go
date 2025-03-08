package capture

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/aras/http_traffic_listener/pkg/config"
	"github.com/aras/http_traffic_listener/pkg/parser"
)

// Global variables for all running goroutines and shutdown operations
var (
	handles        []*pcap.Handle
	handlesMutex   sync.Mutex
	shutdownSignal chan struct{}
	globalStats    struct {
		HTTPPackets    int
		HTTPSPackets   int
		TotalBytes     int
		UniqueIPs      map[string]bool
		UniqueDomains  map[string]bool
		UniqueURLs     map[string]bool
		mutex          sync.Mutex
	}
)

// StartCapturingAllInterfaces starts monitoring on all available interfaces
func StartCapturingAllInterfaces(logFilePath string) error {
	// Create lumberjack logger for log rotation
	ljLogger := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    config.DefaultLogRotationConfig.MaxSize,
		MaxBackups: config.DefaultLogRotationConfig.MaxBackups,
		MaxAge:     config.DefaultLogRotationConfig.MaxAge,
		Compress:   config.DefaultLogRotationConfig.Compress,
	}

	// Initialize global variables
	shutdownSignal = make(chan struct{})
	handles = make([]*pcap.Handle, 0)
	globalStats.UniqueIPs = make(map[string]bool)
	globalStats.UniqueDomains = make(map[string]bool)
	globalStats.UniqueURLs = make(map[string]bool)

	// Add header
	header := "Timestamp | Interface | Protocol | Source -> Destination | Real IP | Flags | Size | URL\n"
	header += "---------------------------------------------------------------------------------------------\n"
	if _, err := ljLogger.Write([]byte(header)); err != nil {
		return fmt.Errorf("could not write header: %v", err)
	}

	// Log program start
	startLog := fmt.Sprintf("--- HTTP/HTTPS Traffic Monitoring Started (All Interfaces): %s ---\n",
		time.Now().Format("2006-01-02 15:04:05"))
	if _, err := ljLogger.Write([]byte(startLog)); err != nil {
		return fmt.Errorf("could not write start log: %v", err)
	}

	// Create logger for logging
	logger := log.New(ljLogger, "", 0)

	// Find available devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("could not list devices: %v", err)
	}

	if len(devices) == 0 {
		return fmt.Errorf("no available network interfaces found")
	}

	// WaitGroup for completion
	var wg sync.WaitGroup

	// Start goroutine for each interface
	activeInterfaces := 0
	for _, device := range devices {
		// Skip loopback interfaces
		isLoopback := false
		for _, addr := range device.Addresses {
			if addr.IP.IsLoopback() {
				isLoopback = true
				break
			}
		}

		if isLoopback {
			fmt.Printf("Skipping loopback interface: %s\n", device.Name)
			continue
		}

		wg.Add(1)
		activeInterfaces++

		go func(dev pcap.Interface) {
			defer wg.Done()

			fmt.Printf("Monitoring: %s\n", dev.Name)

			// Settings for live capture (with timeout)
			handle, err := pcap.OpenLive(dev.Name, 1600, false, 500*time.Millisecond)
			if err != nil {
				fmt.Printf("Could not open device %s: %v\n", dev.Name, err)
				return
			}

			// Add handle to global list
			handlesMutex.Lock()
			handles = append(handles, handle)
			handlesMutex.Unlock()

			// Close handle on function exit
			defer func() {
				handlesMutex.Lock()
				handle.Close()
				handlesMutex.Unlock()
			}()

			// Filter only TCP packets
			if err := handle.SetBPFFilter("tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 443 or tcp port 8443"); err != nil {
				fmt.Printf("Could not set BPF filter %s: %v\n", dev.Name, err)
				return
			}

			// Create packet source
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packetChan := packetSource.Packets()

			// Process packets and listen for shutdown signal
			for {
				select {
				case <-shutdownSignal:
					// Shutdown signal received, exit
					return
				case packet, ok := <-packetChan:
					if !ok {
						// Channel closed
						return
					}

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
								timestamp, dev.Name, protocol, srcIP, srcPort, dstIP, dstPort)

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
								globalStats.mutex.Lock()
								if protocol == "HTTP" {
									globalStats.HTTPPackets++
								} else if protocol == "HTTPS" {
									globalStats.HTTPSPackets++
								}
								globalStats.TotalBytes += size

								// Save real IP address (if available)
								if realIP != "-" {
									globalStats.UniqueIPs[realIP] = true
								} else if !isLocalIP {
									// Otherwise use source IP if not local
									globalStats.UniqueIPs[srcIP] = true
								}

								// Extract domain from URL
								domain := parser.ExtractDomainFromURL(url)
								
								// Save domain and URL information
								if domain != "" {
									globalStats.UniqueDomains[domain] = true
								}
								globalStats.UniqueURLs[url] = true
								globalStats.mutex.Unlock()

								// Write to log file
								logger.Println(logEntry)

								// Print to console
								fmt.Println(logEntry)
							}
						}
					}
				}
			}
		}(device)
	}

	if activeInterfaces == 0 {
		return fmt.Errorf("no active network interfaces found")
	}

	// Keep main program alive
	fmt.Println("Monitoring all interfaces (with Real IP Support)...")
	fmt.Printf("Monitoring %d active interfaces\n", activeInterfaces)
	fmt.Println("Press Ctrl+C to stop...")

	// Wait for interrupt signal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	fmt.Println("\nStopping packet capture...")

	// Log stop message
	stopMsg := fmt.Sprintf("--- HTTP/HTTPS Traffic Monitoring Stopped: %s ---\n",
		time.Now().Format("2006-01-02 15:04:05"))
	ljLogger.Write([]byte(stopMsg))

	// Send signal to all goroutines
	close(shutdownSignal)

	// Close all handles
	handlesMutex.Lock()
	for _, h := range handles {
		h.Close()
	}
	handlesMutex.Unlock()

	// Wait 3 seconds for all goroutines to complete
	cleanupDone := make(chan struct{}, 1)
	go func() {
		wg.Wait()
		close(cleanupDone)
	}()

	select {
	case <-cleanupDone:
		// All goroutines completed properly
	case <-time.After(3 * time.Second):
		fmt.Println("Some goroutines did not complete in time, but the program will exit")
	}

	// Log statistics
	stats := fmt.Sprintf("\n--- Monitoring Statistics (All Interfaces) ---\n")
	stats += fmt.Sprintf("Total HTTP Packets: %d\n", globalStats.HTTPPackets)
	stats += fmt.Sprintf("Total HTTPS Packets: %d\n", globalStats.HTTPSPackets)
	stats += fmt.Sprintf("Total Transfer Size: %d bytes\n", globalStats.TotalBytes)
	stats += fmt.Sprintf("Unique IP Addresses: %d\n", len(globalStats.UniqueIPs))
	stats += fmt.Sprintf("Unique Domains: %d\n", len(globalStats.UniqueDomains))
	stats += fmt.Sprintf("Unique URLs: %d\n", len(globalStats.UniqueURLs))
	stats += "------------------------\n"

	ljLogger.Write([]byte(stats))
	fmt.Println(stats)

	fmt.Println("Packet capture stopped.")
	return nil
}

// FindPublicInterfaces tries to find all devices with public IPs
func FindPublicInterfaces() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var publicInterfaces []pcap.Interface
	for _, device := range devices {
		// Check if device has IP addresses
		if len(device.Addresses) == 0 {
			continue
		}

		// Check for non-private IPs
		for _, addr := range device.Addresses {
			ip := addr.IP
			// Find IPs that are not loopback, not private, and not unspecified
			if !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() {
				publicInterfaces = append(publicInterfaces, device)
				break
			}
		}
	}

	return publicInterfaces, nil
}
