package parser

import (
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"

	"github.com/aras/http_traffic_listener/pkg/config"
)

// IsHTTPorHTTPS checks if a TCP packet is HTTP or HTTPS
func IsHTTPorHTTPS(tcp *layers.TCP) (bool, string) {
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	if config.HTTPPorts[srcPort] || config.HTTPPorts[dstPort] {
		return true, "HTTP"
	}

	if config.HTTPSPorts[srcPort] || config.HTTPSPorts[dstPort] {
		return true, "HTTPS"
	}

	return false, ""
}

// GetTCPFlags converts TCP flags to a string
func GetTCPFlags(tcp *layers.TCP) string {
	var flags []string

	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}

	if len(flags) == 0 {
		return "-"
	}

	result := ""
	for i, flag := range flags {
		if i > 0 {
			result += ","
		}
		result += flag
	}
	return result
}

// ExtractRealIPFromHTTPHeaders extracts the real IP address and port from HTTP headers
func ExtractRealIPFromHTTPHeaders(payload []byte) (string, uint16) {
	payloadStr := string(payload)
	var realPort uint16 = 0

	// X-Forwarded-Port
	portStr := ExtractHeaderValue(payloadStr, "X-Forwarded-Port:")
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err == nil && port > 0 && port < 65536 {
			realPort = uint16(port)
		}
	}

	// X-Real-Port (sometimes available)
	if realPort == 0 {
		xRealPort := ExtractHeaderValue(payloadStr, "X-Real-Port:")
		if xRealPort != "" {
			port, err := strconv.Atoi(xRealPort)
			if err == nil && port > 0 && port < 65536 {
				realPort = uint16(port)
			}
		}
	}

	// Cloudflare
	cfConnectingIP := ExtractHeaderValue(payloadStr, "CF-Connecting-IP:")
	if cfConnectingIP != "" {
		return cfConnectingIP, realPort
	}

	// X-Forwarded-For header
	xForwardedFor := ExtractHeaderValue(payloadStr, "X-Forwarded-For:")
	if xForwardedFor != "" {
		// If multiple IPs, take the first one
		ip := xForwardedFor
		if strings.Contains(xForwardedFor, ",") {
			ip = strings.TrimSpace(strings.Split(xForwardedFor, ",")[0])
		}

		// Check for IP:Port format
		if strings.Contains(ip, ":") {
			parts := strings.Split(ip, ":")
			if len(parts) == 2 {
				// Get port information
				port, err := strconv.Atoi(parts[1])
				if err == nil && port > 0 && port < 65536 {
					realPort = uint16(port)
				}
				return parts[0], realPort
			}
		}

		return ip, realPort
	}

	// Client IP
	clientIP := ExtractHeaderValue(payloadStr, "Client-IP:")
	if clientIP != "" {
		// Check for IP:Port format
		if strings.Contains(clientIP, ":") {
			parts := strings.Split(clientIP, ":")
			if len(parts) == 2 {
				port, err := strconv.Atoi(parts[1])
				if err == nil && port > 0 && port < 65536 {
					realPort = uint16(port)
				}
				return parts[0], realPort
			}
		}
		return clientIP, realPort
	}

	// X-Real-IP
	xRealIP := ExtractHeaderValue(payloadStr, "X-Real-IP:")
	if xRealIP != "" {
		// Check for IP:Port format
		if strings.Contains(xRealIP, ":") {
			parts := strings.Split(xRealIP, ":")
			if len(parts) == 2 {
				port, err := strconv.Atoi(parts[1])
				if err == nil && port > 0 && port < 65536 {
					realPort = uint16(port)
				}
				return parts[0], realPort
			}
		}
		return xRealIP, realPort
	}

	// True-Client-IP (used by Cloudflare)
	trueClientIP := ExtractHeaderValue(payloadStr, "True-Client-IP:")
	if trueClientIP != "" {
		return trueClientIP, realPort
	}

	return "", realPort
}

// ExtractHeaderValue extracts an HTTP header value
func ExtractHeaderValue(payload string, headerName string) string {
	re := regexp.MustCompile("(?i)" + regexp.QuoteMeta(headerName) + "\\s*([^\\r\\n]+)")
	matches := re.FindStringSubmatch(payload)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// IsLocalIPAddress checks if an IP address is local
func IsLocalIPAddress(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Loopback addresses (127.0.0.0/8)
	if ip.IsLoopback() {
		return true
	}

	// Link-local addresses (169.254.0.0/16)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 169 && ip4[1] == 254
	}

	// Private IP addresses
	// 10.0.0.0/8
	// 172.16.0.0/12
	// 192.168.0.0/16
	if ip.IsPrivate() {
		return true
	}

	return false
}

// ExtractSNI extracts SNI (Server Name Indication) from TLS Client Hello packet
// This function is used to determine which domain is being connected to in HTTPS connections
func ExtractSNI(payload []byte) string {
	if len(payload) < 43 {
		return ""
	}

	// Check TLS protocol
	if payload[0] != 0x16 { // Handshake
		return ""
	}

	// Check TLS version and message type
	// 0x01: Client Hello
	if payload[5] != 0x01 {
		return ""
	}

	offset := 43 // TLS header and Client Hello fixed fields

	// Skip Session ID if present
	if len(payload) > offset {
		sessionIDLength := int(payload[offset])
		offset += 1 + sessionIDLength
	}

	// Skip Cipher Suites
	if len(payload) > offset+2 {
		cipherSuitesLength := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		offset += 2 + cipherSuitesLength
	}

	// Skip Compression Methods
	if len(payload) > offset+1 {
		compressionMethodsLength := int(payload[offset])
		offset += 1 + compressionMethodsLength
	}

	// If we can't reach Extensions, exit
	if len(payload) < offset+2 {
		return ""
	}

	// Extensions total length
	extensionsLength := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	// Examine all extensions
	extensionsEnd := offset + extensionsLength
	for offset < extensionsEnd {
		// Read extension type and length
		if len(payload) < offset+4 {
			return ""
		}
		extensionType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extensionLength := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		// Look for SNI extension (type 0)
		if extensionType == 0 {
			// Skip SNI list length
			if len(payload) < offset+2 {
				return ""
			}
			offset += 2

			// Check entry type (0: hostname)
			if len(payload) < offset+1 || payload[offset] != 0 {
				return ""
			}
			offset++

			// Read hostname length
			if len(payload) < offset+2 {
				return ""
			}
			hostnameLength := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
			offset += 2

			// Extract hostname
			if len(payload) < offset+hostnameLength {
				return ""
			}
			return string(payload[offset : offset+hostnameLength])
		}

		// Skip this extension
		offset += extensionLength
	}

	return ""
}

// ExtractURLFromHTTP extracts the full URL from an HTTP request
func ExtractURLFromHTTP(payload []byte) string {
	payloadStr := string(payload)
	
	// Extract request line
	requestLineRegex := regexp.MustCompile(`^(GET|POST|HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)\s+(\S+)\s+HTTP/[\d.]+`)
	matches := requestLineRegex.FindStringSubmatch(payloadStr)
	
	if len(matches) > 2 {
		path := matches[2]
		
		// Extract host
		host := ExtractHeaderValue(payloadStr, "Host:")
		if host != "" {
			// Check if the path is already a full URL
			if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
				return path
			}
			
			// Construct full URL
			return fmt.Sprintf("http://%s%s", host, path)
		}
	}
	
	return ""
}

// ExtractDomainFromURL extracts the domain part from a URL
func ExtractDomainFromURL(url string) string {
	// Remove protocol
	domain := url
	if strings.HasPrefix(domain, "http://") {
		domain = domain[7:]
	} else if strings.HasPrefix(domain, "https://") {
		domain = domain[8:]
	}
	
	// Remove path and query
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	
	// Remove port if present
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}
	
	return domain
}
