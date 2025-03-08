package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/natefinch/lumberjack.v2"
)

// HTTP ve HTTPS portları
var httpPorts = map[uint16]bool{
	80:   true,
	8080: true,
	8000: true,
}

var httpsPorts = map[uint16]bool{
	443:  true,
	8443: true,
}

// İstatistikleri tutmak için struct
type TrafficStats struct {
	HTTPPackets   int
	HTTPSPackets  int
	TotalBytes    int
	UniqueIPs     map[string]bool
	UniqueDomains map[string]bool
	mutex         sync.Mutex
}

// Tüm çalışan goroutineler ve kapatma işlemleri için global değişkenler
var (
	handles        []*pcap.Handle
	handlesMutex   sync.Mutex
	shutdownSignal chan struct{}
	globalStats    TrafficStats
)

// Log rotasyon ayarları
type LogRotationConfig struct {
	MaxSize    int  // MB cinsinden maksimum dosya boyutu
	MaxBackups int  // Saklanacak maksimum dosya sayısı
	MaxAge     int  // Gün cinsinden maksimum dosya yaşı
	Compress   bool // Eski dosyaları sıkıştır
}

// Varsayılan log rotasyon ayarları
var defaultLogRotationConfig = LogRotationConfig{
	MaxSize:    10,   // 10 MB
	MaxBackups: 5,    // 5 dosya
	MaxAge:     30,   // 30 gün
	Compress:   true, // Sıkıştırma aktif
}

// İzleme durumunu temsil eden struct
type HTTPTrafficLogger struct {
	logFile    *os.File
	deviceName string
	logger     *log.Logger
	stats      TrafficStats
	lumberjack *lumberjack.Logger // Log rotasyon için
}

// Yeni bir izleyici oluşturur
func NewHTTPTrafficLogger(logFilePath, deviceName string) (*HTTPTrafficLogger, error) {
	// Log rotasyon için lumberjack logger oluştur
	ljLogger := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    defaultLogRotationConfig.MaxSize,    // MB
		MaxBackups: defaultLogRotationConfig.MaxBackups, // dosya sayısı
		MaxAge:     defaultLogRotationConfig.MaxAge,     // gün
		Compress:   defaultLogRotationConfig.Compress,   // sıkıştırma
	}

	// Başlık ekle
	header := "Timestamp | Interface | Protocol | Source -> Destination | Real IP | Flags | Size | Domain\n"
	header += "---------------------------------------------------------------------------------------------\n"
	if _, err := ljLogger.Write([]byte(header)); err != nil {
		return nil, fmt.Errorf("başlık yazılamadı: %v", err)
	}

	// Program başlangıcını logla
	startLog := fmt.Sprintf("--- HTTP/HTTPS Trafik İzleme Başlatıldı: %s (Cihaz: %s) ---\n",
		time.Now().Format("2006-01-02 15:04:05"), deviceName)
	if _, err := ljLogger.Write([]byte(startLog)); err != nil {
		return nil, fmt.Errorf("başlangıç logu yazılamadı: %v", err)
	}

	return &HTTPTrafficLogger{
		logFile:    nil, // artık doğrudan dosya kullanmıyoruz
		deviceName: deviceName,
		logger:     log.New(ljLogger, "", 0),
		lumberjack: ljLogger,
		stats: TrafficStats{
			UniqueIPs:     make(map[string]bool),
			UniqueDomains: make(map[string]bool),
		},
	}, nil
}

// Kaynakları temizler
func (l *HTTPTrafficLogger) Close() {
	// İstatistikleri loglayalım
	l.logStatistics()
	// lumberjack otomatik olarak kapatılacak
}

// İstatistikleri loglar
func (l *HTTPTrafficLogger) logStatistics() {
	stats := fmt.Sprintf("\n--- İzleme İstatistikleri ---\n")
	stats += fmt.Sprintf("Toplam HTTP Paketleri: %d\n", l.stats.HTTPPackets)
	stats += fmt.Sprintf("Toplam HTTPS Paketleri: %d\n", l.stats.HTTPSPackets)
	stats += fmt.Sprintf("Toplam Transfer Boyutu: %d bytes\n", l.stats.TotalBytes)
	stats += fmt.Sprintf("Benzersiz IP Adresleri: %d\n", len(l.stats.UniqueIPs))
	stats += fmt.Sprintf("Benzersiz Alan Adları: %d\n", len(l.stats.UniqueDomains))
	stats += "------------------------\n"

	l.lumberjack.Write([]byte(stats))
	fmt.Println(stats)
}

// HTTP veya HTTPS paketi mi kontrol eder
func isHTTPorHTTPS(tcp *layers.TCP) (bool, string) {
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	if httpPorts[srcPort] || httpPorts[dstPort] {
		return true, "HTTP"
	}

	if httpsPorts[srcPort] || httpsPorts[dstPort] {
		return true, "HTTPS"
	}

	return false, ""
}

// TCP bayraklarını string'e dönüştürür
func getTCPFlags(tcp *layers.TCP) string {
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

// HTTP başlıklarından gerçek IP adresini ve portunu çıkarır
func extractRealIPFromHTTPHeaders(payload []byte) (string, uint16) {
	payloadStr := string(payload)
	var realPort uint16 = 0

	// X-Forwarded-Port
	portStr := extractHeaderValue(payloadStr, "X-Forwarded-Port:")
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err == nil && port > 0 && port < 65536 {
			realPort = uint16(port)
		}
	}

	// X-Real-Port (bazen kullanılabilir)
	if realPort == 0 {
		xRealPort := extractHeaderValue(payloadStr, "X-Real-Port:")
		if xRealPort != "" {
			port, err := strconv.Atoi(xRealPort)
			if err == nil && port > 0 && port < 65536 {
				realPort = uint16(port)
			}
		}
	}

	// Cloudflare
	cfConnectingIP := extractHeaderValue(payloadStr, "CF-Connecting-IP:")
	if cfConnectingIP != "" {
		return cfConnectingIP, realPort
	}

	// X-Forwarded-For başlığı
	xForwardedFor := extractHeaderValue(payloadStr, "X-Forwarded-For:")
	if xForwardedFor != "" {
		// Birden fazla IP varsa ilkini al
		ip := xForwardedFor
		if strings.Contains(xForwardedFor, ",") {
			ip = strings.TrimSpace(strings.Split(xForwardedFor, ",")[0])
		}

		// IP:Port formatı kontrolü
		if strings.Contains(ip, ":") {
			parts := strings.Split(ip, ":")
			if len(parts) == 2 {
				// Port bilgisini al
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
	clientIP := extractHeaderValue(payloadStr, "Client-IP:")
	if clientIP != "" {
		// IP:Port formatı kontrolü
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
	xRealIP := extractHeaderValue(payloadStr, "X-Real-IP:")
	if xRealIP != "" {
		// IP:Port formatı kontrolü
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

	// True-Client-IP (Cloudflare'de kullanılır)
	trueClientIP := extractHeaderValue(payloadStr, "True-Client-IP:")
	if trueClientIP != "" {
		return trueClientIP, realPort
	}

	return "", realPort
}

// HTTP başlık değerini çıkarır
func extractHeaderValue(payload string, headerName string) string {
	re := regexp.MustCompile("(?i)" + regexp.QuoteMeta(headerName) + "\\s*([^\\r\\n]+)")
	matches := re.FindStringSubmatch(payload)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// Bir IP adresinin local olup olmadığını kontrol eder
func isLocalIPAddress(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Loopback adresleri (127.0.0.0/8)
	if ip.IsLoopback() {
		return true
	}

	// Link-local adresler (169.254.0.0/16)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 169 && ip4[1] == 254
	}

	// Private IP adresleri
	// 10.0.0.0/8
	// 172.16.0.0/12
	// 192.168.0.0/16
	if ip.IsPrivate() {
		return true
	}

	return false
}

// TLS Client Hello paketinden SNI (Server Name Indication) bilgisini çıkarır
// Bu fonksiyon HTTPS bağlantılarında hangi domain'e bağlanıldığını bulmak için kullanılır
func extractSNI(payload []byte) string {
	if len(payload) < 43 {
		return ""
	}

	// TLS protokolü kontrolü
	if payload[0] != 0x16 { // Handshake
		return ""
	}

	// TLS sürümü ve mesaj türü kontrolü
	// 0x01: Client Hello
	if payload[5] != 0x01 {
		return ""
	}

	offset := 43 // TLS başlığı ve Client Hello sabit alanları

	// Session ID varsa atla
	if len(payload) > offset {
		sessionIDLength := int(payload[offset])
		offset += 1 + sessionIDLength
	}

	// Cipher Suites'i atla
	if len(payload) > offset+2 {
		cipherSuitesLength := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		offset += 2 + cipherSuitesLength
	}

	// Compression Methods'u atla
	if len(payload) > offset+1 {
		compressionMethodsLength := int(payload[offset])
		offset += 1 + compressionMethodsLength
	}

	// Extensions'a ulaşamıyorsak çık
	if len(payload) < offset+2 {
		return ""
	}

	// Extensions toplam uzunluğu
	extensionsLength := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	// Tüm uzantıları incele
	extensionsEnd := offset + extensionsLength
	for offset < extensionsEnd {
		// Extension tipi ve uzunluğunu oku
		if len(payload) < offset+4 {
			return ""
		}
		extensionType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extensionLength := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		// SNI uzantısı (tip 0) arama
		if extensionType == 0 {
			// SNI listesi uzunluğunu atla
			if len(payload) < offset+2 {
				return ""
			}
			offset += 2

			// Girdi tipini kontrol et (0: hostname)
			if len(payload) < offset+1 || payload[offset] != 0 {
				return ""
			}
			offset++

			// Hostname uzunluğunu oku
			if len(payload) < offset+2 {
				return ""
			}
			hostnameLength := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
			offset += 2

			// Hostname'i çıkar
			if len(payload) < offset+hostnameLength {
				return ""
			}
			return string(payload[offset : offset+hostnameLength])
		}

		// Bu uzantıyı atla
		offset += extensionLength
	}

	return ""
}

// İzlemeyi başlatır
func (l *HTTPTrafficLogger) StartCapturing() error {
	// Canlı yakalama için ayarlar
	handle, err := pcap.OpenLive(l.deviceName, 1600, false, 500*time.Millisecond) // Timeout ekledik
	if err != nil {
		return fmt.Errorf("cihaz açılamadı %s: %v", l.deviceName, err)
	}
	defer handle.Close()

	// Sadece HTTP ve HTTPS portlarına giden TCP paketlerini filtrele
	if err := handle.SetBPFFilter("tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 443 or tcp port 8443"); err != nil {
		return fmt.Errorf("BPF filtresi ayarlanamadı: %v", err)
	}

	// Paket kaynağı oluştur
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Kesme sinyali yakala
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Paketleri işleme başla
	fmt.Printf("HTTP/HTTPS Trafik İzleyici (Gerçek IP Desteği ile)\n")
	fmt.Printf("----------------------------------------\n")
	fmt.Printf("Cihaz: %s\n", l.deviceName)
	fmt.Printf("HTTP portları izleniyor: 80, 8080, 8000\n")
	fmt.Printf("HTTPS portları izleniyor: 443, 8443\n")
	fmt.Printf("Durdurmak için Ctrl+C'ye basın...\n\n")

	for {
		select {
		case packet := <-packetSource.Packets():
			// IP ve TCP katmanlarını al
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)

			if ipLayer != nil && tcpLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				tcp, _ := tcpLayer.(*layers.TCP)

				// HTTP veya HTTPS trafiği mi kontrol et
				isHTTP, protocol := isHTTPorHTTPS(tcp)
				if isHTTP {
					timestamp := time.Now().Format("2006-01-02 15:04:05.000")
					srcIP := ip.SrcIP.String()
					dstIP := ip.DstIP.String()
					srcPort := uint16(tcp.SrcPort)
					dstPort := uint16(tcp.DstPort)
					flags := getTCPFlags(tcp)
					size := packet.Metadata().Length

					// Gerçek IP için başlangıç değeri
					realIP := "-"

					// Varsayılan log girişi
					logEntry := fmt.Sprintf("%s | %s | %s | %s:%d -> %s:%d",
						timestamp, l.deviceName, protocol, srcIP, srcPort, dstIP, dstPort)

					// HTTPS ise SNI bilgisini çıkarmaya çalış (TLS Client Hello'dan)
					domain := ""
					if protocol == "HTTPS" && tcp.SYN == false && tcp.PSH == true && tcp.ACK == true {
						// Uygulama verilerini al
						appLayer := packet.ApplicationLayer()
						if appLayer != nil {
							payload := appLayer.Payload()
							sni := extractSNI(payload)
							if sni != "" {
								domain = sni
							}
						}
					}

					// HTTP için hem host başlığını hem de gerçek IP adresini çıkarmaya çalış
					if protocol == "HTTP" && tcp.PSH == true && tcp.ACK == true {
						appLayer := packet.ApplicationLayer()
						if appLayer != nil {
							payload := appLayer.Payload()

							// Host başlığını ara
							payloadStr := string(payload)
							hostIndex := strings.Index(payloadStr, "Host: ")
							if hostIndex >= 0 {
								hostEnd := strings.Index(payloadStr[hostIndex:], "\r\n")
								if hostEnd > 0 {
									host := payloadStr[hostIndex+6 : hostIndex+hostEnd]
									domain = host
								}
							}

							// Gerçek IP adresini ve portunu HTTP başlıklarından çıkar
							extractedIP, extractedPort := extractRealIPFromHTTPHeaders(payload)
							if extractedIP != "" {
								realIP = extractedIP
								if extractedPort > 0 {
									realIP = fmt.Sprintf("%s:%d", extractedIP, extractedPort)
								}
							}
						}
					}

					// Lokak IP'leri filtreleme - sadece public IP'leri göster
					isLocalIP := isLocalIPAddress(srcIP)
					if isLocalIP && realIP == "-" {
						// Eğer kaynak IP local ve gerçek IP yoksa, bu paketi atlayabiliriz
						continue
					}

					// Loglamayı tamamla
					logEntry += fmt.Sprintf(" | %s | Flags: %s | Size: %d bytes", realIP, flags, size)

					if domain != "" {
						logEntry += fmt.Sprintf(" | Domain: %s", domain)

						// İstatistikleri güncelle
						l.stats.mutex.Lock()
						if protocol == "HTTP" {
							l.stats.HTTPPackets++
						} else if protocol == "HTTPS" {
							l.stats.HTTPSPackets++
						}
						l.stats.TotalBytes += size

						// Gerçek IP adresini kaydet (varsa)
						if realIP != "-" {
							l.stats.UniqueIPs[realIP] = true
						} else if !isLocalIP {
							// Yoksa ve local değilse kaynak IP'yi kullan
							l.stats.UniqueIPs[srcIP] = true
						}

						// Domain bilgisi varsa kaydet
						l.stats.UniqueDomains[domain] = true
						l.stats.mutex.Unlock()

						// Log dosyasına yaz
						l.logger.Println(logEntry)

						// Konsola da yazdır
						//fmt.Println(logEntry)
					}
				}
			}

		case <-signalChan:
			fmt.Println("\nPaket yakalama durduruluyor...")

			// Bitiş mesajını logla
			stopMsg := fmt.Sprintf("--- HTTP/HTTPS Trafik İzleme Durduruldu: %s ---\n",
				time.Now().Format("2006-01-02 15:04:05"))
			l.lumberjack.Write([]byte(stopMsg))

			return nil
		}
	}
}

// Tüm arayüzlerde izleme başlatır
func StartCapturingAllInterfaces(logFilePath string) error {
	// Log rotasyon için lumberjack logger oluştur
	ljLogger := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    defaultLogRotationConfig.MaxSize,    // MB
		MaxBackups: defaultLogRotationConfig.MaxBackups, // dosya sayısı
		MaxAge:     defaultLogRotationConfig.MaxAge,     // gün
		Compress:   defaultLogRotationConfig.Compress,   // sıkıştırma
	}

	// Global değişkenleri başlat
	shutdownSignal = make(chan struct{})
	handles = make([]*pcap.Handle, 0)
	globalStats = TrafficStats{
		UniqueIPs:     make(map[string]bool),
		UniqueDomains: make(map[string]bool),
	}

	// Başlık ekle
	header := "Timestamp | Interface | Protocol | Source -> Destination | Real IP | Flags | Size | Domain\n"
	header += "---------------------------------------------------------------------------------------------\n"
	if _, err := ljLogger.Write([]byte(header)); err != nil {
		return fmt.Errorf("başlık yazılamadı: %v", err)
	}

	// Program başlangıcını logla
	startLog := fmt.Sprintf("--- HTTP/HTTPS Trafik İzleme Başlatıldı (Tüm Arayüzler): %s ---\n",
		time.Now().Format("2006-01-02 15:04:05"))
	if _, err := ljLogger.Write([]byte(startLog)); err != nil {
		return fmt.Errorf("başlangıç logu yazılamadı: %v", err)
	}

	// Loglama için logger oluştur
	logger := log.New(ljLogger, "", 0)

	// Kullanılabilir cihazları bul
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("cihazlar listelenemiyor: %v", err)
	}

	if len(devices) == 0 {
		return fmt.Errorf("kullanılabilir ağ arabirimi bulunamadı")
	}

	// Tamamlanma için WaitGroup
	var wg sync.WaitGroup

	// Her bir arayüz için goroutine başlat
	activeInterfaces := 0
	for _, device := range devices {
		// Loopback arayüzlerini atla
		isLoopback := false
		for _, addr := range device.Addresses {
			if addr.IP.IsLoopback() {
				isLoopback = true
				break
			}
		}

		if isLoopback {
			fmt.Printf("Loopback arayüzü atlanıyor: %s\n", device.Name)
			continue
		}

		wg.Add(1)
		activeInterfaces++

		go func(dev pcap.Interface) {
			defer wg.Done()

			fmt.Printf("İzleniyor: %s\n", dev.Name)

			// Canlı yakalama için ayarlar (timeout değeriyle)
			handle, err := pcap.OpenLive(dev.Name, 1600, false, 500*time.Millisecond) // Timeout ekledik
			if err != nil {
				fmt.Printf("Cihaz açılamadı %s: %v\n", dev.Name, err)
				return
			}

			// Handle'ı global listeye ekle
			handlesMutex.Lock()
			handles = append(handles, handle)
			handlesMutex.Unlock()

			// Fonksiyon çıkışında handle'ı kapat
			defer func() {
				handlesMutex.Lock()
				handle.Close()
				handlesMutex.Unlock()
			}()

			// Sadece TCP paketlerini filtrele
			if err := handle.SetBPFFilter("tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 443 or tcp port 8443"); err != nil {
				fmt.Printf("BPF filtresi ayarlanamadı %s: %v\n", dev.Name, err)
				return
			}

			// Paket kaynağı oluştur
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packetChan := packetSource.Packets()

			// Paketleri işle ve aynı zamanda shutdown sinyalini dinle
			for {
				select {
				case <-shutdownSignal:
					// Shutdown sinyali alındı, çık
					return
				case packet, ok := <-packetChan:
					if !ok {
						// Kanal kapandı
						return
					}

					// IP ve TCP katmanlarını al
					ipLayer := packet.Layer(layers.LayerTypeIPv4)
					tcpLayer := packet.Layer(layers.LayerTypeTCP)

					if ipLayer != nil && tcpLayer != nil {
						ip, _ := ipLayer.(*layers.IPv4)
						tcp, _ := tcpLayer.(*layers.TCP)

						// HTTP veya HTTPS trafiği mi kontrol et
						isHTTP, protocol := isHTTPorHTTPS(tcp)
						if isHTTP {
							timestamp := time.Now().Format("2006-01-02 15:04:05.000")
							srcIP := ip.SrcIP.String()
							dstIP := ip.DstIP.String()
							srcPort := uint16(tcp.SrcPort)
							dstPort := uint16(tcp.DstPort)
							flags := getTCPFlags(tcp)
							size := packet.Metadata().Length

							// Gerçek IP için başlangıç değeri
							realIP := "-"

							// Varsayılan log girişi
							logEntry := fmt.Sprintf("%s | %s | %s | %s:%d -> %s:%d",
								timestamp, dev.Name, protocol, srcIP, srcPort, dstIP, dstPort)

							// HTTPS ise SNI bilgisini çıkarmaya çalış (TLS Client Hello'dan)
							domain := ""
							if protocol == "HTTPS" && tcp.SYN == false && tcp.PSH == true && tcp.ACK == true {
								// Uygulama verilerini al
								appLayer := packet.ApplicationLayer()
								if appLayer != nil {
									payload := appLayer.Payload()
									sni := extractSNI(payload)
									if sni != "" {
										domain = sni
									}
								}
							}

							// HTTP için hem host başlığını hem de gerçek IP adresini çıkarmaya çalış
							if protocol == "HTTP" && tcp.PSH == true && tcp.ACK == true {
								appLayer := packet.ApplicationLayer()
								if appLayer != nil {
									payload := appLayer.Payload()

									// Host başlığını ara
									payloadStr := string(payload)
									hostIndex := strings.Index(payloadStr, "Host: ")
									if hostIndex >= 0 {
										hostEnd := strings.Index(payloadStr[hostIndex:], "\r\n")
										if hostEnd > 0 {
											host := payloadStr[hostIndex+6 : hostIndex+hostEnd]
											domain = host
										}
									}

									// Gerçek IP adresini ve portunu HTTP başlıklarından çıkar
									extractedIP, extractedPort := extractRealIPFromHTTPHeaders(payload)
									if extractedIP != "" {
										realIP = extractedIP
										if extractedPort > 0 {
											realIP = fmt.Sprintf("%s:%d", extractedIP, extractedPort)
										}
									}
								}
							}

							// Lokak IP'leri filtreleme - sadece public IP'leri göster
							isLocalIP := isLocalIPAddress(srcIP)
							if isLocalIP && realIP == "-" {
								// Eğer kaynak IP local ve gerçek IP yoksa, bu paketi atlayabiliriz
								continue
							}

							// Loglamayı tamamla
							logEntry += fmt.Sprintf(" | %s | Flags: %s | Size: %d bytes", realIP, flags, size)

							if domain != "" {
								logEntry += fmt.Sprintf(" | Domain: %s", domain)

								// İstatistikleri güncelle
								globalStats.mutex.Lock()
								if protocol == "HTTP" {
									globalStats.HTTPPackets++
								} else if protocol == "HTTPS" {
									globalStats.HTTPSPackets++
								}
								globalStats.TotalBytes += size

								// Gerçek IP adresini kaydet (varsa)
								if realIP != "-" {
									globalStats.UniqueIPs[realIP] = true
								} else if !isLocalIP {
									// Yoksa ve local değilse kaynak IP'yi kullan
									globalStats.UniqueIPs[srcIP] = true
								}

								// Domain bilgisi varsa kaydet
								globalStats.UniqueDomains[domain] = true
								globalStats.mutex.Unlock()

								// Log dosyasına yaz
								logger.Println(logEntry)

								// Konsola da yazdır
								fmt.Println(logEntry)
							}
						}
					}
				}
			}
		}(device)
	}

	if activeInterfaces == 0 {
		return fmt.Errorf("hiçbir aktif ağ arayüzü bulunamadı")
	}

	// Ana program sonlanmasın diye beklet
	fmt.Println("Tüm arayüzler izleniyor (Gerçek IP Desteği ile)...")
	fmt.Printf("Toplam %d aktif arayüz izleniyor\n", activeInterfaces)
	fmt.Println("Durdurmak için Ctrl+C'ye basın...")

	// Kesme sinyali için bekle
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	fmt.Println("\nPaket yakalama durduruluyor...")

	// Bitiş mesajını logla
	stopMsg := fmt.Sprintf("--- HTTP/HTTPS Trafik İzleme Durduruldu: %s ---\n",
		time.Now().Format("2006-01-02 15:04:05"))
	ljLogger.Write([]byte(stopMsg))

	// Tüm goroutinelere sinyal gönder
	close(shutdownSignal)

	// Tüm handle'ları kapat
	handlesMutex.Lock()
	for _, h := range handles {
		h.Close()
	}
	handlesMutex.Unlock()

	// 3 saniye bekle ve tüm goroutinelerin tamamlanması için
	cleanupDone := make(chan struct{}, 1)
	go func() {
		wg.Wait()
		close(cleanupDone)
	}()

	select {
	case <-cleanupDone:
		// Tüm goroutineler düzgün bir şekilde tamamlandı
	case <-time.After(3 * time.Second):
		fmt.Println("Bazı goroutineler zamanında tamamlanmadı, ancak program çıkacak")
	}

	// İstatistikleri loglayalım
	stats := fmt.Sprintf("\n--- İzleme İstatistikleri (Tüm Arayüzler) ---\n")
	stats += fmt.Sprintf("Toplam HTTP Paketleri: %d\n", globalStats.HTTPPackets)
	stats += fmt.Sprintf("Toplam HTTPS Paketleri: %d\n", globalStats.HTTPSPackets)
	stats += fmt.Sprintf("Toplam Transfer Boyutu: %d bytes\n", globalStats.TotalBytes)
	stats += fmt.Sprintf("Benzersiz IP Adresleri: %d\n", len(globalStats.UniqueIPs))
	stats += fmt.Sprintf("Benzersiz Alan Adları: %d\n", len(globalStats.UniqueDomains))
	stats += "------------------------\n"

	ljLogger.Write([]byte(stats))
	fmt.Println(stats)

	fmt.Println("Paket yakalama durduruldu.")
	return nil
}

// Tüm public IP'leri olan cihazları bulmaya çalışır
func findPublicInterfaces() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var publicInterfaces []pcap.Interface
	for _, device := range devices {
		// Cihazın IP adresleri var mı kontrol et
		if len(device.Addresses) == 0 {
			continue
		}

		// Private olmayan IP'leri kontrol et
		for _, addr := range device.Addresses {
			ip := addr.IP
			// Loopback olmayan ve private range'de olmayan IP'leri bul
			if !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() {
				publicInterfaces = append(publicInterfaces, device)
				break
			}
		}
	}

	return publicInterfaces, nil
}

func main() {
	// Komut satırı argümanlarını işle
	var logFilePath string
	var deviceName string
	var listenAllInterfaces bool = false
	var logRotationConfig LogRotationConfig = defaultLogRotationConfig

	args := os.Args[1:]

	// Argümanları işle
	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Log rotasyon ayarları için kontrol
		if arg == "--max-size" && i+1 < len(args) {
			if size, err := strconv.Atoi(args[i+1]); err == nil {
				logRotationConfig.MaxSize = size
				i++
				continue
			}
		}

		if arg == "--max-backups" && i+1 < len(args) {
			if backups, err := strconv.Atoi(args[i+1]); err == nil {
				logRotationConfig.MaxBackups = backups
				i++
				continue
			}
		}

		if arg == "--max-age" && i+1 < len(args) {
			if age, err := strconv.Atoi(args[i+1]); err == nil {
				logRotationConfig.MaxAge = age
				i++
				continue
			}
		}

		if arg == "--no-compress" {
			logRotationConfig.Compress = false
			continue
		}

		// Diğer argümanları işle
		if i == 0 {
			if arg == "all" || arg == "any" {
				listenAllInterfaces = true
			} else {
				logFilePath = arg
			}
		} else if i == 1 && listenAllInterfaces {
			logFilePath = arg
		} else if i == 1 && !listenAllInterfaces {
			// İkinci argüman cihaz adı olabilir
			deviceName = arg
		} else if i == 2 && !listenAllInterfaces {
			// Üçüncü argüman cihaz adı olabilir
			deviceName = arg
		}
	}

	// Varsayılan log dosyası yolu
	if logFilePath == "" {
		logFilePath = "/var/log/http_traffic.log"
	}

	// Rotasyon ayarlarını güncelle
	defaultLogRotationConfig = logRotationConfig

	// Log rotasyon ayarlarını göster
	fmt.Println("Log Rotasyon Ayarları:")
	fmt.Printf("  Maksimum Dosya Boyutu: %d MB\n", defaultLogRotationConfig.MaxSize)
	fmt.Printf("  Maksimum Yedek Sayısı: %d\n", defaultLogRotationConfig.MaxBackups)
	fmt.Printf("  Maksimum Dosya Yaşı: %d gün\n", defaultLogRotationConfig.MaxAge)
	fmt.Printf("  Sıkıştırma: %v\n", defaultLogRotationConfig.Compress)

	// Tüm arayüzleri dinle ya da belirli bir arayüzü dinle
	if listenAllInterfaces {
		fmt.Println("Tüm ağ arayüzleri dinleniyor...")
		if err := StartCapturingAllInterfaces(logFilePath); err != nil {
			log.Fatalf("Tüm arayüzleri izleme başlatılamadı: %v", err)
		}
	} else {
		// Belirli bir arayüzü dinle
		logger, err := NewHTTPTrafficLogger(logFilePath, deviceName)
		if err != nil {
			log.Fatalf("İzleyici oluşturulamadı: %v", err)
		}
		defer logger.Close()

		fmt.Printf("%s arayüzü dinleniyor...\n", deviceName)
		if err := logger.StartCapturing(); err != nil {
			log.Fatalf("İzleme başlatılamadı: %v", err)
		}
	}

	fmt.Printf("Log dosyası kaydedildi: %s\n", logFilePath)
}
