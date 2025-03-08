package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/aras/http_traffic_listener/pkg/capture"
	"github.com/aras/http_traffic_listener/pkg/config"
	"github.com/aras/http_traffic_listener/pkg/logger"
)

func main() {
	// Process command line arguments
	var logFilePath string
	var deviceName string
	var listenAllInterfaces bool = false
	var logRotationConfig config.LogRotationConfig = config.DefaultLogRotationConfig

	args := os.Args[1:]

	// Process arguments
	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Check for log rotation settings
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

		// Process other arguments
		if i == 0 {
			if arg == "all" || arg == "any" {
				listenAllInterfaces = true
			} else {
				logFilePath = arg
			}
		} else if i == 1 && listenAllInterfaces {
			logFilePath = arg
		} else if i == 1 && !listenAllInterfaces {
			// Second argument could be device name
			deviceName = arg
		} else if i == 2 && !listenAllInterfaces {
			// Third argument could be device name
			deviceName = arg
		}
	}

	// Default log file path
	if logFilePath == "" {
		logFilePath = "/var/log/http_traffic.log"
	}

	// Update rotation settings
	config.DefaultLogRotationConfig = logRotationConfig

	// Show log rotation settings
	fmt.Println("Log Rotation Settings:")
	fmt.Printf("  Maximum File Size: %d MB\n", config.DefaultLogRotationConfig.MaxSize)
	fmt.Printf("  Maximum Backup Count: %d\n", config.DefaultLogRotationConfig.MaxBackups)
	fmt.Printf("  Maximum File Age: %d days\n", config.DefaultLogRotationConfig.MaxAge)
	fmt.Printf("  Compression: %v\n", config.DefaultLogRotationConfig.Compress)

	// Listen on all interfaces or a specific interface
	if listenAllInterfaces {
		fmt.Println("Listening on all network interfaces...")
		if err := capture.StartCapturingAllInterfaces(logFilePath); err != nil {
			log.Fatalf("Could not start monitoring all interfaces: %v", err)
		}
	} else {
		// Listen on a specific interface
		trafficLogger, err := logger.NewHTTPTrafficLogger(logFilePath, deviceName)
		if err != nil {
			log.Fatalf("Could not create logger: %v", err)
		}
		defer trafficLogger.Close()

		fmt.Printf("Listening on interface %s...\n", deviceName)
		if err := trafficLogger.StartCapturing(); err != nil {
			log.Fatalf("Could not start monitoring: %v", err)
		}
	}

	fmt.Printf("Log file saved: %s\n", logFilePath)
}
