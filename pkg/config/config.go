package config

// LogRotationConfig defines the log rotation settings
type LogRotationConfig struct {
	MaxSize    int  // Maximum file size in MB
	MaxBackups int  // Maximum number of backups to keep
	MaxAge     int  // Maximum age of backup files in days
	Compress   bool // Whether to compress old files
}

// DefaultLogRotationConfig provides default log rotation settings
var DefaultLogRotationConfig = LogRotationConfig{
	MaxSize:    10,   // 10 MB
	MaxBackups: 5,    // 5 files
	MaxAge:     30,   // 30 days
	Compress:   true, // Compression enabled
}

// Ports defines the HTTP and HTTPS ports to monitor
var (
	// HTTPPorts contains the ports used for HTTP traffic
	HTTPPorts = map[uint16]bool{
		80:   true,
		8080: true,
		8000: true,
	}

	// HTTPSPorts contains the ports used for HTTPS traffic
	HTTPSPorts = map[uint16]bool{
		443:  true,
		8443: true,
	}
)
