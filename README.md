# HTTP Traffic Listener

A powerful network monitoring tool that captures and logs HTTP and HTTPS traffic across network interfaces. The tool provides detailed insights into web traffic, including full URLs, protocols, and connection statistics.

## Features

- Captures both HTTP and HTTPS traffic
- Displays complete URLs for all requests
  - HTTP: Extracts full URL from request line and Host header
  - HTTPS: Uses SNI (Server Name Indication) information with https:// prefix
- Real-time traffic monitoring
- Detailed logging with the following information:
  - Timestamp
  - Network interface
  - Protocol (HTTP/HTTPS)
  - Source and destination addresses
  - Real IP (extracted from headers)
  - TCP flags
  - Packet size
  - Complete URLs
- Traffic statistics tracking:
  - HTTP and HTTPS packet counts
  - Total bytes transferred
  - Unique IPs
  - Unique domains
  - Unique URLs
- Log rotation support with configurable:
  - Maximum log file size
  - Number of backup files
  - Maximum age of backup files
  - Compression options

## Installation

```bash
# Clone the repository
git clone [repository-url]
cd http_traffic_listener

# Build the project
./build.sh
```

## Usage

```bash
./http_traffic_listener [options]

or

go run cmd/http_traffic_listener/main.go
```

### Command Line Options

- `--max-size`: Maximum size of log files in MB before rotation
- `--max-backups`: Maximum number of backup log files to keep
- `--device`: Specify network interface to monitor (e.g., en0, eth0)
- `--log`: Path to the log file
- `--all`: Monitor all available network interfaces

### Examples

```bash
# Monitor specific interface
./http_traffic_listener --device en0 --log traffic.log

# Monitor all interfaces with custom log rotation
./http_traffic_listener --all --log traffic.log --max-size 100 --max-backups 5
```

### Example Output

```
Timestamp | Interface | Protocol | Source -> Destination | Real IP | Flags | Size | URL
---------------------------------------------------------------------------------------------
2025-03-08 10:45:23 | en0 | HTTPS | 192.168.1.100:52431 -> 93.184.216.34:443 | - | [SYN] | 74 | https://example.com
2025-03-08 10:45:24 | en0 | HTTP | 192.168.1.100:52432 -> 93.184.216.34:80 | - | [PSH,ACK] | 428 | http://example.com/path/to/resource

--- Traffic Statistics ---
HTTP Packets: 1
HTTPS Packets: 1
Total Bytes: 502
Unique IPs: 2
Unique Domains: 1
Unique URLs: 2
```

The tool maintains real-time statistics about captured traffic, including:
- Number of HTTP and HTTPS packets
- Total bytes transferred
- Count of unique IP addresses
- Count of unique domains
- Count of unique complete URLs

## Requirements

- Go 1.21 or higher
- libpcap development files
- Root/sudo privileges (required for packet capture)

### Dependencies
- github.com/google/gopacket v1.1.19 (packet capture and analysis)
- gopkg.in/natefinch/lumberjack.v2 v2.2.1 (log rotation)

## Log Format

The log file contains entries in the following format:
```
Timestamp | Interface | Protocol | Source -> Destination | Real IP | Flags | Size | URL
```

## License

[License information]
