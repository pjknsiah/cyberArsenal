# Port Scanner

A Python-based TCP port scanner for network reconnaissance and security assessment.

## Quick Start

```bash
python port_scanner.py
```

Enter target (hostname/IP), start port, and end port when prompted.

## Features

- TCP port scanning with configurable ranges (1-65535)
- Automatic hostname resolution
- Service identification for open ports
- Clean, timestamped output
- Error handling and graceful exits

## Requirements

- Python 3.6+
- Standard library only (no external dependencies)

## Usage Examples

**Scan local machine:**
```
Target: localhost
Ports: 1-1000
```

**Scan web server:**
```
Target: example.com
Ports: 80-443
```

## Technical Overview

### Architecture

Uses TCP connect scanning via Python's `socket` module. Completes full three-way handshake for reliability.

### Key Functions

**`scan_port(target, port, timeout=1)`**  
Attempts TCP connection to specified port. Returns `True` if open.

**`get_service_name(port)`**  
Maps port numbers to known services (http, ssh, etc.).

**`scan_target(target, start_port, end_port)`**  
Orchestrates port range scanning and result reporting.

### Output Format

```
Scanning target: 192.168.1.1
[+] Port 22 is OPEN - Service: ssh
[+] Port 80 is OPEN - Service: http
Total open ports found: 2
```

## Security & Legal Notice

⚠️ **Educational purposes only. Only scan systems you own or have explicit permission to test.**

Unauthorized port scanning may violate computer crime laws including the CFAA. Always obtain written authorization.

## Code Quality

- Input validation for ports and hostnames
- Exception handling for network errors
- Keyboard interrupt support
- Type hints ready (future enhancement)

## Future Enhancements

- Multi-threading for faster scans
- CLI arguments (`-t`, `-p`, `-o`)
- Banner grabbing and version detection
- JSON/CSV output formats
- UDP support
- Progress indicators

## Project Structure

```
port-scanner/
├── port_scanner.py    # Main scanner implementation
└── README.md          # This file
```

## Performance

- Sequential scanning: ~1 second per port
- Timeout configurable (default: 1s)
- Full port scan (65535 ports): ~18 hours
- Recommended range: 1-1024 (common ports)

## Learning Outcomes

This project demonstrates:
- Socket programming in Python
- Network protocol understanding (TCP/IP)
- Error handling and user input validation
- Security tool development principles
- Ethical hacking foundations

## Related Tools

- **Nmap** - Industry standard port scanner
- **Masscan** - High-speed scanner
- **Netcat** - Network utility for testing

## License

MIT License - See LICENSE file for details

---
