# PyRecon Port Scanner

A fast, multi-threaded port scanner written in Python that helps identify open ports on target systems.

PyRecon is a network reconnaissance tool designed to scan TCP ports on target hosts to identify which services are running and accessible. It uses Python's threading capabilities to perform fast, concurrent port scans while providing detailed logging and flexible output options.

**Key Features:**
- Multi-threaded scanning for improved performance
- Support for single ports, port lists, and port ranges
- Verbose and quiet output modes
- Results can be saved to file
- Cross-platform compatibility (Windows, Linux, macOS)
- Graceful handling of interruptions (Ctrl+C)
- Hostname resolution support

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

## Installation

Since PyRecon uses only Python's standard library, no additional installation is required.

1. **Download the script:**
   
   - Clone or download pyrecon.py to your local machine

2. **Make it executable (Linux/macOS):**
   ```bash
   chmod +x pyrecon.py
   ```

## Usage

### Basic Syntax
```bash
python pyrecon.py [target] [options]
```

### Quick Examples

**Scan common ports on a target:**
```bash
python pyrecon.py 192.168.1.1
```

**Scan specific ports:**
```bash
python pyrecon.py example.com -p 22,80,443,3389
```

**Scan a port range:**
```bash
python pyrecon.py 10.0.0.1 -p 1-100
```

**Scan with verbose output:**
```bash
python pyrecon.py 192.168.1.1 -v
```

**Save results to file:**
```bash
python pyrecon.py 192.168.1.1 -o scan_results.txt
```

**Custom thread count for faster scanning:**
```bash
python pyrecon.py 192.168.1.1 -t 100
```

**Comprehensive scan with all options:**
```bash
python pyrecon.py example.com -p 1-65535 -t 200 -v -o full_scan.txt
```

### Help Command Output

```
usage: pyrecon.py [-h] [--version] [-p PORTS] [-t THREADS] [-v] [-o OUTPUT] target

PyRecon port scanner

positional arguments:
  target                Target IP address or hostname

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p PORTS, --ports PORTS
                        Comma-separated list of ports or range (default = 1-1023)
  -t THREADS, --threads THREADS
                        Number of threads to use (default = 50)
  -v, --verbose         Enable verbose output - show all ports, including closed ones(optional)
  -o OUTPUT, --output OUTPUT
                        Output results of scan to a .txt file (optional)
```

## Options Explained

| Option | Description | Default |
|--------|-------------|---------|
| `target` | IP address or hostname to scan | Required |
| `-p, --ports` | Ports to scan (single, list, or range) | 1-1023 |
| `-t, --threads` | Number of concurrent threads | 50 |
| `-v, --verbose` | Show all ports (including closed) | Only open ports |
| `-o, --output` | Save results to specified file | Screen output only |
| `--version` | Display version information | - |

## Legal Notice

This tool is intended for authorized network testing and security assessment only. Always ensure you have proper permission before scanning networks or systems that you do not own or administer.