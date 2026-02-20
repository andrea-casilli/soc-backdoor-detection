# SOC Backdoor Detector for Linux

A security tool for detecting potential backdoors on Linux/Unix systems. Designed for SOC analysts and system administrators to identify suspicious files, processes, network connections, and persistence mechanisms.

## Features

- **File Analysis**: Detects setuid/setgid binaries, suspicious executables, and known backdoor hashes
- **Process Monitoring**: Identifies reverse shells, netcat listeners, and anomalous processes
- **Network Scanning**: Discovers non-standard listening ports and suspicious connections
- **Persistence Detection**: Analyzes cron jobs and systemd services for backdoor indicators
- **Comprehensive Reporting**: Generates detailed JSON reports with timestamp and hostname

## Installation

```bash
git clone https://github.com/yourusername/soc-backdoor-detector-linux.git
cd soc-backdoor-detector-linux
pip3 install -r requirements.txt
