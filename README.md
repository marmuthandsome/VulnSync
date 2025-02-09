# VulnSync - Automated Vulnerability Scanner & Exploitation Tool

VulnSync is an advanced security tool that combines port scanning, vulnerability assessment, and exploitation capabilities in one streamlined interface. It's designed for security professionals and penetration testers to efficiently identify and verify security vulnerabilities in target systems.

## Features

- **Multiple Scan Types:**
  - Fast Scan
  - Full Scan
  - Top Port Scan
  - UDP Scan

- **Service-Specific Vulnerability Scanning:**
  - SSH (Port 22)
  - FTP (Port 21)
  - Telnet (Port 23)
  - SMTP (Port 25)
  - HTTP/HTTPS (Ports 80/443)
  - SMB (Ports 139/445)
  - Redis (Port 6379)
  - VNC (Ports 5800/5801/5900/5901)
  - MongoDB (Ports 27017/27018)
  - PostgreSQL (Ports 5432/5433)
  - RDP (Port 3389)
  - MySQL (Port 3306)

- **Automated Exploitation:**
  - Built-in exploitation modules for confirmed vulnerabilities
  - Integration with Metasploit Framework
  - Custom exploit suggestions based on findings

## Prerequisites

- Root/sudo privileges
- Python 3.x
- Nmap
- Metasploit Framework
- Hydra (optional, for brute force attacks)
- MongoDB client (optional, for MongoDB exploitation)
- Various Python dependencies

## Installation

```bash
git clone https://github.com/yourusername/VulnSync.git
cd VulnSync
sudo python3 main_script.py
```

## Usage

1. Run the script with root privileges:
   ```bash
   sudo python3 main_script.py
   ```

2. Select scan type:
   - 1: Fast Scan
   - 2: Full Scan
   - 3: Top Port Scan
   - 4: UDP Scan

3. Enter target IP/URL when prompted

4. Review scan results and choose exploitation options if vulnerabilities are found

## Security Notice

This tool should only be used against systems you own or have explicit permission to test. Unauthorized scanning or exploitation of systems is illegal and unethical.

## Contributing

Contributions are welcome! Please feel free to submit pull requests with improvements or bug fixes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and professional security testing purposes only. Users are responsible for ensuring they have appropriate permissions before scanning any systems or networks.
