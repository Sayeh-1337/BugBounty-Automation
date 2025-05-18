# Bug Bounty Automation Script

A comprehensive bug bounty automation script that streamlines the process of reconnaissance, vulnerability scanning, and security assessment for bug bounty programs.

## 🚀 Features

- **Subdomain Enumeration**: Uses multiple tools (Subfinder, Amass, Assetfinder) for comprehensive subdomain discovery
- **Alive Host Detection**: Identifies active subdomains using HTTPX
- **Port Scanning**: Performs detailed port scanning with Nmap and Masscan
- **Screenshot Capture**: Takes screenshots of web applications using EyeWitness or Aquatone
- **Content Discovery**: Performs directory bruteforcing and content discovery
- **JavaScript Analysis**: Analyzes JavaScript files for sensitive information and endpoints
- **Parameter Discovery**: Discovers URL parameters using ParamSpider and Arjun
- **Vulnerability Scanning**: 
  - Security headers analysis
  - XSS detection
  - SQL injection testing
  - SSRF detection
  - LFI/RFI testing
  - Open redirect detection
- **S3 Bucket Enumeration**: Discovers and analyzes S3 buckets
- **CMS Enumeration**: Identifies content management systems
- **WAF Detection**: Detects web application firewalls
- **Information Disclosure**: Checks for exposed sensitive information
- **API Reconnaissance**: Discovers and analyzes API endpoints
- **Report Generation**: Creates detailed reports of findings

## 📋 Prerequisites

The script requires several tools to be installed. Here's a list of the main dependencies:

```bash
# Core tools
subfinder
amass
assetfinder
httpx
nmap
masscan
eyewitness/aquatone
ffuf/gobuster
linkfinder
gf
paramspider
arjun
nuclei
awsbucketdump
cms-seek
wafw00f
git-dumper
msfvenom
kiterunner
```

## 🛠️ Installation

1. Clone the repository:
```bash
git clone https://github.com/Sayeh-1337/BugBounty-Automation.git
cd BugBounty-Automation/bug-bounty-automation/bug-bounty
```

2. Make the script executable:
```bash
chmod +x BB-Auto.sh
```

3. Install the required dependencies:
```bash
# Example installation commands (adjust based on your system)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# ... install other dependencies
```

## 💻 Usage

Basic usage:
```bash
./BB-Auto.sh example.com
```

Advanced usage with options:
```bash
./BB-Auto.sh example.com -w /path/to/wordlist -t 20 --timeout 15
```

### Command Line Options

- `-w, --wordlist`: Path to wordlist for directory bruteforcing
- `-t, --threads`: Number of threads to use
- `--timeout`: Timeout in seconds for requests
- `-h, --help`: Show help message

## 📁 Output Structure

The script creates a directory structure for organizing results:

```
recon_example.com/
├── subdomains.txt
├── alive.txt
├── screenshots/
├── js_files/
├── endpoints.txt
├── vulnerabilities/
├── ports/
├── s3_buckets/
├── cms/
├── waf/
├── git_repos/
├── api/
└── report.md
```

## ⚠️ Disclaimer

This tool is for EDUCATIONAL PURPOSES ONLY. Always:
- Obtain proper authorization before testing
- Follow responsible disclosure practices
- Respect the scope of bug bounty programs
- Adhere to the terms of service of target websites

## 🔒 Security Considerations

- The script includes rate limiting to prevent overwhelming target servers
- Resource checks are performed before intensive operations
- Progress tracking allows for resuming interrupted scans
- Error handling and logging are implemented throughout

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Thanks to all the open-source tools and their developers that make this automation possible
- The bug bounty community for their continuous support and feedback

## 📧 Contact

For questions or suggestions, please open an issue in the repository. 