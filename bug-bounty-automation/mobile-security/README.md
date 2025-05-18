# Mobile Security Analysis Script

A powerful automation tool for mobile application security analysis using Mobile Security Framework (MobSF). This script provides a streamlined workflow for analyzing Android and iOS applications for security vulnerabilities.

## 🚨 Disclaimer

This tool is for **EDUCATIONAL PURPOSES ONLY**. Always:
- Obtain proper authorization before testing any application
- Follow responsible disclosure practices
- Respect the application's terms of service
- Use this tool ethically and legally

## 🛠️ Features

### 1. Static Analysis
- Code analysis
- Manifest analysis
- Permission analysis
- Security score calculation
- Vulnerability detection
- Malware detection
- Third-party library analysis

### 2. Dynamic Analysis (Android Only)
- Runtime analysis
- Network traffic monitoring
- API endpoint discovery
- Screenshot capture
- Activity monitoring
- Intent analysis

### 3. Report Generation
- PDF reports
- JSON reports
- Summary generation
- Vulnerability categorization
- Risk assessment

## 📋 Prerequisites

### Required Tools
```bash
# Install curl
sudo apt install curl

# Install jq
sudo apt install jq

# Install MobSF
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh
```

### MobSF Setup
1. Start MobSF server:
```bash
./run.sh
```

2. Get your API key from MobSF dashboard:
   - Go to http://localhost:8000
   - Navigate to Settings > API Key
   - Copy your API key

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/Sayeh-1337/BugBounty-Automation.git
cd BugBounty-Automation/bug-bounty-automation/mobile-security-analysis
```

2. Make the script executable:
```bash
chmod +x mobile-security.sh
```

3. Configure your API key (optional):
```bash
export MOBSF_API_KEY="your_api_key_here"
```

## 💻 Usage

### Basic Usage
```bash
./mobile-security.sh path/to/app.apk
```

### Advanced Usage
```bash
./mobile-security.sh path/to/app.apk [options]

Options:
  -u, --url URL        MobSF server URL (default: http://localhost:8000)
  -k, --api-key KEY    MobSF API key
  -t, --type TYPE      Scan type: static, dynamic, or both (default: static)
  -h, --help           Show help message
```

### Examples

1. Static analysis only:
```bash
./mobile-security.sh app.apk -t static
```

2. Dynamic analysis only (Android):
```bash
./mobile-security.sh app.apk -t dynamic
```

3. Both static and dynamic analysis:
```bash
./mobile-security.sh app.apk -t both
```

4. Custom MobSF server:
```bash
./mobile-security.sh app.apk -u http://your-mobsf-server:8000
```

## 📁 Output Structure

```
mobile_analysis_TIMESTAMP/
├── reports/
│   ├── report.pdf
│   └── report.json
├── screenshots/
├── logs/
└── summary.txt
```

## 🔧 Configuration

The script can be configured through command-line arguments or environment variables:

```bash
# Environment variables
export MOBSF_URL="http://your-mobsf-server:8000"
export MOBSF_API_KEY="your_api_key_here"
export SCAN_TYPE="both"
```

## 📝 Features in Detail

### Static Analysis
- Code quality assessment
- Security vulnerability detection
- Permission analysis
- Manifest analysis
- Third-party library scanning
- Malware detection
- Hardcoded secrets detection

### Dynamic Analysis
- Runtime behavior analysis
- Network traffic monitoring
- API endpoint discovery
- Screenshot capture
- Activity monitoring
- Intent analysis
- SSL/TLS analysis

### Report Generation
- Comprehensive PDF reports
- Detailed JSON reports
- Vulnerability summaries
- Risk assessment
- Remediation suggestions

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Mobile Security Framework (MobSF) team
- The mobile security community
- Contributors and maintainers

## ⚠️ Important Notes

1. Always respect rate limits
2. Keep MobSF updated
3. Monitor system resources
4. Use responsibly and ethically
5. Follow responsible disclosure

## 🔍 Troubleshooting

### Common Issues

1. **MobSF not running**
   - Check if MobSF server is running
   - Verify server URL
   - Check server logs

2. **API key issues**
   - Verify API key
   - Check API key permissions
   - Regenerate API key if needed

3. **Analysis failures**
   - Check app file format
   - Verify app permissions
   - Check MobSF logs

### Getting Help

- Check MobSF documentation
- Review script logs
- Open an issue
- Join the community

## 📞 Support

For support, please:
1. Check the documentation
2. Search existing issues
3. Open a new issue if needed

## 🔄 Updates

Stay updated with the latest changes:
```bash
git pull origin main
```

## 📚 Additional Resources

- [MobSF Documentation](https://mobsf.github.io/docs/)
- [Mobile Security Best Practices](https://github.com/Sayeh-1337/mobile-security-best-practices)
- [Android Security Guidelines](https://github.com/Sayeh-1337/android-security-guidelines)
- [iOS Security Guidelines](https://github.com/Sayeh-1337/ios-security-guidelines) 