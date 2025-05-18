# Chrome Extension Security Analysis Script

A powerful automation tool for analyzing the security of Chrome browser extensions. This script helps identify potential security vulnerabilities and provides recommendations for improving extension security.

## 🚨 Disclaimer

This tool is for **EDUCATIONAL PURPOSES ONLY**. Always:
- Obtain proper authorization before testing any extension
- Follow responsible disclosure practices
- Respect the extension's terms of service
- Use this tool ethically and legally

## 🛠️ Features

### 1. Manifest Analysis
- Permission analysis
- Content Security Policy review
- Host permissions analysis
- Extension configuration review

### 2. JavaScript Analysis
- Dangerous function detection (eval, innerHTML)
- Storage usage analysis
- Chrome API usage analysis
- Code quality assessment

### 3. HTML Analysis
- Inline script detection
- Event handler analysis
- External resource analysis
- Content Security Policy compliance

### 4. CSS Analysis
- External resource detection
- URL pattern analysis
- Resource loading analysis

### 5. Sensitive Data Detection
- API key detection
- Password detection
- Token detection
- Credential analysis

## 📋 Prerequisites

### Required Tools
```bash
# Install unzip
sudo apt install unzip

# Install jq
sudo apt install jq

# Install grep (usually pre-installed)
```

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/Sayeh-1337/extension-security-analysis.git
cd extension-security-analysis
```

2. Make the script executable:
```bash
chmod +x extension-security.sh
```

## 💻 Usage

### Basic Usage
```bash
./extension-security.sh path/to/extension.crx
```

### Supported File Formats
- `.crx` (Chrome Extension)
- `.zip` (Unpacked Extension)

## 📁 Output Structure

```
extension_analysis_TIMESTAMP/
├── js_files/
│   └── [JavaScript files]
├── html_files/
│   └── [HTML files]
├── css_files/
│   └── [CSS files]
├── images/
├── permissions.txt
├── vulnerabilities.txt
└── report.md
```

## 📝 Analysis Details

### Manifest Analysis
- Reviews extension permissions
- Analyzes Content Security Policy
- Checks host permissions
- Validates extension configuration

### JavaScript Analysis
- Identifies dangerous functions:
  - eval()
  - innerHTML
  - document.write
- Analyzes storage usage:
  - localStorage
  - chrome.storage
- Reviews Chrome API usage

### HTML Analysis
- Detects inline scripts
- Identifies inline event handlers
- Analyzes external resources
- Checks CSP compliance

### CSS Analysis
- Identifies external resources
- Analyzes URL patterns
- Reviews resource loading

### Sensitive Data Analysis
- Detects potential API keys
- Identifies hardcoded passwords
- Finds tokens and credentials
- Analyzes sensitive information

## 🔍 Security Checks

### 1. Permission Analysis
- Reviews requested permissions
- Identifies excessive permissions
- Suggests permission minimization

### 2. Content Security
- Analyzes CSP implementation
- Identifies security misconfigurations
- Suggests security improvements

### 3. Code Quality
- Identifies dangerous patterns
- Suggests secure alternatives
- Reviews best practices

### 4. Data Security
- Identifies sensitive data
- Suggests secure storage methods
- Reviews data handling

## 📊 Report Generation

The script generates a comprehensive report including:
1. Permission analysis
2. Vulnerability findings
3. Security recommendations
4. Best practices

## 🔧 Configuration

The script can be configured through environment variables:

```bash
# Set output directory
export EXTENSION_OUTPUT_DIR="/path/to/output"

# Set analysis depth
export ANALYSIS_DEPTH="deep"
```

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

- Chrome Extension Security Best Practices
- Web Security Community
- Contributors and maintainers

## ⚠️ Important Notes

1. Always respect rate limits
2. Keep tools updated
3. Monitor system resources
4. Use responsibly and ethically
5. Follow responsible disclosure

## 🔍 Troubleshooting

### Common Issues

1. **Extension extraction fails**
   - Check file format
   - Verify file permissions
   - Check disk space

2. **Analysis errors**
   - Verify prerequisites
   - Check file permissions
   - Review error messages

3. **Report generation fails**
   - Check disk space
   - Verify file permissions
   - Review error messages

### Getting Help

- Check the documentation
- Review error messages
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

- [Chrome Extension Security Best Practices](https://developer.chrome.com/docs/extensions/mv3/security/)
- [Content Security Policy](https://developer.chrome.com/docs/extensions/mv3/contentSecurityPolicy/)
- [Chrome Extension Development](https://developer.chrome.com/docs/extensions/mv3/)
- [Web Security Guidelines](https://developer.chrome.com/docs/extensions/mv3/security/) 