#!/bin/bash

# Chrome Extension Security Analysis Script
# This script automates security analysis of Chrome browser extensions

# Colors for better output readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables
EXTENSION_PATH=$1
OUTPUT_DIR="extension_analysis_$(date +%Y%m%d_%H%M%S)"
MANIFEST_FILE="manifest.json"
PERMISSIONS_FILE="$OUTPUT_DIR/permissions.txt"
VULNERABILITIES_FILE="$OUTPUT_DIR/vulnerabilities.txt"
JS_FILES_DIR="$OUTPUT_DIR/js_files"
HTML_FILES_DIR="$OUTPUT_DIR/html_files"
CSS_FILES_DIR="$OUTPUT_DIR/css_files"
IMAGES_DIR="$OUTPUT_DIR/images"
REPORT_FILE="$OUTPUT_DIR/report.md"
ESPRIMA_ANALYSIS_FILE="$OUTPUT_DIR/esprima_analysis.txt"

# Banner
echo -e "${RED}"
cat << "EOF"
  _____ _                     _    _____                                 _   
 / ____| |                   | |  |  __ \                               | |  
| |    | |__   ___ _ __   ___| |  | |__) |___  ___ _ __   ___  _ __  ___| |_ 
| |    | '_ \ / _ \ '_ \ / _ \ |  |  _  // _ \/ _ \ '_ \ / _ \| '_ \/ __| __|
| |____| | | |  __/ | | |  __/ |  | | \ \  __/  __/ |_) | (_) | | | \__ \ |_ 
 \_____|_| |_|\___|_| |_|\___|_|  |_|  \_\___|\___| .__/ \___/|_| |_|___/\__|
                                                   | |                       
                                                   |_|                       
EOF
echo -e "${NC}"
echo -e "${CYAN}[*] Chrome Extension Security Analysis Script${NC}"
echo -e "${CYAN}[*] Author: Claude${NC}"
echo -e "${CYAN}[*] DISCLAIMER: This tool is for EDUCATIONAL PURPOSES ONLY. Always obtain proper authorization before testing any extension.${NC}"
echo ""

# Error handling function
handle_error() {
    local error_msg="$1"
    local error_code="${2:-1}"
    echo -e "${RED}[!] Error: $error_msg${NC}"
    exit "$error_code"
}

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}[*] Checking prerequisites...${NC}"
    
    # Check if unzip is installed
    if ! command -v unzip &> /dev/null; then
        handle_error "unzip is not installed. Please install it first."
    fi
    
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        handle_error "jq is not installed. Please install it first."
    fi
    
    # Check if grep is installed
    if ! command -v grep &> /dev/null; then
        handle_error "grep is not installed. Please install it first."
    fi
    
    # Check if node is installed
    if ! command -v node &> /dev/null; then
        handle_error "Node.js is not installed. Please install it first."
    fi
    
    # Check if npm is installed
    if ! command -v npm &> /dev/null; then
        handle_error "npm is not installed. Please install it first."
    fi
    
    # Install esprima if not already installed
    if ! npm list -g esprima &> /dev/null; then
        echo -e "${YELLOW}[*] Installing esprima...${NC}"
        npm install -g esprima
    fi
    
    echo -e "${GREEN}[+] Prerequisites check passed${NC}"
}

# Setup directories
setup_directories() {
    echo -e "${BLUE}[*] Setting up directory structure...${NC}"
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$JS_FILES_DIR"
    mkdir -p "$HTML_FILES_DIR"
    mkdir -p "$CSS_FILES_DIR"
    mkdir -p "$IMAGES_DIR"
    echo -e "${GREEN}[+] Directory structure created${NC}"
}

# Extract extension
extract_extension() {
    echo -e "${BLUE}[*] Extracting extension...${NC}"
    
    if [[ "$EXTENSION_PATH" == *.crx ]]; then
        # Convert .crx to .zip
        unzip -q "$EXTENSION_PATH" -d "$OUTPUT_DIR/extracted"
    elif [[ "$EXTENSION_PATH" == *.zip ]]; then
        unzip -q "$EXTENSION_PATH" -d "$OUTPUT_DIR/extracted"
    else
        handle_error "Unsupported file format. Please provide a .crx or .zip file."
    fi
    
    echo -e "${GREEN}[+] Extension extracted successfully${NC}"
}

# Analyze manifest
analyze_manifest() {
    echo -e "${BLUE}[*] Analyzing manifest.json...${NC}"
    
    if [ ! -f "$OUTPUT_DIR/extracted/$MANIFEST_FILE" ]; then
        handle_error "manifest.json not found in the extension"
    fi
    
    # Extract and analyze permissions
    echo "## Permissions Analysis" > "$PERMISSIONS_FILE"
    jq -r '.permissions[]' "$OUTPUT_DIR/extracted/$MANIFEST_FILE" >> "$PERMISSIONS_FILE"
    
    # Extract and analyze content security policy
    echo -e "\n## Content Security Policy" >> "$PERMISSIONS_FILE"
    jq -r '.content_security_policy' "$OUTPUT_DIR/extracted/$MANIFEST_FILE" >> "$PERMISSIONS_FILE"
    
    # Extract and analyze host permissions
    echo -e "\n## Host Permissions" >> "$PERMISSIONS_FILE"
    jq -r '.host_permissions[]' "$OUTPUT_DIR/extracted/$MANIFEST_FILE" >> "$PERMISSIONS_FILE"
    
    echo -e "${GREEN}[+] Manifest analysis completed${NC}"
}

# Analyze JavaScript files
analyze_javascript() {
    echo -e "${BLUE}[*] Analyzing JavaScript files...${NC}"
    
    # Find all JavaScript files
    find "$OUTPUT_DIR/extracted" -name "*.js" -exec cp {} "$JS_FILES_DIR/" \;
    
    # Check for common vulnerabilities
    echo "## JavaScript Security Analysis" > "$VULNERABILITIES_FILE"
    
    # Check for eval usage
    echo -e "\n### Eval Usage" >> "$VULNERABILITIES_FILE"
    grep -r "eval(" "$JS_FILES_DIR" >> "$VULNERABILITIES_FILE"
    
    # Check for innerHTML usage
    echo -e "\n### innerHTML Usage" >> "$VULNERABILITIES_FILE"
    grep -r "innerHTML" "$JS_FILES_DIR" >> "$VULNERABILITIES_FILE"
    
    # Check for document.write usage
    echo -e "\n### document.write Usage" >> "$VULNERABILITIES_FILE"
    grep -r "document.write" "$JS_FILES_DIR" >> "$VULNERABILITIES_FILE"
    
    # Check for localStorage usage
    echo -e "\n### localStorage Usage" >> "$VULNERABILITIES_FILE"
    grep -r "localStorage" "$JS_FILES_DIR" >> "$VULNERABILITIES_FILE"
    
    # Check for chrome.storage usage
    echo -e "\n### chrome.storage Usage" >> "$VULNERABILITIES_FILE"
    grep -r "chrome.storage" "$JS_FILES_DIR" >> "$VULNERABILITIES_FILE"
    
    echo -e "${GREEN}[+] JavaScript analysis completed${NC}"
}

# Analyze JavaScript files with Esprima
analyze_javascript_esprima() {
    echo -e "${BLUE}[*] Performing deep JavaScript analysis with Esprima...${NC}"
    
    echo "## Esprima AST Analysis" > "$ESPRIMA_ANALYSIS_FILE"
    
    # Create temporary Node.js script for Esprima analysis
    cat > "$OUTPUT_DIR/analyze.js" << 'EOF'
const fs = require('fs');
const esprima = require('esprima');
const path = require('path');

const jsFilesDir = process.argv[2];
const outputFile = process.argv[3];

function analyzeFile(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const ast = esprima.parseScript(content, { loc: true, range: true });
        
        let analysis = `\n### Analysis of ${path.basename(filePath)}\n`;
        
        // Analyze function declarations
        const functions = [];
        const walk = (node) => {
            if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression') {
                functions.push({
                    name: node.id ? node.id.name : 'anonymous',
                    loc: node.loc
                });
            }
            for (const key in node) {
                if (node[key] && typeof node[key] === 'object') {
                    walk(node[key]);
                }
            }
        };
        walk(ast);
        
        analysis += "\n#### Function Declarations\n";
        functions.forEach(func => {
            analysis += `- ${func.name} at line ${func.loc.start.line}\n`;
        });
        
        // Analyze variable declarations
        const variables = [];
        const walkVars = (node) => {
            if (node.type === 'VariableDeclarator') {
                variables.push({
                    name: node.id.name,
                    loc: node.loc
                });
            }
            for (const key in node) {
                if (node[key] && typeof node[key] === 'object') {
                    walkVars(node[key]);
                }
            }
        };
        walkVars(ast);
        
        analysis += "\n#### Variable Declarations\n";
        variables.forEach(variable => {
            analysis += `- ${variable.name} at line ${variable.loc.start.line}\n`;
        });
        
        // Analyze potential security issues
        const securityIssues = [];
        const walkSecurity = (node) => {
            if (node.type === 'CallExpression') {
                const callee = node.callee;
                if (callee.name === 'eval' || 
                    (callee.property && callee.property.name === 'innerHTML') ||
                    (callee.property && callee.property.name === 'outerHTML')) {
                    securityIssues.push({
                        type: callee.name || callee.property.name,
                        loc: node.loc
                    });
                }
            }
            for (const key in node) {
                if (node[key] && typeof node[key] === 'object') {
                    walkSecurity(node[key]);
                }
            }
        };
        walkSecurity(ast);
        
        analysis += "\n#### Potential Security Issues\n";
        securityIssues.forEach(issue => {
            analysis += `- ${issue.type} usage at line ${issue.loc.start.line}\n`;
        });
        
        return analysis;
    } catch (error) {
        return `\n### Error analyzing ${path.basename(filePath)}: ${error.message}\n`;
    }
}

const files = fs.readdirSync(jsFilesDir);
let analysis = '';

files.forEach(file => {
    if (file.endsWith('.js')) {
        const filePath = path.join(jsFilesDir, file);
        analysis += analyzeFile(filePath);
    }
});

fs.writeFileSync(outputFile, analysis, { flag: 'a' });
EOF

    # Run the Node.js analysis script
    node "$OUTPUT_DIR/analyze.js" "$JS_FILES_DIR" "$ESPRIMA_ANALYSIS_FILE"
    
    # Append Esprima analysis to vulnerabilities file
    cat "$ESPRIMA_ANALYSIS_FILE" >> "$VULNERABILITIES_FILE"
    
    echo -e "${GREEN}[+] Esprima analysis completed${NC}"
}

# Analyze HTML files
analyze_html() {
    echo -e "${BLUE}[*] Analyzing HTML files...${NC}"
    
    # Find all HTML files
    find "$OUTPUT_DIR/extracted" -name "*.html" -exec cp {} "$HTML_FILES_DIR/" \;
    
    # Check for common vulnerabilities
    echo -e "\n## HTML Security Analysis" >> "$VULNERABILITIES_FILE"
    
    # Check for inline scripts
    echo -e "\n### Inline Scripts" >> "$VULNERABILITIES_FILE"
    grep -r "<script>" "$HTML_FILES_DIR" >> "$VULNERABILITIES_FILE"
    
    # Check for inline event handlers
    echo -e "\n### Inline Event Handlers" >> "$VULNERABILITIES_FILE"
    grep -r "onclick=" "$HTML_FILES_DIR" >> "$VULNERABILITIES_FILE"
    grep -r "onload=" "$HTML_FILES_DIR" >> "$VULNERABILITIES_FILE"
    
    # Check for external resources
    echo -e "\n### External Resources" >> "$VULNERABILITIES_FILE"
    grep -r "http://" "$HTML_FILES_DIR" >> "$VULNERABILITIES_FILE"
    grep -r "https://" "$HTML_FILES_DIR" >> "$VULNERABILITIES_FILE"
    
    echo -e "${GREEN}[+] HTML analysis completed${NC}"
}

# Analyze CSS files
analyze_css() {
    echo -e "${BLUE}[*] Analyzing CSS files...${NC}"
    
    # Find all CSS files
    find "$OUTPUT_DIR/extracted" -name "*.css" -exec cp {} "$CSS_FILES_DIR/" \;
    
    # Check for common vulnerabilities
    echo -e "\n## CSS Security Analysis" >> "$VULNERABILITIES_FILE"
    
    # Check for external resources
    echo -e "\n### External Resources" >> "$VULNERABILITIES_FILE"
    grep -r "url(" "$CSS_FILES_DIR" >> "$VULNERABILITIES_FILE"
    
    echo -e "${GREEN}[+] CSS analysis completed${NC}"
}

# Check for sensitive data
check_sensitive_data() {
    echo -e "${BLUE}[*] Checking for sensitive data...${NC}"
    
    echo -e "\n## Sensitive Data Analysis" >> "$VULNERABILITIES_FILE"
    
    # Check for API keys
    echo -e "\n### Potential API Keys" >> "$VULNERABILITIES_FILE"
    grep -r "api[_-]key" "$OUTPUT_DIR/extracted" >> "$VULNERABILITIES_FILE"
    
    # Check for passwords
    echo -e "\n### Potential Passwords" >> "$VULNERABILITIES_FILE"
    grep -r "password" "$OUTPUT_DIR/extracted" >> "$VULNERABILITIES_FILE"
    
    # Check for tokens
    echo -e "\n### Potential Tokens" >> "$VULNERABILITIES_FILE"
    grep -r "token" "$OUTPUT_DIR/extracted" >> "$VULNERABILITIES_FILE"
    
    echo -e "${GREEN}[+] Sensitive data check completed${NC}"
}

# Generate report
generate_report() {
    echo -e "${BLUE}[*] Generating security report...${NC}"
    
    echo "# Chrome Extension Security Analysis Report" > "$REPORT_FILE"
    echo "Generated on: $(date)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Add permissions analysis
    echo "## Permissions Analysis" >> "$REPORT_FILE"
    cat "$PERMISSIONS_FILE" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Add vulnerability analysis
    echo "## Vulnerability Analysis" >> "$REPORT_FILE"
    cat "$VULNERABILITIES_FILE" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Add recommendations
    echo "## Security Recommendations" >> "$REPORT_FILE"
    echo "1. Review and minimize permissions" >> "$REPORT_FILE"
    echo "2. Implement proper Content Security Policy" >> "$REPORT_FILE"
    echo "3. Avoid using eval() and innerHTML" >> "$REPORT_FILE"
    echo "4. Use chrome.storage.sync instead of localStorage" >> "$REPORT_FILE"
    echo "5. Implement proper input validation" >> "$REPORT_FILE"
    echo "6. Use HTTPS for all external resources" >> "$REPORT_FILE"
    echo "7. Implement proper error handling" >> "$REPORT_FILE"
    echo "8. Regular security audits" >> "$REPORT_FILE"
    
    echo -e "${GREEN}[+] Report generated: $REPORT_FILE${NC}"
}

# Cleanup
cleanup() {
    echo -e "${BLUE}[*] Cleaning up...${NC}"
    rm -rf "$OUTPUT_DIR/extracted"
    echo -e "${GREEN}[+] Cleanup completed${NC}"
}

# Main function
main() {
    # Check if extension path is provided
    if [ -z "$EXTENSION_PATH" ]; then
        echo -e "${RED}[!] Error: No extension file specified${NC}"
        echo -e "${YELLOW}[*] Usage: ./extension-security.sh <path_to_extension>${NC}"
        exit 1
    fi
    
    # Check if extension file exists
    if [ ! -f "$EXTENSION_PATH" ]; then
        handle_error "Extension file not found: $EXTENSION_PATH"
    fi
    
    # Check prerequisites
    check_prerequisites
    
    # Setup directories
    setup_directories
    
    # Extract extension
    extract_extension
    
    # Analyze manifest
    analyze_manifest
    
    # Analyze JavaScript files
    analyze_javascript
    
    # Perform Esprima analysis
    analyze_javascript_esprima
    
    # Analyze HTML files
    analyze_html
    
    # Analyze CSS files
    analyze_css
    
    # Check for sensitive data
    check_sensitive_data
    
    # Generate report
    generate_report
    
    # Cleanup
    cleanup
    
    echo -e "${GREEN}[+] Analysis completed successfully!${NC}"
    echo -e "${GREEN}[+] Results saved in: $OUTPUT_DIR${NC}"
}

# Set up trap for cleanup
trap cleanup EXIT

# Start script execution
main "$@" 