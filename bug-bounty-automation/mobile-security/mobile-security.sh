#!/bin/bash

# Mobile Security Analysis Script using MobSF
# This script automates mobile app security analysis using Mobile Security Framework

# Colors for better output readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables
APP_PATH=$1
OUTPUT_DIR="mobile_analysis_$(date +%Y%m%d_%H%M%S)"
MOBSF_URL="http://localhost:8000"
API_KEY=""
SCAN_TYPE="static"  # static, dynamic, or both
PLATFORM=""  # android or ios

# Banner
echo -e "${RED}"
cat << "EOF"
 __  __       _ _     _____       _     _   _             
|  \/  |     | | |   / ____|     | |   | | (_)            
| \  / | ___ | | |  | (___   ___ | |__ | |_ _ _ __   __ _ 
| |\/| |/ _ \| | |   \___ \ / _ \| '_ \| __| | '_ \ / _` |
| |  | | (_) | | |   ____) | (_) | |_) | |_| | | | | (_| |
|_|  |_|\___/|_|_|  |_____/ \___/|_.__/ \__|_|_| |_|\__, |
                                                     __/ |
                                                    |___/ 
EOF
echo -e "${NC}"
echo -e "${CYAN}[*] Mobile App Security Analysis Script${NC}"
echo -e "${CYAN}[*] Using Mobile Security Framework (MobSF)${NC}"
echo -e "${CYAN}[*] Author: Claude${NC}"
echo -e "${CYAN}[*] DISCLAIMER: This tool is for EDUCATIONAL PURPOSES ONLY. Always obtain proper authorization before testing any application.${NC}"
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
    
    # Check if curl is installed
    if ! command -v curl &> /dev/null; then
        handle_error "curl is not installed. Please install it first."
    fi
    
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        handle_error "jq is not installed. Please install it first."
    fi
    
    # Check if MobSF is running
    if ! curl -s "$MOBSF_URL/api/v1/health" &> /dev/null; then
        handle_error "MobSF is not running at $MOBSF_URL. Please start MobSF first."
    fi
    
    echo -e "${GREEN}[+] Prerequisites check passed${NC}"
}

# Setup directories
setup_directories() {
    echo -e "${BLUE}[*] Setting up directory structure...${NC}"
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR/reports"
    mkdir -p "$OUTPUT_DIR/screenshots"
    mkdir -p "$OUTPUT_DIR/logs"
    echo -e "${GREEN}[+] Directory structure created${NC}"
}

# Upload app to MobSF
upload_app() {
    echo -e "${BLUE}[*] Uploading app to MobSF...${NC}"
    
    # Determine platform based on file extension
    if [[ "$APP_PATH" == *.apk ]]; then
        PLATFORM="android"
    elif [[ "$APP_PATH" == *.ipa ]]; then
        PLATFORM="ios"
    else
        handle_error "Unsupported file format. Please provide an APK or IPA file."
    fi
    
    # Upload the app
    UPLOAD_RESPONSE=$(curl -s -X POST \
        -H "Authorization: $API_KEY" \
        -F "file=@$APP_PATH" \
        "$MOBSF_URL/api/v1/upload")
    
    # Extract scan hash from response
    SCAN_HASH=$(echo "$UPLOAD_RESPONSE" | jq -r '.hash')
    
    if [ -z "$SCAN_HASH" ] || [ "$SCAN_HASH" == "null" ]; then
        handle_error "Failed to upload app to MobSF"
    fi
    
    echo -e "${GREEN}[+] App uploaded successfully. Scan hash: $SCAN_HASH${NC}"
}

# Start static analysis
start_static_analysis() {
    echo -e "${BLUE}[*] Starting static analysis...${NC}"
    
    ANALYSIS_RESPONSE=$(curl -s -X POST \
        -H "Authorization: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"hash\": \"$SCAN_HASH\", \"scan_type\": \"static\"}" \
        "$MOBSF_URL/api/v1/scan")
    
    if [ $? -ne 0 ]; then
        handle_error "Failed to start static analysis"
    fi
    
    echo -e "${GREEN}[+] Static analysis started${NC}"
}

# Start dynamic analysis
start_dynamic_analysis() {
    echo -e "${BLUE}[*] Starting dynamic analysis...${NC}"
    
    if [ "$PLATFORM" != "android" ]; then
        echo -e "${YELLOW}[!] Dynamic analysis is only supported for Android apps${NC}"
        return
    }
    
    DYNAMIC_RESPONSE=$(curl -s -X POST \
        -H "Authorization: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"hash\": \"$SCAN_HASH\", \"scan_type\": \"dynamic\"}" \
        "$MOBSF_URL/api/v1/dynamic_analyzer")
    
    if [ $? -ne 0 ]; then
        handle_error "Failed to start dynamic analysis"
    fi
    
    echo -e "${GREEN}[+] Dynamic analysis started${NC}"
}

# Monitor analysis progress
monitor_progress() {
    echo -e "${BLUE}[*] Monitoring analysis progress...${NC}"
    
    while true; do
        PROGRESS_RESPONSE=$(curl -s -X GET \
            -H "Authorization: $API_KEY" \
            "$MOBSF_URL/api/v1/scan_status/$SCAN_HASH")
        
        STATUS=$(echo "$PROGRESS_RESPONSE" | jq -r '.status')
        
        if [ "$STATUS" == "completed" ]; then
            echo -e "${GREEN}[+] Analysis completed${NC}"
            break
        elif [ "$STATUS" == "failed" ]; then
            handle_error "Analysis failed"
        fi
        
        echo -e "${YELLOW}[*] Analysis in progress...${NC}"
        sleep 10
    done
}

# Download report
download_report() {
    echo -e "${BLUE}[*] Downloading analysis report...${NC}"
    
    # Download PDF report
    curl -s -X GET \
        -H "Authorization: $API_KEY" \
        "$MOBSF_URL/api/v1/download_pdf/$SCAN_HASH" \
        -o "$OUTPUT_DIR/reports/report.pdf"
    
    # Download JSON report
    curl -s -X GET \
        -H "Authorization: $API_KEY" \
        "$MOBSF_URL/api/v1/report_json/$SCAN_HASH" \
        -o "$OUTPUT_DIR/reports/report.json"
    
    echo -e "${GREEN}[+] Reports downloaded to $OUTPUT_DIR/reports/${NC}"
}

# Generate summary
generate_summary() {
    echo -e "${BLUE}[*] Generating analysis summary...${NC}"
    
    # Extract key findings from JSON report
    jq -r '.security_score, .code_analysis, .manifest_analysis, .permissions' \
        "$OUTPUT_DIR/reports/report.json" > "$OUTPUT_DIR/summary.txt"
    
    echo -e "${GREEN}[+] Summary generated: $OUTPUT_DIR/summary.txt${NC}"
}

# Cleanup
cleanup() {
    echo -e "${BLUE}[*] Cleaning up...${NC}"
    
    # Delete scan from MobSF
    curl -s -X POST \
        -H "Authorization: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"hash\": \"$SCAN_HASH\"}" \
        "$MOBSF_URL/api/v1/delete_scan"
    
    echo -e "${GREEN}[+] Cleanup completed${NC}"
}

# Main function
main() {
    # Check if app path is provided
    if [ -z "$APP_PATH" ]; then
        echo -e "${RED}[!] Error: No app file specified${NC}"
        echo -e "${YELLOW}[*] Usage: ./mobile-security.sh <path_to_app> [options]${NC}"
        exit 1
    fi
    
    # Check if app file exists
    if [ ! -f "$APP_PATH" ]; then
        handle_error "App file not found: $APP_PATH"
    fi
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--url)
                MOBSF_URL="$2"
                shift 2
                ;;
            -k|--api-key)
                API_KEY="$2"
                shift 2
                ;;
            -t|--type)
                SCAN_TYPE="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: ./mobile-security.sh <path_to_app> [options]"
                echo "Options:"
                echo "  -u, --url URL        MobSF server URL (default: http://localhost:8000)"
                echo "  -k, --api-key KEY    MobSF API key"
                echo "  -t, --type TYPE      Scan type: static, dynamic, or both (default: static)"
                echo "  -h, --help           Show this help message"
                exit 0
                ;;
            *)
                shift
                ;;
        esac
    done
    
    # Check prerequisites
    check_prerequisites
    
    # Setup directories
    setup_directories
    
    # Upload app
    upload_app
    
    # Start analysis based on scan type
    case "$SCAN_TYPE" in
        "static")
            start_static_analysis
            ;;
        "dynamic")
            start_dynamic_analysis
            ;;
        "both")
            start_static_analysis
            start_dynamic_analysis
            ;;
        *)
            handle_error "Invalid scan type: $SCAN_TYPE"
            ;;
    esac
    
    # Monitor progress
    monitor_progress
    
    # Download reports
    download_report
    
    # Generate summary
    generate_summary
    
    # Cleanup
    cleanup
    
    echo -e "${GREEN}[+] Analysis completed successfully!${NC}"
    echo -e "${GREEN}[+] Results saved in: $OUTPUT_DIR${NC}"
}

# Set up trap for cleanup
trap cleanup EXIT

# Start script execution
main "$@" 