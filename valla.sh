#!/bin/bash
# js-harvest.sh - Harvest JS URLs from hosts using waybackurls + gau + subjs + hakrawler

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

# Usage
usage() {
    echo -e "${CYAN}Usage:${RESET} $0 <hosts_file> [output_file]"
    echo ""
    echo "  hosts_file   — file with one domain per line"
    echo "  output_file  — optional, defaults to js_urls.txt"
    echo ""
    echo "Example: $0 hosts.txt js_urls.txt"
    exit 1
}

[[ $# -lt 1 ]] && usage

HOSTS_FILE="$1"
OUTPUT_FILE="${2:-js_urls.txt}"

[[ ! -f "$HOSTS_FILE" ]] && echo -e "${RED}[!] File not found: $HOSTS_FILE${RESET}" && exit 1

# Check & install dependencies
install_go_tool() {
    local binary="$1"
    local pkg="$2"

    if ! command -v "$binary" &>/dev/null; then
        echo -e "${YELLOW}[~] $binary not found — installing...${RESET}"
        go install "$pkg" 2>/dev/null
        if ! command -v "$binary" &>/dev/null; then
            echo -e "${RED}[!] Failed to install $binary. Install manually:${RESET}"
            echo "    go install $pkg"
            exit 1
        fi
        echo -e "${GREEN}[+] $binary installed${RESET}"
    else
        echo -e "${GREEN}[✓] $binary found${RESET}"
    fi
}

# Check Go is installed
if ! command -v go &>/dev/null; then
    echo -e "${RED}[!] Go is not installed. Install from https://golang.org/dl/${RESET}"
    exit 1
fi

echo -e "${CYAN}[*] Checking dependencies...${RESET}"
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool "subjs" "github.com/lc/subjs@latest"
install_go_tool "hakrawler" "github.com/hakluke/hakrawler@latest"

# Step 1: Archived JS via waybackurls + gau
echo -e "\n${CYAN}[*] Step 1: Fetching archived JS URLs (waybackurls + gau)...${RESET}"

> "${OUTPUT_FILE}.tmp_archived"

while IFS= read -r host; do
    [[ -z "$host" || "$host" == \#* ]] && continue

    echo -e "${YELLOW}    → waybackurls: $host${RESET}"
    waybackurls "$host" 2>/dev/null \
        | grep -E '\.js(\?|$|#)' \
        | grep -v '\.json' \
        >> "${OUTPUT_FILE}.tmp_archived" || true

    echo -e "${YELLOW}    → gau: $host${RESET}"
    gau "$host" 2>/dev/null \
        | grep -E '\.js(\?|$|#)' \
        | grep -v '\.json' \
        >> "${OUTPUT_FILE}.tmp_archived" || true

done < "$HOSTS_FILE"

ARCHIVED_COUNT=$(wc -l < "${OUTPUT_FILE}.tmp_archived")
echo -e "${GREEN}[+] Found $ARCHIVED_COUNT archived JS URLs${RESET}"

# Step 2: Live JS via subjs
echo -e "\n${CYAN}[*] Step 2: Fetching live JS URLs via subjs...${RESET}"

> "${OUTPUT_FILE}.tmp_live"

cat "$HOSTS_FILE" \
    | subjs 2>/dev/null \
    >> "${OUTPUT_FILE}.tmp_live" || true

LIVE_COUNT=$(wc -l < "${OUTPUT_FILE}.tmp_live")
echo -e "${GREEN}[+] Found $LIVE_COUNT live JS URLs${RESET}"

# Step 3: Crawled JS via hakrawler (your pipeline)
echo -e "\n${CYAN}[*] Step 3: Crawling JS via hakrawler...${RESET}"

cat "$HOSTS_FILE" \
    | hakrawler -d 2 \
    | grep -E '\.js(\?|$|#)' \
    | sort -u \
    | tee -a "${OUTPUT_FILE}.tmp_crawled" >/dev/null || true

CRAWLED_COUNT=$(wc -l < "${OUTPUT_FILE}.tmp_crawled")
echo -e "${GREEN}[+] Found $CRAWLED_COUNT crawled JS URLs${RESET}"

# Step 4: Merge & deduplicate
echo -e "\n${CYAN}[*] Step 4: Merging and deduplicating...${RESET}"

cat "${OUTPUT_FILE}.tmp_archived" \
    "${OUTPUT_FILE}.tmp_live" \
    "${OUTPUT_FILE}.tmp_crawled" \
    | sort -u \
    > "$OUTPUT_FILE"

# Cleanup temp files
rm -f "${OUTPUT_FILE}.tmp_archived" \
      "${OUTPUT_FILE}.tmp_live" \
      "${OUTPUT_FILE}.tmp_crawled"

TOTAL=$(wc -l < "$OUTPUT_FILE")
echo -e "${GREEN}[+] Total unique JS URLs: $TOTAL → saved to $OUTPUT_FILE${RESET}"
