#!/bin/bash
                 #################################################################################
                 # Original works https://github.com/pyro0ownz/bashscript/blob/master/bashscript #
                 # 			   Revised 5/9/2025                                      #
                 #                  Reporting tool remade for recon reporting			 #
                 #                         Made By Joshua Ragland                                #
                 #              Derrived from CIS129 - CIS 229  Henry ford College               # 
############################################################################################################
# Public tools used (shodanIO api, dnsdumpster api, dig, Whois, curl, nmap)#################################
###Spinner taken from https://stackoverflow.com/questions/68648536/same-line-bash-spinner ##################
###Progress bar takem from https://stackoverflow.com/questions/38339434/making-simple-shell-progress-bar ###
#### Logic taken from My OWN works https://github.com/pyro0ownz/nmapAutomator/blob/master/Automation.sh    #
####              https://github.com/pyro0ownz/bashscript/blob/master/bashscript 			   #
############################################################################################################

# Regular Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BBLUE='\033[1;34m'

# Reset
NC='\033[0m'  # No Color

# Arrays
declare -a ip_list
declare -A org_map rdns_map headers_map tlsdns_map shodan_map nmap_map

###open ai junk tool check
tool_check() {
  required_tools=(whois dig nmap curl jq openssl timeout)
  missing_tools=()

  # Detect package manager
  if command -v apt >/dev/null 2>&1; then
    PM="apt"
    INSTALL_CMD="sudo apt install -y"
  elif command -v dnf >/dev/null 2>&1; then
    PM="dnf"
    INSTALL_CMD="sudo dnf install -y"
  elif command -v yum >/dev/null 2>&1; then
    PM="yum"
    INSTALL_CMD="sudo yum install -y"
  elif command -v pacman >/dev/null 2>&1; then
    PM="pacman"
    INSTALL_CMD="sudo pacman -S --noconfirm"
  elif command -v brew >/dev/null 2>&1; then
    PM="brew"
    INSTALL_CMD="brew install"
  else
    echo "Unsupported package manager. Install tools manually."
    exit 1
  fi

  # Check for missing tools
  for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing_tools+=("$tool")
    fi
  done

  if [ "${#missing_tools[@]}" -eq 0 ]; then
    echo "All required tools are installed."
    return 0
  fi

  echo "Missing tools: ${missing_tools[*]}"
  read -p "Do you want to install them using $PM? [y/N] " response
  if [[ "$response" =~ ^[Yy]$ ]]; then
    for tool in "${missing_tools[@]}"; do
      echo "Installing $tool..."
      $INSTALL_CMD "$tool" || { echo "Failed to install $tool. Please install it manually."; }
    done
  else
    echo "Cannot continue without required tools."
    exit 1
  fi
}


##############################################################
banner(){

echo -e "${GREEN}# .·:'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''':·."
echo -e "${GREEN}# : :  #####                                   #     #               : :"
echo -e "${GREEN}# : : #     # #    #  ####   ####  #####       ##   ##   ##   #####  : :"
echo -e "${GREEN}# : : #       #    # #    # #        #         # # # #  #  #  #    # : :"
echo -e "${GREEN}# : : #  #### ###### #    #  ####    #   ##### #  #  # #    # #    # : :"
echo -e "${GREEN}# : : #     # #    # #    #      #   #         #     # ###### #####  : :"
echo -e "${GREEN}# : : #     # #    # #    # #    #   #         #     # #    # #      : :"
echo -e "${GREEN}# : :  #####  #    #  ####   ####    #         #     # #    # #      : :"
echo -e "${GREEN}# '·:................................................................:·'"
echo -e "$NC"
} 

#############################################################
##Stack overflow###
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr="‹.·'¯'·...·'¯'·.›"
    while kill -0 "$pid" 2>/dev/null; do
        for i in $(seq 0 3); do
            printf "\r[%s] " "${spinstr:$i:1}"
            sleep "$delay"
        done
    done
    printf "\r    \r"  # clear spinner
}
input(){
#input 
read -p "Enter path to input file containing IPs:" input_file
read -p "Enter desired output HTML file name (e.g., report.html): " html_output
read -p "Enter your Shodan API key: " shodan_api_key
read -p "Enter your DNSDumpster API key: " dnsdumpster_apikey
read -p "Enter your nmap flags your going to use: (-Pn, -sS, -sV, --vuln etc): " nmapargs
}

#############################################################################################

###########################################################################################


# progress bar 
show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percent=$(( 100 * current / total ))
    local filled=$(( width * current / total ))
    local empty=$(( width - filled ))

	printf "\033[0;32m\r["
	printf "%0.s#" $(seq 1 $filled)
	printf "%0.s-" $(seq 1 $empty)
	printf "] %3d%%\033[0m" "$percent"

}



loadipz() {
# IP list load 
while IFS= read -r line; do
    ip=$(echo "$line" | xargs)
    [[ -z "$ip" ]] && continue
    ip_list+=("$ip")
done < "$input_file"

# prime total and counter 
total_ips=${#ip_list[@]}
count=0
} 

##########################################################################################################################

osint(){
#  whois, dig, openssl etc 
for ip in "${ip_list[@]}"; do
    ((count++))
    show_progress "$count" "$total_ips"
    echo -e "$RED[Checking...]$NC $ip"
    sleep 10 & spinner $!
    org=$(whois "$ip" | awk -F: '/^OrgName|^Organization|^org-name|^netname|^owner/ {gsub(/^ +| +$/, "", $2); print $2; exit}') 
    [[ -z "$org" ]] && org="N/A"
    org_map["$ip"]="$org"
    sleep 10 & spinner $!
    rdns=$(dig -x "$ip" +short 2>/dev/null | tr -d '\n') 
    [[ -z "$rdns" ]] && rdns="N/A"
    rdns_map["$ip"]="$rdns"
    sleep 10 & spinner $! 
    headers_http=$(curl -m 5 -I "http://$ip" 2>/dev/null | tr '\n' ' ') 
    headers_https=$(curl -m 5 -k -I "https://$ip" 2>/dev/null | tr '\n' ' ') 
    headers="$headers_http $headers_https"
    [[ -z "$headers" ]] && headers="N/A"
    headers_map["$ip"]="$headers"
    sleep 10 & spinner $! 
    cert_raw=$(echo | timeout 5 openssl s_client -connect "$ip:443" -servername "$ip" 2>/dev/null) 
    if echo "$cert_raw" | grep -q "BEGIN CERTIFICATE"; then
        tlsdns=$(echo "$cert_raw" | openssl x509 -noout -text 2>/dev/null | grep DNS: | tr '\n' ' ') 
    else
        tlsdns="No cert or handshake failed"
    fi
    tlsdns_map["$ip"]="$tlsdns"

    shodan_out=$(curl -s "https://api.shodan.io/shodan/host/$ip?key=$shodan_api_key")
    sleep 10 & spinner $! 
    shodan_ports=$(echo "$shodan_out" | jq -r '.ports | join(", ")' 2>/dev/null)
    shodan_os=$(echo "$shodan_out" | jq -r '.os' 2>/dev/null)
    [[ "$shodan_ports" == "null" ]] && shodan_ports="N/A"
    [[ "$shodan_os" == "null" ]] && shodan_os="Unknown"
    shodan_map["$ip"]="OS: $shodan_os | Ports: $shodan_ports"
done
echo -e "$BLUE Osint Finished $NC"
} 

#################################################################################3

nmap_scan() {
# Nmap scan for ip list 
echo -e "$BBLUE Starting Nmap Scanz.....$NC"
count=0
total_ips=${#ip_list[@]}
for ip in "${ip_list[@]}"; do
    ((count++))
    show_progress "$count" "$total_ips"
    echo -e "$BLUE[Scanning....] Nmap $ip $NC"
    nmap_out=$(nmap $nmapargs "$ip") 
    [[ -z "$nmap_out" ]] && nmap_out="No open ports"
    nmap_map["$ip"]="$nmap_out"
    sleep 1 & spinner $!
done
echo -e "$RED Done Scanning with Nmap $NC"
} 

html() {
echo -e "$GREEN generating HTML $NC"
# Generate html 
echo "<html><head><title>Recon Report</title></head><body><h1>Recon Results</h1>" > "$html_output"
echo "<table border=1><tr><th>IP</th><th>Org</th><th>Reverse DNS</th><th>Headers</th><th>TLS Cert DNS</th><th>Shodan</th><th>Nmap</th></tr>" >> "$html_output"

for ip in "${ip_list[@]}"; do
    echo "<tr><td>$ip</td><td>${org_map[$ip]}</td><td>${rdns_map[$ip]}</td><td>${headers_map[$ip]}</td><td>${tlsdns_map[$ip]}</td><td>${shodan_map[$ip]}</td><td><pre>${nmap_map[$ip]}</pre></td></tr>" >> "$html_output"
done

echo "</table>" >> "$html_output"


# Pull all found domains from osint 
declare -A seen_domains
for ip in "${ip_list[@]}"; do
    rdns="${rdns_map[$ip]}"
    cert_dns="${tlsdns_map[$ip]}"
    all_domains=$(echo "$rdns $cert_dns" | grep -oP '[a-zA-Z0-9.-]+\.[a-z]{2,}' | sort -u) 
    for domain in $all_domains; do
        if [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then continue; fi
        seen_domains["$domain"]=1
    done
done


# Add dns dumpster results table
echo "<h2>DNSDumpster Host/IP Recon</h2><table border=1><tr><th>Host</th><th>IP</th><th>PTR</th></tr>" >> "$html_output"
for domain in "${!seen_domains[@]}"; do
    echo -e "$GREEN Dumping:$NC $domain"
    curl -s -H "X-API-Key:$dnsdumpster_apikey" "https://api.dnsdumpster.com/domain/$domain" | \
    grep -iE '"(host|ip|ptr)"' | \
    awk '/"host"/{h=$2;gsub(/[",]/,"",h)} /"ip"/{i=$2;gsub(/[",]/,"",i)} /"ptr"/{p=$2;gsub(/[",]/,"",p);printf "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", h, i, p}' >> "$html_output"
    sleep 2 & spinner $! 
done

echo "</table></body></html>" >> "$html_output"
echo -e "${GREEN}Done results are here: $(realpath "$html_output")${NC}"

} 


#######################################################################################

#Actual program to call functions that were defined. 
help_text() {
echo -e "$RED Runs Basic recon using shodanIO api, dnsdumpster api, dig, Whois, curl, nmap $NC"
echo -e "$RED If the tools are not found it gives you the option to automatically install $NC" 
echo -e "$RED Cuts down on manual identification just feed the external ip scope in and run $NC" 
echo -e "$RED Requires shodan.io and dnsdumpster API keys you can get them at shodan.io and dnsdumpster.com $NC"
echo -e "$RED The nmap input only requires the flags as the script iterates through the ip list and calls nmap $NC" 
}


main(){
banner
help_text
tool_check
input
loadipz
osint
nmap_scan
html  
}


main 
exit 0 
