<!-- Source: https://wazuh.com/blog/integrating-dependency-track-with-wazuh/ | Article: Integrating Dependency-Track with  Wazuh -->
#!/bin/bash
# File: /var/ossec/custom-script/dependency_track_monitor.sh

# Configuration
DT_API_URL="http://<UBUNTU_IP>:8081/api/v1"
DT_API_KEY="<API_KEY>"
PROJECT_UUID="<PROJECT_UUID>"
LOG_FILE="/var/log/dependency_track.log"

# Function to log messages
log_message() {
    	echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Function to query vulnerabilities
get_vulnerabilities() {
    	local response
    	response=$(curl -s -H "X-API-Key: $DT_API_KEY" \
    	"$DT_API_URL/vulnerability/project/$PROJECT_UUID")

    	if [ $? -eq 0 ] && [ -n "$response" ]; then
    	echo "$response" | jq -c '.[] | {
            	vulnId: .vulnId,
            	severity: .severity,
            	cvssScore: (.cvssV3BaseScore // .cvssV2BaseScore),
            	component: .components[0].name,
            	version: .components[0].version,
            	project: .components[0].project.name,
            	description: .description,
            	published: .published
    	}' 2>/dev/null
    	else
    	log_message "ERROR: Failed to fetch vulnerabilities from Dependency-Track"
    	return 1
    	fi
}

# Function to send to Wazuh
send_to_wazuh() {
    	local vuln_data="$1"

    	# Format for Wazuh logging
    	echo "dependency_track: $vuln_data" | logger -t dependency_track -p local0.info
    	log_message "Sent vulnerability data to Wazuh: $(echo "$vuln_data" | jq -r '.vulnId // "unknown"')"
}

# Main execution
main() {
    	log_message "Starting Dependency-Track vulnerability scan"

    	# Check if jq is installed
    	if ! command -v jq &> /dev/null; then
    	log_message "ERROR: jq is not installed. Please install it with: apt install jq"
    	exit 1
    	fi

    	# Get vulnerabilities and process them
    	while IFS= read -r vuln; do
    	if [ -n "$vuln" ]; then
            	send_to_wazuh "$vuln"
    	fi
    	done < <(get_vulnerabilities)

    	log_message "Dependency-Track vulnerability scan completed"
}

# Execute main function
main "$@"