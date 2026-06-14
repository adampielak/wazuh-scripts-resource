<!-- Source: https://wazuh.com/blog/monitoring-hashicorp-vault-activities-with-wazuh/ | Article: Monitoring HashiCorp Vault activities with Wazuh -->
#!/bin/bash
# Wazuh - Vault Seal Active Response

LOG_FILE="/var/ossec/logs/active-responses.log"
VAULT_EXE="/usr/bin/vault"
TOKEN_FILE="/etc/vault.d/vault-seal.token"

#------------------------- Read Wazuh input -----------#
read INPUT_JSON
COMMAND=$(echo "$INPUT_JSON" | grep -o '"command":"[^"]*"' | cut -d'"' -f4)

if [ "$COMMAND" != "add" ]; then
    echo "$(date "+%b %d %H:%M:%S") $(hostname) vault-seal: INFO - Ignoring command '$COMMAND'." >> "$LOG_FILE"
    exit 0
fi

#------------------------- Environment setup ----------------------#
export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_SKIP_VERIFY=true #When using self-signed certificates (Vault default)

# Read token from protected file
if [ ! -f "$TOKEN_FILE" ]; then
    echo "$(date "+%b %d %H:%M:%S") $(hostname) vault-seal: ERROR - Token file not found." >> "$LOG_FILE"
    exit 1
fi
export VAULT_TOKEN=$(cat "$TOKEN_FILE")

#------------------------- Main workflow --------------------------#
$VAULT_EXE status > /dev/null 2>&1
case $? in
    2) echo "$(date "+%b %d %H:%M:%S") $(hostname) vault-seal: INFO - Already sealed." >> "$LOG_FILE"; exit 0 ;;
    1) echo "$(date "+%b %d %H:%M:%S") $(hostname) vault-seal: ERROR - Vault unreachable." >> "$LOG_FILE"; exit 1 ;;
esac

OUTPUT=$($VAULT_EXE operator seal 2>&1)
if [ $? -eq 0 ]; then
    echo "$(date "+%b %d %H:%M:%S") $(hostname) vault-seal: SUCCESS - Vault sealed. INVESTIGATE IMMEDIATELY." >> "$LOG_FILE"
else
    echo "$(date "+%b %d %H:%M:%S") $(hostname) vault-seal: ERROR - Seal failed: $OUTPUT" >> "$LOG_FILE"
    exit 1
fi