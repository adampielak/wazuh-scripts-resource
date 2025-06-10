#!/usr/bin/env bash
#
# Author: Adam 'tick' Pielak (tick@linuxmafia.pl)
# File: add-agent-to-group.sh
# Version 0.1 (06/2025)
#
# This script assigns (and retrieves the list of agents using Wazuh API) each agent to a group based on its OS: WINDOWS, LINUX, or MACOS.
# It automatically creates the required groups if they do not exist.
#

set -euo pipefail

API="https://wazuh.local:55000"
USER="wazuh-wui"
PASS="wazuh-wui"
CURL_OPTS="-s -k"

# Get JWT token
TOKEN=$(curl $CURL_OPTS -u "$USER:$PASS" -X POST "$API/security/user/authenticate?raw=true")

# Ensure groups exist
for GROUP in WINDOWS LINUX MACOS; do
  curl $CURL_OPTS -X POST "$API/groups" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"group_id\":\"$GROUP\"}" \
    || echo "Group $GROUP already exists"
done

# Get agents with os.platform info
AGENTS_JSON=$(curl $CURL_OPTS -X GET "$API/agents?select=id,os.platform" \
  -H "Authorization: Bearer $TOKEN")

# Assign agent to groups
echo "$AGENTS_JSON" | jq -c '.data.affected_items[]' | while read agent; do
  ID=$(echo "$agent" | jq -r '.id')
  PLATFORM=$(echo "$agent" | jq -r '.os.platform // ""' | awk '{print tolower($0)}')

  if [[ "$PLATFORM" == *"win"* ]]; then
    TARGET=WINDOWS
  elif [[ "$PLATFORM" == *"darwin"* ]] || [[ "$PLATFORM" == *"macos"* ]]; then
    TARGET=MACOS
  else
    TARGET=LINUX
  fi

  echo "Agent ID: $ID add to group: $TARGET"

  curl $CURL_OPTS -X PUT "$API/agents/$ID/group/$TARGET" \
    -H "Authorization: Bearer $TOKEN" \
    || echo "Error assigning Agent ID $ID"
done

echo "Done!"
