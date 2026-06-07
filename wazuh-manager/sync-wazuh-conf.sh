#!/bin/bash
#
# Author: Adam 'tick' Pielak (tick@linuxmafia.pl)
# File: sync-wazuh-conf.sh
# Version 0.1 (01/2025)
#
# Script to synchronize Wazuh cluster configuration across all worker nodes.
# Based on Kevin Branch sync-ossec-conf script
# When grouping sections in the ossec.conf configuration by specifying the office, vulnmgmt, or simply nosync modules
# configuration will not be propagated to the worker.
#
# <!--
# <nosync>
# -->
#   <haproxy_helper>
#     <haproxy_disabled>no</haproxy_disabled>
#     <haproxy_address>lb.wazuh.siem</haproxy_address>
#     <haproxy_backend>wazuh_cluster</haproxy_backend>
#   </haproxy_helper>
# <!--
# </nosync>
# -->


RESTART_DELAY=15
CONFIG_MASTER="/var/ossec/etc/ossec.conf"
TMPDIR="/tmp"

# load all workers into the table
mapfile -t WORKERS < <(/var/ossec/bin/cluster_control -l | awk '/worker/ {print $1 "|" $4}' | sort)

for ENTRY in "${WORKERS[@]}"; do
    NODENAME="${ENTRY%%|*}"
    NODEIP="${ENTRY##*|}"

    echo "[+] Syncing Wazuh config to worker node: $NODENAME ($NODEIP)"

    CONFIG_TMP="$TMPDIR/${NODENAME}.ossec.conf"

    # prepare ossec.conf
    sed -e "s|<node_name>.*</node_name>|<node_name>$NODENAME</node_name>|" \
        -e "s|<node_type>.*</node_type>|<node_type>worker</node_type>|" \
        "$CONFIG_MASTER" > "$CONFIG_TMP"

    # sanitize
    sed -i -e 's|<interval>3h</interval>|<interval>300s</interval>|' \
           -e '/<office>/,/<\/office>/d' \
           -e '/<vulnmgmt>/,/<\/vulnmgmt>/d' \
           -e '/<nosync>/,/<\/nosync>/d' "$CONFIG_TMP"

    echo "[+] Backing up ossec.conf on $NODENAME..."
    ssh -q -T root@"$NODEIP" "mkdir -p /var/ossec/backup && cp /var/ossec/etc/ossec.conf /var/ossec/backup/ossec.conf.bak.$(date +%Y%m%d_%H%M%S)"

    echo "[+] Transferring configuration and files to $NODENAME..."
    scp -q "$CONFIG_TMP" root@"$NODEIP":"/var/ossec/etc/ossec.conf"
    scp -qr /var/ossec/etc/lists/* root@"$NODEIP":"/var/ossec/etc/lists/"
    scp -qr /var/ossec/integrations/* root@"$NODEIP":"/var/ossec/integrations/"
    scp -qr /var/ossec/active-response/bin/* root@"$NODEIP":"/var/ossec/active-response/bin/"
    scp -q /var/ossec/wodles/*.py root@"$NODEIP":"/var/ossec/wodles/"
    scp -q /var/ossec/wodles/*.conf root@"$NODEIP":"/var/ossec/wodles/"

    echo "[+] Adjusting permissions on $NODENAME..."
    ssh -q -T root@"$NODEIP" bash <<< '
[ -d /var/ossec/etc/lists ] && chown wazuh:wazuh /var/ossec/etc/lists/* && chmod 0660 /var/ossec/etc/lists/*
[ -d /var/ossec/etc/lists/amazon ] && chmod 0770 /var/ossec/etc/lists/amazon
[ -d /var/ossec/integrations ] && chown root:wazuh /var/ossec/integrations/* && chmod 0750 /var/ossec/integrations/*
[ -d /var/ossec/active-response/bin ] && chown root:wazuh /var/ossec/active-response/bin/* && chmod 0750 /var/ossec/active-response/bin/*
[ -d /var/ossec/wodles ] && chown root:wazuh /var/ossec/wodles/*.py /var/ossec/wodles/*.conf && chmod 0750 /var/ossec/wodles/*.py
chown wazuh:wazuh /var/ossec/etc/ossec.conf
systemctl restart wazuh-manager
'
    echo "[+] Verifying status on $NODENAME..."
    ssh -n root@"$NODEIP" 'systemctl status wazuh-manager | egrep -i "( Active: |WARNING|ERROR)" | sed "s/^\s\+/   /"'
    echo "[OK] Node $NODENAME done. Sleeping $RESTART_DELAY seconds."
    echo "--------------------------------------------------------------------------------------"
    sleep $RESTART_DELAY
done

echo "[Done] Wazuh cluster ossec.conf sync and restart complete."
