#!/bin/bash
# oneliner
# echo -e "logcollector.rlimit_nofile=1048576\nlogcollector.max_files=100000\nlogcollector.max_lines=5000\nsca.remote_commands=1\nwazuh_command.remote_commands=1\nlogcollector.remote_commands=1\nlogcollector.queue_size=10000" > /var/ossec/etc/local_internal_options.conf

echo "
logcollector.rlimit_nofile=1048576
logcollector.max_files=100000
logcollector.remote_commands=1
wazuh_command.remote_commands=1
sca.remote_commands=1
logcollector.queue_size=10000
logcollector.max_lines=5000
" > /var/ossec/etc/local_internal_options.conf

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent.service

