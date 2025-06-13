echo "logcollector.remote_commands=1" | out-file -encoding ASCII "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
echo "logcollector.rlimit_nofile=1048576" | out-file -encoding ASCII "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
echo "logcollector.max_files=100000" | out-file -encoding ASCII "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
echo "logcollector.max_lines=5000" | out-file -encoding ASCII "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
echo "sca.remote_commands=1" | out-file -encoding ASCII "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
echo "wazuh_command.remote_commands=1" | out-file -encoding ASCII "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
echo "logcollector.queue_size=10000" | out-file -encoding ASCII "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"

Write-Host "Restarting agent... "
Start-Sleep -s 5
Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue | Restart-Service -ErrorAction SilentlyContinue

#Restart-Service -Name WazuhSvc
#NET START WazuhSvc
