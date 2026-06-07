$optionsPath = "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"

@"
logcollector.remote_commands=1
logcollector.rlimit_nofile=1048576
logcollector.max_files=100000
logcollector.max_lines=5000
logcollector.queue_size=10000
sca.remote_commands=1
wazuh_command.remote_commands=1
"@ | Set-Content -Path $optionsPath -Encoding ASCII

Write-Host "Restarting agent..."
Start-Sleep -Seconds 5
Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue | Restart-Service -ErrorAction SilentlyContinue
